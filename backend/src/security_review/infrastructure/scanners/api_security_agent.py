import base64
import json
import re
from pathlib import Path
from urllib.parse import urljoin

import httpx

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity

_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_=-]+\.[a-zA-Z0-9_=-]+\.[a-zA-Z0-9_=-]*")
_RATE_LIMIT_PROBE_COUNT = 15
_MALICIOUS_JWT_CLAIMS = {
    "alg-none admin claim": {"sub": "admin", "role": "admin", "exp": 9999999999},
    "alg-none expired token": {"sub": "test-user", "exp": 1},
}

# Common well-known locations where an OpenAPI/Swagger spec is published.
_OPENAPI_SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
)

# Common admin/debug/internal endpoints attackers probe for that are frequently
# left undocumented ("hidden") in the published API spec.
_HIDDEN_ENDPOINT_CANDIDATES = (
    "/admin",
    "/api/admin",
    "/internal",
    "/api/internal",
    "/debug",
    "/api/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/metrics",
    "/api/metrics",
    "/api/v2",
    "/api/v1/users",
    "/api/users",
    "/graphql",
    "/api/graphql",
    "/.env",
    "/.git/config",
    "/swagger-ui",
    "/swagger-ui.html",
    "/config",
    "/api/config",
    "/backup",
    "/api/backup",
    "/test",
    "/api/test",
)


class ApiSecurityAgent(Agent):
    """Tests API endpoints for common security issues."""
    
    agent_type = AgentType.API_SECURITY

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Test API endpoints for security vulnerabilities."""
        findings = []
        
        if not target:
            return findings
        
        # Check if target looks like a URL
        if target.startswith("http://") or target.startswith("https://"):
            findings.extend(self._test_api_endpoint(target, authorized=authorized))
        else:
            # Otherwise treat as file path to OpenAPI spec
            findings.extend(self._analyze_openapi_spec(target, authorized=authorized))
        
        if not findings:
            findings.append(
                Finding(
                    title="API security scan completed",
                    severity=FindingSeverity.LOW,
                    description="No critical API security issues detected in preliminary scan.",
                    evidence=target or "API endpoint",
                    remediation="Continue monitoring API security best practices.",
                )
            )
        
        return findings
    
    def _test_api_endpoint(self, url: str, *, authorized: bool = False) -> list[Finding]:
        """Test an API endpoint for common vulnerabilities."""
        findings = []
        last_response: httpx.Response | None = None
        
        try:
            with httpx.Client(timeout=10.0) as client:
                # Test 1: Check for authentication
                try:
                    response = client.get(url)
                    last_response = response
                    if response.status_code == 200 and "api" in url.lower():
                        # Might be missing auth
                        findings.append(
                            Finding(
                                title="Potentially missing authentication",
                                severity=FindingSeverity.HIGH,
                                description="API endpoint returned 200 without credentials.",
                                evidence=url,
                                remediation="Verify endpoint requires proper authentication.",
                            )
                        )
                except Exception:
                    pass
                
                # Test 2: Check security headers
                try:
                    response = client.get(url)
                    last_response = response
                    headers = response.headers
                    
                    missing_headers = []
                    if not headers.get("x-content-type-options"):
                        missing_headers.append("X-Content-Type-Options")
                    if not headers.get("x-frame-options"):
                        missing_headers.append("X-Frame-Options")
                    if not headers.get("strict-transport-security"):
                        missing_headers.append("Strict-Transport-Security")
                    
                    if missing_headers:
                        findings.append(
                            Finding(
                                title="Missing security headers",
                                severity=FindingSeverity.MEDIUM,
                                description=f"API missing: {', '.join(missing_headers)}",
                                evidence=url,
                                remediation=f"Add security headers: {', '.join(missing_headers)}",
                            )
                        )
                except Exception:
                    pass

                # Passive check: inspect any JWT observed in the responses collected so
                # far for insecure claims (no extra requests needed).
                if last_response is not None:
                    findings.extend(self._check_exposed_jwt_claims(last_response, url))
                
                # Test 3: CORS policy
                try:
                    response = client.get(
                        url,
                        headers={"Origin": "https://attacker.com"}
                    )
                    cors_header = response.headers.get("access-control-allow-origin")
                    if cors_header == "*":
                        findings.append(
                            Finding(
                                title="Overly permissive CORS policy",
                                severity=FindingSeverity.HIGH,
                                description="CORS allows requests from any origin.",
                                evidence=url,
                                remediation="Restrict Access-Control-Allow-Origin to trusted domains.",
                            )
                        )
                except Exception:
                    pass

                # Test 4: Import the OpenAPI/Swagger spec (if published) and probe for
                # endpoints that exist live but aren't documented in it; test rate
                # limiting; and actively probe for weak JWT validation.
                if authorized:
                    findings.extend(self._discover_hidden_endpoints_from_live_target(client, url))
                    findings.extend(self._check_rate_limiting(client, url))
                    findings.extend(self._check_jwt_handling(client, url))
                else:
                    findings.append(
                        Finding(
                            title="Active API security testing skipped (authorization required)",
                            severity=FindingSeverity.LOW,
                            description=(
                                "OpenAPI spec discovery, undocumented-endpoint probing, rate-limit "
                                "testing, and JWT validation testing were skipped because the scan "
                                "job did not set target_authorization_confirmed=true."
                            ),
                            evidence=url,
                            remediation=(
                                "Re-run with target_authorization_confirmed=true once you have "
                                "explicit authorization to actively probe this target."
                            ),
                        )
                    )
        
        except Exception as e:
            findings.append(
                Finding(
                    title="API security test error",
                    severity=FindingSeverity.LOW,
                    description=f"Could not test API endpoint: {str(e)}",
                    evidence=url,
                    remediation="Verify the API endpoint is accessible.",
                )
            )
        
        return findings

    def _discover_hidden_endpoints_from_live_target(self, client: httpx.Client, url: str) -> list[Finding]:
        """Best-effort: locate a published OpenAPI/Swagger spec for ``url``'s origin,
        then probe a curated list of commonly-forgotten admin/debug endpoints and flag
        any that respond live but aren't present in the spec's documented paths."""
        findings: list[Finding] = []
        base_url = f"{httpx.URL(url).scheme}://{httpx.URL(url).netloc.decode()}"

        spec, spec_path = self._fetch_openapi_spec(client, base_url)
        documented_paths: set[str] = set()
        if spec is not None:
            documented_paths = self._extract_documented_paths(spec)
            findings.append(
                Finding(
                    title="OpenAPI/Swagger specification discovered",
                    severity=FindingSeverity.LOW,
                    description=(
                        f"Found a published API specification at {spec_path} declaring "
                        f"{len(documented_paths)} documented path(s)."
                    ),
                    evidence=urljoin(base_url, spec_path or ""),
                    remediation="Ensure the published spec accurately reflects all live endpoints.",
                )
            )

        findings.extend(self._probe_hidden_endpoints(client, base_url, documented_paths))
        return findings

    def _check_rate_limiting(self, client: httpx.Client, url: str) -> list[Finding]:
        """Send a burst of rapid consecutive requests and confirm the API enforces
        rate limiting (HTTP 429) rather than accepting unlimited traffic."""
        statuses: list[int] = []
        for _ in range(_RATE_LIMIT_PROBE_COUNT):
            try:
                response = client.get(url)
            except Exception:
                break
            statuses.append(response.status_code)
            if response.status_code == 429:
                break

        if not statuses or 429 in statuses:
            return []

        return [
            Finding(
                title="No rate limiting detected",
                severity=FindingSeverity.MEDIUM,
                description=(
                    f"Sent {len(statuses)} rapid consecutive requests to {url} without receiving "
                    "an HTTP 429 (Too Many Requests) response."
                ),
                evidence=f"{len(statuses)} requests, status codes observed: {sorted(set(statuses))}",
                remediation=(
                    "Implement per-client rate limiting (e.g. token-bucket/fixed-window) on this "
                    "endpoint to mitigate brute-force and denial-of-service abuse."
                ),
            )
        ]

    def _check_jwt_handling(self, client: httpx.Client, url: str) -> list[Finding]:
        """Actively probe for weak JWT validation by sending crafted 'alg: none' tokens
        (no signature required) and checking whether the server accepts them."""
        findings: list[Finding] = []

        try:
            baseline = client.get(url)
        except Exception:
            return findings

        for label, claims in _MALICIOUS_JWT_CLAIMS.items():
            token = self._craft_alg_none_jwt(claims)
            try:
                response = client.get(url, headers={"Authorization": f"Bearer {token}"})
            except Exception:
                continue

            if response.status_code < 300 and baseline.status_code >= 400:
                findings.append(
                    Finding(
                        title=f"Potential JWT validation weakness: {label}",
                        severity=FindingSeverity.CRITICAL,
                        description=(
                            "A crafted JWT using the insecure 'alg: none' algorithm was accepted "
                            f"(HTTP {response.status_code}) even though an unauthenticated request "
                            f"received HTTP {baseline.status_code}, suggesting the server does not "
                            "verify JWT signatures/claims."
                        ),
                        evidence=f"curl -H 'Authorization: Bearer {token}' {url}",
                        remediation=(
                            "Explicitly reject tokens using the 'none' algorithm, verify signatures "
                            "against a fixed allow-list of algorithms, and enforce exp/nbf validation."
                        ),
                    )
                )

        return findings

    def _check_exposed_jwt_claims(self, response: httpx.Response, url: str) -> list[Finding]:
        """Passively inspect any JWT observed in an already-fetched response body for
        insecure claims (no additional requests made)."""
        findings: list[Finding] = []

        try:
            match = _JWT_PATTERN.search(response.text)
        except Exception:
            return findings
        if not match:
            return findings

        parts = match.group(0).split(".")
        if len(parts) < 2:
            return findings

        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1])) if parts[1] else {}
        except Exception:
            return findings

        if str(header.get("alg", "")).lower() == "none":
            findings.append(
                Finding(
                    title="JWT issued with insecure 'alg: none'",
                    severity=FindingSeverity.CRITICAL,
                    description=(
                        "A JWT observed in the response is signed with the 'none' algorithm, "
                        "meaning anyone can forge a valid-looking token."
                    ),
                    evidence=url,
                    remediation=(
                        "Issue tokens signed with a strong algorithm (e.g. RS256/HS256) and "
                        "reject the 'none' algorithm server-side."
                    ),
                )
            )
        elif "exp" not in payload:
            findings.append(
                Finding(
                    title="JWT missing expiration (exp) claim",
                    severity=FindingSeverity.HIGH,
                    description=(
                        "A JWT observed in the response does not include an 'exp' claim, so it "
                        "never expires once issued."
                    ),
                    evidence=url,
                    remediation="Always set a short-lived 'exp' claim on issued tokens.",
                )
            )

        return findings

    @staticmethod
    def _b64url_decode(segment: str) -> bytes:
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    @staticmethod
    def _b64url_encode_json(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @classmethod
    def _craft_alg_none_jwt(cls, payload: dict) -> str:
        header = {"alg": "none", "typ": "JWT"}
        return f"{cls._b64url_encode_json(header)}.{cls._b64url_encode_json(payload)}."

    @staticmethod
    def _fetch_openapi_spec(client: httpx.Client, base_url: str) -> tuple[dict | None, str | None]:
        for spec_path in _OPENAPI_SPEC_PATHS:
            try:
                response = client.get(urljoin(base_url, spec_path))
            except Exception:
                continue

            if response.status_code != 200:
                continue

            spec = ApiSecurityAgent._parse_spec_body(response.text, spec_path)
            if spec is not None and "paths" in spec:
                return spec, spec_path

        return None, None

    @staticmethod
    def _parse_spec_body(body: str, spec_path: str) -> dict | None:
        try:
            if spec_path.endswith((".yaml", ".yml")):
                import yaml

                return yaml.safe_load(body)
            return json.loads(body)
        except Exception:
            return None

    @staticmethod
    def _extract_documented_paths(spec: dict) -> set[str]:
        return {
            ApiSecurityAgent._normalize_path(path)
            for path in spec.get("paths", {})
            if isinstance(path, str)
        }

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = path.split("?")[0].rstrip("/")
        return normalized or "/"

    def _probe_hidden_endpoints(
        self, client: httpx.Client, base_url: str, documented_paths: set[str]
    ) -> list[Finding]:
        findings: list[Finding] = []

        for candidate in _HIDDEN_ENDPOINT_CANDIDATES:
            if self._normalize_path(candidate) in documented_paths:
                continue

            candidate_url = urljoin(base_url, candidate)
            try:
                response = client.get(candidate_url)
            except Exception:
                continue

            if response.status_code == 404:
                continue

            if response.status_code < 300:
                severity = FindingSeverity.HIGH
                access = "publicly accessible"
            elif response.status_code < 400:
                severity = FindingSeverity.MEDIUM
                access = "redirects"
            elif response.status_code in (401, 403):
                severity = FindingSeverity.MEDIUM
                access = "exists but access-controlled"
            else:
                continue

            findings.append(
                Finding(
                    title=f"Hidden/undocumented endpoint discovered: {candidate}",
                    severity=severity,
                    description=(
                        f"'{candidate}' is not present in the published OpenAPI spec's paths but "
                        f"responded with HTTP {response.status_code} ({access})."
                    ),
                    evidence=f"curl -i {candidate_url}",
                    remediation=(
                        "Either document this endpoint in the API spec and secure it appropriately, "
                        "or remove/disable it if it should not be exposed."
                    ),
                )
            )

        return findings
    
    def _analyze_openapi_spec(self, spec_path: str, *, authorized: bool = False) -> list[Finding]:
        """Analyze OpenAPI specification for security issues."""
        findings = []
        
        try:
            spec_file = Path(spec_path)
            if not spec_file.exists():
                return findings
            
            with open(spec_file) as f:
                if spec_file.suffix.lower() == ".json":
                    spec = json.load(f)
                else:
                    import yaml
                    spec = yaml.safe_load(f)
            
            # Check for security definitions
            if "securityDefinitions" not in spec and "components" not in spec:
                findings.append(
                    Finding(
                        title="Missing security definitions in OpenAPI spec",
                        severity=FindingSeverity.HIGH,
                        description="No security schemes defined in the API specification.",
                        evidence=spec_path,
                        remediation="Add securityDefinitions or components/securitySchemes to the spec.",
                    )
                )
            
            # Check for unprotected endpoints
            if "paths" in spec:
                for path, path_item in spec["paths"].items():
                    for method, operation in path_item.items():
                        if method not in ["get", "post", "put", "delete", "patch"]:
                            continue
                        
                        if "security" not in operation and "security" not in spec:
                            findings.append(
                                Finding(
                                    title=f"Unprotected endpoint: {method.upper()} {path}",
                                    severity=FindingSeverity.HIGH,
                                    description="Endpoint lacks security requirements.",
                                    evidence=f"{method.upper()} {path}",
                                    remediation="Add security requirements to the endpoint.",
                                )
                            )
                            break  # Only report once per path

            # If the spec declares a live server and we're authorized to actively test
            # it, cross-reference documented paths against commonly-hidden endpoints.
            servers = spec.get("servers") or []
            server_url = servers[0].get("url") if servers and isinstance(servers[0], dict) else None
            if server_url and (server_url.startswith("http://") or server_url.startswith("https://")):
                if authorized:
                    documented_paths = self._extract_documented_paths(spec)
                    try:
                        with httpx.Client(timeout=10.0) as client:
                            findings.extend(
                                self._probe_hidden_endpoints(client, server_url, documented_paths)
                            )
                    except Exception:
                        pass
                else:
                    findings.append(
                        Finding(
                            title="Hidden-endpoint discovery skipped (authorization required)",
                            severity=FindingSeverity.LOW,
                            description=(
                                f"The spec declares a live server ({server_url}) but undocumented-"
                                "endpoint probing was skipped because target_authorization_confirmed "
                                "was not set."
                            ),
                            evidence=server_url,
                            remediation=(
                                "Re-run with target_authorization_confirmed=true once you have "
                                "explicit authorization to actively probe this target."
                            ),
                        )
                    )
        
        except Exception as e:
            findings.append(
                Finding(
                    title="OpenAPI analysis error",
                    severity=FindingSeverity.LOW,
                    description=f"Could not analyze OpenAPI spec: {str(e)}",
                    evidence=spec_path,
                    remediation="Verify the OpenAPI specification file is valid.",
                )
            )
        
        return findings

