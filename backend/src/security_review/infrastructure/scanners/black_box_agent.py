import re
import socket
import uuid
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urljoin, urlparse

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity
from security_review.infrastructure.security.outbound_url_validation import (
    UnsafeOutboundUrlError,
    validate_public_http_url,
)

if TYPE_CHECKING:
    import httpx

_LINK_PATTERN = re.compile(r'href=["\']([^"\'#\s]+)', re.IGNORECASE)
_FORM_PATTERN = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_CSRF_TOKEN_HINT = re.compile(r"csrf|_token|authenticity_token", re.IGNORECASE)
_SQL_ERROR_SIGNATURES = (
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql",
    "ora-01756",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "pg_query",
    "syntax error at or near",
    "warning: mysql",
)
_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
}
_MAX_CRAWL_PAGES = 15
_SCANNER_USER_AGENT = "security-review-ai-blackbox-agent/1.0 (+authorized-security-assessment)"


class BlackBoxAgent(Agent):
    """External reconnaissance and vulnerability assessment."""

    agent_type = AgentType.BLACK_BOX

    _COMMON_PORTS = [
        (80, "HTTP"),
        (443, "HTTPS"),
        (22, "SSH"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (27017, "MongoDB"),
        (9200, "Elasticsearch"),
    ]

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Perform black-box testing on the target."""
        findings = []

        if not target:
            return findings

        is_url = target.startswith(("http://", "https://"))
        try:
            validate_public_http_url(target if is_url else f"https://{target}")
        except UnsafeOutboundUrlError as exc:
            return [
                Finding(
                    title="External target rejected by network safety policy",
                    severity=FindingSeverity.LOW,
                    description=str(exc),
                    evidence=target,
                    remediation="Use a publicly routable target that is explicitly authorized for testing.",
                )
            ]

        # Extract host from URL or use as hostname
        if is_url:
            host = urlparse(target).netloc.split(":")[0]
        else:
            host = target.split(":")[0]

        open_ports = []
        for port, service in self._COMMON_PORTS:
            if self._is_port_open(host, port):
                open_ports.append((port, service))
                findings.append(
                    Finding(
                        title=f"Exposed service detected: {service} on port {port}",
                        severity=FindingSeverity.MEDIUM,
                        description=f"Detected accessible {service} service on the external surface.",
                        evidence=f"{host}:{port}",
                        remediation=f"Verify if {service} should be exposed externally. Use firewall rules to restrict access.",
                    )
                )

        # Additional check for standard web server issues
        if any(port == 80 or port == 443 for port, _ in open_ports):
            findings.extend(self._check_web_server(target))

        if is_url:
            if authorized:
                findings.extend(self._deep_web_assessment(target))
            else:
                findings.append(
                    Finding(
                        title="Deep active testing skipped (authorization required)",
                        severity=FindingSeverity.LOW,
                        description=(
                            "Crawling, injection probing, CSRF/header analysis were skipped because "
                            "the scan job did not set target_authorization_confirmed=true."
                        ),
                        evidence=target,
                        remediation=(
                            "Re-run the scan job with target_authorization_confirmed=true once you "
                            "have explicit authorization to actively test this target."
                        ),
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    title="Black-box assessment completed",
                    severity=FindingSeverity.LOW,
                    description="No obvious external vulnerabilities detected in preliminary assessment.",
                    evidence=target,
                    remediation="Continue monitoring external surface for emerging threats.",
                )
            )

        return findings

    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a port is open on the host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _check_web_server(self, target: str) -> list[Finding]:
        """Check web server for common issues."""
        findings = []

        try:
            import httpx

            with httpx.Client(timeout=5.0, headers={"User-Agent": _SCANNER_USER_AGENT}) as client:
                response = client.get(target, follow_redirects=False)

                # Check for default pages
                if any(phrase in response.text.lower() for phrase in ["apache", "nginx", "iis"]):
                    findings.append(
                        Finding(
                            title="Default/placeholder web content detected",
                            severity=FindingSeverity.MEDIUM,
                            description="Web server appears to be running default configuration.",
                            evidence=target,
                            remediation="Deploy actual application and hide server version information.",
                        )
                    )

        except Exception:
            pass

        return findings

    def _deep_web_assessment(self, target: str) -> list[Finding]:
        """Authorized-only active testing: crawl, discover endpoints, and probe for
        common web vulnerabilities (missing security headers, CSRF, reflected XSS,
        error-based SQL injection), producing PoC requests as evidence."""
        findings: list[Finding] = []

        try:
            import httpx

            with httpx.Client(
                timeout=5.0, headers={"User-Agent": _SCANNER_USER_AGENT}, follow_redirects=False
            ) as client:
                pages = self._crawl(client, target)

                if pages:
                    first_url, first_response = pages[0]
                    findings.extend(self._check_security_headers(first_response, first_url))

                for url, response in pages:
                    findings.extend(self._check_csrf_forms(response.text, url))
                    if urlparse(url).query:
                        findings.extend(self._check_reflected_xss(client, url))
                        findings.extend(self._check_sql_error_signatures(client, url))
        except Exception:
            pass

        return findings

    def _crawl(self, client, start_url: str) -> list[tuple[str, "httpx.Response"]]:
        """Breadth-first, same-origin crawl of GET-able pages (read-only, capped)."""
        origin = urlparse(start_url).netloc
        visited: set[str] = set()
        queue = [start_url]
        pages: list[tuple[str, "httpx.Response"]] = []

        while queue and len(pages) < _MAX_CRAWL_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                response = client.get(url)
            except Exception:
                continue

            pages.append((url, response))

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type:
                continue

            for match in _LINK_PATTERN.finditer(response.text):
                candidate = urljoin(url, match.group(1))
                if urlparse(candidate).netloc == origin and candidate not in visited:
                    queue.append(candidate)

        return pages

    def _check_security_headers(self, response, url: str) -> list[Finding]:
        findings = []
        headers_lower = {key.lower() for key in response.headers.keys()}
        missing = [name for key, name in _SECURITY_HEADERS.items() if key not in headers_lower]
        if missing:
            findings.append(
                Finding(
                    title="Missing recommended security headers",
                    severity=FindingSeverity.MEDIUM,
                    description=f"The following security headers are missing: {', '.join(missing)}.",
                    evidence=f"curl -I {url}",
                    remediation="Configure the web server/application to send these headers on all responses.",
                )
            )
        return findings

    def _check_csrf_forms(self, html: str, url: str) -> list[Finding]:
        findings = []
        for form_match in _FORM_PATTERN.finditer(html):
            form_html = form_match.group(0)
            if "post" in form_html.lower() and not _CSRF_TOKEN_HINT.search(form_html):
                findings.append(
                    Finding(
                        title="Form without visible CSRF protection",
                        severity=FindingSeverity.MEDIUM,
                        description="A state-changing form was found with no recognizable CSRF token field.",
                        evidence=url,
                        remediation="Add anti-CSRF tokens (e.g. synchronizer token pattern) to all state-changing forms.",
                    )
                )
                break
        return findings

    def _check_reflected_xss(self, client, url: str) -> list[Finding]:
        findings = []
        marker = f"sra{uuid.uuid4().hex[:8]}<b>"
        probe_url = self._replace_query_values(url, marker)
        try:
            response = client.get(probe_url)
        except Exception:
            return findings

        if marker in response.text:
            findings.append(
                Finding(
                    title="Potential reflected Cross-Site Scripting (XSS)",
                    severity=FindingSeverity.HIGH,
                    description=(
                        "A query parameter value was reflected back in the response body "
                        "without apparent encoding."
                    ),
                    evidence=f"curl '{probe_url}'",
                    remediation="Contextually encode/escape all user-controlled output before rendering it in HTML.",
                )
            )
        return findings

    def _check_sql_error_signatures(self, client, url: str) -> list[Finding]:
        findings = []
        probe_url = self._replace_query_values(url, "'")
        try:
            response = client.get(probe_url)
        except Exception:
            return findings

        body = response.text.lower()
        if any(signature in body for signature in _SQL_ERROR_SIGNATURES):
            findings.append(
                Finding(
                    title="Potential SQL Injection (error-based)",
                    severity=FindingSeverity.CRITICAL,
                    description="Injecting a single quote into a query parameter surfaced a database error message.",
                    evidence=f"curl '{probe_url}'",
                    remediation="Use parameterized queries/prepared statements and disable verbose DB error output.",
                )
            )
        return findings

    @staticmethod
    def _replace_query_values(url: str, replacement: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        new_query = "&".join(f"{key}={replacement}" for key in params)
        return parsed._replace(query=new_query).geturl()

