import json
from pathlib import Path

import httpx

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class ApiSecurityAgent(Agent):
    """Tests API endpoints for common security issues."""
    
    agent_type = AgentType.API_SECURITY

    def execute(self, target: str | None) -> list[Finding]:
        """Test API endpoints for security vulnerabilities."""
        findings = []
        
        if not target:
            return findings
        
        # Check if target looks like a URL
        if target.startswith("http://") or target.startswith("https://"):
            findings.extend(self._test_api_endpoint(target))
        else:
            # Otherwise treat as file path to OpenAPI spec
            findings.extend(self._analyze_openapi_spec(target))
        
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
    
    def _test_api_endpoint(self, url: str) -> list[Finding]:
        """Test an API endpoint for common vulnerabilities."""
        findings = []
        
        try:
            with httpx.Client(timeout=10.0) as client:
                # Test 1: Check for authentication
                try:
                    response = client.get(url)
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
    
    def _analyze_openapi_spec(self, spec_path: str) -> list[Finding]:
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
