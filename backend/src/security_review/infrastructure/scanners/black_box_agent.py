import socket
from urllib.parse import urlparse

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class BlackBoxAgent(Agent):
    """External reconnaissance and vulnerability assessment."""
    
    agent_type = AgentType.BLACK_BOX

    def execute(self, target: str | None) -> list[Finding]:
        """Perform black-box testing on the target."""
        findings = []
        
        if not target:
            return findings
        
        # Extract host from URL or use as hostname
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            host = parsed.netloc.split(":")[0]
        else:
            host = target.split(":")[0]
        
        # Common ports to check
        common_ports = [
            (80, "HTTP"),
            (443, "HTTPS"),
            (22, "SSH"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (27017, "MongoDB"),
            (9200, "Elasticsearch"),
        ]
        
        open_ports = []
        for port, service in common_ports:
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
            
            with httpx.Client(timeout=5.0) as client:
                response = client.get(target, follow_redirects=True)
                
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
