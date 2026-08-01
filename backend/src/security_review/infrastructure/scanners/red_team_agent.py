import re
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class RedTeamAgent(Agent):
    """Offensive security assessment - simulates attacker perspective."""
    
    agent_type = AgentType.RED_TEAM

    def execute(self, target: str | None) -> list[Finding]:
        """Perform red-team (offensive) analysis."""
        findings = []
        
        if not target:
            return findings
        
        # Analyze code for common attack patterns
        findings.extend(self._analyze_attack_vectors(target))
        findings.extend(self._check_auth_bypass_vectors(target))
        findings.extend(self._check_injection_vectors(target))
        
        if not findings:
            findings.append(
                Finding(
                    title="Red team assessment completed",
                    severity=FindingSeverity.LOW,
                    description="No obvious exploitable attack paths detected in preliminary assessment.",
                    evidence=target,
                    remediation="Conduct regular red-team exercises to validate defenses.",
                )
            )
        
        return findings
    
    def _analyze_attack_vectors(self, target: str) -> list[Finding]:
        """Check for common attack vectors."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                # Look for dangerous patterns in code
                for py_file in target_path.rglob("*.py"):
                    try:
                        with open(py_file) as f:
                            content = f.read()
                        
                        # Check for dangerous patterns
                        if re.search(r"eval\s*\(", content):
                            findings.append(
                                Finding(
                                    title="Dangerous eval() usage detected",
                                    severity=FindingSeverity.CRITICAL,
                                    description="Code uses eval() which can lead to arbitrary code execution.",
                                    evidence=str(py_file),
                                    remediation="Replace eval() with safer alternatives like ast.literal_eval().",
                                )
                            )
                        
                        if re.search(r"exec\s*\(", content):
                            findings.append(
                                Finding(
                                    title="Dangerous exec() usage detected",
                                    severity=FindingSeverity.CRITICAL,
                                    description="Code uses exec() which can lead to arbitrary code execution.",
                                    evidence=str(py_file),
                                    remediation="Replace exec() with safer alternatives.",
                                )
                            )
                        
                        if re.search(r"pickle\.(loads|load)\s*\(", content):
                            findings.append(
                                Finding(
                                    title="Insecure deserialization with pickle",
                                    severity=FindingSeverity.CRITICAL,
                                    description="Pickle deserialization can execute arbitrary code.",
                                    evidence=str(py_file),
                                    remediation="Use JSON or other safe serialization formats.",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_auth_bypass_vectors(self, target: str) -> list[Finding]:
        """Check for authentication bypass opportunities."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for py_file in target_path.rglob("*.py"):
                    try:
                        with open(py_file) as f:
                            content = f.read()
                        
                        # Check for hardcoded credentials
                        if re.search(r"password\s*=\s*['\"]([^'\"]{1,})['\"]", content, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Hardcoded credentials detected",
                                    severity=FindingSeverity.CRITICAL,
                                    description="Passwords or API keys appear to be hardcoded in source.",
                                    evidence=str(py_file),
                                    remediation="Use environment variables or secure vaults for credentials.",
                                )
                            )
                        
                        # Check for authentication shortcuts
                        if re.search(r"if\s+.*password.*==.*pass", content, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Weak authentication check",
                                    severity=FindingSeverity.HIGH,
                                    description="Authentication logic appears overly simplistic.",
                                    evidence=str(py_file),
                                    remediation="Use proper authentication libraries (e.g., bcrypt, argon2).",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_injection_vectors(self, target: str) -> list[Finding]:
        """Check for injection vulnerabilities."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for py_file in target_path.rglob("*.py"):
                    try:
                        with open(py_file) as f:
                            content = f.read()
                        
                        # Check for SQL injection patterns
                        if re.search(r'query.*\+.*input|format\(.*query|f["\'].*\{.*query', content, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Potential SQL injection vulnerability",
                                    severity=FindingSeverity.CRITICAL,
                                    description="Query construction uses string concatenation with user input.",
                                    evidence=str(py_file),
                                    remediation="Use parameterized queries and prepared statements.",
                                )
                            )
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
