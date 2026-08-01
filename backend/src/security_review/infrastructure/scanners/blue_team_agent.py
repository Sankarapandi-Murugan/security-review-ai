import re
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class BlueTeamAgent(Agent):
    """Defensive security assessment - hardening and detection."""
    
    agent_type = AgentType.BLUE_TEAM

    def execute(self, target: str | None) -> list[Finding]:
        """Perform blue-team (defensive) analysis."""
        findings = []
        
        if not target:
            return findings
        
        # Check defensive measures
        findings.extend(self._check_logging_instrumentation(target))
        findings.extend(self._check_error_handling(target))
        findings.extend(self._check_input_validation(target))
        
        if not findings:
            findings.append(
                Finding(
                    title="Blue team assessment completed",
                    severity=FindingSeverity.LOW,
                    description="Good defensive practices detected in preliminary assessment.",
                    evidence=target,
                    remediation="Maintain strong security logging and incident response capabilities.",
                )
            )
        
        return findings
    
    def _check_logging_instrumentation(self, target: str) -> list[Finding]:
        """Check for proper logging and monitoring instrumentation."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                has_logging = False
                
                for py_file in target_path.rglob("*.py"):
                    try:
                        with open(py_file) as f:
                            content = f.read()
                        
                        if "logging" in content or "logger" in content:
                            has_logging = True
                            break
                    except Exception:
                        pass
                
                if not has_logging:
                    findings.append(
                        Finding(
                            title="Insufficient logging instrumentation",
                            severity=FindingSeverity.MEDIUM,
                            description="Application lacks proper logging for security events.",
                            evidence=target,
                            remediation="Add comprehensive logging for authentication, authorization, and sensitive operations.",
                        )
                    )
        
        except Exception:
            pass
        
        return findings
    
    def _check_error_handling(self, target: str) -> list[Finding]:
        """Check for proper error handling and information disclosure."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                for py_file in target_path.rglob("*.py"):
                    try:
                        with open(py_file) as f:
                            content = f.read()
                        
                        # Check for bare except
                        if re.search(r"except\s*:", content):
                            findings.append(
                                Finding(
                                    title="Bare except clause found",
                                    severity=FindingSeverity.LOW,
                                    description="Bare except can hide bugs and make debugging difficult.",
                                    evidence=str(py_file),
                                    remediation="Catch specific exceptions and log them appropriately.",
                                )
                            )
                            break
                        
                        # Check if raising exceptions with sensitive data
                        if re.search(r"raise.*f['\"].*password|raise.*f['\"].*token", content, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    title="Potential sensitive data in exceptions",
                                    severity=FindingSeverity.MEDIUM,
                                    description="Exception messages may leak sensitive information.",
                                    evidence=str(py_file),
                                    remediation="Sanitize exception messages before exposing to users.",
                                )
                            )
                            break
                    
                    except Exception:
                        pass
        
        except Exception:
            pass
        
        return findings
    
    def _check_input_validation(self, target: str) -> list[Finding]:
        """Check for input validation and sanitization."""
        findings = []
        
        try:
            target_path = Path(target)
            if target_path.is_dir():
                has_validation = False
                
                for py_file in target_path.rglob("*.py"):
                    try:
                        with open(py_file) as f:
                            content = f.read()
                        
                        # Look for validation patterns
                        if re.search(r"validate|sanitize|escape|strip|check", content, re.IGNORECASE):
                            has_validation = True
                            break
                    except Exception:
                        pass
                
                if not has_validation:
                    findings.append(
                        Finding(
                            title="Limited input validation observed",
                            severity=FindingSeverity.MEDIUM,
                            description="Code may lack sufficient input validation and sanitization.",
                            evidence=target,
                            remediation="Implement comprehensive input validation using libraries like Pydantic.",
                        )
                    )
        
        except Exception:
            pass
        
        return findings
