import json
import subprocess
import tempfile
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class SecretDetectionAgent(Agent):
    """Detects secrets and sensitive data in source code using detect-secrets."""
    
    agent_type = AgentType.SECRET_DETECTION

    def execute(self, target: str | None) -> list[Finding]:
        """Scan for exposed secrets and credentials."""
        findings = []
        
        if not target:
            return findings
        
        try:
            target_path = Path(target)
            if not target_path.exists():
                return [
                    Finding(
                        title="Target path not found",
                        severity=FindingSeverity.LOW,
                        description=f"Could not access target path: {target}",
                        evidence=target,
                        remediation="Verify the target path is accessible.",
                    )
                ]
            
            # Run detect-secrets scan
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "secrets-report.json"
                
                subprocess.run(
                    [
                        "detect-secrets",
                        "scan",
                        "--baseline", str(output_file),
                        str(target_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                
                if output_file.exists():
                    with open(output_file) as f:
                        report = json.load(f)
                    
                    # Process findings from detect-secrets baseline
                    for file_path, secrets in report.get("results", {}).items():
                        for secret in secrets:
                            findings.append(
                                Finding(
                                    title=f"Potential secret detected: {secret.get('type', 'unknown')}",
                                    severity=FindingSeverity.CRITICAL,
                                    description=f"Detected possible {secret.get('type', 'credential')} in source code",
                                    evidence=f"{file_path}:{secret.get('line_number', 'unknown')}",
                                    remediation=(
                                        "1. Immediately rotate the exposed credential "
                                        "2. Remove from version control history "
                                        "3. Add to .gitignore and secret scanning CI"
                                    ),
                                )
                            )
        
        except subprocess.TimeoutExpired:
            findings.append(
                Finding(
                    title="Secret scan timeout",
                    severity=FindingSeverity.MEDIUM,
                    description="Secret detection scan timed out",
                    evidence=target,
                    remediation="Try scanning a smaller codebase.",
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    title="Secret detection error",
                    severity=FindingSeverity.LOW,
                    description=f"Failed to scan for secrets: {str(e)}",
                    evidence=target,
                    remediation="Verify the target path is accessible.",
                )
            )
        
        return findings
