import json
import subprocess
import tempfile
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class WhiteBoxAgent(Agent):
    """Static code analysis using Bandit for Python code security."""
    
    agent_type = AgentType.WHITE_BOX

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Run Bandit on Python code and parse results."""
        findings = []
        
        if not target:
            return findings
        
        try:
            # Create a temporary directory for Bandit output
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "bandit-report.json"
                
                # Run Bandit with JSON output
                subprocess.run(
                    [
                        "bandit",
                        "-r",
                        target,
                        "-f", "json",
                        "-o", str(output_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                # Parse the JSON output regardless of exit code
                if output_file.exists():
                    with open(output_file) as f:
                        report = json.load(f)
                    
                    # Convert Bandit results to findings
                    for result_item in report.get("results", []):
                        severity_map = {
                            "LOW": FindingSeverity.LOW,
                            "MEDIUM": FindingSeverity.MEDIUM,
                            "HIGH": FindingSeverity.HIGH,
                        }
                        
                        findings.append(
                            Finding(
                                title=result_item.get("test_name", "Code Security Issue"),
                                severity=severity_map.get(
                                    result_item.get("severity", "MEDIUM"),
                                    FindingSeverity.MEDIUM,
                                ),
                                description=result_item.get("issue_text", ""),
                                evidence=f"{result_item.get('filename')}:{result_item.get('line_number')}",
                                remediation=(
                                    "Review the flagged code pattern and apply appropriate "
                                    "secure coding practices as per OWASP guidelines."
                                ),
                            )
                        )
        except subprocess.TimeoutExpired:
            findings.append(
                Finding(
                    title="Bandit scan timeout",
                    severity=FindingSeverity.MEDIUM,
                    description="Static analysis scan timed out while scanning the target.",
                    evidence=target,
                    remediation="Try scanning a smaller codebase or increase timeout.",
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    title="White-box analysis error",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Failed to run static analysis: {str(e)}",
                    evidence=target,
                    remediation="Verify the target path is valid and accessible.",
                )
            )
        
        return findings
