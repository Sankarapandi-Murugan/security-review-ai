import json
import subprocess
import sys
import tempfile
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class WhiteBoxAgent(Agent):
    """Static code analysis using Bandit for Python code security."""

    agent_type = AgentType.WHITE_BOX

    @staticmethod
    def _resolve_target_path(target: str) -> str:
        candidate = Path(target).expanduser()
        if candidate.exists():
            return str(candidate)

        linux_root = "/workspaces/security-review-ai"
        if target.startswith(linux_root):
            relative = target[len(linux_root) :].lstrip("/")
            resolved = (Path.cwd().resolve().parent / relative).resolve()
            if resolved.exists():
                return str(resolved)

        return target

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Run Bandit on Python code and parse results."""
        findings = []

        if not target:
            return findings

        try:
            resolved_target = self._resolve_target_path(target)

            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "bandit-report.json"

                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "bandit",
                        "-r",
                        resolved_target,
                        "-f",
                        "json",
                        "-o",
                        str(output_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if output_file.exists():
                    with open(output_file) as f:
                        report = json.load(f)

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
