import json
import subprocess
import tempfile
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class TrivyAgent(Agent):
    """Filesystem/container scanner using the Trivy CLI.

    This adapter invokes the `trivy` binary (must be installed on the host/container)
    and parses JSON output into `Finding` objects.
    """

    agent_type = AgentType.TRIVY

    def execute(self, target: str | None) -> list[Finding]:
        findings: list[Finding] = []

        if not target:
            return findings

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "trivy-report.json"

                # Use Trivy filesystem scan for a directory target. Quiet mode and JSON output.
                # Falls back to image scan if the target looks like an image reference.
                cmd = [
                    "trivy",
                    "fs",
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                    str(target),
                ]

                subprocess.run(cmd, capture_output=True, text=True, timeout=120)

                if output_file.exists():
                    with open(output_file) as f:
                        report = json.load(f)

                    # Trivy JSON has a list of results with 'Vulnerabilities'
                    for result in report.get("Results", []) or report.get("results", []) or []:
                        for vuln in result.get("Vulnerabilities", []):
                            sev_map = {
                                "UNKNOWN": FindingSeverity.LOW,
                                "LOW": FindingSeverity.LOW,
                                "MEDIUM": FindingSeverity.MEDIUM,
                                "HIGH": FindingSeverity.HIGH,
                                "CRITICAL": FindingSeverity.CRITICAL,
                            }

                            findings.append(
                                Finding(
                                    title=f"{vuln.get('VulnerabilityID', 'VULN')} - {vuln.get('PkgName', '')}",
                                    severity=sev_map.get(vuln.get("Severity", "MEDIUM"), FindingSeverity.MEDIUM),
                                    description=vuln.get("Description", ""),
                                    evidence=f"{vuln.get('PkgName','')} {vuln.get('InstalledVersion','')}",
                                    remediation=f"Upgrade to: {vuln.get('FixedVersion','') or 'see advisory'}",
                                )
                            )

        except subprocess.TimeoutExpired:
            findings.append(
                Finding(
                    title="Trivy scan timeout",
                    severity=FindingSeverity.MEDIUM,
                    description="Trivy scan timed out while scanning the target.",
                    evidence=target,
                    remediation="Try scanning a smaller target or increase timeout.",
                )
            )
        except FileNotFoundError:
            findings.append(
                Finding(
                    title="Trivy not installed",
                    severity=FindingSeverity.MEDIUM,
                    description="Trivy binary not found on PATH.",
                    evidence=target,
                    remediation="Install Trivy: https://aquasecurity.github.io/trivy/installation/",
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    title="Trivy scan error",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Error running Trivy: {str(e)}",
                    evidence=target,
                    remediation="Verify the target and Trivy installation.",
                )
            )

        return findings
