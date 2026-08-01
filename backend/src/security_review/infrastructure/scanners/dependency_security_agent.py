import json
import subprocess
import tempfile
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity


class DependencySecurityAgent(Agent):
    """Scans Python dependencies for known vulnerabilities using Safety."""
    
    agent_type = AgentType.DEPENDENCY_SECURITY

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Check dependencies for vulnerabilities using Safety."""
        findings = []
        
        if not target:
            return findings
        
        try:
            # Look for requirements.txt or pyproject.toml
            target_path = Path(target)
            requirements_files = []
            
            if target_path.is_file():
                requirements_files = [target_path]
            else:
                # Search for common dependency files
                requirements_files = list(target_path.glob("**/requirements*.txt"))
                requirements_files += list(target_path.glob("**/setup.py"))
            
            if not requirements_files:
                return [
                    Finding(
                        title="No dependency files found",
                        severity=FindingSeverity.CRITICAL,
                        description="Could not locate requirements.txt, setup.py, or other dependency files.",
                        evidence=target,
                        remediation="Ensure dependency files are present in the target directory.",
                    )
                ]
            
            # Check each requirements file
            for req_file in requirements_files:
                findings.extend(self._scan_requirements(req_file))
        
        except Exception as e:
            findings.append(
                Finding(
                    title="Dependency check error",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Failed to scan dependencies: {str(e)}",
                    evidence=target,
                    remediation="Verify the target path contains valid Python dependency files.",
                )
            )
        
        return findings
    
    def _scan_requirements(self, req_file: Path) -> list[Finding]:
        """Scan a requirements file using Safety."""
        findings = []
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_file = Path(tmpdir) / "safety-report.json"
                
                # Run Safety with JSON output
                subprocess.run(
                    [
                        "safety",
                        "check",
                        "--file", str(req_file),
                        "--json",
                        "--output", str(output_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                # Parse JSON output
                if output_file.exists():
                    with open(output_file) as f:
                        data = json.load(f)
                    
                    # Safety returns either a list of vulnerabilities or a dict with 'report'
                    vulns = data if isinstance(data, list) else data.get("report", [])
                    
                    for vuln in vulns:
                        severity = FindingSeverity.HIGH if vuln.get("advisory", "").count("critical") > 0 else FindingSeverity.MEDIUM
                        
                        findings.append(
                            Finding(
                                title=f"Vulnerable dependency: {vuln.get('package', 'unknown')}",
                                severity=severity,
                                description=vuln.get("advisory", "Known vulnerability in dependency"),
                                evidence=f"{vuln.get('package', 'unknown')} {vuln.get('vulnerable_spec', 'unknown version')}",
                                remediation=f"Update {vuln.get('package', 'package')} to version {vuln.get('safe_version', 'latest safe version')}",
                            )
                        )
        except subprocess.TimeoutExpired:
            findings.append(
                Finding(
                    title="Dependency scan timeout",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Safety check timed out scanning {req_file.name}",
                    evidence=str(req_file),
                    remediation="Try again or check network connectivity.",
                )
            )
        except json.JSONDecodeError:
            # Safety might not find vulnerabilities or may not return JSON
            pass
        except Exception as e:
            findings.append(
                Finding(
                    title="Dependency scan error",
                    severity=FindingSeverity.LOW,
                    description=f"Error scanning {req_file.name}: {str(e)}",
                    evidence=str(req_file),
                    remediation="Verify the requirements file is valid.",
                )
            )
        
        return findings
