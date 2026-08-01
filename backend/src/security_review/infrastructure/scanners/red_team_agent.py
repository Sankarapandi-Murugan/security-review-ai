import re
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity

_INTERNAL_HOST_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
_PRIV_ESC_PATTERN = re.compile(
    r"os\.system\([^)]*sudo|subprocess\.\w+\([^)]*sudo"
    r"|chmod\s*\(\s*[\"']?0?o?777|is_admin\s*=\s*True|role\s*==\s*[\"']admin[\"']",
    re.IGNORECASE,
)


class RedTeamAgent(Agent):
    """Offensive security assessment - simulates attacker perspective."""
    
    agent_type = AgentType.RED_TEAM

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Perform red-team (offensive) analysis."""
        findings = []
        
        if not target:
            return findings
        
        # Analyze code for common attack patterns
        findings.extend(self._analyze_attack_vectors(target))
        findings.extend(self._check_auth_bypass_vectors(target))
        findings.extend(self._check_injection_vectors(target))
        findings.extend(self._check_privilege_escalation_vectors(target))
        findings.extend(self._check_lateral_movement_indicators(target))

        # Simulate attacker behavior: chain individually-modest findings that live in
        # the same file into a single, higher-severity end-to-end attack path.
        findings.extend(self._chain_attack_paths(findings))

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

    def _check_privilege_escalation_vectors(self, target: str) -> list[Finding]:
        """Simulate attempts to escalate privileges: look for code that shells out with
        elevated privileges, sets overly-permissive file modes, or gates admin access on
        naive/trusted-input checks."""
        findings = []

        try:
            target_path = Path(target)
            if target_path.is_dir():
                for py_file in target_path.rglob("*.py"):
                    try:
                        content = py_file.read_text()
                    except Exception:
                        continue

                    if _PRIV_ESC_PATTERN.search(content):
                        findings.append(
                            Finding(
                                title="Potential privilege escalation vector",
                                severity=FindingSeverity.HIGH,
                                description=(
                                    "Code contains a pattern commonly abused to escalate privileges "
                                    "(elevated shell-out, overly-permissive file mode, or a "
                                    "trust-the-caller admin check)."
                                ),
                                evidence=str(py_file),
                                remediation=(
                                    "Avoid running subprocesses with elevated privileges from application "
                                    "code, use least-permissive file modes, and derive admin status from a "
                                    "verified session/role, never from client-controlled input."
                                ),
                            )
                        )

        except Exception:
            pass

        return findings

    def _check_lateral_movement_indicators(self, target: str) -> list[Finding]:
        """Simulate reconnaissance for lateral movement: hardcoded internal network
        addresses in source code are a common pivot point (SSRF targets, forgotten
        internal admin panels, service credentials reused across hosts)."""
        findings = []

        try:
            target_path = Path(target)
            if target_path.is_dir():
                for py_file in target_path.rglob("*.py"):
                    try:
                        content = py_file.read_text()
                    except Exception:
                        continue

                    match = _INTERNAL_HOST_PATTERN.search(content)
                    if match:
                        findings.append(
                            Finding(
                                title="Hardcoded internal network address (lateral movement risk)",
                                severity=FindingSeverity.MEDIUM,
                                description=(
                                    f"Found a hardcoded internal/private network address ({match.group(0)}) "
                                    "in source code. If this code path is reachable by an attacker (e.g. "
                                    "via SSRF), it discloses an internal pivot point."
                                ),
                                evidence=str(py_file),
                                remediation=(
                                    "Move internal endpoints to configuration/secrets management, and "
                                    "validate/allowlist any user-influenced network destinations."
                                ),
                            )
                        )

        except Exception:
            pass

        return findings

    def _chain_attack_paths(self, findings: list[Finding]) -> list[Finding]:
        """Group findings by file and, where multiple weaknesses in the same file could
        be combined by an attacker, emit a single higher-severity finding describing the
        end-to-end attack path (credential theft -> auth bypass -> injection -> RCE)."""
        chains: list[Finding] = []
        titles_by_file: dict[str, set[str]] = {}

        for finding in findings:
            file_key = (finding.evidence or "").split(":")[0]
            if not file_key:
                continue
            titles_by_file.setdefault(file_key, set()).add(finding.title.lower())

        for file_key, titles in titles_by_file.items():
            steps = []
            if any("credential" in title for title in titles):
                steps.append("harvest hardcoded credentials")
            if any("authentication check" in title for title in titles):
                steps.append("bypass weak authentication logic")
            if any("injection" in title for title in titles):
                steps.append("exploit an injection vulnerability")
            if any(
                "eval()" in title or "exec()" in title or "deserialization" in title
                for title in titles
            ):
                steps.append("achieve arbitrary code execution")
            if any("privilege escalation" in title for title in titles):
                steps.append("escalate privileges")
            if any("lateral movement" in title for title in titles):
                steps.append("pivot to internal network assets")

            if len(steps) >= 2:
                chains.append(
                    Finding(
                        title="Chained attack path identified",
                        severity=FindingSeverity.CRITICAL,
                        description=(
                            "Multiple weaknesses in the same file could be chained by an attacker: "
                            + " -> ".join(steps) + "."
                        ),
                        evidence=file_key,
                        remediation=(
                            "Remediate each step, prioritizing the earliest one in the chain to break "
                            "the attack path with the least effort."
                        ),
                    )
                )

        return chains
