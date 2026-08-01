import re
from collections import Counter
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_FAILED_LOGIN_PATTERN = re.compile(
    r"failed password|authentication failure|invalid user|login failed|failed login|401 unauthorized",
    re.IGNORECASE,
)
_BRUTE_FORCE_THRESHOLD = 5

_INJECTION_SIGNATURES = (
    "union select",
    "' or '1'='1",
    " or 1=1",
    "<script>",
    "../../../",
    "etc/passwd",
    "select * from",
    "drop table",
)

_PRIVILEGED_COMMAND_SIGNATURES = (
    "sudo su",
    "useradd",
    "usermod -ag sudo",
    "chmod 777",
    "/etc/shadow",
    "nc -e",
    "| sh",
    "| bash",
)

_SCANNER_PATH_SIGNATURES = (
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/xmlrpc.php",
    "/actuator/env",
    "/.aws/credentials",
)
_SCANNER_PATH_THRESHOLD = 3

_LOG_FILE_GLOBS = (
    "*.log",
    "*.log.*",
    "*access*.log*",
    "*auth*.log*",
    "*audit*.log*",
    "*.jsonl",
)
_MAX_LOG_FILES = 20
_MAX_LINES_PER_FILE = 5000


class BlueTeamAgent(Agent):
    """Defensive security assessment - hardening and detection."""
    
    agent_type = AgentType.BLUE_TEAM

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        """Perform blue-team (defensive) analysis."""
        findings = []
        
        if not target:
            return findings
        
        # Check defensive measures
        findings.extend(self._check_logging_instrumentation(target))
        findings.extend(self._check_error_handling(target))
        findings.extend(self._check_input_validation(target))
        findings.extend(self._analyze_logs(target))
        
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

    def _analyze_logs(self, target: str) -> list[Finding]:
        """Ingest SIEM/EDR/firewall-style log files (plain-text or JSON-lines), detect
        suspicious behavior, and produce an incident-report-style summary with
        recommended detection rules and mitigations."""
        findings: list[Finding] = []

        target_path = Path(target)
        log_files = self._discover_log_files(target_path)
        if not log_files:
            return findings

        brute_force_counter: Counter[tuple[str, str]] = Counter()
        scanner_counter: Counter[str] = Counter()
        event_findings: list[Finding] = []

        for log_file in log_files:
            try:
                lines = log_file.read_text(errors="ignore").splitlines()[:_MAX_LINES_PER_FILE]
            except (OSError, UnicodeDecodeError):
                continue

            for line in lines:
                if _FAILED_LOGIN_PATTERN.search(line):
                    ip_match = _IP_PATTERN.search(line)
                    ip = ip_match.group(0) if ip_match else "unknown"
                    brute_force_counter[(str(log_file), ip)] += 1

                lowered = line.lower()

                for signature in _INJECTION_SIGNATURES:
                    if signature in lowered:
                        event_findings.append(
                            Finding(
                                title="Web attack payload detected in logs",
                                severity=FindingSeverity.CRITICAL,
                                description=(
                                    f"Log entry contains a known attack signature ('{signature}'), "
                                    "indicating an active SQL injection or XSS attempt."
                                ),
                                evidence=f"{log_file}: {line.strip()[:200]}",
                                remediation=(
                                    "Add a SIEM correlation rule alerting on this payload signature; "
                                    "verify the request was blocked by the WAF/input validation."
                                ),
                            )
                        )
                        break

                for signature in _PRIVILEGED_COMMAND_SIGNATURES:
                    if signature in lowered:
                        event_findings.append(
                            Finding(
                                title="Suspicious privileged command in logs",
                                severity=FindingSeverity.HIGH,
                                description=(
                                    f"Log entry references a sensitive/privileged command ('{signature}'), "
                                    "consistent with post-exploitation or privilege escalation activity."
                                ),
                                evidence=f"{log_file}: {line.strip()[:200]}",
                                remediation=(
                                    "Investigate the originating session/user immediately; alert on this "
                                    "command pattern in EDR going forward."
                                ),
                            )
                        )
                        break

                if any(path in lowered for path in _SCANNER_PATH_SIGNATURES):
                    ip_match = _IP_PATTERN.search(line)
                    scanner_counter[ip_match.group(0) if ip_match else str(log_file)] += 1

        for (log_file_str, ip), count in brute_force_counter.items():
            if count >= _BRUTE_FORCE_THRESHOLD:
                event_findings.append(
                    Finding(
                        title="Brute-force login attempts detected",
                        severity=FindingSeverity.HIGH,
                        description=(
                            f"Source {ip} produced {count} failed authentication log entries in "
                            f"{log_file_str}, consistent with a brute-force/credential-stuffing attack."
                        ),
                        evidence=f"{ip} -> {count} failed logins in {log_file_str}",
                        remediation=(
                            "Recommended detection rule: alert when a single source IP exceeds "
                            f"{_BRUTE_FORCE_THRESHOLD} failed authentications within 5 minutes; "
                            "enforce account lockout/rate limiting and require MFA."
                        ),
                    )
                )

        for ip, count in scanner_counter.items():
            if count >= _SCANNER_PATH_THRESHOLD:
                event_findings.append(
                    Finding(
                        title="Automated vulnerability scanning detected",
                        severity=FindingSeverity.MEDIUM,
                        description=(
                            f"{ip} probed {count} well-known sensitive paths (e.g. /wp-login.php, "
                            "/.env, /.git/config), consistent with automated reconnaissance tooling."
                        ),
                        evidence=ip,
                        remediation=(
                            "Recommended detection rule: alert on repeated 404s against known "
                            "sensitive paths from a single source; consider a WAF rule or IP block."
                        ),
                    )
                )

        # Incident-report-style summary, always emitted once logs were successfully ingested.
        if event_findings:
            severity_counts = Counter(finding.severity.value for finding in event_findings)
            findings.append(
                Finding(
                    title="Blue Team log analysis: incident summary",
                    severity=FindingSeverity.HIGH,
                    description=(
                        f"Ingested {len(log_files)} log file(s) and identified {len(event_findings)} "
                        f"suspicious event(s): {dict(severity_counts)}."
                    ),
                    evidence=", ".join(str(f) for f in log_files[:5]),
                    remediation=(
                        "Review each finding below, escalate CRITICAL/HIGH events to incident response, "
                        "and deploy the recommended detection rules in your SIEM/EDR."
                    ),
                )
            )
            findings.extend(event_findings)
        else:
            findings.append(
                Finding(
                    title="No suspicious activity detected in ingested logs",
                    severity=FindingSeverity.LOW,
                    description=f"Ingested {len(log_files)} log file(s); no known attack signatures matched.",
                    evidence=", ".join(str(f) for f in log_files[:5]),
                    remediation=(
                        "Baseline detection rules to consider: alert on "
                        f">= {_BRUTE_FORCE_THRESHOLD} failed logins per source IP in 5 minutes, "
                        "repeated 404s against sensitive paths, and known injection payload signatures."
                    ),
                )
            )

        return findings

    @staticmethod
    def _discover_log_files(target_path: Path) -> list[Path]:
        if target_path.is_file():
            return [target_path]

        if not target_path.is_dir():
            return []

        discovered: list[Path] = []
        seen: set[Path] = set()
        for pattern in _LOG_FILE_GLOBS:
            for candidate in target_path.rglob(pattern):
                if candidate.is_file() and candidate not in seen:
                    seen.add(candidate)
                    discovered.append(candidate)
                if len(discovered) >= _MAX_LOG_FILES:
                    return discovered
        return discovered
    
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
