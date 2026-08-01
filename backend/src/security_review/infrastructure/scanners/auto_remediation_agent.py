from __future__ import annotations

import re
import subprocess
from pathlib import Path

from security_review.core.agent import Agent
from security_review.domain.assessment.models import AgentType, Finding, FindingSeverity
from security_review.infrastructure.scanners.white_box_agent import WhiteBoxAgent

_HTTP_METHODS = ("get", "post", "put", "delete", "head", "patch", "request")
# Matches e.g. requests.get(url) / requests.post(url, json=payload) — calls that Bandit
# (rule B113) flags for lacking an explicit timeout, which can hang indefinitely (CWE-400).
_REQUESTS_CALL_PATTERN = re.compile(r"requests\.(" + "|".join(_HTTP_METHODS) + r")\(([^)]*)\)")

_BRANCH_NAME = "security-review-ai/auto-remediation"


class AutoRemediationAgent(Agent):
    """Applies a curated set of safe, automatic fixes for findings raised by the
    White Box agent, re-scans to verify the fix, and (best-effort) opens a GitHub
    pull request with the change.

    Scope is intentionally narrow: automatically rewriting arbitrary source code is
    risky, so this agent only fixes patterns where the remediation is mechanical and
    behavior-preserving. Currently supported: adding a missing `timeout=` to
    `requests` calls (Bandit B113 / CWE-400, unbounded resource consumption).
    """

    agent_type = AgentType.AUTO_REMEDIATION

    def __init__(self, scanner: Agent | None = None) -> None:
        self._scanner = scanner or WhiteBoxAgent()

    def execute(self, target: str | None, *, authorized: bool = False) -> list[Finding]:
        if not target:
            return []

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

        baseline_findings = self._scanner.execute(target)
        fixable = [finding for finding in baseline_findings if self._is_fixable(finding)]

        if not fixable:
            return [
                Finding(
                    title="No auto-fixable findings detected",
                    severity=FindingSeverity.LOW,
                    description=(
                        f"White Box scan found {len(baseline_findings)} finding(s), none matched "
                        "a known safe auto-remediation pattern (currently: missing request timeouts)."
                    ),
                    evidence=target,
                    remediation="Review the remaining findings manually.",
                )
            ]

        patched_files = self._apply_timeout_fixes(fixable)

        after_findings = self._scanner.execute(target) if patched_files else baseline_findings
        resolved_count = max(len(baseline_findings) - len(after_findings), 0)

        results = [
            Finding(
                title="Auto-remediation applied: missing request timeout",
                severity=FindingSeverity.MEDIUM,
                description=(
                    f"Patched {len(patched_files)} file(s) to add explicit timeouts to `requests` "
                    f"calls flagged by static analysis. Findings before: {len(baseline_findings)}, "
                    f"after: {len(after_findings)} (resolved: {resolved_count})."
                ),
                evidence=", ".join(sorted(patched_files)) or target,
                remediation="Re-run the full scan suite to confirm no regressions were introduced.",
            )
        ]

        pr_url = self._open_pull_request(target_path, patched_files)
        if pr_url:
            results.append(
                Finding(
                    title="Pull request opened with auto-remediation",
                    severity=FindingSeverity.LOW,
                    description="A pull request was opened with the automatic fix for review.",
                    evidence=pr_url,
                    remediation="Review and merge the pull request after CI passes.",
                )
            )

        return results

    @staticmethod
    def _is_fixable(finding: Finding) -> bool:
        return "timeout" in finding.title.lower() or "timeout" in (finding.description or "").lower()

    def _apply_timeout_fixes(self, findings: list[Finding]) -> set[str]:
        patched_files: set[str] = set()
        for finding in findings:
            if not finding.evidence or ":" not in finding.evidence:
                continue
            file_path_str, _, _line = finding.evidence.rpartition(":")
            file_path = Path(file_path_str)
            if not file_path.is_file():
                continue
            if self._patch_file(file_path):
                patched_files.add(str(file_path))
        return patched_files

    @staticmethod
    def _patch_file(file_path: Path) -> bool:
        try:
            original = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return False

        def _add_timeout(match: re.Match[str]) -> str:
            method, args = match.group(1), match.group(2)
            if "timeout" in args:
                return match.group(0)
            args = args.rstrip()
            separator = ", " if args else ""
            return f"requests.{method}({args}{separator}timeout=10)"

        patched = _REQUESTS_CALL_PATTERN.sub(_add_timeout, original)
        if patched == original:
            return False

        file_path.write_text(patched, encoding="utf-8")
        return True

    @staticmethod
    def _open_pull_request(target_path: Path, patched_files: set[str]) -> str | None:
        """Best-effort: commit the fix on a new branch and open a PR via the `gh` CLI.

        Silently does nothing if the target isn't a git repo, there's no remote to
        push to, or the `gh` CLI isn't installed/authenticated — PR creation is a
        convenience on top of the already-applied local fix, not a hard requirement.
        """
        if not patched_files:
            return None

        try:
            subprocess.run(
                ["git", "-C", str(target_path), "checkout", "-B", _BRANCH_NAME],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(target_path), "add", "--", *sorted(patched_files)],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            commit = subprocess.run(
                [
                    "git",
                    "-C",
                    str(target_path),
                    "commit",
                    "-m",
                    "fix: add missing timeout to requests calls (auto-remediation)",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if commit.returncode != 0:
                return None

            push = subprocess.run(
                ["git", "-C", str(target_path), "push", "-u", "origin", _BRANCH_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if push.returncode != 0:
                return None

            pr = subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--title",
                    "Auto-remediation: add missing request timeouts",
                    "--body",
                    "Automatically generated by the Auto-Remediation security agent.",
                    "--head",
                    _BRANCH_NAME,
                ],
                cwd=str(target_path),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if pr.returncode != 0:
                return None
            return pr.stdout.strip() or None
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError):
            return None
