from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

_ALLOWED_URL_SCHEMES = ("https://", "http://")


class RepositoryIngestionError(Exception):
    """Raised when cloning a repository fails or its URL/branch is invalid."""


@dataclass
class IngestionResult:
    local_path: Path
    commit_hash: str


def _validate_repository_url(url: str) -> None:
    """Guard against SSRF/local-file access and git argument injection.

    Only http(s) URLs are accepted (no file://, ssh://, ext:: or other git transports),
    and the value may not start with '-' which would let it be parsed as a CLI flag.
    """
    if not url or not url.strip():
        raise RepositoryIngestionError("Repository URL must not be empty.")
    if url.startswith("-"):
        raise RepositoryIngestionError("Repository URL must not start with '-'.")
    if not url.startswith(_ALLOWED_URL_SCHEMES):
        raise RepositoryIngestionError(
            "Only http:// and https:// repository URLs are supported."
        )
    parsed = urlparse(url)
    if not parsed.hostname:
        raise RepositoryIngestionError("Repository URL must include a hostname.")


def _validate_branch(branch: str) -> str:
    branch = (branch or "main").strip()
    if not branch:
        return "main"
    if branch.startswith("-"):
        raise RepositoryIngestionError("Branch name must not start with '-'.")
    return branch


class GitRepositoryIngestionService:
    """Clones remote git repositories to local disk so scanners can operate on real code."""

    def __init__(
        self,
        base_dir: str | Path | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        self._base_dir = Path(
            base_dir or os.getenv("SECURITY_REVIEW_REPO_WORKDIR", "data/repos")
        )
        self._timeout_seconds = timeout_seconds or int(
            os.getenv("SECURITY_REVIEW_GIT_CLONE_TIMEOUT_SECONDS", "120")
        )

    def clone(self, url: str, branch: str, repository_id: UUID) -> IngestionResult:
        _validate_repository_url(url)
        safe_branch = _validate_branch(branch)

        dest = self._base_dir / str(repository_id)
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)

        env = dict(os.environ)
        env["GIT_TERMINAL_PROMPT"] = "0"

        try:
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "protocol.file.allow=never",
                    "-c",
                    "protocol.ext.allow=never",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    safe_branch,
                    "--single-branch",
                    "--",
                    url,
                    str(dest),
                ],
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            shutil.rmtree(dest, ignore_errors=True)
            raise RepositoryIngestionError(
                f"Cloning timed out after {self._timeout_seconds}s."
            ) from exc

        if result.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            stderr = (result.stderr or "").strip()[-1000:]
            raise RepositoryIngestionError(f"git clone failed: {stderr or 'unknown error'}")

        commit_hash = self._resolve_commit_hash(dest)
        return IngestionResult(local_path=dest, commit_hash=commit_hash)

    def _resolve_commit_hash(self, dest: Path) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(dest), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            return ""
