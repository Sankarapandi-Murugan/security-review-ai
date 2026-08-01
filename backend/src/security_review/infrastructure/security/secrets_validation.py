"""Fail-loud startup validation for secrets/configuration.

Only enforced when ``SECURITY_REVIEW_ENVIRONMENT=production`` — local dev, tests, and
staging are unaffected, so this never gets in the way of day-to-day development. In
production, refuses to start (raises ``InsecureConfigurationError``) rather than
silently running with a known-insecure default secret.
"""

from __future__ import annotations

import os

INSECURE_JWT_SECRET_DEFAULT = "dev-insecure-secret-change-me-in-production-32b"
INSECURE_API_KEY_DEFAULT = "demo-key"
INSECURE_WEBHOOK_SECRET_PLACEHOLDERS = {"change-me-in-production", "top-secret"}
MIN_JWT_SECRET_LENGTH = 32


class InsecureConfigurationError(RuntimeError):
    """Raised when the app is configured to run in production with missing,
    default, or otherwise weak secrets."""


def _is_production() -> bool:
    return os.getenv("SECURITY_REVIEW_ENVIRONMENT", "development").strip().lower() == "production"


def _auth_required() -> bool:
    return os.getenv("SECURITY_REVIEW_AUTH_REQUIRED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def validate_production_secrets() -> None:
    """Raise ``InsecureConfigurationError`` if running in production with
    missing/default/weak secrets. No-op outside of production."""
    if not _is_production():
        return

    issues: list[str] = []

    jwt_secret = os.getenv("SECURITY_REVIEW_JWT_SECRET", "")
    if not jwt_secret or jwt_secret == INSECURE_JWT_SECRET_DEFAULT:
        issues.append(
            "SECURITY_REVIEW_JWT_SECRET is unset or uses the insecure development default."
        )
    elif len(jwt_secret) < MIN_JWT_SECRET_LENGTH:
        issues.append(
            f"SECURITY_REVIEW_JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters "
            f"long (got {len(jwt_secret)})."
        )

    if _auth_required():
        api_key = os.getenv("SECURITY_REVIEW_API_KEY", "")
        if not api_key or api_key == INSECURE_API_KEY_DEFAULT:
            issues.append(
                "SECURITY_REVIEW_AUTH_REQUIRED is enabled but SECURITY_REVIEW_API_KEY is "
                "unset or uses the insecure development default ('demo-key')."
            )

    webhook_secret = os.getenv("SECURITY_REVIEW_WEBHOOK_SECRET")
    if webhook_secret and webhook_secret in INSECURE_WEBHOOK_SECRET_PLACEHOLDERS:
        issues.append(
            "SECURITY_REVIEW_WEBHOOK_SECRET is set to a known placeholder value from "
            ".env.example rather than a real secret."
        )

    if issues:
        formatted_issues = "\n  - ".join(issues)
        raise InsecureConfigurationError(
            "Refusing to start with SECURITY_REVIEW_ENVIRONMENT=production due to insecure "
            f"secret configuration:\n  - {formatted_issues}\n"
            "Set strong, unique secrets (e.g. `openssl rand -hex 32`) before deploying to "
            "production."
        )
