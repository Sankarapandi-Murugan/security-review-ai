"""Optional error tracking (Sentry) integration.

Soft dependency: ``sentry-sdk`` is not a hard requirement of this project. If it's
installed AND ``SECURITY_REVIEW_SENTRY_DSN`` is set, errors are reported to Sentry;
otherwise this is a no-op (errors are still captured in structured logs either way).
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_initialized = False


def init_error_tracking() -> bool:
    """Initialize Sentry if configured. Returns True if it was actually enabled."""
    global _initialized
    if _initialized:
        return True

    dsn = os.getenv("SECURITY_REVIEW_SENTRY_DSN")
    if not dsn:
        logger.info("Error tracking disabled: SECURITY_REVIEW_SENTRY_DSN not set.")
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
    except ImportError:
        logger.warning(
            "SECURITY_REVIEW_SENTRY_DSN is set but the 'sentry-sdk' package is not "
            "installed; error tracking remains disabled. Install it with "
            "`uv add sentry-sdk` to enable Sentry reporting."
        )
        return False

    sentry_sdk.init(
        dsn=dsn,
        environment=os.getenv("SECURITY_REVIEW_ENVIRONMENT", "development"),
        traces_sample_rate=float(os.getenv("SECURITY_REVIEW_SENTRY_TRACES_SAMPLE_RATE", "0.0")),
        integrations=[FastApiIntegration()],
    )
    _initialized = True
    logger.info("Error tracking enabled via Sentry.")
    return True


def capture_exception(exc: BaseException) -> None:
    """Best-effort forward of an exception to Sentry, if enabled. Never raises."""
    if not _initialized:
        return
    try:
        import sentry_sdk

        sentry_sdk.capture_exception(exc)
    except Exception:
        pass
