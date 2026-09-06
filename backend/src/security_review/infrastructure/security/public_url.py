"""Trusted public application URL used in externally delivered links."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

PUBLIC_BASE_URL_ENV = "SECURITY_REVIEW_PUBLIC_BASE_URL"
_DEVELOPMENT_DEFAULT = "http://localhost:8000"


class PublicBaseUrlConfigurationError(RuntimeError):
    """Raised when the deployment's canonical public URL is unsafe or missing."""


def get_public_base_url() -> str:
    """Return the configured canonical URL, never a request-controlled Host value."""

    configured = os.getenv(PUBLIC_BASE_URL_ENV)
    if not configured:
        if os.getenv("SECURITY_REVIEW_ENVIRONMENT", "development").lower() == "production":
            raise PublicBaseUrlConfigurationError(
                f"{PUBLIC_BASE_URL_ENV} must be set in production."
            )
        return _DEVELOPMENT_DEFAULT

    value = configured.rstrip("/")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise PublicBaseUrlConfigurationError(
            f"{PUBLIC_BASE_URL_ENV} must be a valid absolute HTTP(S) URL."
        ) from exc

    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise PublicBaseUrlConfigurationError(
            f"{PUBLIC_BASE_URL_ENV} must be a valid absolute HTTP(S) URL without credentials."
        )
    if os.getenv("SECURITY_REVIEW_ENVIRONMENT", "development").lower() == "production" and parsed.scheme != "https":
        raise PublicBaseUrlConfigurationError(f"{PUBLIC_BASE_URL_ENV} must use HTTPS in production.")

    return value
