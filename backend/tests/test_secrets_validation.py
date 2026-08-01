import pytest

from security_review.infrastructure.security.secrets_validation import (
    InsecureConfigurationError,
    validate_production_secrets,
)


def test_noop_outside_production(monkeypatch):
    monkeypatch.delenv("SECURITY_REVIEW_ENVIRONMENT", raising=False)
    monkeypatch.delenv("SECURITY_REVIEW_JWT_SECRET", raising=False)

    validate_production_secrets()  # must not raise


def test_raises_when_jwt_secret_unset_in_production(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.delenv("SECURITY_REVIEW_JWT_SECRET", raising=False)
    monkeypatch.delenv("SECURITY_REVIEW_AUTH_REQUIRED", raising=False)

    with pytest.raises(InsecureConfigurationError, match="JWT_SECRET"):
        validate_production_secrets()


def test_raises_when_jwt_secret_is_the_dev_default(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.setenv(
        "SECURITY_REVIEW_JWT_SECRET", "dev-insecure-secret-change-me-in-production-32b"
    )

    with pytest.raises(InsecureConfigurationError, match="insecure development default"):
        validate_production_secrets()


def test_raises_when_jwt_secret_too_short(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.setenv("SECURITY_REVIEW_JWT_SECRET", "too-short")

    with pytest.raises(InsecureConfigurationError, match="at least 32 characters"):
        validate_production_secrets()


def test_raises_when_auth_required_with_default_api_key(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.setenv("SECURITY_REVIEW_JWT_SECRET", "a" * 40)
    monkeypatch.setenv("SECURITY_REVIEW_AUTH_REQUIRED", "true")
    monkeypatch.delenv("SECURITY_REVIEW_API_KEY", raising=False)

    with pytest.raises(InsecureConfigurationError, match="API_KEY"):
        validate_production_secrets()


def test_raises_when_webhook_secret_is_placeholder(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.setenv("SECURITY_REVIEW_JWT_SECRET", "a" * 40)
    monkeypatch.setenv("SECURITY_REVIEW_WEBHOOK_SECRET", "change-me-in-production")

    with pytest.raises(InsecureConfigurationError, match="WEBHOOK_SECRET"):
        validate_production_secrets()


def test_passes_with_strong_unique_secrets(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_ENVIRONMENT", "production")
    monkeypatch.setenv("SECURITY_REVIEW_JWT_SECRET", "a" * 40)
    monkeypatch.setenv("SECURITY_REVIEW_AUTH_REQUIRED", "true")
    monkeypatch.setenv("SECURITY_REVIEW_API_KEY", "a-real-unique-production-api-key")
    monkeypatch.setenv("SECURITY_REVIEW_WEBHOOK_SECRET", "a-real-unique-webhook-secret")

    validate_production_secrets()  # must not raise
