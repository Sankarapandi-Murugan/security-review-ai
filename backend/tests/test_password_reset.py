import smtplib
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from security_review.infrastructure.email.email_provider import (
    ConsoleEmailProvider,
    EmailProviderError,
    SmtpEmailProvider,
    get_email_provider,
)
from security_review.infrastructure.security.password_hasher import hash_token, verify_token
from security_review.main import app

# ---------------------------------------------------------------------------
# EmailProvider unit tests
# ---------------------------------------------------------------------------


def test_get_email_provider_defaults_to_console(monkeypatch):
    monkeypatch.delenv("SECURITY_REVIEW_EMAIL_PROVIDER", raising=False)
    assert isinstance(get_email_provider(), ConsoleEmailProvider)


def test_console_provider_does_not_raise(caplog):
    ConsoleEmailProvider().send_password_reset_email("a@example.com", "https://app/reset?token=x")


def test_smtp_provider_requires_host_and_from_address(monkeypatch):
    monkeypatch.delenv("SECURITY_REVIEW_SMTP_HOST", raising=False)
    monkeypatch.delenv("SECURITY_REVIEW_SMTP_FROM_ADDRESS", raising=False)
    with pytest.raises(EmailProviderError, match="SECURITY_REVIEW_SMTP_HOST"):
        SmtpEmailProvider()


def test_smtp_provider_sends_via_smtplib(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SECURITY_REVIEW_SMTP_FROM_ADDRESS", "noreply@example.com")
    monkeypatch.setenv("SECURITY_REVIEW_SMTP_USERNAME", "user")
    monkeypatch.setenv("SECURITY_REVIEW_SMTP_PASSWORD", "pass")

    fake_smtp = MagicMock()
    fake_smtp.__enter__.return_value = fake_smtp
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(return_value=fake_smtp))

    provider = SmtpEmailProvider()
    provider.send_password_reset_email("a@example.com", "https://app/reset?token=x")

    fake_smtp.starttls.assert_called_once()
    fake_smtp.login.assert_called_once_with("user", "pass")
    fake_smtp.send_message.assert_called_once()


def test_smtp_provider_wraps_connection_errors(monkeypatch):
    monkeypatch.setenv("SECURITY_REVIEW_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SECURITY_REVIEW_SMTP_FROM_ADDRESS", "noreply@example.com")
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(side_effect=OSError("connection refused")))

    provider = SmtpEmailProvider()
    with pytest.raises(EmailProviderError, match="Failed to send"):
        provider.send_password_reset_email("a@example.com", "https://app/reset?token=x")


# ---------------------------------------------------------------------------
# Token hashing helpers
# ---------------------------------------------------------------------------


def test_hash_token_is_deterministic():
    token = "abc123"
    assert hash_token(token) == hash_token(token)


def test_verify_token_accepts_matching_and_rejects_mismatched():
    token = "abc123"
    token_hash = hash_token(token)
    assert verify_token(token, token_hash) is True
    assert verify_token("wrong", token_hash) is False


# ---------------------------------------------------------------------------
# Full password reset flow (router-level)
# ---------------------------------------------------------------------------


def _signup(client: TestClient) -> tuple[str, str]:
    email = f"user-{uuid.uuid4().hex}@example.com"
    response = client.post(
        "/auth/signup",
        json={"organization_name": "Reset org", "email": email, "password": "original-password"},
    )
    assert response.status_code == 201
    return response.json()["access_token"], email


def test_forgot_password_always_returns_generic_success_for_unknown_email():
    client = TestClient(app)
    response = client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
    assert response.status_code == 200
    assert "reset link has been sent" in response.json()["detail"]


def test_full_password_reset_flow_changes_password_and_invalidates_token(monkeypatch, caplog):
    client = TestClient(app)
    _token, email = _signup(client)

    # Capture the reset URL logged by the default ConsoleEmailProvider.
    captured = {}
    from security_review.infrastructure.email import email_provider as email_provider_module

    original_send = email_provider_module.ConsoleEmailProvider.send_password_reset_email

    def _capture(self, to_email, reset_url):
        captured["reset_url"] = reset_url
        return original_send(self, to_email, reset_url)

    monkeypatch.setattr(email_provider_module.ConsoleEmailProvider, "send_password_reset_email", _capture)

    forgot_response = client.post("/auth/forgot-password", json={"email": email})
    assert forgot_response.status_code == 200
    assert "reset_url" in captured

    reset_token = captured["reset_url"].split("reset_token=")[1]

    reset_response = client.post(
        "/auth/reset-password", json={"token": reset_token, "new_password": "brand-new-password"}
    )
    assert reset_response.status_code == 200

    # Old password no longer works; new password does.
    old_login = client.post("/auth/login", json={"email": email, "password": "original-password"})
    assert old_login.status_code == 401

    new_login = client.post("/auth/login", json={"email": email, "password": "brand-new-password"})
    assert new_login.status_code == 200

    # The token has been consumed and cannot be reused.
    reuse_response = client.post(
        "/auth/reset-password", json={"token": reset_token, "new_password": "another-password"}
    )
    assert reuse_response.status_code == 400


def test_reset_password_rejects_unknown_token():
    client = TestClient(app)
    response = client.post(
        "/auth/reset-password", json={"token": "not-a-real-token", "new_password": "whatever123"}
    )
    assert response.status_code == 400


def test_reset_password_rejects_expired_token(monkeypatch):
    from datetime import timedelta

    import security_review.infrastructure.persistence.sqlite_password_reset_repository as reset_repo_module

    monkeypatch.setattr(reset_repo_module, "RESET_TOKEN_TTL", timedelta(seconds=-1))

    client = TestClient(app)
    _token, email = _signup(client)

    captured = {}
    from security_review.infrastructure.email import email_provider as email_provider_module

    def _capture(self, to_email, reset_url):
        captured["reset_url"] = reset_url

    monkeypatch.setattr(email_provider_module.ConsoleEmailProvider, "send_password_reset_email", _capture)

    client.post("/auth/forgot-password", json={"email": email})
    reset_token = captured["reset_url"].split("reset_token=")[1]

    response = client.post(
        "/auth/reset-password", json={"token": reset_token, "new_password": "brand-new-password"}
    )
    assert response.status_code == 400
