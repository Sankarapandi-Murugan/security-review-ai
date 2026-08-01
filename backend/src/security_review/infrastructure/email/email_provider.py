"""Pluggable transactional email delivery.

``ConsoleEmailProvider`` is the default — it logs the email instead of sending it,
which is the standard, safe local-dev behavior (mirrors e.g. Django's console email
backend) rather than silently failing to deliver or requiring real credentials to
run the app at all. ``SmtpEmailProvider`` is a real integration using the stdlib
``smtplib`` against any standard SMTP server (Gmail, SES, Mailgun, Postmark, etc. all
expose SMTP) — select it via ``SECURITY_REVIEW_EMAIL_PROVIDER=smtp`` plus real SMTP
credentials; missing configuration fails loudly rather than silently dropping mail.
"""

from __future__ import annotations

import logging
import os
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage

logger = logging.getLogger(__name__)


class EmailProviderError(Exception):
    """Raised when an email cannot be sent (e.g. missing/invalid SMTP configuration)."""


class EmailProvider(ABC):
    @abstractmethod
    def send_password_reset_email(self, to_email: str, reset_url: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def send_invite_email(self, to_email: str, organization_name: str, set_password_url: str) -> None:
        raise NotImplementedError


class ConsoleEmailProvider(EmailProvider):
    """Logs the email instead of sending it. Safe default for local dev/tests —
    no external dependency or credentials required to run the app."""

    def send_password_reset_email(self, to_email: str, reset_url: str) -> None:
        logger.info(
            "Password reset email (not actually sent -- SECURITY_REVIEW_EMAIL_PROVIDER=console)",
            extra={"to_email": to_email, "reset_url": reset_url},
        )

    def send_invite_email(self, to_email: str, organization_name: str, set_password_url: str) -> None:
        logger.info(
            "Team invite email (not actually sent -- SECURITY_REVIEW_EMAIL_PROVIDER=console)",
            extra={"to_email": to_email, "organization_name": organization_name, "set_password_url": set_password_url},
        )


class SmtpEmailProvider(EmailProvider):
    """Sends real email via SMTP (works with any standard SMTP provider)."""

    def __init__(self) -> None:
        self._host = os.getenv("SECURITY_REVIEW_SMTP_HOST")
        self._port = int(os.getenv("SECURITY_REVIEW_SMTP_PORT", "587"))
        self._username = os.getenv("SECURITY_REVIEW_SMTP_USERNAME")
        self._password = os.getenv("SECURITY_REVIEW_SMTP_PASSWORD")
        self._from_address = os.getenv("SECURITY_REVIEW_SMTP_FROM_ADDRESS")

        if not self._host or not self._from_address:
            raise EmailProviderError(
                "SECURITY_REVIEW_EMAIL_PROVIDER=smtp requires SECURITY_REVIEW_SMTP_HOST and "
                "SECURITY_REVIEW_SMTP_FROM_ADDRESS to be set (SECURITY_REVIEW_SMTP_USERNAME/"
                "_PASSWORD are also required unless the server allows anonymous relay)."
            )

    def send_password_reset_email(self, to_email: str, reset_url: str) -> None:
        message = EmailMessage()
        message["Subject"] = "Reset your Vigil AI password"
        message["From"] = self._from_address
        message["To"] = to_email
        message.set_content(
            "We received a request to reset your Vigil AI password.\n\n"
            f"Reset it here (valid for 30 minutes): {reset_url}\n\n"
            "If you didn't request this, you can safely ignore this email."
        )
        self._send(message)

    def send_invite_email(self, to_email: str, organization_name: str, set_password_url: str) -> None:
        message = EmailMessage()
        message["Subject"] = f"You've been invited to {organization_name} on Vigil AI"
        message["From"] = self._from_address
        message["To"] = to_email
        message.set_content(
            f"You've been invited to join {organization_name} on Vigil AI.\n\n"
            f"Set your password here (valid for 30 minutes): {set_password_url}\n\n"
            "If you weren't expecting this, you can safely ignore this email."
        )
        self._send(message)

    def _send(self, message: EmailMessage) -> None:
        try:
            with smtplib.SMTP(self._host, self._port, timeout=10) as smtp:
                smtp.starttls()
                if self._username and self._password:
                    smtp.login(self._username, self._password)
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise EmailProviderError(f"Failed to send email: {exc}") from exc


def get_email_provider() -> EmailProvider:
    provider_name = os.getenv("SECURITY_REVIEW_EMAIL_PROVIDER", "console").strip().lower()
    if provider_name == "smtp":
        return SmtpEmailProvider()
    return ConsoleEmailProvider()
