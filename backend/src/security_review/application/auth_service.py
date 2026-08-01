from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt

from security_review.domain.auth.models import (
    ForgotPasswordRequest,
    LoginRequest,
    Organization,
    ResetPasswordRequest,
    SignupRequest,
    TokenResponse,
    User,
    UserResponse,
    UserRole,
)
from security_review.infrastructure.email.email_provider import EmailProvider, get_email_provider
from security_review.infrastructure.persistence.sqlite_password_reset_repository import (
    SqlitePasswordResetRepository,
)
from security_review.infrastructure.persistence.sqlite_user_repository import (
    SqliteUserRepository,
)
from security_review.infrastructure.security.password_hasher import (
    hash_password,
    verify_password,
)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(hours=12)


class InvalidCredentialsError(Exception):
    """Raised when signup/login credentials are invalid."""


class InvalidTokenError(Exception):
    """Raised when a JWT access token is missing, malformed, or expired."""


class InvalidResetTokenError(Exception):
    """Raised when a password-reset token is missing, unknown, expired, or already used."""


class AuthService:
    def __init__(
        self,
        repository: SqliteUserRepository | None = None,
        reset_repository: SqlitePasswordResetRepository | None = None,
        email_provider: EmailProvider | None = None,
    ) -> None:
        self._repository = repository or SqliteUserRepository()
        self._repository.initialize()
        self._reset_repository = reset_repository or SqlitePasswordResetRepository()
        self._reset_repository.initialize()
        self._email_provider = email_provider or get_email_provider()

    @staticmethod
    def _jwt_secret() -> str:
        return os.getenv("SECURITY_REVIEW_JWT_SECRET", "dev-insecure-secret-change-me-in-production-32b")

    def signup(self, payload: SignupRequest) -> TokenResponse:
        if self._repository.email_exists(payload.email):
            raise InvalidCredentialsError("Email is already registered.")

        organization = Organization(name=payload.organization_name)
        self._repository.create_organization(organization)

        user = User(
            email=payload.email,
            hashed_password=hash_password(payload.password),
            organization_id=organization.id,
            role=UserRole.OWNER,
        )
        self._repository.create_user(user)

        return self._issue_token(user)

    def login(self, payload: LoginRequest) -> TokenResponse:
        user = self._repository.get_user_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.hashed_password):
            raise InvalidCredentialsError("Invalid email or password.")

        return self._issue_token(user)

    def get_current_user(self, token: str) -> User:
        try:
            claims = jwt.decode(token, self._jwt_secret(), algorithms=[JWT_ALGORITHM])
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("Invalid or expired access token.") from exc

        user = self._repository.get_user_by_id(UUID(claims["sub"]))
        if user is None:
            raise InvalidTokenError("User no longer exists.")

        return user

    def request_password_reset(self, payload: ForgotPasswordRequest, base_url: str) -> None:
        """Generate and email a password-reset link if the email is registered.

        Always succeeds regardless of whether the email exists, to avoid leaking
        which emails are registered (a classic user-enumeration vector).
        """
        user = self._repository.get_user_by_email(payload.email)
        if user is None:
            return

        raw_token = secrets.token_urlsafe(32)
        self._reset_repository.create(uuid4(), user.id, raw_token)

        reset_url = f"{base_url}/ui/?reset_token={raw_token}"
        self._email_provider.send_password_reset_email(user.email, reset_url)

    def reset_password(self, payload: ResetPasswordRequest) -> None:
        user_id = self._reset_repository.resolve_valid_user_id(payload.token)
        if user_id is None:
            raise InvalidResetTokenError("This password reset link is invalid or has expired.")

        self._repository.update_user_password(user_id, hash_password(payload.new_password))
        self._reset_repository.mark_used(payload.token)

    def _issue_token(self, user: User) -> TokenResponse:
        now = datetime.now(UTC)
        claims = {
            "sub": str(user.id),
            "org": str(user.organization_id),
            "role": user.role.value,
            "iat": now,
            "exp": now + ACCESS_TOKEN_TTL,
        }
        access_token = jwt.encode(claims, self._jwt_secret(), algorithm=JWT_ALGORITHM)

        return TokenResponse(
            access_token=access_token,
            user=UserResponse(
                id=user.id,
                email=user.email,
                organization_id=user.organization_id,
                role=user.role,
                created_at=user.created_at,
            ),
        )
