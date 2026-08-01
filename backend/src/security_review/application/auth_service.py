from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt

from security_review.domain.auth.models import (
    LoginRequest,
    Organization,
    SignupRequest,
    TokenResponse,
    User,
    UserResponse,
    UserRole,
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


class AuthService:
    def __init__(self, repository: SqliteUserRepository | None = None) -> None:
        self._repository = repository or SqliteUserRepository()
        self._repository.initialize()

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
