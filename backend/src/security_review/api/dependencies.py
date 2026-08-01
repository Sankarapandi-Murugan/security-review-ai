from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status

from security_review.application.auth_service import AuthService, InvalidTokenError
from security_review.domain.auth.models import User, UserRole

_auth_service = AuthService()


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def get_optional_current_user(authorization: str | None = Header(default=None)) -> User | None:
    """Return the authenticated user if a valid bearer token is provided, else None."""
    token = _extract_bearer_token(authorization)
    if not token:
        return None

    try:
        return _auth_service.get_current_user(token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc


def get_current_user(authorization: str | None = Header(default=None)) -> User:
    """Require a valid bearer token and return the authenticated user."""
    token = _extract_bearer_token(authorization)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    try:
        return _auth_service.get_current_user(token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc


def get_current_organization_id(current_user: User = Depends(get_current_user)) -> UUID:
    """Resolve the organization id for the request. Requires a valid bearer token —
    there is no anonymous/legacy fallback; all assessment, billing, and audit endpoints
    require signing up or logging in first.
    """
    return current_user.organization_id


def require_roles(*allowed_roles: UserRole) -> Callable[[User], User]:
    """Build a FastAPI dependency that requires the current user's role to be one of
    ``allowed_roles``, raising 403 otherwise. Use for role-gated actions (billing
    changes, team management, destructive operations) — most endpoints should
    remain open to any authenticated org member via ``get_current_user``.
    """

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            allowed = ", ".join(role.value for role in allowed_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of the following roles: {allowed}.",
            )
        return current_user

    return _dependency
