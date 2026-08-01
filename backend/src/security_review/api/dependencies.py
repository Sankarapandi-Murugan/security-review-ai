from __future__ import annotations

from uuid import UUID

from fastapi import Header, HTTPException, status

from security_review.application.auth_service import AuthService, InvalidTokenError
from security_review.domain.auth.models import NIL_ORGANIZATION_ID, User

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


def get_current_organization_id(authorization: str | None = Header(default=None)) -> UUID:
    """Resolve the organization id for the request.

    Returns the authenticated user's organization when a valid bearer token is present,
    otherwise falls back to a fixed "legacy" organization id so unauthenticated/demo usage
    keeps working exactly as before multi-tenancy was introduced.
    """
    user = get_optional_current_user(authorization)
    return user.organization_id if user else NIL_ORGANIZATION_ID
