from __future__ import annotations

import secrets
from uuid import UUID, uuid4

from security_review.domain.auth.models import User, UserRole
from security_review.infrastructure.email.email_provider import EmailProvider, get_email_provider
from security_review.infrastructure.persistence.sqlite_password_reset_repository import (
    SqlitePasswordResetRepository,
)
from security_review.infrastructure.persistence.sqlite_user_repository import SqliteUserRepository
from security_review.infrastructure.security.password_hasher import hash_password


class TeamError(Exception):
    """Raised when a team-management action can't be completed (e.g. duplicate email)."""


class LastOwnerError(Exception):
    """Raised when an action would leave an organization with zero owners."""


class TeamService:
    """Invite/list/role-change/remove teammates within an organization."""

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

    def list_members(self, organization_id: UUID) -> list[User]:
        return self._repository.list_users_by_organization(organization_id)

    def invite_member(
        self,
        organization_id: UUID,
        email: str,
        role: UserRole,
        base_url: str,
    ) -> User:
        if self._repository.email_exists(email):
            raise TeamError(f"A user with email '{email}' already exists.")

        organization = self._repository.get_organization(organization_id)
        organization_name = organization.name if organization else "your organization"

        # The invited user needs a password on the account, but must set their own
        # rather than being emailed one — generate a random, never-disclosed
        # placeholder and immediately send a "set your password" link (reusing the
        # password-reset token mechanism) instead of a separate invite-token system.
        placeholder_password = secrets.token_urlsafe(32)
        user = User(
            email=email,
            hashed_password=hash_password(placeholder_password),
            organization_id=organization_id,
            role=role,
        )
        self._repository.create_user(user)

        raw_token = secrets.token_urlsafe(32)
        self._reset_repository.create(uuid4(), user.id, raw_token)
        set_password_url = f"{base_url}/ui/?reset_token={raw_token}"
        self._email_provider.send_invite_email(user.email, organization_name, set_password_url)

        return user

    def update_member_role(self, organization_id: UUID, user_id: UUID, new_role: UserRole) -> User:
        target = self._get_member(organization_id, user_id)

        if target.role == UserRole.OWNER and new_role != UserRole.OWNER:
            self._require_not_last_owner(organization_id)

        self._repository.update_user_role(user_id, new_role)
        return self._repository.get_user_by_id(user_id)

    def remove_member(self, organization_id: UUID, user_id: UUID) -> None:
        target = self._get_member(organization_id, user_id)

        if target.role == UserRole.OWNER:
            self._require_not_last_owner(organization_id)

        self._repository.delete_user(user_id)

    def _get_member(self, organization_id: UUID, user_id: UUID) -> User:
        user = self._repository.get_user_by_id(user_id)
        if user is None or user.organization_id != organization_id:
            raise KeyError(user_id)
        return user

    def _require_not_last_owner(self, organization_id: UUID) -> None:
        owners = [member for member in self.list_members(organization_id) if member.role == UserRole.OWNER]
        if len(owners) <= 1:
            raise LastOwnerError(
                "Cannot remove or demote the only owner. Promote another member to owner first."
            )
