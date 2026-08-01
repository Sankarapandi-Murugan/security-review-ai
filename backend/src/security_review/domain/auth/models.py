from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, EmailStr, Field

from security_review.domain.billing.models import PlanTier

# Fixed organization id used for unauthenticated/legacy requests so existing
# single-tenant behavior keeps working when no auth token is provided.
NIL_ORGANIZATION_ID = UUID("00000000-0000-0000-0000-000000000000")


class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


@dataclass
class Organization:
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    plan: PlanTier = PlanTier.FREE
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class User:
    id: UUID = field(default_factory=uuid4)
    email: str = ""
    hashed_password: str = ""
    organization_id: UUID = field(default_factory=uuid4)
    role: UserRole = UserRole.MEMBER
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class SignupRequest(BaseModel):
    organization_name: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.MEMBER


class ChangeMemberRoleRequest(BaseModel):
    role: UserRole


class UserResponse(BaseModel):
    id: UUID
    email: str
    organization_id: UUID
    role: UserRole
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
