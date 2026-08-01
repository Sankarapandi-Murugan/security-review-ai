"""Billing domain: plan tiers, limits, and API schemas.

No real payment processor is wired up (see infrastructure/billing for the pluggable
provider abstraction) — this module defines the plan catalog and enforcement limits
used to gate usage per organization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel


class PlanTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class PlanDefinition:
    tier: PlanTier
    name: str
    price_usd_per_month: float | None
    max_assessments: int | None  # None = unlimited
    max_scan_jobs: int | None  # None = unlimited
    features: list[str] = field(default_factory=list)


PLAN_CATALOG: dict[PlanTier, PlanDefinition] = {
    PlanTier.FREE: PlanDefinition(
        tier=PlanTier.FREE,
        name="Free",
        price_usd_per_month=0,
        max_assessments=3,
        max_scan_jobs=20,
        features=[
            "All 9 autonomous security agents",
            "Up to 3 assessments",
            "Up to 20 scan jobs total",
            "Community support",
        ],
    ),
    PlanTier.PRO: PlanDefinition(
        tier=PlanTier.PRO,
        name="Pro",
        price_usd_per_month=49,
        max_assessments=50,
        max_scan_jobs=1000,
        features=[
            "All 9 autonomous security agents",
            "Up to 50 assessments",
            "Up to 1,000 scan jobs",
            "Webhooks + SSE live scan status",
            "Priority support",
        ],
    ),
    PlanTier.ENTERPRISE: PlanDefinition(
        tier=PlanTier.ENTERPRISE,
        name="Enterprise",
        price_usd_per_month=None,
        max_assessments=None,
        max_scan_jobs=None,
        features=[
            "Unlimited assessments and scan jobs",
            "SSO/SAML, audit logs, custom SLAs",
            "Dedicated support",
        ],
    ),
}


class PlanResponse(BaseModel):
    tier: PlanTier
    name: str
    price_usd_per_month: float | None
    max_assessments: int | None
    max_scan_jobs: int | None
    features: list[str]
    # Only set on POST /billing/subscribe when a plan requires real payment
    # collection (e.g. Stripe Checkout) that hasn't completed yet.
    checkout_url: str | None = None


class SubscribeRequest(BaseModel):
    plan: PlanTier


class UsageResponse(BaseModel):
    plan: PlanResponse
    assessments_used: int
    scan_jobs_used: int


def plan_to_response(definition: PlanDefinition) -> PlanResponse:
    return PlanResponse(
        tier=definition.tier,
        name=definition.name,
        price_usd_per_month=definition.price_usd_per_month,
        max_assessments=definition.max_assessments,
        max_scan_jobs=definition.max_scan_jobs,
        features=definition.features,
    )
