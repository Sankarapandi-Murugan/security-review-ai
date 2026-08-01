from __future__ import annotations

from uuid import UUID

from security_review.domain.assessment.exceptions import PlanLimitExceededError
from security_review.domain.auth.models import NIL_ORGANIZATION_ID
from security_review.domain.billing.models import PLAN_CATALOG, PlanDefinition, PlanTier, UsageResponse, plan_to_response
from security_review.infrastructure.billing.payment_provider import PaymentProvider, get_payment_provider
from security_review.infrastructure.persistence.sqlite_assessment_repository import (
    SqliteAssessmentRepository,
)
from security_review.infrastructure.persistence.sqlite_user_repository import SqliteUserRepository


class BillingService:
    """Plan catalog, subscription changes, and usage-limit enforcement."""

    def __init__(
        self,
        user_repository: SqliteUserRepository | None = None,
        assessment_repository: SqliteAssessmentRepository | None = None,
        payment_provider: PaymentProvider | None = None,
    ) -> None:
        self._user_repository = user_repository or SqliteUserRepository()
        self._user_repository.initialize()
        self._assessment_repository = assessment_repository or SqliteAssessmentRepository()
        self._assessment_repository.initialize()
        self._payment_provider = payment_provider or get_payment_provider()

    @staticmethod
    def list_plans() -> list[dict]:
        return [plan_to_response(definition).model_dump() for definition in PLAN_CATALOG.values()]

    def get_plan_definition(self, organization_id: UUID) -> PlanDefinition:
        organization = self._user_repository.get_organization(organization_id)
        tier = organization.plan if organization else PlanTier.FREE
        return PLAN_CATALOG[tier]

    def change_plan(
        self,
        organization_id: UUID,
        plan: PlanTier,
        *,
        customer_email: str,
        success_url: str,
        cancel_url: str,
    ) -> tuple[PlanDefinition, str | None]:
        """Start a plan change. Returns ``(plan_definition, checkout_url)`` —
        ``checkout_url`` is set (and the plan NOT yet changed) when real payment
        collection is still pending (e.g. Stripe Checkout); otherwise the plan is
        already active and ``checkout_url`` is None.
        """
        organization = self._user_repository.get_organization(organization_id)
        stripe_customer_id = organization.stripe_customer_id if organization else None
        stripe_subscription_id = organization.stripe_subscription_id if organization else None

        result = self._payment_provider.start_plan_change(
            organization_id=organization_id,
            plan=plan,
            customer_email=customer_email,
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
            success_url=success_url,
            cancel_url=cancel_url,
        )

        if not result.activated_immediately:
            return PLAN_CATALOG[plan], result.checkout_url

        self._user_repository.update_organization_plan(organization_id, result.plan)
        if result.plan == PlanTier.FREE:
            # Downgrading to Free means any previous subscription is gone.
            self._user_repository.update_organization_stripe_ids(
                organization_id, stripe_customer_id=stripe_customer_id, stripe_subscription_id=None
            )
        return PLAN_CATALOG[result.plan], None

    def handle_stripe_webhook(self, payload: bytes, signature_header: str | None) -> None:
        """Process an inbound Stripe webhook event and reconcile plan state."""
        outcome = self._payment_provider.handle_webhook(payload, signature_header)
        if outcome is None:
            return

        organization_id = outcome.organization_id
        if organization_id is None and outcome.stripe_customer_id:
            organization_id = self._user_repository.get_organization_id_by_stripe_customer_id(
                outcome.stripe_customer_id
            )
        if organization_id is None:
            return  # Can't resolve which organization this event belongs to.

        self._user_repository.update_organization_plan(organization_id, outcome.plan)
        self._user_repository.update_organization_stripe_ids(
            organization_id,
            stripe_customer_id=outcome.stripe_customer_id,
            stripe_subscription_id=outcome.stripe_subscription_id,
        )

    def get_usage(self, organization_id: UUID) -> UsageResponse:
        definition = self.get_plan_definition(organization_id)
        assessments = self._assessment_repository.list(organization_id)
        scan_jobs_used = sum(len(assessment.scan_jobs) for assessment in assessments)
        return UsageResponse(
            plan=plan_to_response(definition),
            assessments_used=len(assessments),
            scan_jobs_used=scan_jobs_used,
        )

    def enforce_assessment_limit(self, organization_id: UUID) -> None:
        if organization_id == NIL_ORGANIZATION_ID:
            return  # Shared legacy/unauthenticated bucket keeps unrestricted demo behavior.
        definition = self.get_plan_definition(organization_id)
        if definition.max_assessments is None:
            return
        current = self._assessment_repository.count(organization_id)
        if current >= definition.max_assessments:
            raise PlanLimitExceededError(
                f"The '{definition.name}' plan allows up to {definition.max_assessments} "
                "assessment(s). Upgrade your plan to create more."
            )

    def enforce_scan_job_limit(self, organization_id: UUID) -> None:
        if organization_id == NIL_ORGANIZATION_ID:
            return  # Shared legacy/unauthenticated bucket keeps unrestricted demo behavior.
        definition = self.get_plan_definition(organization_id)
        if definition.max_scan_jobs is None:
            return
        assessments = self._assessment_repository.list(organization_id)
        current = sum(len(assessment.scan_jobs) for assessment in assessments)
        if current >= definition.max_scan_jobs:
            raise PlanLimitExceededError(
                f"The '{definition.name}' plan allows up to {definition.max_scan_jobs} scan "
                "job(s) total. Upgrade your plan to run more."
            )
