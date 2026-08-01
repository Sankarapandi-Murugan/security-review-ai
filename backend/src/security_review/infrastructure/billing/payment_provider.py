"""Pluggable payment provider abstraction for subscription changes.

``MockPaymentProvider`` is the default and simply "activates" a plan change
immediately with no real payment collection — sufficient for local dev/demos.
``StripePaymentProvider`` is a real integration using the official Stripe SDK:
Checkout Sessions for self-serve upgrades, and webhook handling to reconcile
plan state once payment actually completes. Select it via
``SECURITY_REVIEW_PAYMENT_PROVIDER=stripe`` plus real Stripe credentials
(``STRIPE_SECRET_KEY``, ``STRIPE_PRICE_ID_PRO``, ``STRIPE_WEBHOOK_SECRET``) —
without them, it fails loudly at construction time rather than silently
granting access.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from security_review.domain.billing.models import PlanTier


class PaymentProviderError(Exception):
    """Raised when a payment provider cannot process a plan change."""


@dataclass
class SubscriptionResult:
    plan: PlanTier
    provider_reference: str | None = None
    checkout_url: str | None = None
    # True when the plan should be activated in our DB right away (e.g. mock
    # provider, or downgrading to Free). False when real payment is still
    # pending completion (Stripe Checkout) — the org's plan must NOT change
    # until the corresponding webhook event confirms payment.
    activated_immediately: bool = True


@dataclass
class WebhookOutcome:
    """The plan change a payment provider's webhook event resolved to.

    ``organization_id`` may be None (e.g. Stripe's ``customer.subscription.deleted``
    only carries a Stripe customer id) — callers should resolve the organization
    via ``stripe_customer_id`` in that case.
    """

    plan: PlanTier
    organization_id: UUID | None = None
    stripe_customer_id: str | None = None
    stripe_subscription_id: str | None = None


class PaymentProvider(ABC):
    @abstractmethod
    def start_plan_change(
        self,
        *,
        organization_id: UUID,
        plan: PlanTier,
        customer_email: str,
        stripe_customer_id: str | None,
        stripe_subscription_id: str | None,
        success_url: str,
        cancel_url: str,
    ) -> SubscriptionResult:
        """Begin changing ``organization_id``'s plan to ``plan``.

        For plans requiring real payment collection, returns a
        ``checkout_url`` the caller must redirect the user's browser to;
        ``activated_immediately`` is False until the webhook confirms payment.
        """
        raise NotImplementedError

    @abstractmethod
    def handle_webhook(self, payload: bytes, signature_header: str | None) -> WebhookOutcome | None:
        """Verify and process an inbound webhook payload.

        Returns None if the event is valid but not relevant to plan changes.
        Raises ``PaymentProviderError`` if the signature is missing/invalid.
        """
        raise NotImplementedError


class MockPaymentProvider(PaymentProvider):
    """Activates plan changes immediately with no real payment collection.

    Suitable for local development, demos, and a free/self-serve launch before a
    real payment processor is integrated. Has no webhooks of its own.
    """

    def start_plan_change(
        self,
        *,
        organization_id: UUID,
        plan: PlanTier,
        customer_email: str,
        stripe_customer_id: str | None,
        stripe_subscription_id: str | None,
        success_url: str,
        cancel_url: str,
    ) -> SubscriptionResult:
        return SubscriptionResult(
            plan=plan,
            provider_reference=f"mock-{organization_id}-{plan.value}",
            activated_immediately=True,
        )

    def handle_webhook(self, payload: bytes, signature_header: str | None) -> WebhookOutcome | None:
        return None


class StripePaymentProvider(PaymentProvider):
    """Real Stripe Billing integration.

    - Upgrading to a paid plan creates a Stripe Checkout Session (self-serve,
      hosted by Stripe) — the plan is only activated once
      ``checkout.session.completed`` arrives via webhook.
    - Downgrading to Free cancels any existing Stripe subscription immediately.
    - Enterprise is not self-serve (no fixed price) — callers are told to
      contact sales.

    Requires ``STRIPE_SECRET_KEY`` and ``STRIPE_PRICE_ID_PRO`` at minimum;
    ``STRIPE_WEBHOOK_SECRET`` is required to process webhooks. Missing/invalid
    configuration fails loudly (``PaymentProviderError``) rather than silently
    granting access.
    """

    def __init__(self) -> None:
        secret_key = os.getenv("STRIPE_SECRET_KEY")
        if not secret_key:
            raise PaymentProviderError(
                "SECURITY_REVIEW_PAYMENT_PROVIDER=stripe but STRIPE_SECRET_KEY is not set. "
                "Set it to a real Stripe secret key, or use SECURITY_REVIEW_PAYMENT_PROVIDER=mock "
                "for local development."
            )

        try:
            import stripe
        except ImportError as exc:
            raise PaymentProviderError(
                "SECURITY_REVIEW_PAYMENT_PROVIDER=stripe but the 'stripe' package is not "
                "installed. Install it with `uv add stripe`."
            ) from exc

        stripe.api_key = secret_key
        self._stripe = stripe
        self._webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        self._price_ids: dict[PlanTier, str | None] = {
            PlanTier.PRO: os.getenv("STRIPE_PRICE_ID_PRO"),
        }

    def start_plan_change(
        self,
        *,
        organization_id: UUID,
        plan: PlanTier,
        customer_email: str,
        stripe_customer_id: str | None,
        stripe_subscription_id: str | None,
        success_url: str,
        cancel_url: str,
    ) -> SubscriptionResult:
        if plan == PlanTier.FREE:
            if stripe_subscription_id:
                self._stripe.Subscription.cancel(stripe_subscription_id)
            return SubscriptionResult(plan=PlanTier.FREE, activated_immediately=True)

        if plan == PlanTier.ENTERPRISE:
            raise PaymentProviderError(
                "Enterprise is not self-serve. Contact sales to upgrade this organization."
            )

        price_id = self._price_ids.get(plan)
        if not price_id:
            raise PaymentProviderError(
                f"No Stripe price is configured for the '{plan.value}' plan. Set "
                f"STRIPE_PRICE_ID_{plan.value.upper()}."
            )

        session_kwargs: dict[str, object] = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            "client_reference_id": str(organization_id),
            "metadata": {"organization_id": str(organization_id), "plan": plan.value},
        }
        if stripe_customer_id:
            session_kwargs["customer"] = stripe_customer_id
        else:
            session_kwargs["customer_email"] = customer_email

        session = self._stripe.checkout.Session.create(**session_kwargs)
        return SubscriptionResult(
            plan=plan,
            provider_reference=session.id,
            checkout_url=session.url,
            activated_immediately=False,
        )

    def handle_webhook(self, payload: bytes, signature_header: str | None) -> WebhookOutcome | None:
        if not self._webhook_secret:
            raise PaymentProviderError(
                "STRIPE_WEBHOOK_SECRET is not configured; cannot verify webhook signatures."
            )
        if not signature_header:
            raise PaymentProviderError("Missing Stripe-Signature header.")

        try:
            event = self._stripe.Webhook.construct_event(payload, signature_header, self._webhook_secret)
        except (ValueError, self._stripe.error.SignatureVerificationError) as exc:
            raise PaymentProviderError(f"Invalid Stripe webhook payload/signature: {exc}") from exc

        event_type = event["type"]
        data = event["data"]["object"]

        if event_type == "checkout.session.completed":
            org_id = data.get("client_reference_id")
            if not org_id:
                return None
            plan_value = (data.get("metadata") or {}).get("plan", PlanTier.PRO.value)
            return WebhookOutcome(
                plan=PlanTier(plan_value),
                organization_id=UUID(org_id),
                stripe_customer_id=data.get("customer"),
                stripe_subscription_id=data.get("subscription"),
            )

        if event_type == "customer.subscription.deleted":
            return WebhookOutcome(
                plan=PlanTier.FREE,
                stripe_customer_id=data.get("customer"),
                stripe_subscription_id=None,
            )

        return None


def get_payment_provider() -> PaymentProvider:
    provider_name = os.getenv("SECURITY_REVIEW_PAYMENT_PROVIDER", "mock").strip().lower()
    if provider_name == "stripe":
        return StripePaymentProvider()
    return MockPaymentProvider()

