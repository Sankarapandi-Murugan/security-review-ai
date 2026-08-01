import uuid
from unittest.mock import MagicMock

import pytest
import stripe
from fastapi.testclient import TestClient

import security_review.api.routers.billing as billing_router
from security_review.application.billing_service import BillingService
from security_review.domain.auth.models import Organization
from security_review.domain.billing.models import PlanTier
from security_review.infrastructure.billing.payment_provider import (
    PaymentProviderError,
    StripePaymentProvider,
    SubscriptionResult,
    WebhookOutcome,
)
from security_review.main import app
from tests._auth_helpers import signup_headers

# ---------------------------------------------------------------------------
# StripePaymentProvider unit tests -- the real Stripe SDK is installed, but
# network-hitting calls (Session.create, Subscription.cancel, Webhook.construct_event)
# are monkeypatched, matching this project's convention of mocking network clients
# rather than hitting real external services in tests.
# ---------------------------------------------------------------------------


def test_stripe_provider_requires_secret_key(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    with pytest.raises(PaymentProviderError, match="STRIPE_SECRET_KEY"):
        StripePaymentProvider()


def test_stripe_provider_free_plan_cancels_existing_subscription(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.setattr(stripe, "Subscription", MagicMock())
    provider = StripePaymentProvider()

    result = provider.start_plan_change(
        organization_id=uuid.uuid4(),
        plan=PlanTier.FREE,
        customer_email="a@example.com",
        stripe_customer_id="cus_1",
        stripe_subscription_id="sub_1",
        success_url="https://app/success",
        cancel_url="https://app/cancel",
    )

    stripe.Subscription.cancel.assert_called_once_with("sub_1")
    assert result.plan == PlanTier.FREE
    assert result.activated_immediately is True
    assert result.checkout_url is None


def test_stripe_provider_enterprise_is_not_self_serve(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    provider = StripePaymentProvider()

    with pytest.raises(PaymentProviderError, match="not self-serve"):
        provider.start_plan_change(
            organization_id=uuid.uuid4(),
            plan=PlanTier.ENTERPRISE,
            customer_email="a@example.com",
            stripe_customer_id=None,
            stripe_subscription_id=None,
            success_url="https://app/success",
            cancel_url="https://app/cancel",
        )


def test_stripe_provider_pro_without_price_id_raises(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.delenv("STRIPE_PRICE_ID_PRO", raising=False)
    provider = StripePaymentProvider()

    with pytest.raises(PaymentProviderError, match="STRIPE_PRICE_ID_PRO"):
        provider.start_plan_change(
            organization_id=uuid.uuid4(),
            plan=PlanTier.PRO,
            customer_email="a@example.com",
            stripe_customer_id=None,
            stripe_subscription_id=None,
            success_url="https://app/success",
            cancel_url="https://app/cancel",
        )


def test_stripe_provider_pro_creates_checkout_session(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.setenv("STRIPE_PRICE_ID_PRO", "price_123")
    fake_session = MagicMock(id="cs_test_1", url="https://checkout.stripe.com/cs_test_1")
    fake_checkout = MagicMock()
    fake_checkout.Session.create.return_value = fake_session
    monkeypatch.setattr(stripe, "checkout", fake_checkout)
    provider = StripePaymentProvider()

    org_id = uuid.uuid4()
    result = provider.start_plan_change(
        organization_id=org_id,
        plan=PlanTier.PRO,
        customer_email="a@example.com",
        stripe_customer_id=None,
        stripe_subscription_id=None,
        success_url="https://app/success",
        cancel_url="https://app/cancel",
    )

    assert result.checkout_url == "https://checkout.stripe.com/cs_test_1"
    assert result.activated_immediately is False
    call_kwargs = fake_checkout.Session.create.call_args.kwargs
    assert call_kwargs["client_reference_id"] == str(org_id)
    assert call_kwargs["customer_email"] == "a@example.com"
    assert call_kwargs["line_items"] == [{"price": "price_123", "quantity": 1}]


def test_stripe_provider_webhook_requires_secret(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    provider = StripePaymentProvider()

    with pytest.raises(PaymentProviderError, match="STRIPE_WEBHOOK_SECRET"):
        provider.handle_webhook(b"{}", "sig")


def test_stripe_provider_webhook_checkout_completed(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_123")
    org_id = uuid.uuid4()
    fake_event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": str(org_id),
                "customer": "cus_1",
                "subscription": "sub_1",
                "metadata": {"plan": "pro"},
            }
        },
    }
    fake_webhook = MagicMock()
    fake_webhook.construct_event.return_value = fake_event
    monkeypatch.setattr(stripe, "Webhook", fake_webhook)
    provider = StripePaymentProvider()

    outcome = provider.handle_webhook(b"raw-body", "sig-header")

    assert outcome.organization_id == org_id
    assert outcome.plan == PlanTier.PRO
    assert outcome.stripe_customer_id == "cus_1"
    assert outcome.stripe_subscription_id == "sub_1"


def test_stripe_provider_webhook_subscription_deleted(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_123")
    fake_event = {"type": "customer.subscription.deleted", "data": {"object": {"customer": "cus_1"}}}
    fake_webhook = MagicMock()
    fake_webhook.construct_event.return_value = fake_event
    monkeypatch.setattr(stripe, "Webhook", fake_webhook)
    provider = StripePaymentProvider()

    outcome = provider.handle_webhook(b"raw-body", "sig-header")

    assert outcome.organization_id is None
    assert outcome.plan == PlanTier.FREE
    assert outcome.stripe_customer_id == "cus_1"


def test_stripe_provider_webhook_ignores_irrelevant_events(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_123")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_123")
    fake_event = {"type": "invoice.paid", "data": {"object": {}}}
    fake_webhook = MagicMock()
    fake_webhook.construct_event.return_value = fake_event
    monkeypatch.setattr(stripe, "Webhook", fake_webhook)
    provider = StripePaymentProvider()

    assert provider.handle_webhook(b"raw-body", "sig-header") is None


# ---------------------------------------------------------------------------
# BillingService tests using a duck-typed stub provider (no real/mocked Stripe
# SDK involved) -- verifies the checkout-deferred-activation and webhook
# reconciliation logic in isolation.
# ---------------------------------------------------------------------------


class _StubProvider:
    def __init__(self, result: SubscriptionResult, webhook_outcome: WebhookOutcome | None = None):
        self._result = result
        self._webhook_outcome = webhook_outcome

    def start_plan_change(self, **kwargs):
        return self._result

    def handle_webhook(self, payload, signature_header):
        return self._webhook_outcome


def _service(billing_repos, provider):
    user_repository, assessment_repository = billing_repos
    return BillingService(
        user_repository=user_repository,
        assessment_repository=assessment_repository,
        payment_provider=provider,
    )


@pytest.fixture
def billing_repos():
    return billing_router.service._user_repository, billing_router.service._assessment_repository


def test_change_plan_defers_activation_when_checkout_pending(billing_repos):
    org_id = uuid.uuid4()
    user_repository, _ = billing_repos
    user_repository.create_organization(Organization(id=org_id, name="Test", plan=PlanTier.FREE))
    service = _service(
        billing_repos,
        _StubProvider(SubscriptionResult(plan=PlanTier.PRO, checkout_url="https://checkout/x", activated_immediately=False)),
    )

    definition, checkout_url = service.change_plan(
        org_id, PlanTier.PRO, customer_email="a@example.com", success_url="s", cancel_url="c"
    )

    assert checkout_url == "https://checkout/x"
    # Plan must NOT have changed in the DB yet -- still Free until the webhook confirms payment.
    assert service.get_plan_definition(org_id).tier == PlanTier.FREE


def test_change_plan_activates_immediately_when_no_checkout_needed(billing_repos):
    org_id = uuid.uuid4()
    user_repository, _ = billing_repos
    user_repository.create_organization(Organization(id=org_id, name="Test", plan=PlanTier.PRO))
    service = _service(billing_repos, _StubProvider(SubscriptionResult(plan=PlanTier.FREE, activated_immediately=True)))

    definition, checkout_url = service.change_plan(
        org_id, PlanTier.FREE, customer_email="a@example.com", success_url="s", cancel_url="c"
    )

    assert checkout_url is None
    assert service.get_plan_definition(org_id).tier == PlanTier.FREE


def test_handle_stripe_webhook_resolves_org_by_customer_id_and_updates_plan(billing_repos):
    org_id = uuid.uuid4()
    user_repository, _ = billing_repos
    user_repository.create_organization(
        Organization(id=org_id, name="Test", plan=PlanTier.PRO, stripe_customer_id="cus_1", stripe_subscription_id="sub_1")
    )
    outcome = WebhookOutcome(plan=PlanTier.FREE, organization_id=None, stripe_customer_id="cus_1", stripe_subscription_id=None)
    service = _service(billing_repos, _StubProvider(SubscriptionResult(plan=PlanTier.PRO), webhook_outcome=outcome))

    service.handle_stripe_webhook(b"payload", "sig")

    org = user_repository.get_organization(org_id)
    assert org.plan == PlanTier.FREE
    assert org.stripe_subscription_id is None


def test_handle_stripe_webhook_noop_when_outcome_none(billing_repos):
    service = _service(billing_repos, _StubProvider(SubscriptionResult(plan=PlanTier.PRO), webhook_outcome=None))
    service.handle_stripe_webhook(b"payload", "sig")  # must not raise


# ---------------------------------------------------------------------------
# Router-level integration tests
# ---------------------------------------------------------------------------


def test_subscribe_endpoint_returns_checkout_url(monkeypatch, billing_repos):
    client = TestClient(app)
    headers = signup_headers(client)

    stub = _StubProvider(SubscriptionResult(plan=PlanTier.PRO, checkout_url="https://checkout/abc", activated_immediately=False))
    monkeypatch.setattr(billing_router, "service", _service(billing_repos, stub))

    response = client.post("/billing/subscribe", json={"plan": "pro"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["checkout_url"] == "https://checkout/abc"


def test_webhook_endpoint_processes_event_and_returns_200(monkeypatch, billing_repos):
    outcome = WebhookOutcome(plan=PlanTier.PRO, organization_id=uuid.uuid4())
    stub = _StubProvider(SubscriptionResult(plan=PlanTier.PRO), webhook_outcome=outcome)
    monkeypatch.setattr(billing_router, "service", _service(billing_repos, stub))

    client = TestClient(app)
    response = client.post("/billing/webhooks/stripe", content=b"{}", headers={"stripe-signature": "sig"})

    assert response.status_code == 200
    assert response.json() == {"received": True}


def test_webhook_endpoint_returns_400_on_provider_error(monkeypatch, billing_repos):
    class _ErrorProvider(_StubProvider):
        def handle_webhook(self, payload, signature_header):
            raise PaymentProviderError("bad signature")

    monkeypatch.setattr(billing_router, "service", _service(billing_repos, _ErrorProvider(SubscriptionResult(plan=PlanTier.PRO))))

    client = TestClient(app)
    response = client.post("/billing/webhooks/stripe", content=b"{}", headers={"stripe-signature": "bad"})

    assert response.status_code == 400
