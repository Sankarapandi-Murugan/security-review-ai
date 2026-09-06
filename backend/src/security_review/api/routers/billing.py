from fastapi import APIRouter, Depends, HTTPException, Request, status

from security_review.api.dependencies import get_current_organization_id, require_roles
from security_review.application.billing_service import BillingService
from security_review.domain.auth.models import User, UserRole
from security_review.domain.billing.models import PlanResponse, SubscribeRequest, UsageResponse, plan_to_response
from security_review.infrastructure.billing.payment_provider import PaymentProviderError
from security_review.infrastructure.security.public_url import get_public_base_url

router = APIRouter(prefix="/billing", tags=["Billing"])
service = BillingService()


@router.get("/plans", response_model=list[PlanResponse])
def list_plans() -> list[dict]:
    return service.list_plans()


@router.get("/usage", response_model=UsageResponse)
def get_usage(organization_id=Depends(get_current_organization_id)) -> UsageResponse:
    return service.get_usage(organization_id)


@router.post("/subscribe", response_model=PlanResponse)
def subscribe(
    payload: SubscribeRequest,
    organization_id=Depends(get_current_organization_id),
    current_user: User = Depends(require_roles(UserRole.OWNER)),
) -> dict:
    base_url = get_public_base_url()
    try:
        definition, checkout_url = service.change_plan(
            organization_id,
            payload.plan,
            customer_email=current_user.email,
            success_url=f"{base_url}/ui/?checkout=success",
            cancel_url=f"{base_url}/ui/?checkout=cancelled",
        )
    except PaymentProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    response = plan_to_response(definition).model_dump()
    response["checkout_url"] = checkout_url
    return response


@router.post("/webhooks/stripe", include_in_schema=False)
async def stripe_webhook(request: Request) -> dict:
    """Receives Stripe webhook events (not authenticated via bearer token — Stripe
    can't send one; the request is instead verified via its signed payload)."""
    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    try:
        service.handle_stripe_webhook(payload, signature)
    except PaymentProviderError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"received": True}

