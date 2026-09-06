from fastapi import APIRouter, Depends, HTTPException, status

from security_review.api.dependencies import get_current_user
from security_review.api.rate_limiter import (
    enforce_forgot_password_rate_limit,
    enforce_login_rate_limit,
    enforce_signup_rate_limit,
)
from security_review.application.auth_service import (
    AuthService,
    InvalidCredentialsError,
    InvalidResetTokenError,
)
from security_review.domain.auth.models import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
    TokenResponse,
    User,
    UserResponse,
)
from security_review.infrastructure.security.public_url import get_public_base_url

router = APIRouter(prefix="/auth", tags=["Auth"])
service = AuthService()


@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_signup_rate_limit)],
)
def signup(payload: SignupRequest) -> TokenResponse:
    try:
        return service.signup(payload)
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(enforce_login_rate_limit)])
def login(payload: LoginRequest) -> TokenResponse:
    try:
        return service.login(payload)
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        organization_id=current_user.organization_id,
        role=current_user.role,
        created_at=current_user.created_at,
    )


@router.post("/forgot-password", dependencies=[Depends(enforce_forgot_password_rate_limit)])
def forgot_password(payload: ForgotPasswordRequest) -> dict:
    service.request_password_reset(payload, get_public_base_url())
    # Always the same response, regardless of whether the email is registered,
    # to avoid leaking which emails have accounts (user enumeration).
    return {"detail": "If an account with that email exists, a password reset link has been sent."}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest) -> dict:
    try:
        service.reset_password(payload)
    except InvalidResetTokenError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"detail": "Password has been reset. You can now log in."}

