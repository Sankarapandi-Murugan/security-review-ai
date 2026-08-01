from fastapi import APIRouter, Depends, HTTPException, status

from security_review.api.dependencies import get_current_user
from security_review.api.rate_limiter import enforce_login_rate_limit, enforce_signup_rate_limit
from security_review.application.auth_service import AuthService, InvalidCredentialsError
from security_review.domain.auth.models import (
    LoginRequest,
    SignupRequest,
    TokenResponse,
    User,
    UserResponse,
)

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
