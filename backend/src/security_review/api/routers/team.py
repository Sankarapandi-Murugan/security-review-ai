from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from security_review.api.dependencies import get_current_organization_id, require_roles
from security_review.application.team_service import LastOwnerError, TeamError, TeamService
from security_review.domain.auth.models import (
    ChangeMemberRoleRequest,
    InviteMemberRequest,
    UserResponse,
    UserRole,
)
from security_review.infrastructure.security.public_url import get_public_base_url

router = APIRouter(prefix="/team", tags=["Team"])
service = TeamService()


def _to_response(user) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        organization_id=user.organization_id,
        role=user.role,
        created_at=user.created_at,
    )


@router.get("/members", response_model=list[UserResponse])
def list_members(organization_id: UUID = Depends(get_current_organization_id)) -> list[UserResponse]:
    return [_to_response(user) for user in service.list_members(organization_id)]


@router.post("/invite", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def invite_member(
    payload: InviteMemberRequest,
    organization_id: UUID = Depends(get_current_organization_id),
    _current_user=Depends(require_roles(UserRole.OWNER, UserRole.ADMIN)),
) -> UserResponse:
    try:
        user = service.invite_member(organization_id, payload.email, payload.role, get_public_base_url())
    except TeamError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _to_response(user)


@router.patch("/members/{user_id}/role", response_model=UserResponse)
def change_member_role(
    user_id: UUID,
    payload: ChangeMemberRoleRequest,
    organization_id: UUID = Depends(get_current_organization_id),
    _current_user=Depends(require_roles(UserRole.OWNER)),
) -> UserResponse:
    try:
        user = service.update_member_role(organization_id, user_id, payload.role)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found") from exc
    except LastOwnerError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _to_response(user)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    user_id: UUID,
    organization_id: UUID = Depends(get_current_organization_id),
    _current_user=Depends(require_roles(UserRole.OWNER)),
) -> None:
    try:
        service.remove_member(organization_id, user_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found") from exc
    except LastOwnerError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
