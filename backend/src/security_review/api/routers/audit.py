from fastapi import APIRouter, Depends

from security_review.api.dependencies import get_current_organization_id
from security_review.application.assessment_service import AssessmentService
from security_review.domain.audit.models import ConsentAuditEntryResponse

router = APIRouter(prefix="/audit", tags=["Audit"])
service = AssessmentService()


@router.get("/consent-log", response_model=list[ConsentAuditEntryResponse])
def get_consent_audit_log(organization_id=Depends(get_current_organization_id)) -> list[ConsentAuditEntryResponse]:
    """Immutable trail of who confirmed authorization for active/intrusive scanning, and when."""
    entries = service.get_consent_audit_log(organization_id)
    return [
        ConsentAuditEntryResponse(
            id=entry.id,
            organization_id=entry.organization_id,
            assessment_id=entry.assessment_id,
            scan_job_id=entry.scan_job_id,
            agent_type=entry.agent_type,
            target=entry.target,
            confirmed_by=entry.confirmed_by,
            confirmed_at=entry.confirmed_at,
        )
        for entry in entries
    ]
