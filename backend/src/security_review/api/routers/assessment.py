import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, status
from starlette.responses import StreamingResponse

from security_review.api.dependencies import get_current_organization_id, get_current_user, require_roles
from security_review.application.assessment_service import AssessmentService
from security_review.domain.assessment.exceptions import PlanLimitExceededError, RepositoryNotReadyError
from security_review.domain.assessment.models import (
    AgentType,
    AssessmentCreateRequest,
    AssessmentResponse,
    Finding,
    Repository,
    RepositoryCreateRequest,
    ScanJob,
    ScanJobCreateRequest,
    ScanStatus,
    TrivyScanRequest,
)
from security_review.domain.auth.models import UserRole

router = APIRouter(tags=["Assessments"])
service = AssessmentService()


@router.post(
    "/assessments",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_assessment(
    payload: AssessmentCreateRequest,
    organization_id: UUID = Depends(get_current_organization_id),
) -> AssessmentResponse:
    try:
        return service.create_assessment(payload, organization_id)
    except PlanLimitExceededError as exc:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(exc)) from exc


@router.get("/assessments/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(
    assessment_id: UUID, organization_id: UUID = Depends(get_current_organization_id)
) -> AssessmentResponse:
    try:
        return service.get_assessment(assessment_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get("/assessments", response_model=list[AssessmentResponse])
def list_assessments(
    response: Response,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    organization_id: UUID = Depends(get_current_organization_id),
) -> list[AssessmentResponse]:
    response.headers["X-Total-Count"] = str(service.count_assessments(organization_id))
    return service.list_assessments(organization_id, limit=limit, offset=offset)


@router.delete("/assessments/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_assessment(
    assessment_id: UUID,
    organization_id: UUID = Depends(get_current_organization_id),
    _current_user=Depends(require_roles(UserRole.OWNER, UserRole.ADMIN)),
) -> None:
    try:
        service.delete_assessment(assessment_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.post(
    "/assessments/{assessment_id}/repositories",
    response_model=Repository,
    status_code=status.HTTP_201_CREATED,
)
def ingest_repository(
    assessment_id: UUID,
    payload: RepositoryCreateRequest,
    background_tasks: BackgroundTasks,
    organization_id: UUID = Depends(get_current_organization_id),
) -> Repository:
    try:
        repository = service.ingest_repository(assessment_id, payload, organization_id)
        background_tasks.add_task(service.run_repository_ingestion, assessment_id, repository.id)
        return repository
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get(
    "/assessments/{assessment_id}/repositories",
    response_model=list[Repository],
)
def list_repositories(
    assessment_id: UUID, organization_id: UUID = Depends(get_current_organization_id)
) -> list[Repository]:
    try:
        return service.list_repositories(assessment_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get(
    "/assessments/{assessment_id}/repositories/{repository_id}",
    response_model=Repository,
)
def get_repository(
    assessment_id: UUID,
    repository_id: UUID,
    organization_id: UUID = Depends(get_current_organization_id),
) -> Repository:
    try:
        return service.get_repository(assessment_id, repository_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found") from exc


@router.delete(
    "/assessments/{assessment_id}/repositories/{repository_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_repository(
    assessment_id: UUID,
    repository_id: UUID,
    organization_id: UUID = Depends(get_current_organization_id),
    _current_user=Depends(require_roles(UserRole.OWNER, UserRole.ADMIN)),
) -> None:
    try:
        service.delete_repository(assessment_id, repository_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found") from exc


@router.post(
    "/assessments/{assessment_id}/scan-jobs",
    response_model=ScanJob,
    status_code=status.HTTP_201_CREATED,
)
def create_scan_job(
    assessment_id: UUID,
    payload: ScanJobCreateRequest,
    background_tasks: BackgroundTasks,
    organization_id: UUID = Depends(get_current_organization_id),
    current_user=Depends(get_current_user),
) -> ScanJob:
    try:
        scan_job = service.create_scan_job(
            assessment_id, payload, organization_id, confirmed_by=current_user.email
        )
        background_tasks.add_task(service.execute_scan_job, assessment_id, scan_job.id)
        return scan_job
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc
    except RepositoryNotReadyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except PlanLimitExceededError as exc:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=str(exc)) from exc


@router.get(
    "/assessments/{assessment_id}/scan-jobs",
    response_model=list[ScanJob],
)
def list_scan_jobs(
    assessment_id: UUID, organization_id: UUID = Depends(get_current_organization_id)
) -> list[ScanJob]:
    try:
        return service.list_scan_jobs(assessment_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get(
    "/assessments/{assessment_id}/findings",
    response_model=list[Finding],
)
def list_assessment_findings(
    assessment_id: UUID, organization_id: UUID = Depends(get_current_organization_id)
) -> list[Finding]:
    try:
        return service.list_findings(assessment_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get("/assessments/{assessment_id}/report")
def get_assessment_report(
    assessment_id: UUID, organization_id: UUID = Depends(get_current_organization_id)
) -> dict[str, object]:
    try:
        return service.get_assessment_report(assessment_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get(
    "/assessments/{assessment_id}/scan-jobs/{scan_job_id}",
    response_model=ScanJob,
)
def get_scan_job(
    assessment_id: UUID,
    scan_job_id: UUID,
    organization_id: UUID = Depends(get_current_organization_id),
) -> ScanJob:
    try:
        return service.get_scan_job(assessment_id, scan_job_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found") from exc


@router.post(
    "/assessments/{assessment_id}/trivy-scan",
    response_model=list[Finding],
    status_code=status.HTTP_200_OK,
)
def run_trivy_scan(
    assessment_id: UUID,
    payload: TrivyScanRequest,
    organization_id: UUID = Depends(get_current_organization_id),
) -> list[Finding]:
    try:
        return service.run_trivy_scan(assessment_id, payload, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.post(
    "/assessments/{assessment_id}/trivy-scan-async",
    response_model=ScanJob,
    status_code=status.HTTP_201_CREATED,
)
def run_trivy_scan_async(
    assessment_id: UUID,
    payload: TrivyScanRequest,
    background_tasks: BackgroundTasks,
    organization_id: UUID = Depends(get_current_organization_id),
) -> ScanJob:
    try:
        # Create a scan job using the existing service and schedule it in the background
        scan_job_payload = ScanJobCreateRequest(
            agent_type=AgentType.TRIVY,
            target=payload.target,
            webhook_url=payload.webhook_url,
        )
        scan_job = service.create_scan_job(assessment_id, scan_job_payload, organization_id)
        background_tasks.add_task(service.execute_scan_job, assessment_id, scan_job.id)
        return scan_job
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found") from exc


@router.get("/assessments/{assessment_id}/scan-jobs/{scan_job_id}/stream")
async def stream_scan_job_status(
    assessment_id: UUID,
    scan_job_id: UUID,
    organization_id: UUID = Depends(get_current_organization_id),
) -> StreamingResponse:
    """Stream live scan job status updates via Server-Sent Events until the job finishes."""
    try:
        service.get_scan_job(assessment_id, scan_job_id, organization_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found") from exc

    async def event_generator():
        last_payload: str | None = None
        poll_interval = 0.5
        max_polls = 600  # ~5 minutes safety cap

        for _ in range(max_polls):
            try:
                scan_job = service.get_scan_job(assessment_id, scan_job_id, organization_id)
            except KeyError:
                yield (
                    "event: error\n"
                    f"data: {json.dumps({'detail': 'Scan job not found'})}\n\n"
                )
                return

            payload = json.dumps(scan_job.model_dump(mode="json"))
            if payload != last_payload:
                yield f"data: {payload}\n\n"
                last_payload = payload

            if scan_job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                return

            await asyncio.sleep(poll_interval)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )