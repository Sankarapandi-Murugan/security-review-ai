import hashlib
import hmac
import json
import logging
import os
import shutil
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import httpx

from security_review.application.billing_service import BillingService
from security_review.domain.assessment.enums import AssessmentStatus, RepositoryIngestStatus
from security_review.domain.assessment.exceptions import RepositoryNotReadyError
from security_review.domain.assessment.models import (
    AgentType,
    Assessment,
    AssessmentCreateRequest,
    AssessmentResponse,
    Finding,
    FindingSeverity,
    Repository,
    RepositoryCreateRequest,
    ScanJob,
    ScanJobCreateRequest,
    ScanStatus,
    TrivyScanRequest,
)
from security_review.domain.audit.models import ConsentAuditEntry
from security_review.domain.auth.models import NIL_ORGANIZATION_ID
from security_review.infrastructure.observability.metrics import FINDINGS_TOTAL, SCAN_JOBS_TOTAL
from security_review.infrastructure.persistence.sqlite_assessment_repository import (
    SqliteAssessmentRepository,
)
from security_review.infrastructure.persistence.sqlite_audit_log_repository import (
    SqliteAuditLogRepository,
)
from security_review.infrastructure.scanners.agent_factory import AgentFactory
from security_review.infrastructure.vcs.git_repository_ingestion_service import (
    GitRepositoryIngestionService,
    RepositoryIngestionError,
)

logger = logging.getLogger(__name__)


class AssessmentService:
    """SQLite-backed service for managing assessments."""

    def __init__(
        self,
        repository: SqliteAssessmentRepository | None = None,
        git_ingestion_service: GitRepositoryIngestionService | None = None,
        billing_service: BillingService | None = None,
        audit_log_repository: SqliteAuditLogRepository | None = None,
    ) -> None:
        self._repository = repository or SqliteAssessmentRepository()
        self._repository.initialize()
        self._git_ingestion_service = git_ingestion_service or GitRepositoryIngestionService()
        self._billing_service = billing_service or BillingService(assessment_repository=self._repository)
        self._audit_log_repository = audit_log_repository or SqliteAuditLogRepository()
        self._audit_log_repository.initialize()

    def create_assessment(self, payload: AssessmentCreateRequest, organization_id: UUID) -> AssessmentResponse:
        self._billing_service.enforce_assessment_limit(organization_id)
        assessment = Assessment(name=payload.name, description=payload.description, organization_id=organization_id)
        self._repository.save(assessment)
        return assessment.to_response()

    def get_assessment(self, assessment_id: UUID, organization_id: UUID | None = None) -> AssessmentResponse:
        assessment = self._repository.get(assessment_id, organization_id)
        return assessment.to_response()

    def list_assessments(
        self,
        organization_id: UUID | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[AssessmentResponse]:
        assessments = self._repository.list(organization_id, limit=limit, offset=offset)
        return [assessment.to_response() for assessment in assessments]

    def count_assessments(self, organization_id: UUID | None = None) -> int:
        return self._repository.count(organization_id)

    def delete_assessment(self, assessment_id: UUID, organization_id: UUID | None = None) -> None:
        assessment = self._repository.delete(assessment_id, organization_id)
        for repository in assessment.repositories:
            self._cleanup_repository_clone(repository)

    def delete_repository(
        self, assessment_id: UUID, repository_id: UUID, organization_id: UUID | None = None
    ) -> None:
        assessment = self._repository.get(assessment_id, organization_id)
        repository = self._get_repository(assessment, repository_id)
        assessment.repositories.remove(repository)
        assessment.updated_at = datetime.now(UTC)
        self._repository.save(assessment)
        self._cleanup_repository_clone(repository)

    @staticmethod
    def _cleanup_repository_clone(repository: Repository) -> None:
        if not repository.local_path:
            return
        clone_path = Path(repository.local_path).expanduser()
        if not clone_path.is_absolute():
            clone_path = (Path.cwd() / clone_path).resolve()
        else:
            clone_path = clone_path.resolve()

        if not clone_path.exists():
            return

        def _remove_readonly(func: object, path: str, exc_info: object) -> None:  # type: ignore[override]
            try:
                os.chmod(path, os.stat(path).st_mode | stat.S_IWRITE)
                func(path)
            except (PermissionError, OSError):
                pass

        for current_root, dirs, files in os.walk(clone_path, topdown=False):
            for entry in list(dirs) + list(files):
                full_path = Path(current_root) / entry
                try:
                    os.chmod(full_path, os.stat(full_path).st_mode | stat.S_IWRITE)
                except OSError:
                    pass

        shutil.rmtree(clone_path, onerror=_remove_readonly)

    def ingest_repository(
        self, assessment_id: UUID, payload: RepositoryCreateRequest, organization_id: UUID | None = None
    ) -> Repository:
        assessment = self._repository.get(assessment_id, organization_id)
        repository = Repository(name=payload.name, url=payload.url, branch=payload.branch)
        assessment.repositories.append(repository)
        assessment.updated_at = datetime.now(UTC)
        self._repository.save(assessment)
        return repository

    def run_repository_ingestion(self, assessment_id: UUID, repository_id: UUID) -> None:
        """Clone the repository's remote URL to local disk (intended to run in the background)."""
        repository_store = SqliteAssessmentRepository(self._repository.db_path)
        repository_store.initialize()
        assessment = repository_store.get(assessment_id)
        repository = self._get_repository(assessment, repository_id)

        repository.status = RepositoryIngestStatus.CLONING
        assessment.updated_at = datetime.now(UTC)
        repository_store.save(assessment)

        try:
            result = self._git_ingestion_service.clone(
                url=repository.url, branch=repository.branch, repository_id=repository.id
            )
            repository.local_path = str(result.local_path)
            repository.commit_hash = result.commit_hash
            repository.status = RepositoryIngestStatus.READY
            repository.error_message = None
        except RepositoryIngestionError as exc:
            repository.status = RepositoryIngestStatus.FAILED
            repository.error_message = str(exc)
        finally:
            assessment.updated_at = datetime.now(UTC)
            repository_store.save(assessment)

    def create_scan_job(
        self,
        assessment_id: UUID,
        payload: ScanJobCreateRequest,
        organization_id: UUID | None = None,
        confirmed_by: str | None = None,
    ) -> ScanJob:
        if organization_id is not None:
            self._billing_service.enforce_scan_job_limit(organization_id)

        assessment = self._repository.get(assessment_id, organization_id)
        if assessment.status in (AssessmentStatus.CREATED, AssessmentStatus.COMPLETED):
            assessment.start_analysis()

        target = payload.target
        if payload.repository_id is not None:
            repository = self._get_repository(assessment, payload.repository_id)
            if repository.status != RepositoryIngestStatus.READY or not repository.local_path:
                raise RepositoryNotReadyError(
                    f"Repository {repository.id} is not ready for scanning (status={repository.status.value})."
                )
            target = repository.local_path

        scan_job = ScanJob(
            name=f"{payload.agent_type.value} scan",
            agent_type=payload.agent_type,
            target=target,
            status=ScanStatus.PENDING,
            webhook_url=payload.webhook_url,
            target_authorization_confirmed=payload.target_authorization_confirmed,
        )

        if payload.target_authorization_confirmed:
            scan_job.authorized_by = confirmed_by or "unknown"
            scan_job.authorized_at = datetime.now(UTC)
            self._audit_log_repository.record(
                ConsentAuditEntry(
                    organization_id=organization_id or NIL_ORGANIZATION_ID,
                    assessment_id=assessment.id,
                    scan_job_id=scan_job.id,
                    agent_type=payload.agent_type.value,
                    target=target or "",
                    confirmed_by=scan_job.authorized_by,
                    confirmed_at=scan_job.authorized_at,
                )
            )

        assessment.scan_jobs.append(scan_job)
        assessment.updated_at = datetime.now(UTC)
        self._repository.save(assessment)
        return scan_job

    def list_scan_jobs(self, assessment_id: UUID, organization_id: UUID | None = None) -> list[ScanJob]:
        assessment = self._repository.get(assessment_id, organization_id)
        return assessment.scan_jobs

    def get_scan_job(
        self, assessment_id: UUID, scan_job_id: UUID, organization_id: UUID | None = None
    ) -> ScanJob:
        assessment = self._repository.get(assessment_id, organization_id)
        for scan_job in assessment.scan_jobs:
            if scan_job.id == scan_job_id:
                return scan_job
        raise KeyError(scan_job_id)

    def execute_scan_job(self, assessment_id: UUID, scan_job_id: UUID) -> None:
        repository = SqliteAssessmentRepository(self._repository.db_path)
        repository.initialize()
        assessment = repository.get(assessment_id)
        scan_job = self._get_scan_job(assessment, scan_job_id)

        logger.debug(
            "scan job started",
            extra={
                "assessment_id": str(assessment_id),
                "scan_job_id": str(scan_job_id),
                "agent_type": scan_job.agent_type.value,
                "target": scan_job.target,
            },
        )
        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.now(UTC)
        assessment.updated_at = datetime.now(UTC)
        repository.save(assessment)

        findings: list[Finding] = []
        try:
            logger.debug(
                "creating scan agent",
                extra={"scan_job_id": str(scan_job_id), "agent_type": scan_job.agent_type.value},
            )
            agent = AgentFactory.create(scan_job.agent_type)
            logger.debug(
                "executing scan agent",
                extra={
                    "scan_job_id": str(scan_job_id),
                    "agent_type": scan_job.agent_type.value,
                    "authorized": scan_job.target_authorization_confirmed,
                },
            )
            findings = agent.execute(
                scan_job.target, authorized=scan_job.target_authorization_confirmed
            )
            assessment.findings.extend(findings)
            scan_job.status = ScanStatus.COMPLETED
            scan_job.completed_at = datetime.now(UTC)
            logger.debug(
                "scan job completed",
                extra={
                    "scan_job_id": str(scan_job_id),
                    "agent_type": scan_job.agent_type.value,
                    "finding_count": len(findings),
                },
            )
        except Exception as exc:
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.now(UTC)
            scan_job.error_message = str(exc)
            logger.exception(
                "scan job failed",
                extra={
                    "scan_job_id": str(scan_job_id),
                    "agent_type": scan_job.agent_type.value,
                },
            )
        finally:
            self._reconcile_assessment_status(assessment)
            assessment.updated_at = datetime.now(UTC)
            repository.save(assessment)
            self._notify_webhook(scan_job, findings)
            self._record_scan_metrics(scan_job, findings)

    def _record_scan_metrics(self, scan_job: ScanJob, findings: list[Finding]) -> None:
        SCAN_JOBS_TOTAL.labels(agent_type=scan_job.agent_type.value, status=scan_job.status.value).inc()
        for finding in findings:
            FINDINGS_TOTAL.labels(severity=finding.severity.value).inc()

    def _notify_webhook(self, scan_job: ScanJob, findings: list[Finding]) -> None:
        if not scan_job.webhook_url:
            return

        payload = {
            "scan_job_id": str(scan_job.id),
            "agent_type": scan_job.agent_type.value,
            "status": scan_job.status.value,
            "target": scan_job.target,
            "error_message": scan_job.error_message,
            "finding_count": len(findings),
            "findings": [finding.model_dump(mode="json") for finding in findings],
        }

        # Serialize once so the exact bytes sent are the exact bytes signed, allowing
        # receivers to verify the signature against the raw request body.
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        secret = self._webhook_secret()
        if secret:
            signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
            headers["X-Signature-256"] = f"sha256={signature}"

        try:
            httpx.post(scan_job.webhook_url, content=body, headers=headers, timeout=5.0)
        except httpx.HTTPError:
            # Webhook delivery is best-effort; failures must not break the scan job.
            pass

    @staticmethod
    def _webhook_secret() -> str | None:
        return os.getenv("SECURITY_REVIEW_WEBHOOK_SECRET") or None

    def _get_scan_job(self, assessment: Assessment, scan_job_id: UUID) -> ScanJob:
        for scan_job in assessment.scan_jobs:
            if scan_job.id == scan_job_id:
                return scan_job
        raise KeyError(scan_job_id)

    def _get_repository(self, assessment: Assessment, repository_id: UUID) -> Repository:
        for repository in assessment.repositories:
            if repository.id == repository_id:
                return repository
        raise KeyError(repository_id)

    def _reconcile_assessment_status(self, assessment: Assessment) -> None:
        if any(job.status in (ScanStatus.PENDING, ScanStatus.RUNNING) for job in assessment.scan_jobs):
            assessment.status = AssessmentStatus.ANALYZING
            return

        if any(job.status == ScanStatus.FAILED for job in assessment.scan_jobs):
            assessment.status = AssessmentStatus.FAILED
            return

        if any(job.status == ScanStatus.COMPLETED for job in assessment.scan_jobs):
            assessment.status = AssessmentStatus.COMPLETED
            return

        assessment.status = AssessmentStatus.CREATED

    def list_repositories(self, assessment_id: UUID, organization_id: UUID | None = None) -> list[Repository]:
        assessment = self._repository.get(assessment_id, organization_id)
        return assessment.repositories

    def get_repository(
        self, assessment_id: UUID, repository_id: UUID, organization_id: UUID | None = None
    ) -> Repository:
        assessment = self._repository.get(assessment_id, organization_id)
        for repository in assessment.repositories:
            if repository.id == repository_id:
                return repository
        raise KeyError(repository_id)

    def list_findings(self, assessment_id: UUID, organization_id: UUID | None = None) -> list[Finding]:
        assessment = self._repository.get(assessment_id, organization_id)
        return assessment.findings

    def run_trivy_scan(
        self, assessment_id: UUID, payload: TrivyScanRequest, organization_id: UUID | None = None
    ) -> list[Finding]:
        """Run a Trivy filesystem scan synchronously and record findings on the assessment."""
        assessment = self._repository.get(assessment_id, organization_id)

        # Create a scan job record and mark as running
        scan_job = ScanJob(
            name="trivy scan",
            agent_type=AgentType.TRIVY,
            target=payload.target,
            status=ScanStatus.RUNNING,
            webhook_url=payload.webhook_url,
        )

        assessment.scan_jobs.append(scan_job)
        assessment.updated_at = datetime.now(UTC)
        self._repository.save(assessment)

        try:
            agent = AgentFactory.create(scan_job.agent_type)
            findings = agent.execute(
                scan_job.target, authorized=scan_job.target_authorization_confirmed
            )
            assessment.findings.extend(findings)
            scan_job.status = ScanStatus.COMPLETED
            scan_job.completed_at = datetime.now(UTC)
        except Exception as exc:
            scan_job.status = ScanStatus.FAILED
            scan_job.completed_at = datetime.now(UTC)
            scan_job.error_message = str(exc)
            findings = []
        finally:
            self._reconcile_assessment_status(assessment)
            assessment.updated_at = datetime.now(UTC)
            self._repository.save(assessment)
            self._notify_webhook(scan_job, findings)
            self._record_scan_metrics(scan_job, findings)

        return findings

    def get_assessment_report(self, assessment_id: UUID, organization_id: UUID | None = None) -> dict[str, object]:
        assessment = self._repository.get(assessment_id, organization_id)
        findings = assessment.findings
        severity_counts = Counter(finding.severity.value for finding in findings)
        recommendations = [finding.remediation for finding in findings if finding.remediation]
        agent_breakdown = Counter(scan_job.agent_type.value for scan_job in assessment.scan_jobs)

        return {
            "assessment_id": str(assessment.id),
            "name": assessment.name,
            "status": assessment.status.value,
            "finding_count": len(findings),
            "severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
            },
            "agent_breakdown": dict(agent_breakdown),
            "recommendations": recommendations,
            "repositories": [repository.name for repository in assessment.repositories],
        }

    def get_consent_audit_log(self, organization_id: UUID) -> list[ConsentAuditEntry]:
        """Return the immutable authorization-consent trail for active scanning in this org."""
        return self._audit_log_repository.list(organization_id)


    def _finding_title(self, agent_type: object) -> str:
        title_map = {
            "white_box": "White Box analysis completed",
            "black_box": "Black Box reconnaissance completed",
            "red_team": "Red Team simulation completed",
            "blue_team": "Blue Team detection review completed",
            "api_security": "API security review completed",
            "cloud_security": "Cloud security posture review completed",
            "dependency_security": "Dependency vulnerability review completed",
            "secret_detection": "Secret exposure review completed",
            "auto_remediation": "Auto-remediation completed",
        }
        return title_map.get(agent_type.value, "Security scan completed")

    def _finding_severity(self, agent_type: object) -> FindingSeverity:
        severity_map = {
            "white_box": FindingSeverity.HIGH,
            "black_box": FindingSeverity.HIGH,
            "red_team": FindingSeverity.CRITICAL,
            "blue_team": FindingSeverity.MEDIUM,
            "api_security": FindingSeverity.HIGH,
            "cloud_security": FindingSeverity.HIGH,
            "dependency_security": FindingSeverity.HIGH,
            "secret_detection": FindingSeverity.CRITICAL,
            "auto_remediation": FindingSeverity.MEDIUM,
        }
        return severity_map.get(agent_type.value, FindingSeverity.MEDIUM)

    def _finding_description(self, agent_type: object, target: str | None) -> str:
        target_value = target or "the requested scope"
        return (
            f"The {agent_type.value.replace('_', ' ')} agent completed an autonomous security review "
            f"for {target_value}."
        )
