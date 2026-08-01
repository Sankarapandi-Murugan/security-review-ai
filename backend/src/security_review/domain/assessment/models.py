from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from security_review.domain.assessment.enums import AssessmentStatus, RepositoryIngestStatus
from security_review.domain.assessment.exceptions import (
    InvalidAssessmentStateError,
)
from security_review.domain.auth.models import NIL_ORGANIZATION_ID


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentType(str, Enum):
    WHITE_BOX = "white_box"
    BLACK_BOX = "black_box"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    API_SECURITY = "api_security"
    CLOUD_SECURITY = "cloud_security"
    DEPENDENCY_SECURITY = "dependency_security"
    SECRET_DETECTION = "secret_detection"
    TRIVY = "trivy"


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    description: str = ""
    evidence: str | None = None
    remediation: str | None = None


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanJob(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    agent_type: AgentType
    target: str | None = None
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    webhook_url: str | None = None
    target_authorization_confirmed: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanJobCreateRequest(BaseModel):
    agent_type: AgentType
    target: str | None = None
    repository_id: UUID | None = None
    webhook_url: str | None = None
    target_authorization_confirmed: bool = False


class TrivyScanRequest(BaseModel):
    target: str = Field(min_length=1)
    webhook_url: str | None = None


class AssessmentCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    description: str | None = None


class Repository(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    url: str
    branch: str = "main"
    status: RepositoryIngestStatus = RepositoryIngestStatus.PENDING
    local_path: str | None = None
    commit_hash: str | None = None
    error_message: str | None = None
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RepositoryCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    url: str = Field(min_length=1)
    branch: str = "main"


class AssessmentResponse(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    status: AssessmentStatus
    organization_id: UUID = NIL_ORGANIZATION_ID
    findings: list[Finding] = Field(default_factory=list)
    scan_jobs: list[ScanJob] = Field(default_factory=list)
    repositories: list[Repository] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


@dataclass
class Assessment:
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    description: str | None = None
    status: AssessmentStatus = AssessmentStatus.CREATED
    organization_id: UUID = field(default_factory=lambda: NIL_ORGANIZATION_ID)
    findings: list[Finding] = field(default_factory=list)
    scan_jobs: list[ScanJob] = field(default_factory=list)
    repositories: list[Repository] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def rename(self, name: str) -> None:
        """Rename the assessment."""
        self.name = name
        self.updated_at = datetime.now(UTC)

    def start_analysis(self) -> None:
        """Move assessment to ANALYZING state."""
        if self.status not in (AssessmentStatus.CREATED, AssessmentStatus.COMPLETED):
            raise InvalidAssessmentStateError(
                "Only a newly created or previously completed assessment can start analysis."
            )

        self.status = AssessmentStatus.ANALYZING
        self.updated_at = datetime.now(UTC)

    def complete(self) -> None:
        """Mark assessment as completed."""
        if self.status != AssessmentStatus.ANALYZING:
            raise InvalidAssessmentStateError(
                "Only an analyzing assessment can be completed."
            )

        self.status = AssessmentStatus.COMPLETED
        self.updated_at = datetime.now(UTC)

    def fail(self) -> None:
        """Mark assessment as failed."""
        if self.status != AssessmentStatus.ANALYZING:
            raise InvalidAssessmentStateError(
                "Only an analyzing assessment can fail."
            )

        self.status = AssessmentStatus.FAILED
        self.updated_at = datetime.now(UTC)

    def to_response(self) -> AssessmentResponse:
        return AssessmentResponse(
            id=self.id,
            name=self.name,
            description=self.description,
            status=self.status,
            organization_id=self.organization_id,
            findings=self.findings,
            scan_jobs=self.scan_jobs,
            repositories=self.repositories,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.to_response().model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Assessment":
        response = AssessmentResponse.model_validate(data)
        return cls(
            id=response.id,
            name=response.name,
            description=response.description,
            status=response.status,
            organization_id=response.organization_id,
            findings=[Finding.model_validate(item) for item in response.findings],
            scan_jobs=[ScanJob.model_validate(item) for item in response.scan_jobs],
            repositories=[Repository.model_validate(item) for item in response.repositories],
            created_at=response.created_at,
            updated_at=response.updated_at,
        )
