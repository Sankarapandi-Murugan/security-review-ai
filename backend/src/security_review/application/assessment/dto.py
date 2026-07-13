from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class CreateAssessmentRequest:
    name: str


@dataclass(frozen=True)
class CreateAssessmentResponse:
    id: UUID
    name: str
    status: str
    created_at: datetime