from dataclasses import dataclass, field
from datetime import datetime, UTC
from uuid import UUID, uuid4

from security_review.domain.assessment.enums import AssessmentStatus


@dataclass
class Assessment:
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    status: AssessmentStatus = AssessmentStatus.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))