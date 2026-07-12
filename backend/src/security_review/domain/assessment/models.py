from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from security_review.domain.assessment.enums import AssessmentStatus
from security_review.domain.assessment.exceptions import (
    InvalidAssessmentStateError,
)


@dataclass
class Assessment:
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    status: AssessmentStatus = AssessmentStatus.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def rename(self, name: str) -> None:
        """Rename the assessment."""
        self.name = name
        self.updated_at = datetime.now(UTC)

    def start_analysis(self) -> None:
        """Move assessment to ANALYZING state."""
        if self.status != AssessmentStatus.CREATED:
            raise InvalidAssessmentStateError(
                "Only a newly created assessment can start analysis."
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