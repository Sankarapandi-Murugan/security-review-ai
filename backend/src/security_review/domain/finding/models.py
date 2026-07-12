from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from security_review.domain.finding.enums import (
    Confidence,
    FindingStatus,
    Severity,
)
from security_review.domain.finding.exceptions import (
    InvalidFindingStateError,
)
from security_review.domain.finding.value_objects import Location


@dataclass
class Finding:
    id: UUID = field(default_factory=uuid4)
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    location: Location | None = None
    status: FindingStatus = FindingStatus.OPEN

    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def _touch(self):
        self.updated_at = datetime.now(UTC)

    def confirm(self):
        if self.status != FindingStatus.OPEN:
            raise InvalidFindingStateError(
                "Only open findings can be confirmed."
            )

        self.status = FindingStatus.CONFIRMED
        self._touch()

    def resolve(self):
        if self.status != FindingStatus.CONFIRMED:
            raise InvalidFindingStateError(
                "Only confirmed findings can be resolved."
            )

        self.status = FindingStatus.RESOLVED
        self._touch()

    def mark_false_positive(self):
        if self.status != FindingStatus.OPEN:
            raise InvalidFindingStateError(
                "Only open findings can become false positives."
            )

        self.status = FindingStatus.FALSE_POSITIVE
        self._touch()