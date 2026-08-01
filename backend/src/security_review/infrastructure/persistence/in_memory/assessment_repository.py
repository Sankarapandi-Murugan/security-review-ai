from uuid import UUID

from security_review.application.assessment.interfaces import AssessmentRepository
from security_review.domain.assessment import Assessment


class InMemoryAssessmentRepository(AssessmentRepository):
    """In-memory implementation of AssessmentRepository, useful for tests."""

    def __init__(self) -> None:
        self._assessments: dict[UUID, Assessment] = {}

    def save(self, assessment: Assessment) -> Assessment:
        self._assessments[assessment.id] = assessment
        return assessment