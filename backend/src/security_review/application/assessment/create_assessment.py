from security_review.application.assessment.dto import (
    CreateAssessmentRequest,
    CreateAssessmentResponse,
)
from security_review.application.assessment.interfaces import (
    AssessmentRepository,
)
from security_review.domain.assessment import Assessment


class CreateAssessmentUseCase:
    def __init__(self, repository: AssessmentRepository):
        self._repository = repository

    def execute(
        self, request: CreateAssessmentRequest
    ) -> CreateAssessmentResponse:

        assessment = Assessment(name=request.name)

        assessment = self._repository.save(assessment)

        return CreateAssessmentResponse(
            id=assessment.id,
            name=assessment.name,
            status=assessment.status.value,
            created_at=assessment.created_at,
        )