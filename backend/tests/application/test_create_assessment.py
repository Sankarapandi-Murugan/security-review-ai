from security_review.application.assessment.create_assessment import CreateAssessmentUseCase
from security_review.application.assessment.dto import CreateAssessmentRequest
from security_review.infrastructure.persistence.in_memory.assessment_repository import (
    InMemoryAssessmentRepository,
)


def test_create_assessment():
    repository = InMemoryAssessmentRepository()
    use_case = CreateAssessmentUseCase(repository)

    response = use_case.execute(
        CreateAssessmentRequest(name="Demo Assessment")
    )

    assert response.name == "Demo Assessment"
