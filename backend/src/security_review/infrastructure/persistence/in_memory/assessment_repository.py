def test_create_assessment():
    repository = InMemoryAssessmentRepository()
    use_case = CreateAssessmentUseCase(repository)

    response = use_case.execute(
        CreateAssessmentRequest(name="Demo Assessment")
    )

    assert response.name == "Demo Assessment"