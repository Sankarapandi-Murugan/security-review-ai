from security_review.domain.assessment import Assessment, AssessmentStatus


def test_new_assessment_has_created_status():
    assessment = Assessment(name="Demo Assessment")

    assert assessment.status == AssessmentStatus.CREATED
    assert assessment.name == "Demo Assessment"