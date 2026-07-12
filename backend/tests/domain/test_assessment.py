import pytest

from security_review.domain.assessment import Assessment, AssessmentStatus
from security_review.domain.assessment.exceptions import (
    InvalidAssessmentStateError,
)


def test_new_assessment_has_created_status():
    assessment = Assessment(name="Demo")

    assert assessment.status == AssessmentStatus.CREATED


def test_start_analysis():
    assessment = Assessment(name="Demo")

    assessment.start_analysis()

    assert assessment.status == AssessmentStatus.ANALYZING


def test_complete_assessment():
    assessment = Assessment(name="Demo")

    assessment.start_analysis()
    assessment.complete()

    assert assessment.status == AssessmentStatus.COMPLETED


def test_fail_assessment():
    assessment = Assessment(name="Demo")

    assessment.start_analysis()
    assessment.fail()

    assert assessment.status == AssessmentStatus.FAILED


def test_cannot_complete_without_starting():
    assessment = Assessment(name="Demo")

    with pytest.raises(InvalidAssessmentStateError):
        assessment.complete()


def test_cannot_start_twice():
    assessment = Assessment(name="Demo")

    assessment.start_analysis()

    with pytest.raises(InvalidAssessmentStateError):
        assessment.start_analysis()


def test_rename_assessment():
    assessment = Assessment(name="Old Name")

    assessment.rename("New Name")

    assert assessment.name == "New Name"