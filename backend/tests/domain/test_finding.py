import pytest

from security_review.domain.finding import (
    Finding,
    FindingStatus,
    Location,
)
from security_review.domain.finding.exceptions import (
    InvalidFindingStateError,
)


def test_new_finding_is_open():
    finding = Finding(title="SQL Injection")

    assert finding.status == FindingStatus.OPEN


def test_confirm_finding():
    finding = Finding(title="SQL Injection")

    finding.confirm()

    assert finding.status == FindingStatus.CONFIRMED


def test_resolve_finding():
    finding = Finding(title="SQL Injection")

    finding.confirm()
    finding.resolve()

    assert finding.status == FindingStatus.RESOLVED


def test_mark_false_positive():
    finding = Finding(title="SQL Injection")

    finding.mark_false_positive()

    assert finding.status == FindingStatus.FALSE_POSITIVE


def test_location_value_object():
    location = Location(
        file_path="src/UserService.java",
        line=42,
        column=15,
    )

    assert location.line == 42


def test_cannot_resolve_without_confirmation():
    finding = Finding(title="SQL Injection")

    with pytest.raises(InvalidFindingStateError):
        finding.resolve()