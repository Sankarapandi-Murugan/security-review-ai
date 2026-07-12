import pytest

from security_review.domain.repository import (
    BuildSystem,
    Language,
    Repository,
    RepositoryStatus,
)
from security_review.domain.repository.exceptions import (
    InvalidRepositoryStateError,
)


def test_new_repository_is_created():
    repo = Repository(name="Demo")

    assert repo.status == RepositoryStatus.CREATED


def test_mark_repository_ready():
    repo = Repository(name="Demo")

    repo.mark_ready()

    assert repo.status == RepositoryStatus.READY


def test_add_language():
    repo = Repository(name="Demo")

    repo.add_language(Language.JAVA)

    assert repo.is_java()


def test_start_analysis():
    repo = Repository(name="Demo")

    repo.mark_ready()
    repo.start_analysis()

    assert repo.status == RepositoryStatus.ANALYZING


def test_cannot_start_before_ready():
    repo = Repository(name="Demo")

    with pytest.raises(InvalidRepositoryStateError):
        repo.start_analysis()