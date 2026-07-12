from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from security_review.domain.repository.enums import (
    BuildSystem,
    Language,
    RepositoryStatus,
)
from security_review.domain.repository.exceptions import (
    InvalidRepositoryStateError,
)


@dataclass
class Repository:
    id: UUID = field(default_factory=uuid4)
    name: str = ""
    url: str = ""
    default_branch: str = "main"
    commit_hash: str = ""
    languages: list[Language] = field(default_factory=list)
    build_system: BuildSystem = BuildSystem.UNKNOWN
    status: RepositoryStatus = RepositoryStatus.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def _touch(self) -> None:
        self.updated_at = datetime.now(UTC)

    def mark_ready(self) -> None:
        if self.status != RepositoryStatus.CREATED:
            raise InvalidRepositoryStateError(
                "Only a created repository can become ready."
            )

        self.status = RepositoryStatus.READY
        self._touch()

    def start_analysis(self) -> None:
        if self.status != RepositoryStatus.READY:
            raise InvalidRepositoryStateError(
                "Repository must be ready before analysis."
            )

        self.status = RepositoryStatus.ANALYZING
        self._touch()

    def complete(self) -> None:
        if self.status != RepositoryStatus.ANALYZING:
            raise InvalidRepositoryStateError(
                "Only an analyzing repository can be completed."
            )

        self.status = RepositoryStatus.COMPLETED
        self._touch()

    def fail(self) -> None:
        self.status = RepositoryStatus.FAILED
        self._touch()

    def add_language(self, language: Language) -> None:
        if language not in self.languages:
            self.languages.append(language)
            self._touch()

    def is_java(self) -> bool:
        return Language.JAVA in self.languages

    def is_python(self) -> bool:
        return Language.PYTHON in self.languages