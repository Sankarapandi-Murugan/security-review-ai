from enum import Enum


class AssessmentStatus(str, Enum):
    CREATED = "created"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class RepositoryIngestStatus(str, Enum):
    PENDING = "pending"
    CLONING = "cloning"
    READY = "ready"
    FAILED = "failed"