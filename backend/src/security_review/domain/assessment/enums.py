from enum import Enum


class AssessmentStatus(str, Enum):
    CREATED = "created"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"