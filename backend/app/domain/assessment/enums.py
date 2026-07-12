from enum import Enum


class AssessmentStatus(str, Enum):
    """Possible lifecycle states for an assessment."""

    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ARCHIVED = "archived"
