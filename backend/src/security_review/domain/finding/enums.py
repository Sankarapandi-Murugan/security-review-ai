from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"