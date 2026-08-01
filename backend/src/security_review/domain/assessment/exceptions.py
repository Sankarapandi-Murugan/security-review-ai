class AssessmentError(Exception):
    """Base assessment exception."""


class InvalidAssessmentStateError(AssessmentError):
    """Raised when an invalid state transition is attempted."""


class RepositoryNotReadyError(AssessmentError):
    """Raised when a scan job references a repository that has not finished ingesting."""


class UnauthorizedScanTargetError(AssessmentError):
    """Raised when a dynamic (live-network) scan is requested without confirmed authorization."""


class PlanLimitExceededError(AssessmentError):
    """Raised when an organization's plan limit (assessments or scan jobs) is exceeded."""