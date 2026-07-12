class AssessmentError(Exception):
    """Base assessment exception."""


class InvalidAssessmentStateError(AssessmentError):
    """Raised when an invalid state transition is attempted."""