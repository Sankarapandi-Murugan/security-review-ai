class FindingError(Exception):
    """Base exception for Finding domain."""


class InvalidFindingStateError(FindingError):
    """Raised when an invalid finding state transition occurs."""