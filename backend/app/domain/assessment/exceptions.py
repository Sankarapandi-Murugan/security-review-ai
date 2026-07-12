class AssessmentError(Exception):
    """Base exception for assessment domain errors."""


class AssessmentNotFoundError(AssessmentError):
    """Raised when an assessment cannot be found."""


class AssessmentValidationError(AssessmentError):
    """Raised when assessment input is invalid."""
