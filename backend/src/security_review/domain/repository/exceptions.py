class RepositoryError(Exception):
    """Base exception for Repository domain."""


class InvalidRepositoryStateError(RepositoryError):
    """Raised when an invalid repository state transition occurs."""