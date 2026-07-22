"""Closed PF-004 error taxonomy."""


class ResilienceError(Exception):
    """Base safe-degradation error."""


class ResilienceValidationError(ResilienceError):
    """Reject invalid policy, time, or query coordinates."""


class RecallAuthorizationError(ResilienceError):
    """Fail a whole recall when current authority is absent."""


class RecallIntegrityError(ResilienceError):
    """Fail a whole recall when canonical integrity is uncertain."""


class RecallDependencyError(ResilienceError):
    """Degrade one optional recall channel after dependency failure."""
