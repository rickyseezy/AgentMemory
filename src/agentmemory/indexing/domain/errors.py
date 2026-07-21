"""Typed indexing failures safe for application and adapter boundaries."""


class IndexingError(Exception):
    """Base indexing error."""


class IndexingValidationError(IndexingError):
    """Untrusted indexing input violated a domain invariant."""


class IndexingAuthorizationError(IndexingError):
    """The current authority cannot perform the indexing action."""


class IndexingConflictError(IndexingError):
    """An immutable operation or entity conflicts with persisted state."""


class IndexingUnavailableError(IndexingError):
    """A required local parser or persistence dependency is unavailable."""
