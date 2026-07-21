"""Typed content-free failures for the graph bounded context."""


class GraphError(Exception):
    """Base graph-context failure."""


class GraphValidationError(GraphError, ValueError):
    """A graph value violates the closed schema."""


class GraphAuthorizationError(GraphError, PermissionError):
    """An operation is outside its immutable AuthorizedScope."""


class GraphConflictError(GraphError):
    """A stable graph identity was reused for divergent content."""


class GraphIntegrityError(GraphError):
    """Persisted graph state violates a required invariant."""


class GraphUnavailableError(GraphError):
    """The local graph projection is temporarily unavailable."""
