"""Typed ADP-006 retrieval failures."""

from __future__ import annotations


class RetrievalError(Exception):
    """Base error for the retrieval bounded context."""


class RetrievalValidationError(RetrievalError, ValueError):
    """Reject an invalid query or domain value."""


class RetrievalAuthorizationError(RetrievalError):
    """Reject a repository result outside the authorized scope."""


class RetrievalDependencyError(RetrievalError):
    """Report an unavailable local retrieval dependency safely."""


class RetrievalIntegrityError(RetrievalError):
    """Report authenticated canonical evidence that failed verification."""
