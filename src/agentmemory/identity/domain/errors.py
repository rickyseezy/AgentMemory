"""Typed identity-context failures."""

from __future__ import annotations


class IdentityValidationError(ValueError):
    """Reject malformed or internally inconsistent identity evidence."""


class IdentityAuthorizationError(PermissionError):
    """Deny identity observation before host or repository evidence is read."""


class IdentityDependencyError(RuntimeError):
    """Hide database or host-adapter details behind a content-free failure."""


class IdentityConflictError(RuntimeError):
    """Reject a known manifest whose Repository evidence is incompatible."""
