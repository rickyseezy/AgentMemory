"""Typed, safe, field-addressable ingestion failures."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class FieldViolation:
    """One safe validation failure without the rejected value."""

    field: str
    code: str


class IngestionValidationError(ValueError):
    """Reject malformed input with stable field/code detail before persistence."""

    def __init__(self, violations: tuple[FieldViolation, ...]) -> None:
        """Store deduplicated violations and expose only safe field/code pairs."""
        if not violations:
            msg = "at least one ingestion field violation is required"
            raise ValueError(msg)
        self.violations = tuple(sorted(set(violations)))
        super().__init__(
            "; ".join(f"{violation.field}: {violation.code}" for violation in self.violations)
        )

    @classmethod
    def single(cls, field: str, code: str) -> IngestionValidationError:
        """Construct a single-field validation failure."""
        return cls((FieldViolation(field, code),))

    def has_field(self, field: str) -> bool:
        """Return whether any violation addresses the exact field."""
        return any(violation.field == field for violation in self.violations)

    def code_for(self, field: str) -> str | None:
        """Return the first canonical code for a field, if present."""
        return next(
            (violation.code for violation in self.violations if violation.field == field),
            None,
        )


class IngestionAuthorizationError(PermissionError):
    """Reject an event whose adapter or resolved scope is not authorized."""


class IngestionConflictError(RuntimeError):
    """Reject a retry that reuses an immutable identity for different content."""


class IngestionDependencyError(RuntimeError):
    """Hide unavailable adapter or identity dependencies behind a typed failure."""
