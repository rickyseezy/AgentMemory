"""Typed content-free failures for the memory bounded context."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class MemoryFieldViolation:
    """One stable rejected field/code pair without the rejected value."""

    field: str
    code: str


class MemoryValidationError(ValueError):
    """Reject malformed evidence, model output, or aggregate state safely."""

    def __init__(self, violations: tuple[MemoryFieldViolation, ...]) -> None:
        """Retain only canonical field and reason identifiers."""
        if not violations:
            msg = "at least one memory field violation is required"
            raise ValueError(msg)
        self.violations = tuple(sorted(set(violations)))
        super().__init__("; ".join(f"{item.field}: {item.code}" for item in self.violations))

    @classmethod
    def single(cls, field: str, code: str) -> MemoryValidationError:
        """Build one validation failure without echoing sensitive input."""
        return cls((MemoryFieldViolation(field, code),))

    def code_for(self, field: str) -> str | None:
        """Return the stable reason for one field when present."""
        return next((item.code for item in self.violations if item.field == field), None)


class MemoryConflictError(RuntimeError):
    """Reject divergent reuse of an immutable consolidation identity."""

    def __init__(self) -> None:
        """Expose one content-free conflict description."""
        super().__init__("Memory consolidation identity conflicted")


class MemoryDependencyError(RuntimeError):
    """Hide unavailable extractor or persistence details behind a safe error."""

    def __init__(self) -> None:
        """Expose one content-free dependency description."""
        super().__init__("Memory consolidation dependency is unavailable")


class MemoryIntegrityError(RuntimeError):
    """Fail closed when canonical evidence or persisted memory state diverges."""

    def __init__(self) -> None:
        """Expose one content-free integrity description."""
        super().__init__("Memory consolidation integrity verification failed")


class MemoryEvidenceNotFoundError(LookupError):
    """Report an absent authorized terminal task without disclosing other scopes."""

    def __init__(self) -> None:
        """Expose one scope-neutral absence description."""
        super().__init__("Terminal task evidence is unavailable")


class MemoryAuthorizationError(PermissionError):
    """Reject inactive or insufficient current memory-write authority."""

    def __init__(self) -> None:
        """Expose one scope-neutral authorization description."""
        super().__init__("Memory consolidation access is not active")
