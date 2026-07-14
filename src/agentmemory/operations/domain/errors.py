"""Typed privacy-safe Core operation failures."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import override


class ErrorCode(StrEnum):
    """Stable error codes emitted by the PF-001 Core boundary."""

    VALIDATION = "AM_VALIDATION"
    UNAUTHENTICATED = "AM_UNAUTHENTICATED"
    FORBIDDEN = "AM_FORBIDDEN"
    CONFLICT = "AM_CONFLICT"
    DEPENDENCY_UNAVAILABLE = "AM_DEPENDENCY_UNAVAILABLE"
    INTEGRITY_VIOLATION = "AM_INTEGRITY_VIOLATION"
    DEADLINE_EXCEEDED = "AM_DEADLINE_EXCEEDED"
    CAPACITY_EXHAUSTED = "AM_CAPACITY_EXHAUSTED"
    INTERNAL = "AM_INTERNAL"


@dataclass(slots=True)
class OperationError(Exception):
    """A safe typed failure with no raw path, query, credential, or content."""

    code: ErrorCode
    safe_detail: str
    retryable: bool = False

    @override
    def __str__(self) -> str:
        """Return only the approved safe detail."""
        return self.safe_detail


class DomainValidationError(ValueError):
    """Report an invalid domain value before it crosses a port."""
