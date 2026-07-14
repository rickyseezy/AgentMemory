"""Explicit UTC clock boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Provide policy time without ambient clock access."""

    def now(self) -> datetime:
        """Return an aware UTC timestamp."""
        ...


class SystemClock:
    """Production clock backed by the operating system."""

    def now(self) -> datetime:
        """Return current UTC time."""
        return datetime.now(tz=UTC)
