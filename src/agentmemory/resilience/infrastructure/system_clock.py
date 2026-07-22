"""Trusted UTC clock adapter for PF-004 deadline and circuit decisions."""

from datetime import UTC, datetime


class SystemRecallClock:
    """Read current UTC time independently from untrusted request timestamps."""

    def now(self) -> datetime:
        """Return the current UTC wall-clock time."""
        return datetime.now(UTC)
