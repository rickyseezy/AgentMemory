"""System UUIDv7 identity adapter for provider profiles."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid7


@dataclass(frozen=True, slots=True)
class SystemProviderProfileIdentityGenerator:
    """Generate cryptographically random RFC 9562 UUIDv7 values."""

    def new(self) -> str:
        """Return one fresh canonical provider profile identity."""
        return str(uuid7())
