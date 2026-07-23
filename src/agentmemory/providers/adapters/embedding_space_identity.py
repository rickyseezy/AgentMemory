"""System UUIDv7 identity adapter for immutable embedding-space aggregates."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid7


@dataclass(frozen=True, slots=True)
class SystemEmbeddingSpaceIdentityGenerator:
    """Generate cryptographically random RFC 9562 UUIDv7 values."""

    def new(self) -> str:
        """Return one fresh canonical space or generation identity."""
        return str(uuid7())
