"""System UUIDv7 generator for durable identity entities and events."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid7

from agentmemory.identity.domain.value_objects import StableId


@dataclass(frozen=True, slots=True)
class SystemUuid7IdentityGenerator:
    """Generate cryptographically random RFC 9562 UUIDv7 values."""

    def new(self) -> StableId:
        """Return one fresh canonical stable ID."""
        return StableId(str(uuid7()))
