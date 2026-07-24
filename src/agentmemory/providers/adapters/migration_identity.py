"""System UUIDv7 identity adapter for PRO-008 migration aggregates."""

from dataclasses import dataclass
from uuid import uuid7


@dataclass(frozen=True, slots=True)
class SystemEmbeddingMigrationIdentityGenerator:
    """Generate independently unpredictable migration identities."""

    def new(self) -> str:
        """Return one fresh canonical RFC 9562 UUIDv7 string."""
        return str(uuid7())
