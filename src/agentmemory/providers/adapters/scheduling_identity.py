"""System UUIDv7 identities for PRO-006 provider work."""

from dataclasses import dataclass
from uuid import uuid7


@dataclass(frozen=True, slots=True)
class SystemProviderSchedulingIdentityGenerator:
    """Generate independently unpredictable provider work identities."""

    def new(self) -> str:
        """Return one fresh canonical RFC 9562 UUIDv7 string."""
        return str(uuid7())
