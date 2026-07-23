"""System UUIDv7 identities for PRO-005 routing authority."""

from dataclasses import dataclass
from uuid import uuid7


@dataclass(frozen=True, slots=True)
class SystemProviderRoutingIdentityGenerator:
    """Semantically named routing identity adapter sharing the certified UUIDv7 source."""

    def new(self) -> str:
        """Return one fresh canonical RFC 9562 UUIDv7 string."""
        return str(uuid7())
