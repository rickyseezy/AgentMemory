"""Immutable validated values used by Core installation operations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from agentmemory.operations.domain.errors import DomainValidationError

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_RELEASE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_UUID_VERSION = 7


@dataclass(frozen=True, slots=True)
class Sha256Digest:
    """A non-zero lowercase hexadecimal SHA-256 digest."""

    value: str

    def __post_init__(self) -> None:
        """Reject ambiguous, malformed, and zero evidence digests."""
        if _DIGEST_PATTERN.fullmatch(self.value) is None or set(self.value) == {"0"}:
            msg = "digest must be a non-zero lowercase SHA-256 value"
            raise DomainValidationError(msg)

    @classmethod
    def from_bytes(cls, value: bytes) -> Sha256Digest:
        """Hash trusted bytes into one validated digest value."""
        return cls(hashlib.sha256(value).hexdigest())


@dataclass(frozen=True, slots=True)
class OperationId:
    """A bounded opaque launcher operation identifier."""

    value: str

    def __post_init__(self) -> None:
        """Reject identifiers that cannot be safely bound across transports."""
        if _OPERATION_PATTERN.fullmatch(self.value) is None:
            msg = "operation ID is invalid"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class ReleaseId:
    """A signed release identifier using the launcher's closed grammar."""

    value: str

    def __post_init__(self) -> None:
        """Reject release identifiers outside the signed-manifest grammar."""
        if _RELEASE_PATTERN.fullmatch(self.value) is None:
            msg = "release ID is invalid"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class Uuid7Id:
    """A canonical lowercase RFC 9562 UUIDv7 identifier."""

    value: str

    def __post_init__(self) -> None:
        """Reject noncanonical, non-v7, or non-RFC UUID values."""
        try:
            parsed = UUID(self.value)
        except ValueError as error:
            msg = "UUIDv7 value is invalid"
            raise DomainValidationError(msg) from error
        if (
            str(parsed) != self.value
            or parsed.version != _UUID_VERSION
            or parsed.variant != "specified in RFC 4122"
        ):
            msg = "UUIDv7 value is invalid"
            raise DomainValidationError(msg)


def require_utc_microseconds(value: datetime) -> datetime:
    """Return a normalized aware UTC time or reject a naive value."""
    if value.tzinfo is None or value.utcoffset() is None:
        msg = "timestamp must be timezone-aware"
        raise DomainValidationError(msg)
    return value.astimezone(UTC).replace(microsecond=value.microsecond)


def format_rfc3339_microseconds(value: datetime) -> str:
    """Match Go RFC3339Nano formatting after microsecond truncation."""
    normalized = require_utc_microseconds(value)
    base = normalized.strftime("%Y-%m-%dT%H:%M:%S")
    if normalized.microsecond == 0:
        return f"{base}Z"
    fraction = f"{normalized.microsecond:06d}".rstrip("0")
    return f"{base}.{fraction}Z"
