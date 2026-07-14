"""Deterministic host/Core active-release transaction values."""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
    format_rfc3339_microseconds,
    require_utc_microseconds,
)

_POINTER_SCHEMA: Final = 1
_MAX_UINT64: Final = (1 << 64) - 1
_MAX_ENDPOINT_BYTES: Final = 4096
_WINDOWS_PIPE = re.compile(r"^npipe:////\./pipe/[^/\\]+$")


@dataclass(frozen=True, slots=True)
class ActiveReleasePointerInput:
    """Complete validated-input carrier for one candidate pointer."""

    installation_id: Uuid7Id
    release_id: ReleaseId
    generation_id: Uuid7Id
    manifest_digest: Sha256Digest
    compose_digest: Sha256Digest
    readiness_receipt_digest: Sha256Digest
    runtime_endpoint: str
    release_sequence: int
    resource_inventory_version: int
    resource_inventory_digest: Sha256Digest
    security_epoch: int
    activated_at: datetime


@dataclass(frozen=True, slots=True)
class ActiveReleasePointer:
    """Exact Python mirror of the launcher's immutable pointer domain value."""

    installation_id: Uuid7Id
    release_id: ReleaseId
    generation_id: Uuid7Id
    manifest_digest: Sha256Digest
    compose_digest: Sha256Digest
    readiness_receipt_digest: Sha256Digest
    runtime_endpoint: str
    release_sequence: int
    resource_inventory_version: int
    resource_inventory_digest: Sha256Digest
    security_epoch: int
    activated_at: datetime
    pointer_digest: Sha256Digest

    @classmethod
    def create(cls, value: ActiveReleasePointerInput) -> ActiveReleasePointer:
        """Validate and fingerprint the same canonical bytes as Go NewPointer."""
        normalized_time = require_utc_microseconds(value.activated_at)
        _require_local_runtime_endpoint(value.runtime_endpoint)
        for monotonic_value in (
            value.release_sequence,
            value.resource_inventory_version,
            value.security_epoch,
        ):
            if isinstance(monotonic_value, bool) or not 0 < monotonic_value <= _MAX_UINT64:
                msg = "active-release monotonic value is invalid"
                raise DomainValidationError(msg)
        canonical = _pointer_bytes(value, normalized_time)
        return cls(
            installation_id=value.installation_id,
            release_id=value.release_id,
            generation_id=value.generation_id,
            manifest_digest=value.manifest_digest,
            compose_digest=value.compose_digest,
            readiness_receipt_digest=value.readiness_receipt_digest,
            runtime_endpoint=value.runtime_endpoint,
            release_sequence=value.release_sequence,
            resource_inventory_version=value.resource_inventory_version,
            resource_inventory_digest=value.resource_inventory_digest,
            security_epoch=value.security_epoch,
            activated_at=normalized_time,
            pointer_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        )

    @classmethod
    def restore(cls, record: dict[str, object]) -> ActiveReleasePointer:
        """Restore only an exact schema-v1 record with a valid canonical digest."""
        expected_keys = {
            "schema_version",
            "installation_id",
            "release_id",
            "generation_id",
            "manifest_digest",
            "compose_digest",
            "readiness_receipt_digest",
            "runtime_endpoint",
            "release_sequence",
            "resource_inventory_version",
            "resource_inventory_digest",
            "security_epoch",
            "activated_at",
            "pointer_digest",
        }
        if set(record) != expected_keys or record.get("schema_version") != _POINTER_SCHEMA:
            msg = "active-release pointer record is invalid"
            raise DomainValidationError(msg)
        try:
            restored = cls.create(
                ActiveReleasePointerInput(
                    installation_id=Uuid7Id(_string(record, "installation_id")),
                    release_id=ReleaseId(_string(record, "release_id")),
                    generation_id=Uuid7Id(_string(record, "generation_id")),
                    manifest_digest=Sha256Digest(_string(record, "manifest_digest")),
                    compose_digest=Sha256Digest(_string(record, "compose_digest")),
                    readiness_receipt_digest=Sha256Digest(
                        _string(record, "readiness_receipt_digest")
                    ),
                    runtime_endpoint=_string(record, "runtime_endpoint"),
                    release_sequence=_integer(record, "release_sequence"),
                    resource_inventory_version=_integer(record, "resource_inventory_version"),
                    resource_inventory_digest=Sha256Digest(
                        _string(record, "resource_inventory_digest")
                    ),
                    security_epoch=_integer(record, "security_epoch"),
                    activated_at=_parse_canonical_time(_string(record, "activated_at")),
                )
            )
            supplied = Sha256Digest(_string(record, "pointer_digest"))
        except (KeyError, TypeError, ValueError) as error:
            msg = "active-release pointer record is invalid"
            raise DomainValidationError(msg) from error
        if supplied != restored.pointer_digest:
            msg = "active-release pointer integrity violation"
            raise DomainValidationError(msg)
        return restored

    def record(self) -> dict[str, object]:
        """Return the exact launcher-compatible persistence/transport record."""
        return {
            "schema_version": _POINTER_SCHEMA,
            "installation_id": self.installation_id.value,
            "release_id": self.release_id.value,
            "generation_id": self.generation_id.value,
            "manifest_digest": self.manifest_digest.value,
            "compose_digest": self.compose_digest.value,
            "readiness_receipt_digest": self.readiness_receipt_digest.value,
            "runtime_endpoint": self.runtime_endpoint,
            "release_sequence": self.release_sequence,
            "resource_inventory_version": self.resource_inventory_version,
            "resource_inventory_digest": self.resource_inventory_digest.value,
            "security_epoch": self.security_epoch,
            "activated_at": format_rfc3339_microseconds(self.activated_at),
            "pointer_digest": self.pointer_digest.value,
        }


def active_release_stage_digest(
    operation_id: OperationId,
    pointer: ActiveReleasePointer,
) -> Sha256Digest:
    """Bind a durable Core stage receipt to operation, pointer, and readiness proof."""
    canonical = b"".join(
        (
            _field(b"agentmemory.active-release-stage.v1"),
            _field(operation_id.value.encode()),
            _field(pointer.pointer_digest.value.encode()),
            _field(pointer.readiness_receipt_digest.value.encode()),
        )
    )
    return Sha256Digest(hashlib.sha256(canonical).hexdigest())


def permits_replacement(
    current: ActiveReleasePointer | None,
    target: ActiveReleasePointer,
) -> bool:
    """Mirror Go DecideReplacement without treating equality as a mutation."""
    if current is None or current.pointer_digest == target.pointer_digest:
        return True
    if (
        current.installation_id != target.installation_id
        or target.release_sequence < current.release_sequence
        or target.resource_inventory_version < current.resource_inventory_version
        or target.security_epoch < current.security_epoch
    ):
        return False
    return not (
        target.release_sequence == current.release_sequence
        and (
            target.release_id != current.release_id
            or target.manifest_digest != current.manifest_digest
            or target.compose_digest != current.compose_digest
        )
    )


def _pointer_bytes(value: ActiveReleasePointerInput, activated_at: datetime) -> bytes:
    values = (
        "agentmemory.active-release.v1",
        value.installation_id.value,
        value.release_id.value,
        value.generation_id.value,
        value.manifest_digest.value,
        value.compose_digest.value,
        value.readiness_receipt_digest.value,
        value.runtime_endpoint,
    )
    output = b"".join(_field(value.encode()) for value in values)
    output += struct.pack(">Q", value.release_sequence)
    output += struct.pack(">Q", value.resource_inventory_version)
    output += _field(value.resource_inventory_digest.value.encode())
    output += struct.pack(">Q", value.security_epoch)
    unix_microseconds = int(activated_at.timestamp()) * 1_000_000 + activated_at.microsecond
    return output + struct.pack(">Q", unix_microseconds)


def _field(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _require_local_runtime_endpoint(value: str) -> None:
    if (
        not value
        or len(value) > _MAX_ENDPOINT_BYTES
        or any(character in value for character in "\x00\r\n")
    ):
        msg = "active-release runtime endpoint is invalid"
        raise DomainValidationError(msg)
    if value.startswith("unix:///"):
        path = value.removeprefix("unix://")
        if (
            not path.startswith("/")
            or path.endswith("/")
            or "//" in path
            or any(segment in {".", ".."} for segment in path.split("/"))
        ):
            msg = "active-release runtime endpoint is invalid"
            raise DomainValidationError(msg)
        return
    if _WINDOWS_PIPE.fullmatch(value) is None:
        msg = "active-release runtime endpoint is invalid"
        raise DomainValidationError(msg)


def _parse_canonical_time(value: str) -> datetime:
    if not value.endswith("Z"):
        msg = "active-release activation time is invalid"
        raise DomainValidationError(msg)
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        msg = "active-release activation time is invalid"
        raise DomainValidationError(msg) from error
    normalized = require_utc_microseconds(parsed)
    if format_rfc3339_microseconds(normalized) != value:
        msg = "active-release activation time is not canonical"
        raise DomainValidationError(msg)
    return normalized


def _string(record: dict[str, object], key: str) -> str:
    value = record[key]
    if not isinstance(value, str):
        raise TypeError
    return value


def _integer(record: dict[str, object], key: str) -> int:
    value = record[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value
