"""MEM-002 temporal explanation and evidence-availability domain values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.memory.domain.errors import MemoryValidationError

if TYPE_CHECKING:
    from agentmemory.memory.domain.consolidation import Memory

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EVENT_TYPE = re.compile(r"^agentmemory\.[a-z0-9._-]{1,180}\.v[1-9][0-9]*$")


class EvidenceAvailability(StrEnum):
    """Closed source-resolution states safe to expose to an authorized caller."""

    AVAILABLE = "available"
    PURGED = "purged"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class MemoryEvidenceReference:
    """One hash-bound evidence reference with explicit availability."""

    event_id: str
    canonical_event_sha256: str
    availability: EvidenceAvailability
    event_type: str | None
    occurred_at: datetime | None
    resource_uri: str | None

    def __post_init__(self) -> None:
        """Require metadata only when canonical evidence remains resolvable."""
        _require_uuid7(self.event_id, "evidence.event_id")
        _require_digest(self.canonical_event_sha256, "evidence.canonical_event_sha256")
        optional = (self.event_type, self.occurred_at, self.resource_uri)
        occurred_at = self.occurred_at
        if self.availability is EvidenceAvailability.AVAILABLE:
            if (
                self.event_type is None
                or _EVENT_TYPE.fullmatch(self.event_type) is None
                or occurred_at is None
                or self.resource_uri != f"memory://evidence/{self.event_id}"
            ):
                _invalid("evidence", "available_metadata_invalid")
            _require_utc(occurred_at, "evidence.occurred_at")
        elif any(value is not None for value in optional):
            _invalid("evidence", "unavailable_metadata_disclosed")


@dataclass(frozen=True, slots=True)
class MemoryExplanationAccess:
    """Repository input binding exact target, authority, and temporal coordinates."""

    memory_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    authorized_at: datetime
    valid_at: datetime
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class MemoryExplanation:
    """Authorized memory metadata, temporal evaluation, and exact evidence lineage."""

    memory: Memory
    evidence: tuple[MemoryEvidenceReference, ...]
    valid_at: datetime
    recorded_at: datetime
    effective: bool

    @classmethod
    def create(
        cls,
        memory: Memory,
        evidence: tuple[MemoryEvidenceReference, ...],
        valid_at: datetime,
        recorded_at: datetime,
    ) -> MemoryExplanation:
        """Bind one exact evidence set and evaluate half-open bitemporal ranges."""
        _require_utc(valid_at, "valid_at")
        _require_utc(recorded_at, "recorded_at")
        if tuple(item.event_id for item in evidence) != memory.evidence_ids:
            _invalid("evidence", "lineage_mismatch")
        effective = _contains(memory.valid_from, memory.valid_to, valid_at) and _contains(
            memory.recorded_from,
            memory.recorded_to,
            recorded_at,
        )
        return cls(memory, evidence, valid_at, recorded_at, effective)


def _contains(start: datetime, end: datetime | None, value: datetime) -> bool:
    return start <= value and (end is None or value < end)


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        _invalid(field, "invalid_uuid7")


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        _invalid(field, "invalid_digest")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
