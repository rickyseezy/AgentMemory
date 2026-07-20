"""MEM-002 authorization-first memory explanation query."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from agentmemory.memory.domain.errors import (
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)
from agentmemory.memory.domain.explanation import MemoryExplanationAccess

if TYPE_CHECKING:
    from agentmemory.memory.domain.explanation import MemoryExplanation
    from agentmemory.memory.domain.ports import MemoryRepository
    from agentmemory.shared.clock import Clock

_UUID_VERSION = 7


@dataclass(frozen=True, slots=True)
class ExplainMemoryQuery:
    """Exact caller, Brain, target, and bitemporal explanation coordinates."""

    memory_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    valid_at: datetime
    recorded_at: datetime
    requested_at: datetime

    def __post_init__(self) -> None:
        """Reject ambiguous identity and non-UTC temporal coordinates."""
        for value, field in (
            (self.memory_id, "memory_id"),
            (self.brain_id, "brain_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field)
        for timestamp, field in (
            (self.valid_at, "valid_at"),
            (self.recorded_at, "recorded_at"),
            (self.requested_at, "requested_at"),
        ):
            _require_utc(timestamp, field)


@dataclass(frozen=True, slots=True)
class ExplainMemoryHandler:
    """Return no evidence until one repository query proves current authority."""

    repository: MemoryRepository
    clock: Clock

    async def execute(self, query: ExplainMemoryQuery) -> MemoryExplanation:
        """Collapse unauthorized and absent targets to the same not-found boundary."""
        now = self.clock.now()
        if query.requested_at > now:
            field = "requested_at"
            raise MemoryValidationError.single(field, "in_future")
        result = await self.repository.explain_authorized(
            MemoryExplanationAccess(
                query.memory_id,
                query.brain_id,
                query.actor_id,
                query.grant_id,
                now,
                query.valid_at,
                query.recorded_at,
            )
        )
        if result is None:
            raise MemoryEvidenceNotFoundError
        return result


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise MemoryValidationError.single(field, "invalid_uuid7")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise MemoryValidationError.single(field, "not_utc")
