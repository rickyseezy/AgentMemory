"""MEM-004 authorization-first correction history and effective assertion query."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.memory.domain.errors import MemoryEvidenceNotFoundError, MemoryValidationError

if TYPE_CHECKING:
    from agentmemory.memory.domain.consolidation import MemoryScope
    from agentmemory.memory.domain.correction import (
        MemoryAssertionSelection,
        MemoryCorrectionHistory,
        MemoryPrecedencePolicy,
    )
    from agentmemory.memory.domain.ports import MemoryCorrectionReadRepository
    from agentmemory.shared.clock import Clock

_UUID_VERSION = 7


@dataclass(frozen=True, slots=True)
class MemoryCorrectionHistoryQuery:
    """Exact authority, scope, and bitemporal coordinates for a correction history."""

    root_memory_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    query_scope: MemoryScope
    valid_at: datetime
    recorded_at: datetime
    requested_at: datetime

    def __post_init__(self) -> None:
        """Reject malformed or cross-Brain coordinates before repository access."""
        for value, field in (
            (self.root_memory_id, "root_memory_id"),
            (self.brain_id, "brain_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field)
        if self.query_scope.brain_id != self.brain_id:
            _invalid("query_scope.brain_id", "mismatch")
        _require_utc(self.valid_at, "valid_at")
        _require_utc(self.recorded_at, "recorded_at")
        _require_utc(self.requested_at, "requested_at")


@dataclass(frozen=True, slots=True)
class MemoryCorrectionHistoryView:
    """Complete authorized history plus its deterministic effective assertion."""

    history: MemoryCorrectionHistory
    selected: MemoryAssertionSelection

    def __post_init__(self) -> None:
        """Bind the selected assertion to the returned root chain."""
        if self.selected.root_memory_id != self.history.root.root_memory_id:
            _invalid("selected.root_memory_id", "mismatch")


@dataclass(frozen=True, slots=True)
class GetMemoryCorrectionHistoryHandler:
    """Authorize the root, reconstruct history, and apply pinned precedence."""

    repository: MemoryCorrectionReadRepository
    policy: MemoryPrecedencePolicy
    clock: Clock

    async def execute(
        self,
        query: MemoryCorrectionHistoryQuery,
    ) -> MemoryCorrectionHistoryView:
        """Return history or the same scope-neutral absence for missing/unauthorized roots."""
        now = self.clock.now()
        if query.requested_at > now:
            _invalid("requested_at", "in_future")
        history = await self.repository.history_authorized(
            query.root_memory_id,
            query.brain_id,
            query.actor_id,
            query.grant_id,
            now,
        )
        if history is None:
            raise MemoryEvidenceNotFoundError
        selected = self.policy.resolve(
            history.root,
            history.corrections,
            query.query_scope,
            valid_at=query.valid_at,
            recorded_at=query.recorded_at,
        )
        return MemoryCorrectionHistoryView(history, selected)


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        _invalid(field, "invalid_uuid7")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
