"""MEM-003 authorized exact-first, policy-gated memory deduplication use case."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agentmemory.memory.domain.deduplication import (
    DeduplicationCommit,
    DeduplicationResult,
    MemoryCompatibilityPolicy,
    MemoryMergePlan,
    deduplication_idempotency_key,
    validate_deduplication_coordinate,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from agentmemory.memory.domain.ports import (
        MemoryDeduplicationReadRepository,
        MemoryDeduplicationUnitOfWorkFactory,
        SemanticMemoryCandidateFinder,
    )
    from agentmemory.shared.clock import Clock

_MAX_EXACT_CANDIDATES = 256
_MAX_SEMANTIC_CANDIDATES = 64


@dataclass(frozen=True, slots=True)
class DeduplicateMemoriesCommand:
    """One explicit authorized request bound to a target memory and deadline."""

    operation_id: str
    actor_id: str
    grant_id: str
    brain_id: str
    correlation_id: str
    causation_id: str
    memory_id: str
    requested_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        """Validate all UUID coordinates through the canonical idempotency factory."""
        deduplication_idempotency_key(self.operation_id, self.memory_id, self.brain_id)
        for value, field in (
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
            (self.correlation_id, "correlation_id"),
            (self.causation_id, "causation_id"),
        ):
            validate_deduplication_coordinate(value, field)
        _require_utc(self.requested_at, "requested_at")
        _require_utc(self.deadline, "deadline")
        if self.deadline <= self.requested_at:
            field = "deadline"
            raise MemoryValidationError.single(field, "not_after_request")


@dataclass(frozen=True, slots=True)
class DeduplicateMemoriesHandler:
    """Retrieve semantic candidates but let deterministic policy authorize writes."""

    reads: MemoryDeduplicationReadRepository
    semantic_candidates: SemanticMemoryCandidateFinder
    unit_of_work: MemoryDeduplicationUnitOfWorkFactory
    policy: MemoryCompatibilityPolicy
    clock: Clock

    async def execute(self, command: DeduplicateMemoriesCommand) -> DeduplicationResult:
        """Plan outside the writer, then reauthorize and CAS the complete merge atomically."""
        now = self.clock.now()
        if command.requested_at > now:
            field = "requested_at"
            raise MemoryValidationError.single(field, "in_future")
        if command.deadline <= now:
            field = "deadline"
            raise MemoryValidationError.single(field, "expired")
        idempotency_key = deduplication_idempotency_key(
            command.operation_id,
            command.memory_id,
            command.brain_id,
        )
        existing = await self.reads.get_result(idempotency_key)
        if existing is not None:
            return existing
        target = await self.reads.load_authorized(
            command.memory_id,
            command.brain_id,
            command.actor_id,
            command.grant_id,
            now,
        )
        if target is None:
            raise MemoryEvidenceNotFoundError
        exact = await self.reads.find_exact(target, _MAX_EXACT_CANDIDATES)
        plan = MemoryMergePlan.create(target, exact, (), self.policy)
        if plan is None:
            semantic = await self.semantic_candidates.find(target, _MAX_SEMANTIC_CANDIDATES)
            plan = MemoryMergePlan.create(target, exact, semantic, self.policy)
        result = DeduplicationResult.create(
            idempotency_key,
            target,
            plan,
            self.policy.policy_version,
        )
        commit = DeduplicationCommit(
            command.operation_id,
            command.actor_id,
            command.grant_id,
            command.brain_id,
            command.correlation_id,
            command.causation_id,
            target,
            plan,
            result,
            command.requested_at,
            now,
        )
        async with self.unit_of_work() as unit_of_work:
            concurrent = await unit_of_work.repository.get_result(idempotency_key)
            if concurrent is not None:
                return concurrent
            current = await unit_of_work.repository.load_authorized(
                command.memory_id,
                command.brain_id,
                command.actor_id,
                command.grant_id,
                self.clock.now(),
            )
            if current is None:
                raise MemoryEvidenceNotFoundError
            if current != target:
                raise MemoryConflictError
            await unit_of_work.repository.add(commit)
            await unit_of_work.commit()
        return result


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise MemoryValidationError.single(field, "not_utc")
