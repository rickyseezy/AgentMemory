"""TDD orchestration and concurrency tests for MEM-003."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from agentmemory.memory.application.deduplicate_memories import (
    DeduplicateMemoriesCommand,
    DeduplicateMemoriesHandler,
)
from agentmemory.memory.domain.consolidation import MemoryClass, MemoryScope
from agentmemory.memory.domain.deduplication import (
    DeduplicationCommit,
    DeduplicationResult,
    MemoryCompatibilityPolicy,
    MemoryDeduplicationProfile,
    MemoryPolarity,
    SemanticMemoryCandidate,
    deduplication_idempotency_key,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Self

NOW = datetime(2026, 7, 21, 10, tzinfo=UTC)
OPERATION_ID = "018f0000-0000-7000-8000-000000000010"
ACTOR_ID = "018f0000-0000-7000-8000-000000000011"
GRANT_ID = "018f0000-0000-7000-8000-000000000012"
BRAIN_ID = "018f0000-0000-7000-8000-000000000013"
PROJECT_ID = "018f0000-0000-7000-8000-000000000014"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000015"
TARGET_ID = "018f0000-0000-7000-8000-000000000016"
CANDIDATE_ID = "018f0000-0000-7000-8000-000000000017"
EVIDENCE_ONE = "018f0000-0000-7000-8000-000000000018"
EVIDENCE_TWO = "018f0000-0000-7000-8000-000000000019"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000020"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000021"


@pytest.mark.asyncio
async def test_exact_candidates_precede_semantic_lookup_and_commit_lossless_plan() -> None:
    target = _profile(TARGET_ID, EVIDENCE_ONE, NOW)
    candidate = _profile(CANDIDATE_ID, EVIDENCE_TWO, NOW + timedelta(seconds=1))
    reads = _Repository(target=target, exact=(candidate,))
    semantic = _SemanticFinder((SemanticMemoryCandidate(candidate, 10_000),))
    unit = _UnitOfWork(reads)
    handler = DeduplicateMemoriesHandler(
        reads,
        semantic,
        lambda: unit,
        MemoryCompatibilityPolicy(),
        _Clock(),
    )

    result = await handler.execute(_command())

    assert semantic.calls == 0
    assert result.survivor_memory_id == TARGET_ID
    assert result.merged_memory_ids == (CANDIDATE_ID,)
    assert result.evidence_ids == (EVIDENCE_ONE, EVIDENCE_TWO)
    assert reads.commit is not None
    assert unit.committed


@pytest.mark.asyncio
async def test_semantic_candidate_is_only_used_after_exact_miss() -> None:
    target = _profile(TARGET_ID, EVIDENCE_ONE, NOW)
    candidate = replace(
        _profile(CANDIDATE_ID, EVIDENCE_TWO, NOW + timedelta(seconds=1)),
        content_sha256="c" * 64,
    )
    reads = _Repository(target=target)
    semantic = _SemanticFinder((SemanticMemoryCandidate(candidate, 9500),))
    handler = DeduplicateMemoriesHandler(
        reads,
        semantic,
        lambda: _UnitOfWork(reads),
        MemoryCompatibilityPolicy(),
        _Clock(),
    )

    result = await handler.execute(_command())

    assert semantic.calls == 1
    assert result.merged_memory_ids == (CANDIDATE_ID,)


@pytest.mark.asyncio
async def test_committed_retry_returns_receipt_without_reads_or_provider_call() -> None:
    target = _profile(TARGET_ID, EVIDENCE_ONE, NOW)
    key = deduplication_idempotency_key(OPERATION_ID, TARGET_ID, BRAIN_ID)
    existing = DeduplicationResult.create(key, target, None, "memory-compatibility.v1")
    reads = _Repository(target=target, existing=existing)
    semantic = _SemanticFinder(())
    handler = DeduplicateMemoriesHandler(
        reads,
        semantic,
        lambda: _UnitOfWork(reads),
        MemoryCompatibilityPolicy(),
        _Clock(),
    )

    assert await handler.execute(_command()) == existing
    assert reads.loads == 0
    assert semantic.calls == 0


@pytest.mark.asyncio
async def test_absent_or_unauthorized_target_and_concurrent_change_fail_closed() -> None:
    semantic = _SemanticFinder(())
    missing = _Repository(target=None)
    handler = DeduplicateMemoriesHandler(
        missing,
        semantic,
        lambda: _UnitOfWork(missing),
        MemoryCompatibilityPolicy(),
        _Clock(),
    )
    with pytest.raises(MemoryEvidenceNotFoundError):
        await handler.execute(_command())

    target = _profile(TARGET_ID, EVIDENCE_ONE, NOW)
    changed = replace(target, aggregate_version=2)
    reads = _Repository(target=target, transaction_target=changed)
    handler = replace(handler, reads=reads, unit_of_work=lambda: _UnitOfWork(reads))
    with pytest.raises(MemoryConflictError):
        await handler.execute(_command())


@pytest.mark.asyncio
async def test_command_and_execution_time_windows_fail_closed() -> None:
    with pytest.raises(MemoryValidationError):
        replace(_command(), deadline=NOW - timedelta(seconds=2))
    with pytest.raises(MemoryValidationError, match="requested_at"):
        replace(_command(), requested_at=NOW.astimezone(timezone(timedelta(hours=1))))

    target = _profile(TARGET_ID, EVIDENCE_ONE, NOW)
    reads = _Repository(target=target)
    handler = DeduplicateMemoriesHandler(
        reads,
        _SemanticFinder(()),
        lambda: _UnitOfWork(reads),
        MemoryCompatibilityPolicy(),
        _Clock(),
    )
    with pytest.raises(MemoryValidationError, match="requested_at"):
        await handler.execute(replace(_command(), requested_at=NOW + timedelta(seconds=1)))
    with pytest.raises(MemoryValidationError, match="deadline"):
        await handler.execute(replace(_command(), deadline=NOW))


@pytest.mark.asyncio
async def test_transaction_reauthorization_and_concurrent_receipt_are_authoritative() -> None:
    target = _profile(TARGET_ID, EVIDENCE_ONE, NOW)
    key = deduplication_idempotency_key(OPERATION_ID, TARGET_ID, BRAIN_ID)
    concurrent = DeduplicationResult.create(key, target, None, "memory-compatibility.v1")
    reads = _Repository(target=target, transaction_existing=concurrent)
    handler = DeduplicateMemoriesHandler(
        reads,
        _SemanticFinder(()),
        lambda: _UnitOfWork(reads),
        MemoryCompatibilityPolicy(),
        _Clock(),
    )

    assert await handler.execute(_command()) == concurrent
    assert reads.commit is None

    revoked = _Repository(target=target, missing_in_transaction=True)
    handler = replace(handler, reads=revoked, unit_of_work=lambda: _UnitOfWork(revoked))
    with pytest.raises(MemoryEvidenceNotFoundError):
        await handler.execute(_command())


def _command() -> DeduplicateMemoriesCommand:
    return DeduplicateMemoriesCommand(
        OPERATION_ID,
        ACTOR_ID,
        GRANT_ID,
        BRAIN_ID,
        CORRELATION_ID,
        CAUSATION_ID,
        TARGET_ID,
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=1),
    )


def _profile(
    memory_id: str,
    evidence_id: str,
    recorded_from: datetime,
) -> MemoryDeduplicationProfile:
    return MemoryDeduplicationProfile(
        memory_id,
        MemoryClass.DECISION,
        "a" * 64,
        MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
        NOW - timedelta(days=1),
        None,
        MemoryPolarity.AFFIRMED,
        "memory-promotion.v1",
        "memory-compatibility.v1",
        "b" * 64,
        "internal",
        "default",
        (evidence_id,),
        recorded_from,
        1,
    )


@dataclass
class _Clock:
    def now(self) -> datetime:
        return NOW


class _SemanticFinder:
    def __init__(self, candidates: tuple[SemanticMemoryCandidate, ...]) -> None:
        self.candidates = candidates
        self.calls = 0

    async def find(
        self,
        target: MemoryDeduplicationProfile,
        limit: int,
    ) -> tuple[SemanticMemoryCandidate, ...]:
        del target, limit
        self.calls += 1
        return self.candidates


class _Repository:
    def __init__(  # noqa: PLR0913 -- explicit fake transaction controls are test evidence.
        self,
        *,
        target: MemoryDeduplicationProfile | None,
        exact: tuple[MemoryDeduplicationProfile, ...] = (),
        existing: DeduplicationResult | None = None,
        transaction_target: MemoryDeduplicationProfile | None = None,
        transaction_existing: DeduplicationResult | None = None,
        missing_in_transaction: bool = False,
    ) -> None:
        self.target = target
        self.transaction_target = transaction_target
        self.exact = exact
        self.existing = existing
        self.transaction_existing = transaction_existing
        self.missing_in_transaction = missing_in_transaction
        self.loads = 0
        self.in_transaction = False
        self.commit: DeduplicationCommit | None = None

    async def get_result(self, idempotency_key: str) -> DeduplicationResult | None:
        del idempotency_key
        if self.in_transaction:
            return self.transaction_existing
        return self.existing

    async def load_authorized(
        self,
        memory_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> MemoryDeduplicationProfile | None:
        del memory_id, brain_id, actor_id, grant_id, at
        self.loads += 1
        if self.in_transaction and self.missing_in_transaction:
            return None
        if self.in_transaction and self.transaction_target is not None:
            return self.transaction_target
        return self.target

    async def find_exact(
        self,
        target: MemoryDeduplicationProfile,
        limit: int,
    ) -> tuple[MemoryDeduplicationProfile, ...]:
        del target, limit
        return self.exact

    async def add(self, commit: DeduplicationCommit) -> None:
        self.commit = commit


class _UnitOfWork:
    def __init__(self, repository: _Repository) -> None:
        self.repository = repository
        self.committed = False

    async def __aenter__(self) -> Self:
        self.repository.in_transaction = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.repository.in_transaction = False

    async def commit(self) -> None:
        self.committed = True
