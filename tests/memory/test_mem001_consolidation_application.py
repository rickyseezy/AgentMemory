"""MEM-001 consolidation orchestration, poisoning, and idempotency tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self

import pytest

from agentmemory.memory.application.consolidate_task import (
    ConsolidateTaskCommand,
    ConsolidateTaskHandler,
)
from agentmemory.memory.domain.consolidation import (
    ConsolidationCommit,
    ConsolidationResult,
    ExtractorIdentity,
    ExtractorResponse,
    MemoryPromotionPolicy,
    MemoryScope,
    TaskEvidenceBundle,
)
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from tests.memory.test_mem001_consolidation_domain import (
    BRAIN_ID,
    EVENT_ONE,
    EVENT_TWO,
    PROJECT_ID,
    REPOSITORY_ID,
    TASK_ID,
    bundle,
    candidate_document,
    extractor,
)

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.memory.domain.consolidation import ExtractorRequest
    from agentmemory.memory.domain.ports import MemoryConsolidationUnitOfWork

ACTOR_ID = "018f0000-0000-7000-8000-000000000002"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000401"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000402"
GRANT_ID = "018f0000-0000-7000-8000-000000000003"
NOW = datetime(2026, 7, 20, 13, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class FixedClock:
    current: datetime = NOW

    def now(self) -> datetime:
        return self.current


class FakeEvidenceQuery:
    def __init__(self, result: TaskEvidenceBundle | None) -> None:
        self.result = result
        self.calls: list[tuple[str, MemoryScope, int, int]] = []

    async def load(
        self,
        task_id: str,
        terminal_event_id: str,
        scope: MemoryScope,
        maximum_items: int,
        maximum_bytes: int,
    ) -> TaskEvidenceBundle | None:
        assert terminal_event_id == EVENT_TWO
        self.calls.append((task_id, scope, maximum_items, maximum_bytes))
        return self.result


class FakeExtractor:
    def __init__(
        self,
        output: bytes,
        *,
        response_identity: ExtractorIdentity | None = None,
    ) -> None:
        self.output = output
        self.response_identity = response_identity
        self.requests: list[ExtractorRequest] = []

    async def extract(self, request: ExtractorRequest) -> ExtractorResponse:
        self.requests.append(request)
        identity = self.response_identity or request.extractor
        return ExtractorResponse(
            request.operation_id,
            request.idempotency_key,
            request.task_id,
            request.input_sha256,
            identity,
            self.output,
            hashlib.sha256(self.output).hexdigest(),
        )


class FakeConsolidationRepository:
    def __init__(self, existing: ConsolidationResult | None = None) -> None:
        self.existing = existing
        self.commits: list[ConsolidationCommit] = []

    async def get(self, idempotency_key: str) -> ConsolidationResult | None:
        del idempotency_key
        return self.existing

    async def add(self, consolidation: ConsolidationCommit) -> None:
        self.commits.append(consolidation)
        result = consolidation.result
        self.existing = result


class FakeAccessPolicy:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str, MemoryScope, datetime]] = []

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        scope: MemoryScope,
        at: datetime,
    ) -> None:
        self.calls.append((actor_id, grant_id, scope, at))
        if not self.allowed:
            raise MemoryAuthorizationError


class FakeUnitOfWork:
    def __init__(
        self,
        repository: FakeConsolidationRepository,
        access: FakeAccessPolicy,
    ) -> None:
        self.repository = repository
        self.access = access
        self.committed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback

    async def commit(self) -> None:
        self.committed = True


class FakeUnitOfWorkFactory:
    def __init__(
        self,
        repository: FakeConsolidationRepository,
        access: FakeAccessPolicy,
    ) -> None:
        self.repository = repository
        self.access = access
        self.units: list[FakeUnitOfWork] = []

    def __call__(self) -> MemoryConsolidationUnitOfWork:
        unit = FakeUnitOfWork(self.repository, self.access)
        self.units.append(unit)
        return unit


def command(*, deadline: datetime | None = None) -> ConsolidateTaskCommand:
    return ConsolidateTaskCommand(
        operation_id="mem001-consolidation",
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        correlation_id=CORRELATION_ID,
        causation_id=CAUSATION_ID,
        task_id=TASK_ID,
        terminal_event_id=EVENT_TWO,
        scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
        extractor=extractor(),
        requested_at=NOW - timedelta(seconds=1),
        deadline=deadline or NOW + timedelta(minutes=1),
    )


def handler(
    evidence_query: FakeEvidenceQuery,
    extractor_adapter: FakeExtractor,
    repository: FakeConsolidationRepository,
) -> ConsolidateTaskHandler:
    access = FakeAccessPolicy()
    return ConsolidateTaskHandler(
        evidence_query,
        extractor_adapter,
        access,
        repository,
        FakeUnitOfWorkFactory(repository, access),
        MemoryPromotionPolicy.production(),
        FixedClock(),
    )


def build_handler(
    evidence_query: FakeEvidenceQuery,
    extractor_adapter: FakeExtractor,
    receipts: FakeConsolidationRepository,
    repository: FakeConsolidationRepository,
    accesses: tuple[FakeAccessPolicy, FakeAccessPolicy],
) -> tuple[ConsolidateTaskHandler, FakeUnitOfWorkFactory]:
    preflight_access, transactional_access = accesses
    factory = FakeUnitOfWorkFactory(repository, transactional_access)
    return (
        ConsolidateTaskHandler(
            evidence_query,
            extractor_adapter,
            preflight_access,
            receipts,
            factory,
            MemoryPromotionPolicy.production(),
            FixedClock(),
        ),
        factory,
    )


@pytest.mark.asyncio
async def test_golden_extraction_promotes_and_persists_one_evidence_backed_memory() -> None:
    source = bundle()
    evidence_query = FakeEvidenceQuery(source)
    extractor_adapter = FakeExtractor(candidate_document(source))
    repository = FakeConsolidationRepository()
    result = await handler(evidence_query, extractor_adapter, repository).execute(command())

    assert result.promoted == 1
    assert result.rejected == 0
    assert len(result.memory_ids) == 1
    assert len(extractor_adapter.requests) == 1
    request = extractor_adapter.requests[0]
    assert request.input_bytes == source.extractor_input_bytes
    assert request.classification == source.classification
    assert request.purpose == "memory_consolidation"
    assert evidence_query.calls == [(TASK_ID, source.scope, 256, 1024 * 1024)]
    committed = repository.commits[0]
    assert committed.memories[0].evidence_ids == (EVENT_ONE, EVENT_TWO)
    assert committed.source_terminal_event_id == EVENT_TWO
    assert committed.grant_id == GRANT_ID
    assert committed.correlation_id == CORRELATION_ID
    assert committed.causation_id == CAUSATION_ID


@pytest.mark.asyncio
async def test_retry_returns_committed_result_without_calling_extractor_again() -> None:
    source = bundle()
    extractor_adapter = FakeExtractor(candidate_document(source))
    repository = FakeConsolidationRepository()
    use_case = handler(FakeEvidenceQuery(source), extractor_adapter, repository)
    first = await use_case.execute(command())
    second = await use_case.execute(command())
    assert second == first
    assert len(extractor_adapter.requests) == 1
    assert len(repository.commits) == 1


@pytest.mark.asyncio
async def test_malformed_extractor_output_never_reaches_repository() -> None:
    source = bundle()
    repository = FakeConsolidationRepository()
    use_case = handler(FakeEvidenceQuery(source), FakeExtractor(b'{"invented":true}'), repository)
    with pytest.raises(MemoryValidationError):
        await use_case.execute(command())
    assert repository.commits == []


@pytest.mark.asyncio
async def test_extractor_identity_drift_fails_closed_before_model_output_is_trusted() -> None:
    source = bundle()
    repository = FakeConsolidationRepository()
    drifted = ExtractorIdentity(
        "agentmemory.local-extractor",
        "1.0.0",
        "qwen3-4b",
        "qwen3-4b-q4_k_m-r2",
        "memory-candidates.v1",
    )
    use_case = handler(
        FakeEvidenceQuery(source),
        FakeExtractor(candidate_document(source), response_identity=drifted),
        repository,
    )
    with pytest.raises(MemoryIntegrityError):
        await use_case.execute(command())
    assert repository.commits == []


@pytest.mark.asyncio
async def test_unsupported_model_claim_records_content_free_rejection_not_memory() -> None:
    source = bundle()
    unknown = "018f0000-0000-7000-8000-000000000399"
    repository = FakeConsolidationRepository()
    use_case = handler(
        FakeEvidenceQuery(source),
        FakeExtractor(candidate_document(source, evidence_ids=[unknown])),
        repository,
    )
    result = await use_case.execute(command())
    assert result.promoted == 0
    assert result.rejected == 1
    assert result.memory_ids == ()
    assert repository.commits[0].rejections[0].reason_code == "unsupported_evidence"


@pytest.mark.asyncio
async def test_missing_evidence_and_expired_deadline_fail_before_extraction() -> None:
    extractor_adapter = FakeExtractor(b"{}")
    missing = handler(
        FakeEvidenceQuery(None),
        extractor_adapter,
        FakeConsolidationRepository(),
    )
    with pytest.raises(MemoryEvidenceNotFoundError):
        await missing.execute(command())
    assert extractor_adapter.requests == []

    expired = handler(
        FakeEvidenceQuery(bundle()),
        extractor_adapter,
        FakeConsolidationRepository(),
    )
    with pytest.raises(MemoryValidationError):
        await expired.execute(command(deadline=NOW - timedelta(seconds=1)))
    assert extractor_adapter.requests == []


@pytest.mark.asyncio
async def test_authorization_precedes_evidence_and_is_rechecked_in_commit_transaction() -> None:
    source = bundle()
    evidence_query = FakeEvidenceQuery(source)
    extractor_adapter = FakeExtractor(candidate_document(source))
    repository = FakeConsolidationRepository()
    denied = FakeAccessPolicy(allowed=False)
    use_case, _ = build_handler(
        evidence_query,
        extractor_adapter,
        repository,
        repository,
        (denied, FakeAccessPolicy()),
    )
    with pytest.raises(MemoryAuthorizationError):
        await use_case.execute(command())
    assert evidence_query.calls == []
    assert extractor_adapter.requests == []

    preflight = FakeAccessPolicy()
    revoked = FakeAccessPolicy(allowed=False)
    use_case, factory = build_handler(
        FakeEvidenceQuery(source),
        extractor_adapter,
        repository,
        repository,
        (preflight, revoked),
    )
    with pytest.raises(MemoryAuthorizationError):
        await use_case.execute(command())
    assert len(extractor_adapter.requests) == 1
    assert repository.commits == []
    assert len(factory.units) == 1
    assert factory.units[0].committed is False


@pytest.mark.asyncio
async def test_concurrent_idempotency_receipt_wins_without_duplicate_stage() -> None:
    source = bundle()
    seed_repository = FakeConsolidationRepository()
    seed_handler = handler(
        FakeEvidenceQuery(source),
        FakeExtractor(candidate_document(source)),
        seed_repository,
    )
    expected = await seed_handler.execute(command())

    empty_preflight = FakeConsolidationRepository()
    transactional = FakeConsolidationRepository(existing=expected)
    use_case, factory = build_handler(
        FakeEvidenceQuery(source),
        FakeExtractor(candidate_document(source)),
        empty_preflight,
        transactional,
        (FakeAccessPolicy(), FakeAccessPolicy()),
    )
    result = await use_case.execute(command())
    assert result == expected
    assert transactional.commits == []
    assert factory.units[0].committed is False


@pytest.mark.asyncio
async def test_future_request_time_fails_before_authorization_or_extraction() -> None:
    source = bundle()
    access = FakeAccessPolicy()
    extractor_adapter = FakeExtractor(candidate_document(source))
    repository = FakeConsolidationRepository()
    use_case, _ = build_handler(
        FakeEvidenceQuery(source),
        extractor_adapter,
        repository,
        repository,
        (access, access),
    )
    future = replace(command(), requested_at=NOW + timedelta(seconds=1))
    with pytest.raises(MemoryValidationError) as failure:
        await use_case.execute(future)
    assert failure.value.code_for("requested_at") == "in_future"
    assert access.calls == []
    assert extractor_adapter.requests == []
