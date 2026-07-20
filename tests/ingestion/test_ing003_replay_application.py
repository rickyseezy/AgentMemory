"""ING-003 deterministic shadow replay application and worker tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import cast

import pytest

from agentmemory.ingestion.application.ordered_replay import (
    GetOrderedReplayHandler,
    OrderedReplayExecutor,
    OrderedReplayWorker,
    StartOrderedReplayHandler,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.ordered_replay import (
    OrderedProjectionState,
    OrderedReductionInput,
    OrderedReplayRun,
    RecordedOperationEvidence,
    ReplayRunRequest,
    ReplayRunState,
    ReplaySourcePage,
    ReplaySourceRecord,
    generation_digest,
)
from tests.core.support import BRAIN_ID, FixedClock, digest
from tests.ingestion.adp002_support import EVENT_ID, NOW, ORDERING_KEY, PRINCIPAL_ID

EVENT_ID_2 = "018f0000-0000-7000-8000-000000000102"
OPERATION_ID = "018f0000-0000-7000-8000-000000000123"
PROFILE_ID = "018f0000-0000-7000-8000-000000000124"
GRANT_ID = "018f0000-0000-7000-8000-000000000125"
GENERATION_ID = "018f0000-0000-7000-8000-000000000126"
CODE_FINGERPRINT = "a" * 40
NOW_US = round(NOW.timestamp() * 1_000_000)


def request() -> ReplayRunRequest:
    return ReplayRunRequest(
        OPERATION_ID,
        BRAIN_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        "canonical-event-projection-v1",
        GENERATION_ID,
        CODE_FINGERPRINT,
    )


def replay_run(state: ReplayRunState = ReplayRunState.QUEUED) -> OrderedReplayRun:
    leased = state in {ReplayRunState.BUILDING, ReplayRunState.VALIDATING}
    return OrderedReplayRun(
        request(),
        state,
        NOW_US,
        EVENT_ID_2,
        2,
        0,
        None,
        None,
        None,
        None,
        ("paused" if state is ReplayRunState.PARTIAL else None),
        ("replay-worker" if leased else None),
        (NOW_US + 100 if leased else None),
        NOW_US,
        NOW_US,
        None,
    )


def source(ordinal: int, event_id: str, sequence: int) -> ReplaySourceRecord:
    evidence = (
        RecordedOperationEvidence(
            OPERATION_ID,
            PROFILE_ID,
            "b" * 40,
            "extract",
            digest("provider-result").value,
        )
        if sequence == 2
        else None
    )
    return ReplaySourceRecord(
        ordinal,
        NOW_US + ordinal,
        OrderedReductionInput(
            event_id,
            ORDERING_KEY,
            sequence,
            1,
            digest(f"canonical-{sequence}").value,
            digest(f"projection-{sequence}").value,
            evidence is not None,
            evidence,
        ),
    )


@dataclass
class _Access:
    deny: bool = False
    calls: int = 0
    times: list[int] = field(default_factory=list[int])

    async def authorize(self, request: ReplayRunRequest, now_microseconds: int) -> None:
        del request
        self.calls += 1
        self.times.append(now_microseconds)
        if self.deny:
            message = "denied"
            raise IngestionAuthorizationError(message)


@dataclass
class _Repository:
    sources: tuple[ReplaySourceRecord, ...]
    run: OrderedReplayRun = field(default_factory=replay_run)
    states: dict[str, OrderedProjectionState] = field(
        default_factory=dict[str, OrderedProjectionState]
    )
    live_matches: bool = True
    partials: list[str] = field(default_factory=list[str])
    runnable_calls: int = 0

    async def create(self, request: ReplayRunRequest, now_microseconds: int) -> OrderedReplayRun:
        del now_microseconds
        assert request == self.run.request
        return self.run

    async def get(self, operation_id: str) -> OrderedReplayRun | None:
        return self.run if operation_id == OPERATION_ID else None

    async def claim(
        self,
        operation_id: str,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> OrderedReplayRun:
        assert operation_id == OPERATION_ID
        self.run = replace(
            self.run,
            state=ReplayRunState.BUILDING,
            failure_code=None,
            lease_owner=owner,
            lease_until_microseconds=lease_until_microseconds,
            updated_at_microseconds=now_microseconds,
        )
        return self.run

    async def read_page(self, run: OrderedReplayRun, limit: int) -> ReplaySourcePage:
        records = self.sources[run.processed_count : run.processed_count + limit]
        return ReplaySourcePage(records, run.processed_count + len(records) == run.source_count)

    async def shadow_state(
        self, operation_id: str, ordering_key: str
    ) -> OrderedProjectionState | None:
        assert operation_id == OPERATION_ID
        return self.states.get(ordering_key)

    async def append(  # noqa: PLR0913 -- Exact fake mirrors the port.
        self,
        run: OrderedReplayRun,
        source: ReplaySourceRecord,
        prior_state_sha256: str,
        state: OrderedProjectionState | None,
        state_sha256: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        del prior_state_sha256, state_sha256
        if state is not None:
            self.states[state.ordering_key] = state
        self.run = replace(
            run,
            processed_count=run.processed_count + 1,
            cursor_ingested_at_microseconds=source.ingested_at_microseconds,
            cursor_event_id=source.reduction.event_id,
            updated_at_microseconds=now_microseconds,
        )
        return self.run

    async def begin_validation(
        self,
        run: OrderedReplayRun,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> OrderedReplayRun:
        self.run = replace(
            run,
            state=ReplayRunState.VALIDATING,
            lease_until_microseconds=lease_until_microseconds,
            updated_at_microseconds=now_microseconds,
        )
        return self.run

    async def shadow_states(self, operation_id: str) -> tuple[OrderedProjectionState, ...]:
        assert operation_id == OPERATION_ID
        return tuple(self.states.values())

    async def live_states(self, run: OrderedReplayRun) -> tuple[OrderedProjectionState, ...]:
        del run
        if self.live_matches:
            return tuple(self.states.values())
        return (OrderedProjectionState(ORDERING_KEY, 2, "f" * 64),)

    async def finish_validation(
        self,
        run: OrderedReplayRun,
        shadow_digest: str,
        live_digest: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        self.run = replace(
            run,
            state=(
                ReplayRunState.READY if shadow_digest == live_digest else ReplayRunState.SUPERSEDED
            ),
            shadow_digest=shadow_digest,
            live_digest=live_digest,
            lease_owner=None,
            lease_until_microseconds=None,
            completed_at_microseconds=now_microseconds,
            updated_at_microseconds=now_microseconds,
        )
        return self.run

    async def mark_partial(
        self,
        run: OrderedReplayRun,
        failure_code: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        self.partials.append(failure_code)
        self.run = replace(
            run,
            state=ReplayRunState.PARTIAL,
            failure_code=failure_code,
            lease_owner=None,
            lease_until_microseconds=None,
            updated_at_microseconds=now_microseconds,
        )
        return self.run

    async def next_runnable(self, now_microseconds: int) -> str | None:
        del now_microseconds
        self.runnable_calls += 1
        return OPERATION_ID if self.run.state is ReplayRunState.QUEUED else None

    async def recover_expired(self, now_microseconds: int) -> int:
        del now_microseconds
        return 0


@pytest.mark.asyncio
async def test_start_authorizes_before_idempotent_shadow_creation() -> None:
    access = _Access()
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    result = await StartOrderedReplayHandler(access, repository, FixedClock(NOW)).execute(request())
    assert result.state is ReplayRunState.QUEUED
    assert access.calls == 1
    assert access.times == [NOW_US]


@pytest.mark.asyncio
async def test_get_reauthorizes_existing_status_and_hides_unknown_operation() -> None:
    access = _Access()
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    result = await GetOrderedReplayHandler(access, repository, FixedClock(NOW)).execute(
        OPERATION_ID
    )
    assert result == repository.run
    assert access.calls == 1
    with pytest.raises(IngestionValidationError, match="not_found"):
        await GetOrderedReplayHandler(access, repository, FixedClock(NOW)).execute("missing")


@pytest.mark.asyncio
async def test_terminal_replay_is_returned_without_reclaim_or_authorization() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    digest_value = generation_digest((), CODE_FINGERPRINT)
    repository.run = replace(
        repository.run,
        state=ReplayRunState.READY,
        processed_count=2,
        cursor_ingested_at_microseconds=NOW_US,
        cursor_event_id=EVENT_ID_2,
        shadow_digest=digest_value,
        live_digest=digest_value,
        completed_at_microseconds=NOW_US,
    )
    access = _Access(deny=True)
    assert (
        await OrderedReplayExecutor(access, repository, FixedClock(NOW), "replay-worker").execute(
            OPERATION_ID
        )
        == repository.run
    )
    assert access.calls == 0


@pytest.mark.asyncio
async def test_empty_selected_range_validates_as_one_deterministic_empty_generation() -> None:
    repository = _Repository(())
    repository.run = replace(repository.run, source_count=0)
    result = await OrderedReplayExecutor(
        _Access(), repository, FixedClock(NOW), "replay-worker"
    ).execute(OPERATION_ID)
    assert result.state is ReplayRunState.READY
    assert result.processed_count == 0
    assert result.shadow_digest == generation_digest((), CODE_FINGERPRINT)


@pytest.mark.asyncio
async def test_replay_rejects_missing_operation_and_empty_incomplete_page() -> None:
    repository = _Repository(())
    with pytest.raises(IngestionIntegrityError, match="not found"):
        await OrderedReplayExecutor(
            _Access(), repository, FixedClock(NOW), "replay-worker"
        ).execute("missing")
    with pytest.raises(IngestionIntegrityError, match="cursor"):
        await OrderedReplayExecutor(
            _Access(), repository, FixedClock(NOW), "replay-worker"
        ).execute(OPERATION_ID)


@pytest.mark.parametrize(
    ("owner", "page_size"),
    [("", 1), ("x" * 129, 1), ("worker", 0), ("worker", 4097)],
)
def test_replay_executor_rejects_unbounded_owner_or_page(owner: str, page_size: int) -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    with pytest.raises(ValueError, match="invalid"):
        OrderedReplayExecutor(_Access(), repository, FixedClock(NOW), owner, page_size)


@pytest.mark.asyncio
@pytest.mark.parametrize("page_size", [1, 2])
async def test_replay_uses_recorded_evidence_and_matches_live_digest(page_size: int) -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    result = await OrderedReplayExecutor(
        _Access(), repository, FixedClock(NOW), "replay-worker", page_size
    ).execute(OPERATION_ID)
    assert result.state is ReplayRunState.READY
    assert result.shadow_digest == result.live_digest
    assert result.shadow_digest == generation_digest(
        tuple(repository.states.values()), CODE_FINGERPRINT
    )
    assert repository.sources[1].reduction.recorded_operation is not None


@pytest.mark.asyncio
async def test_replay_never_promotes_divergent_shadow_state() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)), live_matches=False)
    result = await OrderedReplayExecutor(
        _Access(), repository, FixedClock(NOW), "replay-worker"
    ).execute(OPERATION_ID)
    assert result.state is ReplayRunState.SUPERSEDED
    assert result.shadow_digest != result.live_digest


@pytest.mark.asyncio
async def test_replay_rejects_noncausal_source_order() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(3, EVENT_ID_2, 2)))
    with pytest.raises(IngestionIntegrityError, match="source order"):
        await OrderedReplayExecutor(
            _Access(), repository, FixedClock(NOW), "replay-worker"
        ).execute(OPERATION_ID)


@pytest.mark.asyncio
async def test_replay_rejects_duplicate_sequence_with_exact_safe_error() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 1)))
    with pytest.raises(IngestionIntegrityError) as caught:
        await OrderedReplayExecutor(
            _Access(), repository, FixedClock(NOW), "replay-worker"
        ).execute(OPERATION_ID)
    assert str(caught.value) == "Ordered replay sequence is not strictly increasing"


@pytest.mark.asyncio
async def test_unsequenced_source_is_recorded_without_inventing_key_state() -> None:
    unsequenced = replace(
        source(1, EVENT_ID, 1),
        reduction=replace(source(1, EVENT_ID, 1).reduction, event_sequence=None),
    )
    repository = _Repository((unsequenced,))
    repository.run = replace(repository.run, source_count=1)
    result = await OrderedReplayExecutor(
        _Access(), repository, FixedClock(NOW), "replay-worker"
    ).execute(OPERATION_ID)
    assert result.state is ReplayRunState.READY
    assert repository.states == {}
    assert result.shadow_digest == generation_digest((), CODE_FINGERPRINT)


@pytest.mark.asyncio
async def test_worker_contains_revoked_authorization_as_resumable_partial() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    worker = OrderedReplayWorker(
        repository,
        OrderedReplayExecutor(_Access(deny=True), repository, FixedClock(NOW), "replay-worker"),
        FixedClock(NOW),
        poll_seconds=0.001,
    )
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop))
    for _ in range(100):
        if repository.partials:
            break
        await asyncio.sleep(0.001)
    stop.set()
    await task
    assert repository.partials == ["authorization_revoked"]


@dataclass
class _FailingExecutor:
    repository: _Repository
    error: Exception

    async def execute(self, operation_id: str) -> OrderedReplayRun:
        del operation_id
        self.repository.run = replace(
            self.repository.run,
            state=ReplayRunState.BUILDING,
            lease_owner="replay-worker",
            lease_until_microseconds=NOW_US + 10,
        )
        raise self.error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (IngestionDependencyError("offline"), "dependency_unavailable"),
        (IngestionIntegrityError("corrupt"), "integrity_violation"),
        (RuntimeError("unexpected secret"), "internal_error"),
    ],
)
async def test_worker_contains_every_failure_class_as_content_free_partial(
    error: Exception,
    expected: str,
) -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    worker = OrderedReplayWorker(
        repository,
        cast("OrderedReplayExecutor", _FailingExecutor(repository, error)),
        FixedClock(NOW),
        poll_seconds=0.001,
    )
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop))
    for _ in range(100):
        if repository.partials:
            break
        await asyncio.sleep(0.001)
    stop.set()
    await task
    assert repository.partials == [expected]
    assert "secret" not in (repository.run.failure_code or "")


@pytest.mark.asyncio
async def test_worker_pre_stopped_and_missing_status_paths_are_noops() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    worker = OrderedReplayWorker(
        repository,
        OrderedReplayExecutor(_Access(), repository, FixedClock(NOW), "replay-worker"),
        FixedClock(NOW),
    )
    stop = asyncio.Event()
    stop.set()
    await worker.run(stop)
    assert repository.partials == []


@pytest.mark.asyncio
async def test_idle_worker_repolls_until_shutdown_signal() -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    ready_digest = generation_digest((), CODE_FINGERPRINT)
    repository.run = replace(
        repository.run,
        state=ReplayRunState.READY,
        processed_count=2,
        cursor_ingested_at_microseconds=NOW_US,
        cursor_event_id=EVENT_ID_2,
        shadow_digest=ready_digest,
        live_digest=ready_digest,
        completed_at_microseconds=NOW_US,
    )
    worker = OrderedReplayWorker(
        repository,
        OrderedReplayExecutor(_Access(), repository, FixedClock(NOW), "replay-worker"),
        FixedClock(NOW),
        poll_seconds=0.001,
    )
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop))
    for _ in range(100):
        if repository.runnable_calls >= 2:
            break
        await asyncio.sleep(0.001)
    stop.set()
    await task
    assert repository.runnable_calls >= 2


@pytest.mark.parametrize("poll_seconds", [0, -1, 10.1])
def test_worker_rejects_invalid_poll_interval(poll_seconds: float) -> None:
    repository = _Repository((source(1, EVENT_ID, 1), source(2, EVENT_ID_2, 2)))
    with pytest.raises(ValueError, match="poll interval"):
        OrderedReplayWorker(
            repository,
            OrderedReplayExecutor(_Access(), repository, FixedClock(NOW), "replay-worker"),
            FixedClock(NOW),
            poll_seconds,
        )
