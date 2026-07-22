"""PF-004 structured-concurrency retrieval fault-matrix tests."""

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from agentmemory.resilience.application.recall import RecallQueryHandler
from agentmemory.resilience.domain.errors import (
    RecallAuthorizationError,
    RecallDependencyError,
    RecallIntegrityError,
    ResilienceValidationError,
)
from agentmemory.resilience.domain.models import (
    ChannelName,
    CircuitPolicy,
    DependencyName,
    RecallCandidate,
    RecallChannelSuccess,
    RecallExecutionPolicy,
    RecallQuery,
)
from agentmemory.resilience.infrastructure.in_memory_health import (
    InMemoryDependencyHealthRepository,
)

NOW = datetime(2026, 7, 22, 16, 0, tzinfo=UTC)


def execution_policy(
    deadlines: dict[ChannelName, float], *, failure_threshold: int = 5
) -> RecallExecutionPolicy:
    return RecallExecutionPolicy(
        channel_deadlines=deadlines,
        bulkhead_limit=2,
        circuit=CircuitPolicy(
            failure_threshold=failure_threshold,
            failure_window_seconds=30,
            open_seconds=30,
        ),
    )


@pytest.mark.asyncio
async def test_pf004_returns_available_channels_with_degradation_and_freshness() -> None:
    exact = Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER)
    lexical = Source(ChannelName.LEXICAL, DependencyName.NONCANONICAL_WORKER, failure="dependency")
    vector = Source(ChannelName.VECTOR, DependencyName.EMBEDDING, delay=0.05)
    graph = Source(ChannelName.GRAPH, DependencyName.NEO4J)
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(exact, lexical, vector, graph),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy(
            {
                ChannelName.EXACT: 0.1,
                ChannelName.LEXICAL: 0.1,
                ChannelName.VECTOR: 0.01,
                ChannelName.GRAPH: 0.1,
            }
        ),
        clock=Clock(),
    )

    response = await handler.execute(query())

    assert tuple(item.candidate_id for item in response.candidates) == ("exact-1", "graph-1")
    assert response.degraded_channels == (ChannelName.LEXICAL, ChannelName.VECTOR)
    assert response.outcomes[ChannelName.LEXICAL].code == "AM_DEPENDENCY_UNAVAILABLE"
    assert response.outcomes[ChannelName.VECTOR].code == "AM_DEADLINE_EXCEEDED"
    assert response.freshness[ChannelName.EXACT] == NOW - timedelta(seconds=1)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["authorization", "integrity"])
async def test_pf004_authorization_and_canonical_integrity_fail_the_whole_query(
    failure: str,
) -> None:
    source = Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER, failure=failure)
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.EXACT: 0.1}),
        clock=Clock(),
    )
    expected = RecallAuthorizationError if failure == "authorization" else RecallIntegrityError
    with pytest.raises(expected):
        await handler.execute(query())


@pytest.mark.asyncio
async def test_pf004_authorization_failure_prevents_every_channel_call() -> None:
    source = Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER)
    handler = RecallQueryHandler.create(
        authorization=Authorization(denied=True),
        sources=(source,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.EXACT: 0.1}),
        clock=Clock(),
    )

    with pytest.raises(RecallAuthorizationError):
        await handler.execute(query())

    assert source.calls == []


@pytest.mark.asyncio
async def test_pf004_fatal_channel_cancels_and_awaits_its_sibling() -> None:
    fatal = Source(
        ChannelName.EXACT,
        DependencyName.CANONICAL_LEDGER,
        failure="integrity",
        delay=0.01,
    )
    sibling = Source(ChannelName.VECTOR, DependencyName.EMBEDDING, delay=10)
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(fatal, sibling),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.EXACT: 0.1, ChannelName.VECTOR: 20}),
        clock=Clock(),
    )

    with pytest.raises(RecallIntegrityError):
        await handler.execute(query())

    assert sibling.started.is_set()
    assert sibling.cancelled is True


@pytest.mark.asyncio
async def test_pf004_open_circuit_skips_calls_and_half_open_allows_one_probe() -> None:
    source = Source(ChannelName.VECTOR, DependencyName.EMBEDDING, failure="dependency")
    health = InMemoryDependencyHealthRepository()
    clock = Clock()
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=health,
        execution_policy=execution_policy({ChannelName.VECTOR: 0.1}, failure_threshold=2),
        clock=clock,
    )
    await handler.execute(query("one"))
    clock.value = NOW + timedelta(seconds=1)
    await handler.execute(query("two", NOW + timedelta(seconds=1)))
    clock.value = NOW + timedelta(seconds=2)
    result = await handler.execute(query("three", NOW + timedelta(seconds=2)))
    assert source.calls == ["one", "two"]
    assert result.outcomes[ChannelName.VECTOR].code == "AM_CIRCUIT_OPEN"

    source.failure = None
    clock.value = NOW + timedelta(seconds=32)
    recovered = await handler.execute(query("probe", NOW + timedelta(seconds=32)))
    assert source.calls == ["one", "two", "probe"]
    assert recovered.degraded_channels == ()


@pytest.mark.asyncio
async def test_pf004_only_one_concurrent_request_receives_half_open_probe() -> None:
    source = Source(ChannelName.VECTOR, DependencyName.EMBEDDING, failure="dependency")
    clock = Clock()
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.VECTOR: 0.1}, failure_threshold=1),
        clock=clock,
    )
    await handler.execute(query("open"))
    source.failure = None
    source.delay = 0.02
    clock.value = NOW + timedelta(seconds=31)

    first, second = await asyncio.gather(
        handler.execute(query("probe-one", clock.value)),
        handler.execute(query("probe-two", clock.value)),
    )

    assert source.calls[0] == "open"
    assert len(source.calls) == 2
    assert sorted(
        (first.outcomes[ChannelName.VECTOR].code, second.outcomes[ChannelName.VECTOR].code)
    ) == [
        "AM_CIRCUIT_OPEN",
        "AM_OK",
    ]


@pytest.mark.asyncio
async def test_pf004_cancelled_half_open_probe_is_released_without_extra_failure() -> None:
    source = Source(ChannelName.VECTOR, DependencyName.EMBEDDING, failure="dependency")
    health = InMemoryDependencyHealthRepository()
    clock = Clock()
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=health,
        execution_policy=execution_policy({ChannelName.VECTOR: 20}, failure_threshold=1),
        clock=clock,
    )
    await handler.execute(query("open"))
    opened = await health.snapshot(DependencyName.EMBEDDING)
    source.failure = None
    source.delay = 10
    source.started = asyncio.Event()
    clock.value = NOW + timedelta(seconds=31)
    task = asyncio.create_task(handler.execute(query("probe", clock.value)))
    await source.started.wait()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    snapshot = await health.snapshot(DependencyName.EMBEDDING)
    assert snapshot.state.value == "open"
    assert snapshot.consecutive_failures == opened.consecutive_failures
    assert snapshot.probe_in_flight is False


@pytest.mark.asyncio
async def test_pf004_cancellation_propagates_and_each_channel_is_billed_at_most_once() -> None:
    source = Source(ChannelName.VECTOR, DependencyName.EMBEDDING, delay=10)
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=RecallExecutionPolicy(
            channel_deadlines={ChannelName.VECTOR: 20},
            bulkhead_limit=1,
            circuit=CircuitPolicy.production(),
        ),
        clock=Clock(),
    )
    task = asyncio.create_task(handler.execute(query()))
    await source.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert source.calls == ["operation"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "dependency",
    [
        DependencyName.NEO4J,
        DependencyName.EMBEDDING,
        DependencyName.RERANKING,
        DependencyName.EXTRACTION,
        DependencyName.NONCANONICAL_WORKER,
    ],
)
async def test_pf004_each_noncanonical_dependency_degrades_without_retry(
    dependency: DependencyName,
) -> None:
    source = Source(ChannelName.VECTOR, dependency, failure="dependency")
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.VECTOR: 0.1}),
        clock=Clock(),
    )

    result = await handler.execute(query(dependency.value))

    assert result.degraded_channels == (ChannelName.VECTOR,)
    assert source.calls == [dependency.value]


@pytest.mark.asyncio
async def test_pf004_expired_caller_deadline_skips_dependency_and_circuit_billing() -> None:
    source = Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER)
    health = InMemoryDependencyHealthRepository()
    clock = Clock(NOW + timedelta(seconds=3))
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=health,
        execution_policy=execution_policy({ChannelName.EXACT: 0.1}),
        clock=clock,
    )

    result = await handler.execute(query())

    assert result.outcomes[ChannelName.EXACT].code == "AM_DEADLINE_EXCEEDED"
    assert source.calls == []
    assert (await health.snapshot(DependencyName.CANONICAL_LEDGER)).consecutive_failures == 0


@pytest.mark.asyncio
async def test_pf004_bulkhead_queue_time_counts_toward_deadline_without_circuit_billing() -> None:
    source = Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER)
    health = InMemoryDependencyHealthRepository()
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=health,
        execution_policy=RecallExecutionPolicy(
            channel_deadlines={ChannelName.EXACT: 0.01},
            bulkhead_limit=1,
            circuit=CircuitPolicy.production(),
        ),
        clock=Clock(),
    )
    await handler.bulkhead.acquire()
    try:
        task = asyncio.create_task(handler.execute(query()))
        await asyncio.sleep(0.03)
    finally:
        handler.bulkhead.release()

    result = await asyncio.wait_for(task, timeout=0.1)

    assert result.outcomes[ChannelName.EXACT].code == "AM_DEADLINE_EXCEEDED"
    assert source.calls == []
    assert (await health.snapshot(DependencyName.CANONICAL_LEDGER)).consecutive_failures == 0


@pytest.mark.asyncio
async def test_pf004_deduplicates_cross_channel_candidates_by_highest_score() -> None:
    exact = Source(
        ChannelName.EXACT,
        DependencyName.CANONICAL_LEDGER,
        candidate_id="shared",
        score_basis_points=9_000,
    )
    lexical = Source(
        ChannelName.LEXICAL,
        DependencyName.NONCANONICAL_WORKER,
        candidate_id="shared",
        score_basis_points=8_000,
    )
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(exact, lexical),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.EXACT: 0.1, ChannelName.LEXICAL: 0.1}),
        clock=Clock(),
    )

    result = await handler.execute(query())

    assert result.candidates == (RecallCandidate("shared", 9_000),)

    ordered = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(
            Source(
                ChannelName.EXACT,
                DependencyName.CANONICAL_LEDGER,
                candidate_id="lower",
                score_basis_points=1_000,
            ),
            Source(
                ChannelName.LEXICAL,
                DependencyName.NONCANONICAL_WORKER,
                candidate_id="higher",
                score_basis_points=9_000,
            ),
        ),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.EXACT: 0.1, ChannelName.LEXICAL: 0.1}),
        clock=Clock(),
    )
    ranking = await ordered.execute(query("ranking"))
    assert [item.candidate_id for item in ranking.candidates] == ["higher", "lower"]


@pytest.mark.asyncio
async def test_pf004_rejects_source_channel_identity_substitution() -> None:
    source = Source(
        ChannelName.EXACT,
        DependencyName.CANONICAL_LEDGER,
        returned_channel=ChannelName.GRAPH,
    )
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(source,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.EXACT: 0.1}),
        clock=Clock(),
    )

    with pytest.raises(RecallIntegrityError, match="substitution"):
        await handler.execute(query())


def test_pf004_rejects_missing_or_duplicate_source_topology() -> None:
    source = Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER)
    with pytest.raises(ResilienceValidationError, match="execution policy"):
        RecallQueryHandler.create(
            authorization=Authorization(),
            sources=(source, source),
            health=InMemoryDependencyHealthRepository(),
            execution_policy=execution_policy({ChannelName.EXACT: 0.1}),
            clock=Clock(),
        )


def query(operation_id: str = "operation", requested_at: datetime = NOW) -> RecallQuery:
    return RecallQuery(
        operation_id, requested_at, requested_at + timedelta(seconds=2), "scope-digest"
    )


@dataclass
class Authorization:
    calls: int = 0
    operations: list[str] = field(default_factory=list[str])
    denied: bool = False

    async def authorize(self, request: RecallQuery) -> None:
        self.calls += 1
        self.operations.append(request.operation_id)
        if self.denied:
            raise RecallAuthorizationError


@dataclass
class Clock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


@dataclass
class Source:
    channel: ChannelName
    dependency: DependencyName
    failure: str | None = None
    delay: float = 0
    calls: list[str] = field(default_factory=list[str])
    started: asyncio.Event = field(default_factory=asyncio.Event)
    candidate_id: str | None = None
    score_basis_points: int = 9_000
    returned_channel: ChannelName | None = None
    cancelled: bool = False

    async def recall(self, request: RecallQuery) -> RecallChannelSuccess:
        self.calls.append(request.operation_id)
        self.started.set()
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        if self.failure == "authorization":
            raise RecallAuthorizationError
        if self.failure == "integrity":
            raise RecallIntegrityError
        if self.failure == "dependency":
            raise RecallDependencyError
        return RecallChannelSuccess(
            self.returned_channel or self.channel,
            (
                RecallCandidate(
                    self.candidate_id or f"{self.channel.value}-1",
                    self.score_basis_points,
                ),
            ),
            NOW - timedelta(seconds=1),
        )
