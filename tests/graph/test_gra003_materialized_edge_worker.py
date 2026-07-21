"""GRA-003 durable projection worker success, retry, and quarantine tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.graph.application.materialized_edge_worker import (
    MaterializedEdgeIntegrityWorker,
    MaterializedEdgeProjectionWorker,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)
from agentmemory.graph.domain.materialized_edges import (
    MaterializedAssertionEdge,
    MaterializedEdgeProjectionJob,
    ProjectionEdgeStatus,
    ProjectionJobFailureCode,
)
from agentmemory.graph.domain.models import GraphClassification
from tests.graph.test_gra003_materialized_edge_application import (
    ACTIVATED_EVENT_ID,
    ASSERTION_ID,
    BRAIN_ID,
    CHECKOUT_ID,
    GENERATION_ID,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    _active,  # pyright: ignore[reportPrivateUsage]
    _edge,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.graph.application.materialized_edges import (
        MaterializeAssertionEdgeHandler,
        ValidateAssertionEdgesHandler,
    )
    from agentmemory.graph.domain.materialized_edge_ports import (
        MaterializedEdgeGenerationResolver,
        MaterializedEdgeIntegrityScopeSource,
        MaterializedEdgeProjectionAuthorization,
        MaterializedEdgeProjectionWorkRepository,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

NOW = datetime(2026, 7, 21, 13, tzinfo=UTC)


@pytest.mark.asyncio
async def test_worker_projects_and_completes_exact_lease_receipt() -> None:
    repository = _WorkRepository(_job())
    worker = _worker(repository=repository)
    assert await worker.execute_once()
    assert len(repository.completed) == 1
    completed_job, generation, digest, status, at = repository.completed[0]
    assert completed_job.source_event_id == ACTIVATED_EVENT_ID
    assert (generation, digest, status, at) == (
        GENERATION_ID,
        _edge(_active(), ACTIVATED_EVENT_ID).projection_digest,
        ProjectionEdgeStatus.ACTIVE,
        NOW,
    )


@pytest.mark.asyncio
async def test_worker_retries_missing_generation_and_dependency_with_backoff() -> None:
    missing = _WorkRepository(_job())
    assert await _worker(repository=missing, generation=None).execute_once()
    assert missing.retried[0][1] is ProjectionJobFailureCode.GENERATION_UNAVAILABLE
    assert missing.retried[0][2:] == (NOW + timedelta(seconds=2), NOW)

    unavailable = _WorkRepository(_job(attempts=2))
    assert await _worker(
        repository=unavailable,
        error=GraphUnavailableError("down"),
    ).execute_once()
    assert unavailable.retried[0][1] is ProjectionJobFailureCode.DEPENDENCY_UNAVAILABLE
    assert unavailable.retried[0][2:] == (NOW + timedelta(seconds=4), NOW)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "code"),
    [
        (GraphAuthorizationError("revoked"), ProjectionJobFailureCode.AUTHORIZATION_REVOKED),
        (GraphConflictError("divergent"), ProjectionJobFailureCode.CONCURRENT_CONFLICT),
        (GraphIntegrityError("corrupt"), ProjectionJobFailureCode.INTEGRITY_VIOLATION),
    ],
)
async def test_worker_quarantines_nonretryable_security_and_integrity_failures(
    error: Exception,
    code: ProjectionJobFailureCode,
) -> None:
    repository = _WorkRepository(_job())
    assert await _worker(repository=repository, error=error).execute_once()
    assert repository.quarantined == [(_job(), code, NOW)]
    assert repository.retried == []


@pytest.mark.asyncio
async def test_worker_bounds_unknown_retries_and_stops_without_work() -> None:
    exhausted = _WorkRepository(_job(attempts=12))
    assert await _worker(repository=exhausted, error=RuntimeError("secret details")).execute_once()
    assert exhausted.quarantined[0][1] is ProjectionJobFailureCode.INTERNAL_ERROR

    empty = _WorkRepository(None)
    worker = _worker(repository=empty)
    assert not await worker.execute_once()
    stop = asyncio.Event()
    stop.set()
    await worker.run(stop)
    with pytest.raises(ValueError, match="configuration"):
        _worker(repository=empty, owner="INVALID OWNER")


@pytest.mark.asyncio
async def test_integrity_worker_scans_bounded_scopes_and_contains_one_failure() -> None:
    scope = _scope("graph.assertion.edge.integrity", (CHECKOUT_ID,))
    scopes = _IntegrityScopes(((scope, GENERATION_ID), (scope, GENERATION_ID)))
    handler = _IntegrityHandler()
    worker = MaterializedEdgeIntegrityWorker(
        cast("MaterializedEdgeIntegrityScopeSource", scopes),
        cast("ValidateAssertionEdgesHandler", handler),
        _Clock(),
        interval_seconds=1,
    )
    assert await worker.execute_once() == (1, 1)
    assert handler.calls == 2
    with pytest.raises(ValueError, match="configuration"):
        MaterializedEdgeIntegrityWorker(
            cast("MaterializedEdgeIntegrityScopeSource", scopes),
            cast("ValidateAssertionEdgesHandler", handler),
            _Clock(),
            scope_limit=101,
        )


def _worker(
    *,
    repository: _WorkRepository,
    generation: str | None = GENERATION_ID,
    error: Exception | None = None,
    owner: str = "edge-worker-1",
) -> MaterializedEdgeProjectionWorker:
    return MaterializedEdgeProjectionWorker(
        owner,
        cast("MaterializedEdgeProjectionWorkRepository", repository),
        cast("MaterializedEdgeProjectionAuthorization", _Authorization()),
        cast("MaterializedEdgeGenerationResolver", _Generation(generation)),
        cast("MaterializeAssertionEdgeHandler", _Handler(error)),
        _Clock(),
    )


def _job(*, attempts: int = 1) -> MaterializedEdgeProjectionJob:
    return MaterializedEdgeProjectionJob(
        ACTIVATED_EVENT_ID,
        ASSERTION_ID,
        BRAIN_ID,
        PRINCIPAL_ID,
        PROJECT_ID,
        REPOSITORY_ID,
        CHECKOUT_ID,
        GraphClassification.INTERNAL,
        1,
        "c" * 64,
        NOW - timedelta(seconds=1),
        attempts,
        "edge-worker-1",
        NOW + timedelta(seconds=30),
    )


@dataclass(slots=True)
class _Clock:
    def now(self) -> datetime:
        return NOW


@dataclass(slots=True)
class _WorkRepository:
    next_job: MaterializedEdgeProjectionJob | None
    completed: list[
        tuple[MaterializedEdgeProjectionJob, str, str, ProjectionEdgeStatus, datetime]
    ] = field(
        default_factory=list[
            tuple[MaterializedEdgeProjectionJob, str, str, ProjectionEdgeStatus, datetime]
        ]
    )
    retried: list[
        tuple[MaterializedEdgeProjectionJob, ProjectionJobFailureCode, datetime, datetime]
    ] = field(
        default_factory=list[
            tuple[MaterializedEdgeProjectionJob, ProjectionJobFailureCode, datetime, datetime]
        ]
    )
    quarantined: list[tuple[MaterializedEdgeProjectionJob, ProjectionJobFailureCode, datetime]] = (
        field(
            default_factory=list[
                tuple[MaterializedEdgeProjectionJob, ProjectionJobFailureCode, datetime]
            ]
        )
    )

    async def claim_next(
        self, owner: str, now: datetime, lease_until: datetime
    ) -> MaterializedEdgeProjectionJob | None:
        del owner, now, lease_until
        value = self.next_job
        self.next_job = None
        return value

    async def complete(
        self,
        job: MaterializedEdgeProjectionJob,
        generation_id: str,
        projection_digest: str,
        status: ProjectionEdgeStatus,
        completed_at: datetime,
    ) -> None:
        self.completed.append((job, generation_id, projection_digest, status, completed_at))

    async def retry(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        not_before: datetime,
        attempted_at: datetime,
    ) -> None:
        self.retried.append((job, code, not_before, attempted_at))

    async def quarantine(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        at: datetime,
    ) -> None:
        self.quarantined.append((job, code, at))


@dataclass(frozen=True, slots=True)
class _Authorization:
    async def authorize(
        self,
        job: MaterializedEdgeProjectionJob,
        action: str,
        at: datetime,
    ) -> AuthorizedScope:
        del job, at
        return _scope(action, (CHECKOUT_ID,))


@dataclass(frozen=True, slots=True)
class _Generation:
    value: str | None

    async def active_generation(self, brain_id: str) -> str | None:
        del brain_id
        return self.value


@dataclass(frozen=True, slots=True)
class _Handler:
    error: Exception | None

    async def execute(self, command: object) -> MaterializedAssertionEdge:
        del command
        if self.error is not None:
            raise self.error
        return _edge(_active(), ACTIVATED_EVENT_ID)


@dataclass(frozen=True, slots=True)
class _IntegrityScopes:
    values: tuple[tuple[AuthorizedScope, str], ...]

    async def integrity_scopes(
        self, at: datetime, limit: int
    ) -> tuple[tuple[AuthorizedScope, str], ...]:
        del at
        return self.values[:limit]


@dataclass(slots=True)
class _IntegrityHandler:
    calls: int = 0

    async def execute(self, command: object) -> tuple[object, ...]:
        del command
        self.calls += 1
        if self.calls == 2:
            message = "down"
            raise GraphUnavailableError(message)
        return ()
