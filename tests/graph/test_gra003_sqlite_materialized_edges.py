"""GRA-003 canonical source, work queue, authorization, and journal integration tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.graph.adapters.outbound import sqlite_assertions
from agentmemory.graph.adapters.outbound.neo4j_materialized_edges import (
    Neo4jMaterializedEdgeProjectionFactory,
)
from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.adapters.outbound.sqlite_materialized_edges import (
    SqliteCanonicalAssertionProjectionSource,
    SqliteMaterializedEdgeAuthorization,
    SqliteMaterializedEdgeGenerationResolver,
    SqliteMaterializedEdgeIntegrityJournal,
    SqliteMaterializedEdgeIntegrityScopeSource,
    SqliteMaterializedEdgeWorkRepository,
)
from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
)
from agentmemory.graph.application.materialized_edge_worker import (
    MaterializedEdgeProjectionWorker,
)
from agentmemory.graph.application.materialized_edges import MaterializeAssertionEdgeHandler
from agentmemory.graph.domain.assertions import (
    AssertionEventType,
    AssertionEvidenceReference,
    AssertionEvidenceRevocation,
    AssertionLifecycleEvent,
    AssertionStatus,
    EvidenceKind,
    EvidenceRevocationReason,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
)
from agentmemory.graph.domain.materialized_edges import (
    EdgeIntegrityFinding,
    EdgeIntegrityFindingKind,
    MaterializedAssertionEdge,
    ProjectionEdgeStatus,
    ProjectionJobFailureCode,
)
from tests.core.support import BRAIN_ID, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    ACTIVATED_EVENT_ID,
    ASSERTION_ID,
    NOW,
    OBJECT_ID,
    PROMPT_EVENT_ID,
    PROMPT_EVIDENCE_ID,
    SUBJECT_ID,
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
    _seed_sources,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra003_neo4j_materialized_edges import (
    _Driver,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _seed_roots as seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from neo4j import AsyncDriver

    from agentmemory.graph.domain.assertions import Assertion
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

GENERATION_ID = "a" * 64


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_assertion_event_atomically_queues_authorized_projection_and_exact_receipt(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        active = await _activate(store)
        generation_resolver = SqliteMaterializedEdgeGenerationResolver(store)
        assert await generation_resolver.active_generation(BRAIN_ID) is None
        await _set_generation(store)
        work = SqliteMaterializedEdgeWorkRepository(store)
        claim_at = NOW + timedelta(seconds=2)
        with pytest.raises(GraphIntegrityError, match="integrity"):
            await work.claim_next("INVALID OWNER", claim_at, claim_at)
        job = await work.claim_next(
            "edge-worker-1",
            claim_at,
            claim_at + timedelta(seconds=30),
        )
        assert job is not None
        assert (job.source_event_id, job.assertion_id, job.aggregate_version, job.attempts) == (
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
            1,
            1,
        )
        authorization = SqliteMaterializedEdgeAuthorization(store)
        scope = await authorization.authorize(
            job,
            "graph.assertion.materialize",
            claim_at,
        )
        with pytest.raises(GraphAuthorizationError, match="action"):
            await authorization.authorize(job, "graph.read", claim_at)
        assertion, event_id, occurred_at = await SqliteCanonicalAssertionProjectionSource(
            store
        ).current_for_event(
            scope,
            job.source_event_id,
            job.assertion_id,
        )
        assert (assertion, event_id, occurred_at) == (
            active,
            ACTIVATED_EVENT_ID,
            NOW + timedelta(seconds=1),
        )
        assert await generation_resolver.active_generation(BRAIN_ID) == GENERATION_ID
        integrity_scopes = await SqliteMaterializedEdgeIntegrityScopeSource(store).integrity_scopes(
            claim_at, 10
        )
        assert len(integrity_scopes) == 1
        assert integrity_scopes[0][0].action == "graph.assertion.edge.integrity"
        assert integrity_scopes[0][1] == GENERATION_ID
        with pytest.raises(GraphIntegrityError, match="integrity"):
            await SqliteMaterializedEdgeIntegrityScopeSource(store).integrity_scopes(claim_at, 0)
        expected = await SqliteCanonicalAssertionProjectionSource(store).expected_edges(
            integrity_scopes[0][0],
            GENERATION_ID,
            claim_at,
        )
        assert len(expected) == 1
        assert expected[0].assertion_id == ASSERTION_ID
        edge = MaterializedAssertionEdge.from_assertion(
            assertion,
            source_event_id=event_id,
            generation_id=GENERATION_ID,
            projected_at=occurred_at,
        )
        completed_at = claim_at + timedelta(seconds=1)
        with pytest.raises(GraphIntegrityError, match="integrity"):
            await work.complete(
                job,
                GENERATION_ID,
                edge.projection_digest,
                ProjectionEdgeStatus.RETIRED,
                completed_at,
            )
        await work.complete(
            job,
            GENERATION_ID,
            edge.projection_digest,
            edge.projection_status,
            completed_at,
        )
        await work.complete(
            job,
            GENERATION_ID,
            edge.projection_digest,
            edge.projection_status,
            completed_at,
        )
        assert (
            await work.claim_next(
                "edge-worker-1",
                claim_at,
                claim_at + timedelta(seconds=30),
            )
            is None
        )
        async with store.engine.connect() as connection:
            receipt = (
                await connection.execute(
                    text(
                        "SELECT projection_status,aggregate_version FROM "
                        "assertion_edge_projection_receipts WHERE source_event_id=:event"
                    ),
                    {"event": ACTIVATED_EVENT_ID},
                )
            ).one()
        assert tuple(receipt) == ("active", 1)
        with pytest.raises(IntegrityError, match="immutable"):
            async with store.engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE assertion_edge_projection_receipts SET completed_at=completed_at+1"
                    )
                )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_production_worker_projects_sqlite_event_into_generation_scoped_direct_edge(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _activate(store)
        await _set_generation(store)
        driver = _Driver(nodes={(BRAIN_ID, SUBJECT_ID), (BRAIN_ID, OBJECT_ID)})
        projections = Neo4jMaterializedEdgeProjectionFactory(
            cast("AsyncDriver", driver),
            "agentmemory",
        )
        source = SqliteCanonicalAssertionProjectionSource(store)
        worker = MaterializedEdgeProjectionWorker(
            "edge-worker-e2e",
            SqliteMaterializedEdgeWorkRepository(store),
            SqliteMaterializedEdgeAuthorization(store),
            SqliteMaterializedEdgeGenerationResolver(store),
            MaterializeAssertionEdgeHandler(source, projections),
            _FixedClock(NOW + timedelta(seconds=2)),
        )
        assert await worker.execute_once()
        projected = driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)]
        assert projected["assertion_id"] == ASSERTION_ID
        assert projected["projection_status"] == "active"
        async with store.engine.connect() as connection:
            state = (
                await connection.execute(
                    text(
                        "SELECT state FROM assertion_edge_projection_jobs "
                        "WHERE source_event_id=:event"
                    ),
                    {"event": ACTIVATED_EVENT_ID},
                )
            ).scalar_one()
        assert state == "completed"
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_delayed_activation_reads_latest_dispute_and_reauthorization_fails_closed(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _activate(store)
        factory = SqliteAssertionRepositoryFactory(store)
        revoked_at = NOW + timedelta(seconds=2)
        disputed = (
            await factory.evidence_catalog(_scope("graph.assertion.evidence.revoke")).revoke(
                AssertionEvidenceRevocation(
                    "assertion-evidence-revoke-gra003",
                    PROMPT_EVIDENCE_ID,
                    EvidenceRevocationReason.USER_RETRACTED,
                    revoked_at,
                )
            )
        )[0]
        assert disputed.status is AssertionStatus.DISPUTED
        work = SqliteMaterializedEdgeWorkRepository(store)
        claim_at = revoked_at + timedelta(seconds=1)
        activation_job = await work.claim_next(
            "edge-worker-race",
            claim_at,
            claim_at + timedelta(seconds=30),
        )
        assert activation_job is not None
        scope = await SqliteMaterializedEdgeAuthorization(store).authorize(
            activation_job,
            "graph.assertion.materialize",
            claim_at,
        )
        current, current_event, current_at = await SqliteCanonicalAssertionProjectionSource(
            store
        ).current_for_event(
            scope,
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
        )
        assert current == disputed
        assert current_event != ACTIVATED_EVENT_ID
        assert current_at == revoked_at
        await work.quarantine(
            activation_job,
            ProjectionJobFailureCode.CONCURRENT_CONFLICT,
            claim_at,
        )

        dispute_job = await work.claim_next(
            "edge-worker-race",
            claim_at,
            claim_at + timedelta(seconds=30),
        )
        assert dispute_job is not None
        assert dispute_job.source_event_id == current_event
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:at"),
                {"at": round(claim_at.timestamp() * 1_000_000)},
            )
        with pytest.raises(GraphAuthorizationError, match="not authorized"):
            await SqliteMaterializedEdgeAuthorization(store).authorize(
                dispute_job,
                "graph.assertion.materialize",
                claim_at + timedelta(seconds=1),
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_expired_lease_recovers_and_integrity_journal_is_exactly_idempotent(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        active = await _activate(store)
        work = SqliteMaterializedEdgeWorkRepository(store)
        first_at = NOW + timedelta(seconds=2)
        first = await work.claim_next(
            "edge-worker-dead",
            first_at,
            first_at + timedelta(seconds=1),
        )
        assert first is not None
        second_at = first_at + timedelta(seconds=2)
        recovered = await work.claim_next(
            "edge-worker-live",
            second_at,
            second_at + timedelta(seconds=30),
        )
        assert recovered is not None
        assert (recovered.attempts, recovered.lease_owner) == (2, "edge-worker-live")
        with pytest.raises(GraphConflictError, match="conflicted"):
            await work.retry(
                first,
                ProjectionJobFailureCode.DEPENDENCY_UNAVAILABLE,
                second_at + timedelta(seconds=5),
                second_at,
            )
        await work.retry(
            recovered,
            ProjectionJobFailureCode.DEPENDENCY_UNAVAILABLE,
            second_at + timedelta(seconds=5),
            second_at,
        )

        edge = MaterializedAssertionEdge.from_assertion(
            active,
            source_event_id=ACTIVATED_EVENT_ID,
            generation_id=GENERATION_ID,
            projected_at=NOW + timedelta(seconds=1),
        )
        finding = EdgeIntegrityFinding.create(
            EdgeIntegrityFindingKind.MISSING,
            GENERATION_ID,
            ASSERTION_ID,
            edge.projection_digest,
            None,
            second_at,
        )
        scope = _scope("graph.assertion.edge.integrity")
        journal = SqliteMaterializedEdgeIntegrityJournal(store)
        await journal.record(scope, (finding,))
        await journal.record(scope, (finding,))
        repaired_at = second_at + timedelta(seconds=1)
        await journal.repaired(scope, finding, repaired_at)
        await journal.repaired(scope, finding, repaired_at)
        with pytest.raises(GraphConflictError, match="conflicted"):
            await journal.repaired(scope, finding, repaired_at + timedelta(seconds=1))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_projection_snapshot_fails_closed_for_missing_or_corrupt_lifecycle(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _activate(store)
        scope = _scope("graph.assertion.edge.integrity")
        async with store.engine.connect() as connection:
            assert (
                await sqlite_assertions.load_assertion_projection_snapshot(
                    connection,
                    scope,
                    "018f0000-0000-7000-8000-000000000199",
                )
                is None
            )
        async with store.engine.begin() as connection:
            await connection.exec_driver_sql("DROP TRIGGER assertion_lifecycle_no_update")
            await connection.execute(
                text(
                    "UPDATE assertion_lifecycle SET event_digest=:digest "
                    "WHERE assertion_id=:assertion"
                ),
                {"digest": bytes(32), "assertion": ASSERTION_ID},
            )
        async with store.engine.connect() as connection:
            with pytest.raises(GraphIntegrityError, match="integrity"):
                await sqlite_assertions.load_assertion_projection_snapshot(
                    connection,
                    scope,
                    ASSERTION_ID,
                )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_projection_snapshot_scan_is_bounded_and_rejects_disappearing_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _activate(store)
        scope = _scope("graph.assertion.edge.integrity")
        monkeypatch.setattr(sqlite_assertions, "_MAX_PROJECTION_ASSERTIONS", 0)
        async with store.engine.connect() as connection:
            with pytest.raises(GraphIntegrityError, match="integrity"):
                await sqlite_assertions.list_assertion_projection_snapshots(connection, scope)

        monkeypatch.setattr(sqlite_assertions, "_MAX_PROJECTION_ASSERTIONS", 10_000)

        async def _missing_snapshot(
            *_args: object,
            **_kwargs: object,
        ) -> None:
            return None

        monkeypatch.setattr(
            sqlite_assertions,
            "load_assertion_projection_snapshot",
            _missing_snapshot,
        )
        async with store.engine.connect() as connection:
            with pytest.raises(GraphIntegrityError, match="integrity"):
                await sqlite_assertions.list_assertion_projection_snapshots(connection, scope)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_projection_enqueue_requires_the_bound_authorized_operation(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        active = await _activate(store)
        event = AssertionLifecycleEvent.create(
            event_id="018f0000-0000-7000-8000-000000000198",
            operation_id="missing-authorized-operation",
            assertion=active,
            event_type=AssertionEventType.ACTIVATED,
            occurred_at=NOW + timedelta(seconds=3),
        )
        async with store.engine.begin() as connection:
            with pytest.raises(GraphIntegrityError, match="integrity"):
                await sqlite_assertions._insert_domain_event(  # pyright: ignore[reportPrivateUsage]
                    connection,
                    active,
                    event,
                    2,
                )
    finally:
        await store.close()


async def _activate(store: SqliteCoreStore) -> Assertion:
    await seed_roots(store)
    await _seed_sources(store)
    factory = SqliteAssertionRepositoryFactory(store)
    await factory.evidence_catalog(_scope("graph.assertion.evidence.register")).register(
        AssertionEvidenceReference(
            PROMPT_EVIDENCE_ID,
            PROMPT_EVENT_ID,
            EvidenceKind.USER_STATEMENT,
        ),
        NOW,
    )
    candidate = _candidate()
    await ProposeAssertionHandler(factory).execute(
        ProposeAssertionCommand(
            "assertion-propose-gra003",
            _scope("graph.assertion.propose"),
            candidate,
        )
    )
    return await ActivateAssertionHandler(factory).execute(
        ActivateAssertionCommand(
            "assertion-activate-gra003",
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
            _scope("graph.assertion.activate"),
            NOW + timedelta(seconds=1),
        )
    )


async def _set_generation(store: SqliteCoreStore) -> None:
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO active_projection_generations "
                "(brain_id,projection_type,generation_id,activated_at,version,schema_version) "
                "VALUES (:brain,'graph',:generation,:at,1,1)"
            ),
            {
                "brain": BRAIN_ID,
                "generation": bytes.fromhex(GENERATION_ID),
                "at": round(NOW.timestamp() * 1_000_000),
            },
        )


class _FixedClock:
    def __init__(self, value: datetime) -> None:
        self._value = value

    def now(self) -> datetime:
        return self._value
