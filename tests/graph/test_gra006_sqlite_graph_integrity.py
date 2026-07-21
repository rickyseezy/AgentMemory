"""GRA-006 SQLite migration cursor and integrity repair journal tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.graph.adapters.outbound.sqlite_graph_integrity import (
    SqliteGraphIntegrityJournal,
    SqliteGraphMigrationRepository,
)
from agentmemory.graph.domain.errors import GraphConflictError
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityObservation,
    GraphIntegrityPolicy,
    GraphMigrationBatch,
    GraphMigrationRun,
    GraphProjectionKind,
    GraphRepairPolicy,
)
from tests.core.support import BRAIN_ID, FixedClock, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    NOW,
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra006_graph_integrity_domain import (
    CANONICAL,
    CHECKSUM,
    CURRENT_GENERATION,
)
from tests.identity.test_checkout_observation_sqlite import (
    PROJECT_ID,
    REPOSITORY_ID,
    _seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

PROJECTION = "019f54cc-1111-7111-8111-111111111111"


@pytest.mark.asyncio
async def test_sqlite_migration_snapshots_are_resumable_append_only_and_exact(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    await _seed_roots(store)
    try:
        scope = _scope("graph.integrity.migrate")
        repository = SqliteGraphMigrationRepository(store, FixedClock(NOW))
        run = GraphMigrationRun.start(
            operation_id="graph-migration-sqlite-1",
            brain_id=BRAIN_ID,
            migration_id="gra006-backfill-v1",
            migration_checksum=CHECKSUM,
            source_watermark=4,
            batch_size=4,
            started_at=NOW,
        )
        assert await repository.start(scope, run) == run
        assert await repository.start(scope, run) == run
        checkpoint = await repository.checkpoint(scope, run, GraphMigrationBatch(4, 4, 3, 1), NOW)
        validating = await repository.save(scope, checkpoint.begin_validation(NOW))
        completed = await repository.save(scope, validating.complete(NOW))
        assert await repository.get(scope, run.operation_id) == completed

        async with store.engine.connect() as connection:
            count = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM graph_migration_snapshots "
                        "WHERE operation_id=:operation"
                    ),
                    {"operation": run.operation_id},
                )
            ).scalar_one()
            assert count == 4
        with pytest.raises(GraphConflictError):
            await repository.start(
                scope,
                GraphMigrationRun.start(
                    operation_id=run.operation_id,
                    brain_id=BRAIN_ID,
                    migration_id="gra006-backfill-v1",
                    migration_checksum="e" * 64,
                    source_watermark=4,
                    batch_size=4,
                    started_at=NOW,
                ),
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_findings_and_repair_receipts_are_exact_and_immutable(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    await _seed_roots(store)
    try:
        journal = SqliteGraphIntegrityJournal(store, FixedClock(NOW))
        finding = GraphIntegrityPolicy.evaluate(
            (
                GraphIntegrityObservation(
                    projection_id=PROJECTION,
                    projection_kind=GraphProjectionKind.EDGE,
                    brain_id=BRAIN_ID,
                    project_id=PROJECT_ID.value,
                    repository_id=REPOSITORY_ID.value,
                    canonical_id=None,
                    canonical_supported=True,
                    temporal_valid=True,
                    scope_matches=True,
                    generation_id=CURRENT_GENERATION,
                    projection_digest="d" * 64,
                ),
            ),
            CURRENT_GENERATION,
            NOW,
        )[0]
        validate_scope = _scope("graph.integrity.validate")
        assert await journal.record(validate_scope, (finding,)) == (finding,)
        assert await journal.record(validate_scope, (finding,)) == (finding,)

        repair_scope = _scope("graph.integrity.repair")
        assert await journal.get(repair_scope, finding.id) == finding
        plan = GraphRepairPolicy.plan(finding)
        await journal.repaired(repair_scope, "graph-repair-sqlite-1", finding, plan, NOW)
        await journal.repaired(repair_scope, "graph-repair-sqlite-1", finding, plan, NOW)
        with pytest.raises(GraphConflictError):
            await journal.repaired(
                repair_scope, "graph-repair-sqlite-divergent", finding, plan, NOW
            )

        async with store.engine.connect() as connection:
            audit = (
                (
                    await connection.execute(
                        text(
                            "SELECT action,target_ref,before_hash,after_hash FROM audit_events "
                            "WHERE idempotency_key='graph-integrity-repair:graph-repair-sqlite-1'"
                        )
                    )
                )
                .mappings()
                .one()
            )
            assert audit["action"] == "graph.integrity.repair"
            assert audit["target_ref"] == finding.id
            assert bytes(audit["before_hash"]).hex() == finding.projection_digest
            assert len(bytes(audit["after_hash"])) == 32

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError):
                await connection.execute(
                    text(
                        "UPDATE graph_integrity_findings SET canonical_id=:canonical "
                        "WHERE finding_id=:finding"
                    ),
                    {"canonical": CANONICAL, "finding": finding.id},
                )
    finally:
        await store.close()
