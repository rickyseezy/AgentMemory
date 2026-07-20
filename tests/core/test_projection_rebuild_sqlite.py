"""PF-002 real SQLite replay, resume, deletion, and activation integration tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.operations.adapters.outbound.sqlite_projection_rebuild import (
    SqliteProjectionRebuildAdapter,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.application.commands.projection_rebuild import (
    ProjectionRebuilder,
    StartProjectionRebuildHandler,
)
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionType,
    RebuildManifest,
    RebuildState,
    StartProjectionRebuildCommand,
    canonical_json,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    OWNER_ID,
    FixedClock,
    bootstrap_request,
    digest,
    migrated_store,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


def _manifest(seed: str = "one") -> RebuildManifest:
    return RebuildManifest(
        application_build=f"1.0.0+{seed}",
        relational_schema="0002_pf002_projection_rebuild",
        graph_schema="0002_pf002_projection_schema",
        parser_version="parser@1",
        extractor_version="extractor@1",
        provider_versions=("provider@1",),
        embedding_space="embedding@1",
        implementation_fingerprint=digest(f"implementation-{seed}"),
    )


def _command(operation: str, seed: str = "one") -> StartProjectionRebuildCommand:
    return StartProjectionRebuildCommand(
        operation_id=operation,
        brain_id=Uuid7Id(BRAIN_ID),
        actor_id=Uuid7Id(OWNER_ID),
        grant_id=Uuid7Id(GRANT_ID),
        projection_type=ProjectionType.GRAPH,
        manifest=_manifest(seed),
    )


async def _seed_event(
    store: SqliteCoreStore,
    sequence: int,
    *,
    missing: str | None = None,
) -> None:
    payload = canonical_json({"kind": "assertion", "sequence": sequence})
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO domain_events "
                "(sequence,event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,"
                "payload_json,payload_hash,source_digest,missing_dependency,"
                "occurred_at,recorded_at) "
                "VALUES (:sequence,:event,:brain,'graph',:stable,'event',:target,:payload,"
                ":payload_hash,:source_digest,:missing,1,1)"
            ),
            {
                "sequence": sequence,
                "event": f"event-{sequence}",
                "brain": BRAIN_ID,
                "stable": f"assertion-{sequence}",
                "target": bytes.fromhex(digest(f"target-{sequence}").value),
                "payload": payload,
                "payload_hash": bytes.fromhex(Sha256Digest.from_bytes(payload.encode()).value),
                "source_digest": bytes.fromhex(digest(f"source-{sequence}").value),
                "missing": missing,
            },
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_rebuild_is_deterministic_and_activation_is_compare_and_swap(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    clock = FixedClock()
    try:
        await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, clock)).execute(
            bootstrap_request()
        )
        await _seed_event(store, 1)
        await _seed_event(store, 2)
        adapter = SqliteProjectionRebuildAdapter(store, clock)
        starter = StartProjectionRebuildHandler(adapter, adapter, adapter)
        first = await starter.execute(_command("rebuild-a", "a"))
        second = await starter.execute(_command("rebuild-b", "b"))
        assert first.active_generation_at_start is None
        assert second.active_generation_at_start is None
        active = await ProjectionRebuilder(adapter, adapter, adapter, adapter).execute("rebuild-a")
        superseded = await ProjectionRebuilder(adapter, adapter, adapter, adapter).execute(
            "rebuild-b"
        )
        assert active.state is RebuildState.ACTIVE
        assert superseded.state is RebuildState.SUPERSEDED
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM projection_records WHERE brain_id=:brain "
                        "AND projection_type='graph'"
                    ),
                    {"brain": BRAIN_ID},
                )
            ).scalar_one() == 4
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
@pytest.mark.resilience
async def test_sqlite_rebuild_skips_tombstone_and_resumes_missing_dependency(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    clock = FixedClock()
    try:
        await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, clock)).execute(
            bootstrap_request()
        )
        await _seed_event(store, 1)
        await _seed_event(store, 2, missing="artifact_unavailable")
        await _seed_event(store, 3, missing="provider_unavailable")
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO deletion_tombstones "
                    "(id,brain_id,target_type,target_id_hash,effective_at,purge_state,"
                    "restore_guard_version,created_at) VALUES "
                    "('delete-1',:brain,'event',:target,1,'completed',1,1)"
                ),
                {
                    "brain": BRAIN_ID,
                    "target": bytes.fromhex(digest("target-1").value),
                },
            )
        adapter = SqliteProjectionRebuildAdapter(store, clock)
        await StartProjectionRebuildHandler(adapter, adapter, adapter).execute(
            _command("rebuild-resume")
        )
        first = await ProjectionRebuilder(adapter, adapter, adapter, adapter).execute(
            "rebuild-resume"
        )
        assert first.state is RebuildState.PARTIAL
        assert first.cursor == 1
        assert first.skipped_tombstones == 1
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE domain_events SET missing_dependency=NULL WHERE event_id='event-2'")
            )
        second = await ProjectionRebuilder(adapter, adapter, adapter, adapter).execute(
            "rebuild-resume"
        )
        assert second.state is RebuildState.PARTIAL
        assert second.cursor == 2
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE domain_events SET missing_dependency=NULL WHERE event_id='event-3'")
            )
        resumed = await ProjectionRebuilder(adapter, adapter, adapter, adapter).execute(
            "rebuild-resume"
        )
        assert resumed.state is RebuildState.ACTIVE
        assert resumed.record_count == 2
        async with store.engine.connect() as connection:
            audit_actions = (
                (
                    await connection.execute(
                        text(
                            "SELECT action FROM audit_events "
                            "WHERE action LIKE 'projection.rebuild.%' "
                            "ORDER BY sequence"
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert audit_actions.count("projection.rebuild.partial") == 2
        assert audit_actions[-1] == "projection.rebuild.active"
    finally:
        await store.close()
