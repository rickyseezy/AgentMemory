"""MEM-002 canonical SQLite repository and evidence-resolution tests."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.memory.adapters.outbound.sqlite_consolidation import (
    SqliteMemoryConsolidationUnitOfWorkFactory,
)
from agentmemory.memory.adapters.outbound.sqlite_provenance import SqliteMemoryRepository
from agentmemory.memory.domain.errors import MemoryIntegrityError
from agentmemory.memory.domain.explanation import (
    EvidenceAvailability,
    MemoryExplanationAccess,
)
from tests.core.support import migrated_store, write_secret
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority
from tests.memory.test_mem001_consolidation_domain import EVENT_ONE, EVENT_TWO, NOW
from tests.memory.test_mem001_sqlite_boundaries import (
    _database_commit,  # pyright: ignore[reportPrivateUsage]
)
from tests.memory.test_mem001_sqlite_consolidation import (
    _capture_task_events,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.memory.domain.consolidation import ConsolidationCommit
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


async def _persist_memory(store: SqliteCoreStore, key_file: Path) -> ConsolidationCommit:
    await seed_capture_authority(store)
    await _capture_task_events(store, key_file)
    commit = await _database_commit(store, key_file)
    async with SqliteMemoryConsolidationUnitOfWorkFactory(store)() as unit_of_work:
        await unit_of_work.repository.add(commit)
        await unit_of_work.commit()
    return commit


def _access(
    commit: ConsolidationCommit,
    *,
    memory_id: str | None = None,
    brain_id: str | None = None,
    actor_id: str | None = None,
    grant_id: str | None = None,
) -> MemoryExplanationAccess:
    return MemoryExplanationAccess(
        memory_id or commit.memories[0].memory_id,
        brain_id or commit.scope.brain_id,
        actor_id or commit.actor_id,
        grant_id or commit.grant_id,
        NOW + timedelta(seconds=3),
        NOW,
        NOW + timedelta(seconds=2),
    )


@pytest.mark.asyncio
async def test_repository_round_trips_complete_canonical_provenance_and_temporal_state(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        explanation = await SqliteMemoryRepository(store).explain_authorized(_access(commit))
    finally:
        await store.close()

    assert explanation is not None
    assert explanation.memory == commit.memories[0]
    assert explanation.memory.provenance.actor_id == commit.actor_id
    assert explanation.memory.provenance.extractor_input_sha256 == commit.extractor_input_sha256
    assert explanation.effective
    assert tuple(item.event_id for item in explanation.evidence) == (EVENT_ONE, EVENT_TWO)
    assert all(item.availability is EvidenceAvailability.AVAILABLE for item in explanation.evidence)


@pytest.mark.asyncio
async def test_repository_hides_target_for_wrong_actor_grant_brain_or_scope(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        repository = SqliteMemoryRepository(store)
        wrong = "018f0000-0000-7000-8000-000000000999"
        requests = (
            _access(commit, memory_id=wrong),
            _access(commit, brain_id=wrong),
            _access(commit, actor_id=wrong),
            _access(commit, grant_id=wrong),
        )
        results = [await repository.explain_authorized(request) for request in requests]
    finally:
        await store.close()
    assert results == [None, None, None, None]


@pytest.mark.asyncio
async def test_repository_labels_tombstoned_evidence_purged_without_disclosing_metadata(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        async with store.write_lock, store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO deletion_tombstones "
                    "(id,brain_id,target_type,target_id_hash,effective_at,purge_state,"
                    "restore_guard_version,created_at,schema_version) VALUES "
                    "(:id,:brain,'agent_event',:target,:now,'completed',1,:now,1)"
                ),
                {
                    "id": "mem002-purged-evidence",
                    "brain": commit.scope.brain_id,
                    "target": hashlib.sha256(EVENT_TWO.encode()).digest(),
                    "now": round(NOW.timestamp() * 1_000_000),
                },
            )
        explanation = await SqliteMemoryRepository(store).explain_authorized(_access(commit))
    finally:
        await store.close()
    assert explanation is not None
    purged = explanation.evidence[1]
    assert purged.availability is EvidenceAvailability.PURGED
    assert purged.event_type is None
    assert purged.occurred_at is None
    assert purged.resource_uri is None


@pytest.mark.asyncio
async def test_repository_labels_broken_evidence_lineage_missing_without_inventing_metadata(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        async with store.write_lock, store.engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM event_task_lineage WHERE event_id=:event"),
                {"event": EVENT_TWO},
            )
        explanation = await SqliteMemoryRepository(store).explain_authorized(_access(commit))
    finally:
        await store.close()
    assert explanation is not None
    missing = explanation.evidence[1]
    assert missing.availability is EvidenceAvailability.MISSING
    assert missing.event_type is None
    assert missing.occurred_at is None
    assert missing.resource_uri is None


@pytest.mark.asyncio
async def test_consolidation_emits_hash_bound_memory_projected_graph_source(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory = commit.memories[0]
        async with store.engine.connect() as connection:
            event = (
                (
                    await connection.execute(
                        text("SELECT * FROM domain_events WHERE aggregate_id=:memory"),
                        {"memory": memory.memory_id},
                    )
                )
                .mappings()
                .one()
            )
    finally:
        await store.close()
    assert event["event_type"] == "MemoryProjected"
    assert event["projection_type"] == "graph"
    assert event["stable_id"] == memory.memory_id
    assert event["target_type"] == "memory"
    assert event["target_id_hash"] == hashlib.sha256(memory.memory_id.encode()).digest()
    assert event["payload_json"] == event["event_json"]
    assert event["payload_hash"] == hashlib.sha256(str(event["payload_json"]).encode()).digest()
    assert len(event["source_digest"]) == 32


@pytest.mark.asyncio
async def test_repository_rejects_noncanonical_or_cross_table_provenance_drift(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        async with store.write_lock, store.engine.begin() as connection:
            await connection.exec_driver_sql("DROP TRIGGER memory_revision_provenance_no_update")
            await connection.execute(
                text("UPDATE memory_revisions SET provenance_json=:value WHERE memory_id=:memory"),
                {
                    "value": '{"actor_id":"forged"}',
                    "memory": commit.memories[0].memory_id,
                },
            )
        with pytest.raises(MemoryIntegrityError):
            await SqliteMemoryRepository(store).explain_authorized(_access(commit))
    finally:
        await store.close()
