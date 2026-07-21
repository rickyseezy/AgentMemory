"""MEM-005 SQLite lifecycle, scheduler, deletion, and non-disclosure acceptance tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.sqlite_backpressure import (
    LocalDiskSpaceProbe,
    SqliteJobSchedulerRepository,
)
from agentmemory.memory.adapters.outbound.memory_deletion import MemoryDeletionExecutor
from agentmemory.memory.adapters.outbound.sqlite_lifecycle import (
    SqliteMemoryLifecycleRepository,
    SqliteMemoryLifecycleUnitOfWorkFactory,
)
from agentmemory.memory.adapters.outbound.sqlite_provenance import SqliteMemoryRepository
from agentmemory.memory.application.memory_lifecycle import (
    ArchiveMemoryCommand,
    ArchiveMemoryHandler,
    ForgetMemoryCommand,
    ForgetMemoryHandler,
    MemoryExpiryScheduler,
    PinMemoryCommand,
    PinMemoryHandler,
    SetMemoryExpiryCommand,
    SetMemoryExpiryHandler,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
)
from agentmemory.memory.domain.lifecycle import MemoryRecallState
from agentmemory.operations.adapters.outbound.sqlite_projection_rebuild import (
    SqliteProjectionRebuildAdapter,
)
from agentmemory.operations.application.commands.projection_rebuild import (
    ProjectionRebuilder,
    StartProjectionRebuildHandler,
)
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionType,
    StartProjectionRebuildCommand,
)
from agentmemory.operations.domain.value_objects import Uuid7Id
from tests.core.support import migrated_store, write_secret
from tests.core.test_projection_rebuild_sqlite import (
    _manifest,  # pyright: ignore[reportPrivateUsage]
)
from tests.memory.test_mem001_consolidation_domain import NOW
from tests.memory.test_mem002_sqlite_repository import (
    _access,  # pyright: ignore[reportPrivateUsage]
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from neo4j import AsyncDriver

    from agentmemory.memory.domain.consolidation import ConsolidationCommit
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

OPERATION_ID = "018f0000-0000-7000-8000-000000000651"
SECOND_OPERATION_ID = "018f0000-0000-7000-8000-000000000652"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000653"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000654"
WRONG_ID = "018f0000-0000-7000-8000-000000000999"


@dataclass(frozen=True, slots=True)
class _Clock:
    value: datetime = NOW + timedelta(seconds=10)

    def now(self) -> datetime:
        return self.value


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pin_is_atomic_audited_and_exactly_replayable(tmp_path: Path) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        repository = SqliteMemoryLifecycleRepository(store)
        handler = PinMemoryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        )
        command = _pin(commit)

        first, replay = await asyncio.gather(handler.execute(command), handler.execute(command))

        async with store.engine.connect() as connection:
            state = (
                await connection.execute(
                    text(
                        "SELECT recall_state,pinned,aggregate_version FROM memory_lifecycle "
                        "WHERE memory_id=:memory"
                    ),
                    {"memory": command.memory_id},
                )
            ).one()
            operation_count = int(
                (
                    await connection.execute(
                        text("SELECT COUNT(*) FROM memory_lifecycle_operations")
                    )
                ).scalar_one()
            )
            event_count = int(
                (
                    await connection.execute(text("SELECT COUNT(*) FROM memory_lifecycle_events"))
                ).scalar_one()
            )
            event_type = (
                await connection.execute(text("SELECT event_type FROM memory_lifecycle_events"))
            ).scalar_one()
            audit = (
                await connection.execute(
                    text("SELECT action FROM audit_events WHERE action='memory.pin'")
                )
            ).scalar_one()
            topic = (
                await connection.execute(
                    text("SELECT topic FROM outbox_messages WHERE topic='memory.pinned.v1'")
                )
            ).scalar_one()
    finally:
        await store.close()

    assert first == replay
    assert state == ("active", 1, 2)
    assert (operation_count, event_count) == (1, 1)
    assert event_type == "MemoryPinned"
    assert audit == "memory.pin"
    assert topic == "memory.pinned.v1"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_archive_remains_historical_but_cannot_be_corrected(tmp_path: Path) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
        repository = SqliteMemoryLifecycleRepository(store)
        result = await ArchiveMemoryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        ).execute(_archive(commit))
        historical = await SqliteMemoryRepository(store).explain_authorized(_access(commit))
        state = await repository.load_authorized(
            memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            _Clock().now(),
        )
    finally:
        await store.close()

    assert result.recall_state is MemoryRecallState.ARCHIVED
    assert historical is not None
    assert state is not None
    assert state.recall_state is MemoryRecallState.ARCHIVED


@pytest.mark.asyncio
@pytest.mark.integration
async def test_scheduler_expires_at_exact_boundary_through_atomic_event_path(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        repository = SqliteMemoryLifecycleRepository(store)
        expires_at = NOW + timedelta(seconds=20)
        await SetMemoryExpiryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        ).execute(_expiry(commit, expires_at))
        scheduler = MemoryExpiryScheduler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(expires_at),
        )

        outcome = await scheduler.run_once()
        state = await repository.load_authorized(
            commit.memories[0].memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            expires_at,
        )
    finally:
        await store.close()

    assert outcome.expired == 1
    assert state is not None
    assert state.recall_state is MemoryRecallState.EXPIRED


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
async def test_forget_immediately_hides_memory_and_starts_complete_deletion_saga(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
        repository = SqliteMemoryLifecycleRepository(store)
        await ForgetMemoryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        ).execute(_forget(commit))

        visible = await repository.load_authorized(
            memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            _Clock().now(),
        )
        explanation = await SqliteMemoryRepository(store).explain_authorized(_access(commit))
        async with store.engine.connect() as connection:
            state = (
                await connection.execute(
                    text("SELECT recall_state FROM memory_lifecycle WHERE memory_id=:memory"),
                    {"memory": memory_id},
                )
            ).scalar_one()
            tombstones = int(
                (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM deletion_tombstones "
                            "WHERE target_type IN ('memory','memory_assertion')"
                        )
                    )
                ).scalar_one()
            )
            job = (
                await connection.execute(
                    text("SELECT kind,state FROM jobs WHERE kind='governance.memory_deletion'")
                )
            ).one()
            manifest = (
                await connection.execute(
                    text("SELECT state,dependency_types_json FROM memory_deletion_manifests")
                )
            ).one()
    finally:
        await store.close()

    assert visible is None
    assert explanation is None
    assert state == "forgotten"
    assert tombstones >= 2
    assert job == ("governance.memory_deletion", "queued")
    assert manifest[0] == "tombstoned"
    assert '"graph"' in manifest[1]
    assert '"vectors"' in manifest[1]


@dataclass(slots=True)
class _GraphDeletionDriver:
    calls: int = 0

    async def execute_query(
        self,
        query: str | Query,
        **parameters: object,
    ) -> tuple[list[dict[str, object]], None, None]:
        del parameters
        self.calls += 1
        query_text = query.text if isinstance(query, Query) else query
        if "RETURN count(record) AS remaining" in query_text:
            return ([{"remaining": 0}], None, None)
        return ([], None, None)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
async def test_deletion_executor_verifies_and_seals_all_derived_targets_idempotently(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        repository = SqliteMemoryLifecycleRepository(store)
        await ForgetMemoryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        ).execute(_forget(commit))
        async with store.engine.connect() as connection:
            job_id = (
                await connection.execute(text("SELECT job_id FROM memory_deletion_manifests"))
            ).scalar_one()
        scheduled = await SqliteJobSchedulerRepository(
            store,
            LocalDiskSpaceProbe(tmp_path),
        ).get(str(job_id))
        assert scheduled is not None
        driver = _GraphDeletionDriver()
        executor = MemoryDeletionExecutor(
            store,
            cast("AsyncDriver", driver),
            "agentmemory",
            _Clock(),
        )

        first = await executor.execute(scheduled)
        replay = await executor.execute(scheduled)

        async with store.engine.connect() as connection:
            manifest_state = (
                await connection.execute(text("SELECT state FROM memory_deletion_manifests"))
            ).scalar_one()
            target_count = (
                await connection.execute(text("SELECT COUNT(*) FROM memory_deletion_targets"))
            ).scalar_one()
            incomplete = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM deletion_tombstones d "
                        "JOIN memory_deletion_targets t ON t.tombstone_id=d.id "
                        "WHERE d.purge_state<>'completed'"
                    )
                )
            ).scalar_one()
    finally:
        await store.close()

    assert first == replay
    assert len(first) == 64
    assert manifest_state == "completed"
    assert target_count >= 2
    assert incomplete == 0
    assert driver.calls == 2


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
async def test_forgotten_memory_is_never_resurrected_by_projection_rebuild(tmp_path: Path) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
        repository = SqliteMemoryLifecycleRepository(store)
        await ForgetMemoryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        ).execute(_forget(commit))
        adapter = SqliteProjectionRebuildAdapter(store, _Clock())
        command = StartProjectionRebuildCommand(
            operation_id="mem005-non-resurrection",
            brain_id=Uuid7Id(commit.scope.brain_id),
            actor_id=Uuid7Id(commit.actor_id),
            grant_id=Uuid7Id(commit.grant_id),
            projection_type=ProjectionType.GRAPH,
            manifest=_manifest("mem005"),
        )
        await StartProjectionRebuildHandler(adapter, adapter, adapter).execute(command)
        rebuilt = await ProjectionRebuilder(adapter, adapter, adapter, adapter).execute(
            command.operation_id
        )
        async with store.engine.connect() as connection:
            resurrected = (
                await connection.execute(
                    text("SELECT COUNT(*) FROM projection_records WHERE stable_id=:memory"),
                    {"memory": memory_id},
                )
            ).scalar_one()
    finally:
        await store.close()

    assert rebuilt.skipped_tombstones >= 2
    assert resurrected == 0


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_lifecycle_authorization_hides_wrong_coordinates(tmp_path: Path) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        base = _pin(commit)
        repository = SqliteMemoryLifecycleRepository(store)
        handler = PinMemoryHandler(
            repository,
            SqliteMemoryLifecycleUnitOfWorkFactory(store),
            _Clock(),
        )
        for command in (
            replace(base, actor_id=WRONG_ID),
            replace(base, grant_id=WRONG_ID),
            replace(base, brain_id=WRONG_ID),
        ):
            with pytest.raises(MemoryEvidenceNotFoundError):
                await handler.execute(command)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.resilience
async def test_lifecycle_failure_rolls_back_state_receipt_event_and_outbox(tmp_path: Path) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        async with store.write_lock, store.engine.begin() as connection:
            await connection.exec_driver_sql(
                "CREATE TRIGGER fail_memory_pin_audit BEFORE INSERT ON audit_events "
                "WHEN NEW.action='memory.pin' BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
        repository = SqliteMemoryLifecycleRepository(store)
        with pytest.raises(MemoryConflictError):
            await PinMemoryHandler(
                repository,
                SqliteMemoryLifecycleUnitOfWorkFactory(store),
                _Clock(),
            ).execute(_pin(commit))
        async with store.engine.connect() as connection:
            state = (
                await connection.execute(
                    text("SELECT pinned,aggregate_version FROM memory_lifecycle")
                )
            ).one()
            operations = int(
                (
                    await connection.execute(
                        text("SELECT COUNT(*) FROM memory_lifecycle_operations")
                    )
                ).scalar_one()
            )
            events = int(
                (
                    await connection.execute(text("SELECT COUNT(*) FROM memory_lifecycle_events"))
                ).scalar_one()
            )
    finally:
        await store.close()

    assert state == (0, 1)
    assert operations == 0
    assert events == 0


def _store(tmp_path: Path) -> tuple[SqliteCoreStore, Path]:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    return migrated_store(tmp_path), key_file


def _coordinates(
    commit: ConsolidationCommit,
) -> tuple[str, str, str, str, str, str, str, int, datetime, datetime]:
    return (
        OPERATION_ID,
        commit.actor_id,
        commit.grant_id,
        commit.scope.brain_id,
        CORRELATION_ID,
        CAUSATION_ID,
        commit.memories[0].memory_id,
        1,
        NOW + timedelta(seconds=5),
        NOW + timedelta(minutes=1),
    )


def _pin(commit: ConsolidationCommit) -> PinMemoryCommand:
    return PinMemoryCommand(*_coordinates(commit))


def _archive(commit: ConsolidationCommit) -> ArchiveMemoryCommand:
    return ArchiveMemoryCommand(*_coordinates(commit))


def _expiry(commit: ConsolidationCommit, expires_at: datetime) -> SetMemoryExpiryCommand:
    return SetMemoryExpiryCommand(
        *_coordinates(commit),
        expires_at=expires_at,
    )


def _forget(commit: ConsolidationCommit) -> ForgetMemoryCommand:
    return ForgetMemoryCommand(
        *_coordinates(commit),
        confirmation="forget-memory",
    )
