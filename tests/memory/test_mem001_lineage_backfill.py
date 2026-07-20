"""MEM-001 authenticated historical task-lineage backfill acceptance tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import SqliteAgentEventUnitOfWork
from agentmemory.ingestion.adapters.outbound.sqlite_schema_evolution import (
    SqliteCanonicalEventSourceReader,
)
from agentmemory.ingestion.application.append_agent_event import (
    AppendAgentEventCommand,
    AppendAgentEventHandler,
)
from agentmemory.ingestion.domain.agent_event import (
    AgentEventData,
    CaptureCapability,
    EventFamily,
    ResolvedAgentEventIdentity,
)
from agentmemory.ingestion.domain.capture import AdmittedAgentEvent
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.memory.adapters.outbound.sqlite_lineage_backfill import (
    SqliteTaskLineageBackfillRepository,
)
from agentmemory.memory.application.lineage_backfill import TaskLineageBackfillWorker
from agentmemory.memory.domain.errors import MemoryDependencyError, MemoryIntegrityError
from agentmemory.memory.domain.lineage_backfill import TaskLineageBackfillState
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    NOW,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    event,
    privacy_result,
)
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority
from tests.memory.test_mem001_consolidation_domain import TASK_ID

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.ports import AgentEventUnitOfWork

_EVENT_ONE = "018f0000-0000-7000-8000-000000000501"
_EVENT_TWO = "018f0000-0000-7000-8000-000000000502"
_EVENT_THREE = "018f0000-0000-7000-8000-000000000503"
_EVENT_LATE = "018f0000-0000-7000-8000-000000000504"


@dataclass(frozen=True, slots=True)
class _PreMem001UnitOfWorkFactory:
    store: SqliteCoreStore
    clock: FixedClock

    def __call__(self) -> AgentEventUnitOfWork:
        return SqliteAgentEventUnitOfWork(
            self.store,
            self.clock,
            record_task_lineage=False,
        )


class _UnavailableReader:
    async def read(self, event_id: str) -> bytes:
        del event_id
        raise IngestionDependencyError


def _database_config(database: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def _store(database: Path) -> SqliteCoreStore:
    return SqliteCoreStore.create(
        database,
        SqliteRuntimePolicy((3, 0, 0), frozenset()),
    )


def _task_event(event_id: str, family: EventFamily, sequence: int) -> AgentEvent:
    source = event(event_id=event_id, sequence=sequence)
    payload = f'{{"event":"{family.value}"}}'.encode()
    return replace(
        source,
        event_type=family,
        subject=f"task/{TASK_ID}",
        occurred_at=NOW + timedelta(seconds=sequence),
        dataschema=family.dataschema,
        provenance=replace(source.provenance, task_id=TASK_ID),
        capture_capabilities=(CaptureCapability.TASK_LIFECYCLE,),
        payload=AgentEventData(payload, hashlib.sha256(payload).hexdigest()),
    )


async def _append(
    store: SqliteCoreStore,
    key_file: Path,
    item: AgentEvent,
    *,
    legacy: bool,
) -> None:
    clock = FixedClock(NOW)
    keys = SqliteWrappedBrainKeyProvider(store, key_file, clock)
    factory = (
        _PreMem001UnitOfWorkFactory(store, clock)
        if legacy
        else lambda: SqliteAgentEventUnitOfWork(store, clock)
    )
    handler = AppendAgentEventHandler(
        CanonicalAgentEventEncoder(),
        AesGcmAgentEventEncryptor(keys),
        factory,
    )
    if item.payload is None or item.sequence is None:
        raise AssertionError
    admitted = AdmittedAgentEvent(
        item,
        ResolvedAgentEventIdentity(
            BRAIN_ID,
            PRINCIPAL_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            None,
        ),
        NOW + timedelta(seconds=item.sequence + 10),
        0,
        privacy_result(item.payload.value),
    )
    await handler.execute(AppendAgentEventCommand(admitted))


def _repository(
    store: SqliteCoreStore,
    key_file: Path,
) -> SqliteTaskLineageBackfillRepository:
    keys = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
    return SqliteTaskLineageBackfillRepository(
        store,
        SqliteCanonicalEventSourceReader(store, keys),
        FixedClock(NOW + timedelta(minutes=1)),
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_backfill_resumes_a_pre_mem001_database_at_an_immutable_watermark(
    tmp_path: Path,
) -> None:
    database = tmp_path / "historical.sqlite3"
    configuration = _database_config(database)
    command.upgrade(configuration, "0014_ing006_schema_evolution")
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    store = _store(database)
    try:
        await seed_capture_authority(store)
        await _append(
            store,
            key_file,
            _task_event(_EVENT_ONE, EventFamily.TASK_CHECKPOINTED, 1),
            legacy=True,
        )
        await _append(store, key_file, event(event_id=_EVENT_TWO, sequence=2), legacy=True)
        await _append(
            store,
            key_file,
            _task_event(_EVENT_THREE, EventFamily.TASK_COMPLETED, 3),
            legacy=True,
        )
    finally:
        await store.close()

    command.upgrade(configuration, "0015_mem001_memory_consolidation")
    store = _store(database)
    try:
        repository = _repository(store, key_file)
        worker = TaskLineageBackfillWorker(repository, page_size=1)
        assert not await worker.run_page()
        progress = await repository.start_or_resume()
        assert progress.scanned == 1
        interrupted = await repository.interrupt(progress, "interrupted")
        assert interrupted.state is TaskLineageBackfillState.INTERRUPTED

        # A new capture is indexed by the write path but is outside the immutable
        # historical watermark captured by the first backfill page.
        await _append(
            store,
            key_file,
            _task_event(_EVENT_LATE, EventFamily.TASK_COMPLETED, 4),
            legacy=False,
        )
        while not await worker.run_page():
            pass

        completed = await repository.start_or_resume()
        assert completed.state is TaskLineageBackfillState.COMPLETED
        assert (completed.scanned, completed.indexed, completed.ignored, completed.total) == (
            3,
            2,
            1,
            3,
        )
        async with store.engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        text(
                            "SELECT l.event_id,l.created_at,s.created_at AS source_created_at "
                            "FROM event_task_lineage l JOIN event_schema_sources s "
                            "ON s.event_id=l.event_id ORDER BY l.event_id"
                        )
                    )
                )
                .mappings()
                .all()
            )
            assert [str(row["event_id"]) for row in rows] == [
                _EVENT_ONE,
                _EVENT_THREE,
                _EVENT_LATE,
            ]
            assert all(row["created_at"] == row["source_created_at"] for row in rows)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_empty_backfill_completes_once_without_fabricating_lineage(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        progress = await _repository(store, key_file).start_or_resume()
        assert await TaskLineageBackfillWorker(
            _repository(store, key_file),
            page_size=1,
        ).run_page()
        completed = await _repository(store, key_file).start_or_resume()
        assert progress.total == 0
        assert completed.state is TaskLineageBackfillState.COMPLETED
        async with store.engine.connect() as connection:
            count = (
                await connection.execute(text("SELECT COUNT(*) FROM event_task_lineage"))
            ).scalar_one()
            assert count == 0
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_backfill_fails_closed_on_existing_lineage_divergence(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _append(
            store,
            key_file,
            _task_event(_EVENT_ONE, EventFamily.TASK_COMPLETED, 1),
            legacy=False,
        )
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE event_task_lineage SET task_id="
                    "'018f0000-0000-7000-8000-000000000999' WHERE event_id=:event"
                ),
                {"event": _EVENT_ONE},
            )
        repository = _repository(store, key_file)
        with pytest.raises(MemoryIntegrityError):
            await TaskLineageBackfillWorker(repository, page_size=1).run_page()
        progress = await repository.start_or_resume()
        assert progress.state is TaskLineageBackfillState.INTERRUPTED
        assert progress.last_error_code == "integrity_violation"
        # Integrity evidence remains administratively blocked across restart.
        with pytest.raises(MemoryIntegrityError):
            await TaskLineageBackfillWorker(repository, page_size=1).run_page()
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_backfill_retains_zero_progress_on_source_authentication_failure(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _append(
            store,
            key_file,
            _task_event(_EVENT_ONE, EventFamily.TASK_COMPLETED, 1),
            legacy=False,
        )
        async with store.engine.begin() as connection:
            await connection.execute(text("DELETE FROM event_task_lineage"))
            await connection.execute(
                text(
                    "UPDATE event_schema_sources SET original_canonical_sha256=zeroblob(32) "
                    "WHERE event_id=:event"
                ),
                {"event": _EVENT_ONE},
            )
        repository = _repository(store, key_file)
        with pytest.raises(MemoryIntegrityError):
            await TaskLineageBackfillWorker(repository, page_size=1).run_page()
        async with store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT state,scanned,indexed,last_error_code "
                            "FROM memory_task_lineage_backfills"
                        )
                    )
                )
                .mappings()
                .one()
            )
        assert str(row["state"]) == "interrupted"
        assert int(row["scanned"]) == 0
        assert int(row["indexed"]) == 0
        assert str(row["last_error_code"]) == "integrity_violation"
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_backfill_records_dependency_interruption_for_automatic_resume(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _append(
            store,
            key_file,
            _task_event(_EVENT_ONE, EventFamily.TASK_COMPLETED, 1),
            legacy=False,
        )
        repository = SqliteTaskLineageBackfillRepository(
            store,
            _UnavailableReader(),
            FixedClock(NOW),
        )
        with pytest.raises(MemoryDependencyError):
            await TaskLineageBackfillWorker(repository, page_size=1).run_page()
        async with store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT state,scanned,indexed,last_error_code "
                            "FROM memory_task_lineage_backfills"
                        )
                    )
                )
                .mappings()
                .one()
            )
        assert str(row["state"]) == "interrupted"
        assert int(row["scanned"]) == 0
        assert int(row["indexed"]) == 0
        assert str(row["last_error_code"]) == "dependency_unavailable"
    finally:
        await store.close()
