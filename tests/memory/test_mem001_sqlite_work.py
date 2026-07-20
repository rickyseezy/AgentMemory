# pyright: reportPrivateUsage=false
"""MEM-001 durable SQLite work discovery, retry, and lease integration tests."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_schema_evolution import (
    SqliteCanonicalEventSourceReader,
)
from agentmemory.memory.adapters.outbound.sqlite_lineage_backfill import (
    SqliteTaskLineageBackfillRepository,
)
from agentmemory.memory.adapters.outbound.sqlite_work import (
    SqliteMemoryConsolidationWorkRepository,
)
from agentmemory.memory.application.lineage_backfill import TaskLineageBackfillWorker
from agentmemory.memory.domain.work import (
    MemoryWorkErrorCode,
    MemoryWorkRetryPolicy,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority
from tests.memory.test_mem001_consolidation_domain import EVENT_ONE, EVENT_TWO, extractor
from tests.memory.test_mem001_sqlite_consolidation import _capture_task_events

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


async def _complete_backfill(store: SqliteCoreStore, key_file: Path) -> None:
    keys = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock())
    repository = SqliteTaskLineageBackfillRepository(
        store,
        SqliteCanonicalEventSourceReader(store, keys),
        FixedClock(),
    )
    worker = TaskLineageBackfillWorker(repository, page_size=1)
    while not await worker.run_page():
        pass


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_work_discovers_exact_snapshot_retries_and_completes_once(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    now = round((FixedClock().now() + timedelta(seconds=30)).timestamp() * 1_000_000)
    repository = SqliteMemoryConsolidationWorkRepository(store)
    try:
        await seed_capture_authority(store)
        assert await repository.claim_next(extractor(), "worker-1", now, now + 60_000_000) is None
        await _capture_task_events(store, key_file)
        await _complete_backfill(store, key_file)

        work = await repository.claim_next(extractor(), "worker-1", now, now + 60_000_000)
        assert work is not None
        assert work.terminal_event_id == EVENT_ONE
        assert work.attempts == 1

        decision = MemoryWorkRetryPolicy().decide(
            MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE, work.attempts
        )
        await repository.fail(
            work,
            "worker-1",
            MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE,
            decision,
            now + 1,
        )
        completed = await repository.claim_next(extractor(), "worker-1", now + 2, now + 60_000_002)
        assert completed is not None
        assert completed.terminal_event_id == EVENT_TWO
        await repository.succeed(completed, "worker-1", "e" * 64, now + 3)
        assert (
            await repository.claim_next(extractor(), "worker-1", now + 4, now + 60_000_004) is None
        )
        retried = await repository.claim_next(
            extractor(), "worker-1", now + 1_000_001, now + 61_000_001
        )
        assert retried is not None
        assert retried.idempotency_key == work.idempotency_key
        assert retried.attempts == 2
        await repository.succeed(retried, "worker-1", "f" * 64, now + 1_000_002)
        assert (
            await repository.claim_next(extractor(), "worker-1", now + 1_000_003, now + 61_000_003)
            is None
        )

        async with store.engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        text(
                            "SELECT state,attempts,last_error_code,result_sha256 "
                            "FROM memory_consolidation_work"
                        )
                    )
                )
                .mappings()
                .all()
            )
        assert sorted(row["state"] for row in rows) == ["succeeded", "succeeded"]
        retried_row = next(row for row in rows if row["attempts"] == 2)
        assert retried_row["last_error_code"] == "dependency_unavailable"
        assert bytes(retried_row["result_sha256"]) == bytes.fromhex("f" * 64)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_work_recovers_only_expired_leases(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    now = round((FixedClock().now() + timedelta(seconds=30)).timestamp() * 1_000_000)
    repository = SqliteMemoryConsolidationWorkRepository(store)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        await _complete_backfill(store, key_file)
        work = await repository.claim_next(extractor(), "worker-1", now, now + 100)
        assert work is not None
        assert await repository.recover_expired(now + 99) == 0
        assert await repository.recover_expired(now + 100) == 1
        reclaimed = await repository.claim_next(extractor(), "worker-2", now + 100, now + 1_000_100)
        assert reclaimed is not None
        assert reclaimed.attempts == 2
        assert reclaimed.lease_owner == "worker-2"
    finally:
        await store.close()
