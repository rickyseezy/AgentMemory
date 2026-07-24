"""PRO-008 canonical SQLite replay-source integration tests."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.providers.adapters.sqlite_migration_content import (
    SqliteCanonicalEmbeddingContentSource,
    _blob,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.providers.domain.errors import EmbeddingMigrationValidationError
from tests.core.support import (
    BRAIN_ID,
    FixedClock,
    bootstrap_request,
    migrated_store,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_EVENTS = (
    "018f0000-0000-7000-8000-000000000911",
    "018f0000-0000-7000-8000-000000000912",
    "018f0000-0000-7000-8000-000000000913",
)


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    async with store.engine.begin() as connection:
        for index, event_id in enumerate(_EVENTS, start=1):
            document = {
                "classification": "restricted" if index == 1 else "unexpected",
                "statement": f"canonical-{index}",
            }
            payload = json.dumps(document, separators=(",", ":"), sort_keys=True)
            await connection.execute(
                text(
                    "INSERT INTO domain_events "
                    "(event_id,brain_id,projection_type,stable_id,target_type,"
                    "target_id_hash,payload_json,payload_hash,source_digest,"
                    "missing_dependency,occurred_at,recorded_at,schema_version) "
                    "VALUES (:event,:brain,'graph',:stable,:target_type,:target_hash,"
                    ":payload,:payload_hash,:source,NULL,:at,:at,1)"
                ),
                {
                    "at": index,
                    "brain": BRAIN_ID,
                    "event": event_id,
                    "payload": payload,
                    "payload_hash": hashlib.sha256(payload.encode()).digest(),
                    "source": hashlib.sha256(f"source-{index}".encode()).digest(),
                    "stable": event_id,
                    "target_hash": hashlib.sha256(event_id.encode()).digest(),
                    "target_type": "memory",
                },
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_source_reads_only_canonical_content_and_advances_cursor(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        source = SqliteCanonicalEmbeddingContentSource(store)
        assert await source.latest_watermark(BRAIN_ID) == 3
        first = await source.read_page(BRAIN_ID, 0, 3, 1)
        assert first.next_cursor == 1
        assert not first.complete
        assert first.records[0].classification == "restricted"
        assert first.records[0].content_ref == (f"sqlite://domain-events/{_EVENTS[0]}")
        second = await source.read_page(BRAIN_ID, first.next_cursor, 3, 10)
        assert second.complete
        assert second.next_cursor == 3
        assert [record.sequence for record in second.records] == [2, 3]
        assert all(record.classification == "internal" for record in second.records)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_source_rejects_invalid_replay_bounds_before_storage(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        source = SqliteCanonicalEmbeddingContentSource(store)
        with pytest.raises(EmbeddingMigrationValidationError, match="bounds"):
            await source.read_page(BRAIN_ID, 2, 1, 1)
    finally:
        await store.close()


def test_content_hash_decoder_accepts_memoryview_and_rejects_other_types() -> None:
    assert _blob(memoryview(b"canonical")) == b"canonical"
    with pytest.raises(TypeError):
        _blob("not-binary")
