"""ADP-005 encrypted SQLite lease, watermark, and post-ACK erasure tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest

from agentmemory.ingestion.adapters.outbound.offline_spool import (
    EncryptedSqliteSpool,
    SpoolingAgentAdapter,
    SqliteOfflineSpoolRepository,
)
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.ingestion.domain.spool_reconciliation import (
    ClockSkew,
    SpoolAcknowledgement,
    SpoolUploadDisposition,
)
from tests.core.support import write_secret
from tests.ingestion.adp002_support import event

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.ingestion.domain.agent_event import AgentEvent

EVENT_A1 = "018f0000-0000-7000-8000-000000000501"
EVENT_A2 = "018f0000-0000-7000-8000-000000000502"
EVENT_B1 = "018f0000-0000-7000-8000-000000000503"


def spool(tmp_path: Path, *, maximum_bytes: int = 256 * 1024) -> EncryptedSqliteSpool:
    tmp_path.chmod(0o700)
    key = tmp_path / "spool-key"
    write_secret(key, b"k" * 32)
    value = EncryptedSqliteSpool(
        tmp_path / "events.sqlite3",
        key,
        maximum_records=100,
        maximum_bytes=maximum_bytes,
    )
    value.initialize()
    return value


def acknowledgement(
    event_id: str,
    ordering_key: str,
    spool_sequence: int,
    *,
    disposition: SpoolUploadDisposition = SpoolUploadDisposition.ACCEPTED,
    skew: int = 0,
) -> SpoolAcknowledgement:
    return SpoolAcknowledgement(
        event_id,
        ordering_key,
        spool_sequence,
        disposition,
        ClockSkew(skew, 2_000_000),
    )


@pytest.mark.asyncio
async def test_repository_orders_out_of_order_events_and_advances_per_key_watermarks(
    tmp_path: Path,
) -> None:
    value = spool(tmp_path)
    value.enqueue(EVENT_A2, "a", 2, b"a-2")
    value.enqueue(EVENT_B1, "b", 1, b"b-1")
    value.enqueue(EVENT_A1, "a", 1, b"a-1")
    repository = SqliteOfflineSpoolRepository(value)
    assert await repository.try_acquire_lease("worker", 1_000_000, 3_000_000)

    pending = await repository.pending(maximum_items=100, maximum_bytes=1024 * 1024)

    assert [(item.ordering_key, item.sequence) for item in pending] == [
        ("a", 1),
        ("a", 2),
        ("b", 1),
    ]
    assert [(item.ordering_key, item.spool_sequence) for item in pending] == [
        ("a", 1),
        ("a", 2),
        ("b", 1),
    ]
    acknowledged = await repository.acknowledge(
        "worker",
        (
            acknowledgement(EVENT_A1, "a", 1),
            acknowledgement(
                EVENT_B1,
                "b",
                1,
                disposition=SpoolUploadDisposition.DUPLICATE,
                skew=-10,
            ),
        ),
        2_000_000,
    )

    assert acknowledged == 2
    remaining = await repository.pending(maximum_items=100, maximum_bytes=1024 * 1024)
    assert [(item.event_id, item.spool_sequence) for item in remaining] == [(EVENT_A2, 2)]
    with closing(sqlite3.connect(tmp_path / "events.sqlite3")) as connection:
        watermarks = connection.execute(
            "SELECT ordering_key, acknowledged_spool_sequence, last_event_id, "
            "last_disposition, clock_skew_microseconds FROM spool_watermarks "
            "ORDER BY ordering_key"
        ).fetchall()
    assert watermarks == [
        ("a", 1, EVENT_A1, "accepted", 0),
        ("b", 1, EVENT_B1, "duplicate", -10),
    ]


@pytest.mark.asyncio
async def test_repository_refuses_nonprefix_ack_wrong_owner_and_expired_lease(
    tmp_path: Path,
) -> None:
    value = spool(tmp_path)
    value.enqueue(EVENT_A1, "a", 1, b"a-1")
    value.enqueue(EVENT_A2, "a", 2, b"a-2")
    repository = SqliteOfflineSpoolRepository(value)
    assert await repository.try_acquire_lease("worker", 100, 200)

    with pytest.raises(IngestionDependencyError, match="lease failed"):
        await repository.acknowledge(
            "other",
            (acknowledgement(EVENT_A1, "a", 1),),
            150,
        )
    with pytest.raises(IngestionDependencyError, match="watermark conflicted"):
        await repository.acknowledge(
            "worker",
            (acknowledgement(EVENT_A2, "a", 2),),
            150,
        )
    with pytest.raises(IngestionDependencyError, match="lease failed"):
        await repository.acknowledge(
            "worker",
            (acknowledgement(EVENT_A1, "a", 1),),
            200,
        )
    assert await repository.count_pending() == 2


@pytest.mark.asyncio
async def test_expired_lease_is_recoverable_and_exact_owner_release_is_safe(tmp_path: Path) -> None:
    repository = SqliteOfflineSpoolRepository(spool(tmp_path))

    assert await repository.try_acquire_lease("first", 100, 200)
    assert not await repository.try_acquire_lease("first", 101, 250)
    assert not await repository.try_acquire_lease("second", 199, 300)
    await repository.release_lease("second")
    assert not await repository.try_acquire_lease("second", 199, 300)
    assert await repository.try_acquire_lease("second", 200, 300)
    await repository.release_lease("second")
    assert await repository.try_acquire_lease("third", 201, 300)


@pytest.mark.asyncio
async def test_pending_enforces_item_and_plaintext_backpressure(tmp_path: Path) -> None:
    value = spool(tmp_path)
    value.enqueue(EVENT_A1, "a", 1, b"x" * (60 * 1024))
    value.enqueue(EVENT_A2, "a", 2, b"y" * (60 * 1024))
    repository = SqliteOfflineSpoolRepository(value)

    pending = await repository.pending(maximum_items=100, maximum_bytes=96 * 1024)

    assert [item.event_id for item in pending] == [EVENT_A1]


@pytest.mark.asyncio
async def test_post_ack_erases_ciphertext_and_truncates_wal(tmp_path: Path) -> None:
    value = spool(tmp_path)
    value.enqueue(EVENT_A1, "a", 1, b"private-canonical-event")
    with closing(sqlite3.connect(tmp_path / "events.sqlite3")) as connection:
        ciphertext = connection.execute(
            "SELECT ciphertext FROM spool_events WHERE event_id = ?",
            (EVENT_A1,),
        ).fetchone()[0]
    repository = SqliteOfflineSpoolRepository(value)
    assert await repository.try_acquire_lease("worker", 1, 10)

    assert (
        await repository.acknowledge(
            "worker",
            (acknowledgement(EVENT_A1, "a", 1),),
            2,
        )
        == 1
    )

    assert await repository.count_pending() == 0
    artifacts = [tmp_path / "events.sqlite3", tmp_path / "events.sqlite3-wal"]
    assert all(not path.exists() or ciphertext not in path.read_bytes() for path in artifacts)


def test_spool_refuses_public_database_oversized_event_and_invalid_batch_bytes(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    key = tmp_path / "spool-key"
    write_secret(key, b"k" * 32)
    database = tmp_path / "events.sqlite3"
    database.touch(mode=0o644)
    with pytest.raises(IngestionDependencyError, match="path is unsafe"):
        EncryptedSqliteSpool(database, key).initialize()

    database.unlink()
    value = spool(tmp_path)
    with pytest.raises(ValueError, match="maximum size"):
        value.enqueue(EVENT_A1, "a", 1, b"x" * (96 * 1024 + 1))
    with pytest.raises(ValueError, match="batch bytes"):
        value.pending(1, 1024 * 1024 + 1)


def test_spool_creates_database_owner_only_before_sqlite_opens_it(tmp_path: Path) -> None:
    spool(tmp_path)

    assert (tmp_path / "events.sqlite3").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_agent_adapter_decorator_defers_only_after_encrypted_commit(tmp_path: Path) -> None:
    value = spool(tmp_path)

    class StoppedCore:
        async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
            del event
            message = "core stopped"
            raise IngestionDependencyError(message)

    result = await SpoolingAgentAdapter(StoppedCore(), value).execute(event())

    assert result.disposition is AppendDisposition.DEFERRED
    pending = value.pending()
    assert [item.event_id for item in pending] == [event().event_id]
    assert b'"specversion":"1.0"' in pending[0].canonical_event
