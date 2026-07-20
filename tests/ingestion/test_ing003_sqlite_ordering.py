"""ING-003 real SQLite causal ordering, gap, and lease integration tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.domain.durable_processing import ProcessingDisposition
from tests.core.support import migrated_store, write_secret
from tests.ingestion.adp002_support import EVENT_ID, NOW, ORDERING_KEY, event
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority
from tests.ingestion.test_ing001_sqlite_durable_processing import processor

if TYPE_CHECKING:
    from pathlib import Path

EVENT_ID_2 = "018f0000-0000-7000-8000-000000000102"
ORDERING_KEY_2 = "018f0000-0000-7000-8000-000000000132"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sequential_events_advance_one_digest_chained_watermark(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(sequence=1))
        first, _ = processor(store, key_file, "worker-1")
        assert (await first.execute_once()).disposition is ProcessingDisposition.COMPLETED

        await capture.execute(event(event_id=EVENT_ID_2, sequence=2))
        second, _ = processor(store, key_file, "worker-2")
        assert (await second.execute_once()).disposition is ProcessingDisposition.COMPLETED

        async with store.engine.connect() as connection:
            watermark = (
                await connection.execute(
                    text(
                        "SELECT applied_sequence,state_sha256,last_event_id,lease_owner "
                        "FROM projection_order_watermarks"
                    )
                )
            ).one()
            history = (
                (
                    await connection.execute(
                        text(
                            "SELECT event_id,event_sequence,prior_state_sha256,state_sha256 "
                            "FROM ordered_projection_history ORDER BY event_sequence"
                        )
                    )
                )
                .mappings()
                .all()
            )
        assert tuple(watermark[:3]) == (2, history[1]["state_sha256"], EVENT_ID_2)
        assert watermark[3] is None
        assert history[0]["event_id"] == EVENT_ID
        assert history[0]["prior_state_sha256"] == bytes(32)
        assert history[1]["prior_state_sha256"] == history[0]["state_sha256"]
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gap_waits_until_timeout_then_late_predecessor_requires_shadow_replay(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(event_id=EVENT_ID_2, sequence=3))

        waiting, _ = processor(store, key_file, "worker-wait", NOW)
        assert (await waiting.execute_once()).disposition is ProcessingDisposition.RETRY_SCHEDULED
        async with store.engine.connect() as connection:
            gap = (
                await connection.execute(
                    text("SELECT from_sequence,to_sequence,state FROM projection_order_gaps")
                )
            ).one()
            assert tuple(gap) == (1, 2, "waiting")
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM ordered_projection_history"))
            ).scalar_one() == 0

        after_timeout = NOW + timedelta(seconds=61)
        resumed, _ = processor(store, key_file, "worker-resume", after_timeout)
        assert (await resumed.execute_once()).disposition is ProcessingDisposition.COMPLETED

        await capture.execute(event(event_id=EVENT_ID, sequence=1))
        late, _ = processor(store, key_file, "worker-late", after_timeout + timedelta(seconds=1))
        assert (await late.execute_once()).disposition is ProcessingDisposition.REPLAY_REQUIRED
        async with store.engine.connect() as connection:
            evidence = (
                await connection.execute(
                    text(
                        "SELECT r.event_id,r.event_sequence,r.state,o.status,i.state,g.state,"
                        "g.late_event_id FROM ordered_replay_required_events r "
                        "JOIN outbox_messages o ON o.id=r.outbox_message_id "
                        "JOIN inbox_receipts i ON i.message_id=o.id "
                        "JOIN projection_order_gaps g ON g.blocking_event_id=:blocking"
                    ),
                    {"blocking": EVENT_ID_2},
                )
            ).one()
            count = (
                await connection.execute(text("SELECT COUNT(*) FROM ordered_projection_history"))
            ).scalar_one()
        assert tuple(evidence) == (
            EVENT_ID,
            1,
            "pending",
            "replay_required",
            "replay_required",
            "late_arrived",
            EVENT_ID,
        )
        assert count == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_independent_ordering_keys_progress_concurrently(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(sequence=1))
        await capture.execute(
            replace(event(event_id=EVENT_ID_2, sequence=1), ordering_key=ORDERING_KEY_2)
        )
        first, _ = processor(store, key_file, "worker-a")
        second, _ = processor(store, key_file, "worker-b")
        results = await asyncio.gather(first.execute_once(), second.execute_once())
        assert {item.disposition for item in results} == {ProcessingDisposition.COMPLETED}
        async with store.engine.connect() as connection:
            states = (
                await connection.execute(
                    text(
                        "SELECT ordering_key,applied_sequence FROM "
                        "projection_order_watermarks ORDER BY ordering_key"
                    )
                )
            ).all()
        assert tuple((str(row[0]), int(str(row[1]))) for row in states) == (
            (ORDERING_KEY, 1),
            (ORDERING_KEY_2, 1),
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unordered_event_is_recorded_without_creating_a_false_watermark(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(replace(event(), sequence=None))
        handler, _ = processor(store, key_file, "worker-unordered")
        assert (await handler.execute_once()).disposition is ProcessingDisposition.COMPLETED
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM projection_order_watermarks),"
                        "(SELECT COUNT(*) FROM ordered_projection_history "
                        "WHERE event_sequence IS NULL)"
                    )
                )
            ).one()
        assert tuple(counts) == (0, 1)
    finally:
        await store.close()
