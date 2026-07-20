"""ING-002 live consumer inbox concurrency, crash, conflict, and replay tests."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_durable_processing import (
    SqliteCanonicalEventProjectionVerifier,
    SqliteDurableEventProcessingRepository,
)
from agentmemory.ingestion.domain.agent_event import AgentEventData
from agentmemory.ingestion.domain.durable_processing import InboxClaimDisposition
from agentmemory.ingestion.domain.errors import IngestionConflictError, IngestionIntegrityError
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import NOW, event
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_event_duplicate_storm_commits_one_event_outbox_and_audit(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        handler = capture_handler(store, key_file)
        results = await asyncio.gather(*(handler.execute(event()) for _ in range(32)))
        assert sum(result.disposition.value == "accepted" for result in results) == 1
        assert sum(result.disposition.value == "duplicate" for result in results) == 31
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM agent_events),"
                        "(SELECT COUNT(*) FROM outbox_messages),"
                        "(SELECT COUNT(*) FROM audit_events "
                        " WHERE action='agent_event.appended')"
                    )
                )
            ).one()
            assert tuple(counts) == (1, 1, 1)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_event_id_content_conflict_is_rejected_audited_and_deduplicated(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        handler = capture_handler(store, key_file)
        await handler.execute(event())
        payload = b'{"status":"different"}'
        conflicting = replace(
            event(),
            payload=AgentEventData(payload, hashlib.sha256(payload).hexdigest()),
        )
        for _ in range(2):
            with pytest.raises(IngestionConflictError):
                await handler.execute(conflicting)
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM agent_events),"
                        "(SELECT COUNT(*) FROM outbox_messages),"
                        "(SELECT COUNT(*) FROM idempotency_conflicts "
                        " WHERE namespace='agent_event'),"
                        "(SELECT COUNT(*) FROM audit_events "
                        " WHERE action='agent_event.idempotency_conflict')"
                    )
                )
            ).one()
            assert tuple(counts) == (1, 1, 1, 1)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_inbox_duplicate_storm_creates_one_projection_and_audit(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        repository = SqliteDurableEventProcessingRepository(store)
        now = round(NOW.timestamp() * 1_000_000)
        message = await repository.claim_next("dispatcher", now, now + 100)
        assert message is not None
        claims = await asyncio.gather(
            *(
                repository.claim_inbox(
                    message,
                    "canonical-event-projection-v1",
                    f"consumer-{index}",
                    now,
                    now + 100,
                )
                for index in range(32)
            )
        )
        claimed = [item for item in claims if item.disposition is InboxClaimDisposition.CLAIMED]
        assert len(claimed) == 1
        assert sum(item.disposition is InboxClaimDisposition.WAIT for item in claims) == 31
        verifier = SqliteCanonicalEventProjectionVerifier(
            store.engine,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        )
        projection = await verifier.verify(message)
        await repository.complete(message, claimed[0], projection, now)
        replay = await repository.claim_inbox(
            message,
            "canonical-event-projection-v1",
            "consumer-replay",
            now + 1,
            now + 101,
        )
        assert replay.disposition is InboxClaimDisposition.REPLAY
        assert replay.result_sha256 == projection.projection_sha256
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM inbox_receipts),"
                        "(SELECT COUNT(*) FROM event_projection_receipts),"
                        "(SELECT COUNT(*) FROM projection_idempotency_receipts),"
                        "(SELECT COUNT(*) FROM audit_events "
                        " WHERE action='ingestion.event_projected')"
                    )
                )
            ).one()
            assert tuple(counts) == (1, 1, 1, 1)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_inbox_content_conflict_is_rejected_and_audited_once(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        repository = SqliteDurableEventProcessingRepository(store)
        now = round(NOW.timestamp() * 1_000_000)
        message = await repository.claim_next("dispatcher", now, now + 100)
        assert message is not None
        await repository.claim_inbox(
            message,
            "canonical-event-projection-v1",
            "consumer-1",
            now,
            now + 100,
        )
        conflicting = replace(message, payload_sha256="f" * 64)
        for _ in range(2):
            with pytest.raises(IngestionConflictError, match="conflicts"):
                await repository.claim_inbox(
                    conflicting,
                    "canonical-event-projection-v1",
                    "consumer-2",
                    now + 1,
                    now + 101,
                )
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM idempotency_conflicts WHERE namespace='inbox'")
                )
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT status FROM outbox_messages"))
            ).scalar_one() == "repair_required"
            assert (
                await connection.execute(text("SELECT state FROM inbox_receipts"))
            ).scalar_one() == "repair_required"
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_events "
                        "WHERE action='ingestion.idempotency_conflict'"
                    )
                )
            ).scalar_one() == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_consumer_crash_before_completion_reclaims_both_leases_and_projects_once(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        repository = SqliteDurableEventProcessingRepository(store)
        now = round(NOW.timestamp() * 1_000_000)
        abandoned_message = await repository.claim_next("dead-dispatcher", now, now + 10)
        assert abandoned_message is not None
        abandoned_inbox = await repository.claim_inbox(
            abandoned_message,
            "canonical-event-projection-v1",
            "dead-consumer",
            now,
            now + 10,
        )
        assert abandoned_inbox.disposition is InboxClaimDisposition.CLAIMED
        assert await repository.recover_expired_leases(now + 10) == 1
        recovered_message = await repository.claim_next("recovered-dispatcher", now + 10, now + 30)
        assert recovered_message is not None
        recovered_inbox = await repository.claim_inbox(
            recovered_message,
            "canonical-event-projection-v1",
            "recovered-consumer",
            now + 10,
            now + 30,
        )
        assert recovered_inbox.disposition is InboxClaimDisposition.CLAIMED
        assert recovered_inbox.attempt == 2
        projection = await SqliteCanonicalEventProjectionVerifier(
            store.engine,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        ).verify(recovered_message)
        await repository.complete(recovered_message, recovered_inbox, projection, now + 10)
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM event_projection_receipts"))
            ).scalar_one() == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_commit_before_ack_replay_finishes_redelivery_without_second_projection(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        repository = SqliteDurableEventProcessingRepository(store)
        now = round(NOW.timestamp() * 1_000_000)
        first_message = await repository.claim_next("dispatcher-1", now, now + 10)
        assert first_message is not None
        first_inbox = await repository.claim_inbox(
            first_message,
            "canonical-event-projection-v1",
            "consumer-1",
            now,
            now + 10,
        )
        projection = await SqliteCanonicalEventProjectionVerifier(
            store.engine,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        ).verify(first_message)
        await repository.complete(first_message, first_inbox, projection, now)

        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE outbox_messages SET status='leased',lease_owner='dispatcher-2',"
                    "lease_until=:lease,completed_at=NULL WHERE id=:message"
                ),
                {"lease": now + 20, "message": first_message.message_id},
            )
        repeated_message = replace(
            first_message,
            lease_owner="dispatcher-2",
            lease_until_microseconds=now + 20,
        )
        replay = await repository.claim_inbox(
            repeated_message,
            "canonical-event-projection-v1",
            "consumer-2",
            now + 1,
            now + 21,
        )
        assert replay.disposition is InboxClaimDisposition.REPLAY
        await repository.complete_replay(repeated_message, replay, now + 1)
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM event_projection_receipts),"
                        "(SELECT COUNT(*) FROM projection_idempotency_receipts),"
                        "(SELECT COUNT(*) FROM audit_events "
                        " WHERE action='ingestion.event_projected')"
                    )
                )
            ).one()
            assert tuple(counts) == (1, 1, 1)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_projection_key_and_source_generation_are_physically_unique(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        repository = SqliteDurableEventProcessingRepository(store)
        now = round(NOW.timestamp() * 1_000_000)
        message = await repository.claim_next("dispatcher", now, now + 10)
        assert message is not None
        inbox = await repository.claim_inbox(
            message,
            "canonical-event-projection-v1",
            "consumer",
            now,
            now + 10,
        )
        projection = await SqliteCanonicalEventProjectionVerifier(
            store.engine,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        ).verify(message)
        await repository.complete(message, inbox, projection, now)
        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError):
                await connection.execute(
                    text(
                        "INSERT INTO projection_idempotency_receipts "
                        "(projection_name,idempotency_key,brain_id,source_message_id,"
                        "projection_generation,request_sha256,result_sha256,completed_at,"
                        "created_at,schema_version) SELECT projection_name,idempotency_key,"
                        "brain_id,source_message_id,projection_generation,request_sha256,:result,"
                        "completed_at,created_at,schema_version "
                        "FROM projection_idempotency_receipts"
                    ),
                    {"result": b"z" * 32},
                )
        divergent = replace(
            replay := await repository.claim_inbox(
                message,
                "canonical-event-projection-v1",
                "consumer-replay",
                now + 1,
                now + 11,
            ),
            result_sha256="f" * 64,
        )
        with pytest.raises(IngestionIntegrityError):
            await repository.complete_replay(message, divergent, now + 1)
        assert replay.disposition is InboxClaimDisposition.REPLAY
    finally:
        await store.close()
