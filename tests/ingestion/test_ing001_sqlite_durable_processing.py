"""ING-001 real SQLite crash recovery, integrity, and terminal receipt tests."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import SqliteAgentEventUnitOfWorkFactory
from agentmemory.ingestion.adapters.outbound.sqlite_durable_processing import (
    SqliteCanonicalEventProjectionVerifier,
    SqliteDurableEventProcessingRepository,
)
from agentmemory.ingestion.application.append_agent_event import (
    AppendAgentEventCommand,
    AppendAgentEventHandler,
)
from agentmemory.ingestion.application.durable_processing import (
    DurableEventProcessingHandler,
    DurableIngestionWorker,
)
from agentmemory.ingestion.domain.agent_event import PayloadReference, ResolvedAgentEventIdentity
from agentmemory.ingestion.domain.capture import AdmittedAgentEvent
from agentmemory.ingestion.domain.durable_processing import (
    ProcessingDisposition,
    VerifiedEventProjection,
)
from agentmemory.ingestion.domain.errors import IngestionIntegrityError
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    EVENT_ID,
    NOW,
    PAYLOAD,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    event,
)
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority

if TYPE_CHECKING:
    from pathlib import Path


def processor(
    store: SqliteCoreStore,
    key_file: Path,
    owner: str = "core-worker-1",
    observed_at: datetime = NOW,
) -> tuple[DurableEventProcessingHandler, SqliteDurableEventProcessingRepository]:
    repository = SqliteDurableEventProcessingRepository(store)
    verifier = SqliteCanonicalEventProjectionVerifier(
        store.engine,
        SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(observed_at)),
    )
    return (
        DurableEventProcessingHandler(repository, verifier, FixedClock(observed_at), owner),
        repository,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_acknowledged_event_reaches_one_terminal_projection_after_database_restart(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    await seed_capture_authority(store)
    accepted = await capture_handler(store, key_file).execute(event())
    assert accepted.disposition.value == "accepted"
    await store.close()

    restarted = SqliteCoreStore.create(
        tmp_path / "agentmemory.sqlite3",
        SqliteRuntimePolicy((3, 0, 0), frozenset()),
    )
    try:
        handler, repository = processor(restarted, key_file)
        worker = DurableIngestionWorker(
            repository,
            handler,
            FixedClock(NOW),
            poll_seconds=0.001,
        )
        stop = asyncio.Event()
        task = asyncio.create_task(worker.run(stop))
        for _ in range(100):
            async with restarted.engine.connect() as connection:
                projected = (
                    await connection.execute(text("SELECT COUNT(*) FROM event_projection_receipts"))
                ).scalar_one()
            if projected:
                break
            await asyncio.sleep(0.001)
        stop.set()
        await task
        duplicate_idle = await handler.execute_once()
        assert duplicate_idle.disposition is ProcessingDisposition.IDLE
        async with restarted.engine.connect() as connection:
            state = (
                await connection.execute(
                    text("SELECT status,attempts,lease_owner FROM outbox_messages")
                )
            ).one()
            assert tuple(state) == ("completed", 1, None)
            receipt = (
                await connection.execute(
                    text(
                        "SELECT event_id,status,length(canonical_sha256),"
                        "length(projection_sha256) FROM event_projection_receipts"
                    )
                )
            ).one()
            assert tuple(receipt) == (EVENT_ID, "completed", 32, 32)
    finally:
        await restarted.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.parametrize(
    "tamper",
    [
        "outbox_checksum",
        "event_ciphertext",
        "outbox_invalid_json",
        "outbox_non_object",
        "outbox_unexpected_keys",
        "event_index",
    ],
)
async def test_corrupt_acknowledged_record_fails_closed_and_commits_repair_alert(
    tmp_path: Path,
    tamper: str,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        async with store.engine.begin() as connection:
            if tamper == "outbox_checksum":
                await connection.execute(
                    text("UPDATE outbox_messages SET payload_sha256=:value"),
                    {"value": b"x" * 32},
                )
            elif tamper == "event_ciphertext":
                await connection.execute(
                    text("UPDATE agent_event_envelopes SET ciphertext=:value"),
                    {"value": b"x" * 32},
                )
            elif tamper == "event_index":
                await connection.execute(text("UPDATE agent_events SET occurred_at=occurred_at+1"))
            else:
                payloads = {
                    "outbox_invalid_json": b"{",
                    "outbox_non_object": b"[]",
                    "outbox_unexpected_keys": b"{}",
                }
                payload = payloads[tamper]
                await connection.execute(
                    text("UPDATE outbox_messages SET payload=:payload,payload_sha256=:digest"),
                    {
                        "digest": hashlib.sha256(payload).digest(),
                        "payload": payload.decode(),
                    },
                )
        handler, _ = processor(store, key_file)
        result = await handler.execute_once()
        assert result.disposition is ProcessingDisposition.REPAIR_REQUIRED
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT status FROM outbox_messages"))
            ).scalar_one() == "repair_required"
            alert = (
                await connection.execute(
                    text("SELECT error_code,safe_details,state FROM ingestion_repair_alerts")
                )
            ).one()
            assert tuple(alert) == (
                "canonical_integrity_violation",
                "Canonical event integrity verification failed",
                "open",
            )
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM event_projection_receipts"))
            ).scalar_one() == 0
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_events WHERE action='ingestion.repair_required'"
                    )
                )
            ).scalar_one() == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_startup_recovery_releases_only_expired_leases(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        handler, repository = processor(
            store,
            key_file,
            "worker-a",
            NOW + timedelta(microseconds=10),
        )
        now = round(NOW.timestamp() * 1_000_000)
        claimed = await repository.claim_next("worker-a", now, now + 10)
        assert claimed is not None
        assert await repository.recover_expired_leases(now + 9) == 0
        assert await repository.recover_expired_leases(now + 10) == 1
        result = await handler.execute_once()
        assert result.disposition is ProcessingDisposition.COMPLETED
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text("SELECT status,attempts,last_error_code FROM outbox_messages")
                )
            ).one()
            assert tuple(row) == ("completed", 2, None)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_artifact_reference_event_outbox_and_audit_commit_in_one_uow(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        referenced = replace(
            event(),
            payload=None,
            payload_reference=PayloadReference(
                f"cas://sha256/{digest}",
                digest,
                len(PAYLOAD),
            ),
        )
        admitted = AdmittedAgentEvent(
            referenced,
            ResolvedAgentEventIdentity(
                BRAIN_ID,
                PRINCIPAL_ID,
                PROJECT_ID,
                REPOSITORY_ID,
                None,
            ),
            NOW,
            0,
        )
        appender = AppendAgentEventHandler(
            CanonicalAgentEventEncoder(),
            AesGcmAgentEventEncryptor(
                SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
            ),
            SqliteAgentEventUnitOfWorkFactory(store, FixedClock(NOW)),
        )
        result = await appender.execute(AppendAgentEventCommand(admitted))
        assert result.disposition.value == "accepted"
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT a.blob_uri,a.sha256,a.byte_length,e.payload_ref "
                        "FROM agent_events e JOIN artifacts a ON a.id=e.payload_ref"
                    )
                )
            ).one()
            assert tuple(row[:3]) == (f"cas://sha256/{digest}", bytes.fromhex(digest), len(PAYLOAD))
            assert row[3]
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM outbox_messages),"
                        "(SELECT COUNT(*) FROM audit_events WHERE action='agent_event.appended')"
                    )
                )
            ).one()
            assert tuple(counts) == (1, 1)
        handler, _ = processor(store, key_file)
        assert (await handler.execute_once()).disposition is ProcessingDisposition.COMPLETED
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_startup_scan_alerts_committed_event_with_missing_outbox(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        async with store.engine.begin() as connection:
            await connection.execute(text("DELETE FROM outbox_messages"))
        _, repository = processor(store, key_file)
        detected_at = round(NOW.timestamp() * 1_000_000)
        assert await repository.alert_unprocessed_events(detected_at) == 1
        assert await repository.alert_unprocessed_events(detected_at) == 0
        async with store.engine.connect() as connection:
            alert = (
                await connection.execute(
                    text(
                        "SELECT source_event_id,outbox_message_id,error_code,state "
                        "FROM ingestion_repair_alerts"
                    )
                )
            ).one()
            assert tuple(alert) == (EVENT_ID, None, "outbox_missing", "open")
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_retry_release_is_due_time_safe_and_rejects_wrong_lease_owner(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        _, repository = processor(store, key_file)
        now = round(NOW.timestamp() * 1_000_000)
        message = await repository.claim_next("worker-a", now, now + 20)
        assert message is not None
        inbox = await repository.claim_inbox(
            message,
            "canonical-event-projection-v1",
            "worker-a",
            now,
            now + 20,
        )
        await repository.release_retry(message, inbox, "dependency_unavailable", now + 10)
        assert await repository.claim_next("worker-a", now + 9, now + 30) is None
        retried = await repository.claim_next("worker-a", now + 10, now + 30)
        assert retried is not None
        retried_inbox = await repository.claim_inbox(
            retried,
            "canonical-event-projection-v1",
            "worker-a",
            now + 10,
            now + 30,
        )
        with pytest.raises(IngestionIntegrityError, match="lease diverged"):
            await repository.release_retry(
                replace(retried, lease_owner="wrong-worker"),
                retried_inbox,
                "dependency_unavailable",
                now + 40,
            )
        assert await repository.recover_expired_leases(now + 30) == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_malformed_persisted_message_is_alerted_during_claim(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE outbox_messages SET topic="
                    "'am.local.018f0000-0000-7000-8000-000000000999."
                    "ingestion.agent-event-appended.v1'"
                )
            )
        _, repository = processor(store, key_file)
        now = round(NOW.timestamp() * 1_000_000)
        assert await repository.claim_next("worker-a", now, now + 10) is None
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT status FROM outbox_messages"))
            ).scalar_one() == "repair_required"
            assert (
                await connection.execute(text("SELECT error_code FROM ingestion_repair_alerts"))
            ).scalar_one() == "canonical_integrity_violation"
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_missing_envelope_and_projection_identity_mismatch_fail_closed(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        _, repository = processor(store, key_file)
        now = round(NOW.timestamp() * 1_000_000)
        message = await repository.claim_next("worker-a", now, now + 10)
        assert message is not None
        inbox = await repository.claim_inbox(
            message,
            "canonical-event-projection-v1",
            "worker-a",
            now,
            now + 10,
        )
        wrong_event = "018f0000-0000-7000-8000-000000000102"
        with pytest.raises(IngestionIntegrityError, match="integrity verification"):
            await repository.complete(
                message,
                inbox,
                VerifiedEventProjection(wrong_event, "a" * 64, "b" * 64),
                now,
            )
        async with store.engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM agent_event_envelopes WHERE event_id=:event"),
                {"event": EVENT_ID},
            )
        verifier = SqliteCanonicalEventProjectionVerifier(
            store.engine,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        )
        with pytest.raises(IngestionIntegrityError, match="integrity verification"):
            await verifier.verify(message)
        assert await repository.recover_expired_leases(now + 10) == 1
    finally:
        await store.close()
