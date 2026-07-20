"""ING-003 real SQLite deterministic shadow replay and evidence integration tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

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
from agentmemory.ingestion.adapters.outbound.sqlite_ordered_replay import (
    SqliteOrderedReplayAccessPolicy,
    SqliteOrderedReplayRepository,
)
from agentmemory.ingestion.application.ordered_replay import (
    OrderedReplayExecutor,
    StartOrderedReplayHandler,
)
from agentmemory.ingestion.domain.durable_processing import ProcessingDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionIntegrityError,
)
from agentmemory.ingestion.domain.ordered_replay import (
    CANONICAL_EVENT_PROJECTION_FINGERPRINT,
    OrderedProjectionState,
    ReplayRunRequest,
    ReplayRunState,
    reduce_projection,
)
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from tests.core.support import GRANT_ID, FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import BRAIN_ID, EVENT_ID, NOW, PRINCIPAL_ID, event
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority
from tests.ingestion.test_ing001_ack_failure_boundaries import admitted
from tests.ingestion.test_ing001_sqlite_durable_processing import processor

EVENT_ID_2 = "018f0000-0000-7000-8000-000000000102"
OPERATION_ID = "018f0000-0000-7000-8000-000000000201"
GENERATION_ID = "018f0000-0000-7000-8000-000000000202"
PROFILE_ID = "018f0000-0000-7000-8000-000000000203"
PROVIDER_OPERATION_ID = "018f0000-0000-7000-8000-000000000204"


def replay_request(**changes: object) -> ReplayRunRequest:
    value = ReplayRunRequest(
        OPERATION_ID,
        BRAIN_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        "canonical-event-projection-v1",
        GENERATION_ID,
        CANONICAL_EVENT_PROJECTION_FINGERPRINT,
    )
    return replace(value, **cast("Any", changes))


async def _seed_recorded_provider_evidence(store: SqliteCoreStore, now: int) -> None:
    result_digest = b"r" * 32
    result_ref = f"cas://sha256/{result_digest.hex()}"
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO provider_operation_results "
                "(profile_id,idempotency_key,operation_id,brain_id,cache_key_sha256,"
                "request_sha256,state,attempts,lease_owner,lease_until,retry_at,result_sha256,"
                "result_ref,usage_units,last_error_code,completed_at,created_at,updated_at,"
                "schema_version) VALUES (:profile,'reduction-2',:operation,:brain,:cache,"
                ":request,'completed',1,NULL,NULL,:now,:result,:result_ref,7,NULL,:now,:now,"
                ":now,1)"
            ),
            {
                "brain": BRAIN_ID,
                "cache": b"c" * 32,
                "now": now,
                "operation": PROVIDER_OPERATION_ID,
                "profile": PROFILE_ID,
                "request": b"q" * 32,
                "result": result_digest,
                "result_ref": result_ref,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO recorded_reduction_inputs "
                "(projection_name,event_id,brain_id,operation_id,profile_id,model_revision,"
                "purpose,result_sha256,result_ref,created_at,schema_version) VALUES "
                "('canonical-event-projection-v1',:event,:brain,:operation,:profile,:revision,"
                "'extract',:result,:result_ref,:now,1)"
            ),
            {
                "brain": BRAIN_ID,
                "event": EVENT_ID_2,
                "now": now,
                "operation": PROVIDER_OPERATION_ID,
                "profile": PROFILE_ID,
                "result": result_digest,
                "result_ref": result_ref,
                "revision": "d" * 40,
            },
        )


async def _capture_legacy_event(store: SqliteCoreStore, key_file: Path) -> None:
    """Write one event exactly as the pre-ING-005 append transaction did."""
    source = admitted()
    clock = FixedClock(NOW)
    canonical = CanonicalAgentEventEncoder().encode(source.event)
    encrypted = await AesGcmAgentEventEncryptor(
        SqliteWrappedBrainKeyProvider(store, key_file, clock)
    ).encrypt(
        event_id=source.event.event_id,
        brain_id=source.identity.brain_id,
        classification=source.event.classification.value,
        plaintext=canonical,
    )
    unit = SqliteAgentEventUnitOfWork(store, clock)
    async with unit:
        artifact_id = await unit.artifacts.ensure_reference(source, encrypted)
        await unit.events.append(source, encrypted, artifact_id)
        await unit.outbox.enqueue(source)
        await unit.audit.append_agent_event(source, encrypted)
        await unit.commit()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_live_and_replay_digest_match_using_only_recorded_provider_evidence(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(sequence=1))
        first, _ = processor(store, key_file, "live-worker-1")
        assert (await first.execute_once()).disposition is ProcessingDisposition.COMPLETED
        await capture.execute(event(event_id=EVENT_ID_2, sequence=2))
        now = round(NOW.timestamp() * 1_000_000)
        await _seed_recorded_provider_evidence(store, now)
        second, _ = processor(store, key_file, "live-worker-2")
        assert (await second.execute_once()).disposition is ProcessingDisposition.COMPLETED

        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        request = replay_request()
        queued = await StartOrderedReplayHandler(access, repository, processor_clock()).execute(
            request
        )
        duplicate = await StartOrderedReplayHandler(access, repository, processor_clock()).execute(
            request
        )
        assert duplicate == queued
        result = await OrderedReplayExecutor(
            access,
            repository,
            processor_clock(),
            "ordered-replay-test",
            page_size=1,
        ).execute(OPERATION_ID)
        assert result.state is ReplayRunState.READY
        assert result.shadow_digest == result.live_digest
        assert result.processed_count == result.source_count == 2
        async with store.engine.connect() as connection:
            evidence = (
                await connection.execute(
                    text(
                        "SELECT recorded_operation_id FROM ordered_replay_shadow_history "
                        "WHERE event_id=:event"
                    ),
                    {"event": EVENT_ID_2},
                )
            ).scalar_one()
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM ordered_projection_history),"
                        "(SELECT COUNT(*) FROM ordered_replay_shadow_history),"
                        "(SELECT COUNT(*) FROM audit_events WHERE "
                        "action='ingestion.ordered_replay.ready')"
                    )
                )
            ).one()
        assert evidence == PROVIDER_OPERATION_ID
        assert tuple(counts) == (2, 2, 1)

        selected = replay_request(
            operation_id="018f0000-0000-7000-8000-000000000207",
            projection_generation="018f0000-0000-7000-8000-000000000208",
            from_event_id=EVENT_ID_2,
            to_event_id=EVENT_ID_2,
        )
        selected_queued = await StartOrderedReplayHandler(
            access, repository, processor_clock()
        ).execute(selected)
        assert selected_queued.source_count == 1
        selected_result = await OrderedReplayExecutor(
            access,
            repository,
            processor_clock(),
            "ordered-replay-selected",
        ).execute(selected.operation_id)
        assert selected_result.state is ReplayRunState.READY
        assert selected_result.shadow_digest == selected_result.live_digest
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_late_event_replay_stays_shadow_only_when_it_diverges_from_live_state(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(event_id=EVENT_ID_2, sequence=3))
        waiting, _ = processor(store, key_file, "gap-wait", NOW)
        assert (await waiting.execute_once()).disposition is ProcessingDisposition.RETRY_SCHEDULED
        after_timeout = NOW + timedelta(seconds=61)
        resumed, _ = processor(store, key_file, "gap-resume", after_timeout)
        assert (await resumed.execute_once()).disposition is ProcessingDisposition.COMPLETED
        await capture.execute(event(sequence=1))
        late, _ = processor(store, key_file, "late-event", after_timeout + timedelta(seconds=1))
        assert (await late.execute_once()).disposition is ProcessingDisposition.REPLAY_REQUIRED
        async with store.engine.connect() as connection:
            live_before = (
                await connection.execute(
                    text("SELECT applied_sequence,state_sha256 FROM projection_order_watermarks")
                )
            ).one()

        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        request = replay_request()
        replay_clock = FixedClock(after_timeout + timedelta(seconds=2))
        await StartOrderedReplayHandler(access, repository, replay_clock).execute(request)
        result = await OrderedReplayExecutor(
            access,
            repository,
            replay_clock,
            "ordered-replay-late",
        ).execute(OPERATION_ID)
        assert result.state is ReplayRunState.SUPERSEDED
        assert result.shadow_digest != result.live_digest
        async with store.engine.connect() as connection:
            live_after = (
                await connection.execute(
                    text("SELECT applied_sequence,state_sha256 FROM projection_order_watermarks")
                )
            ).one()
            required = (
                await connection.execute(
                    text("SELECT state,replay_operation_id FROM ordered_replay_required_events")
                )
            ).one()
        assert live_after == live_before
        assert tuple(required) == ("pending", None)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_event_captured_before_ing003_migration_replays_with_v1_reducer(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "pre-ing003.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(configuration, "0010_ing002_idempotent_delivery")
    policy = SqliteRuntimePolicy((3, 0, 0), frozenset())
    legacy = SqliteCoreStore.create(database_path, policy)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    await seed_capture_authority(legacy)
    await _capture_legacy_event(legacy, key_file)
    await legacy.close()

    command.upgrade(configuration, "0011_ing003_ordered_replay")
    store = SqliteCoreStore.create(database_path, policy)
    try:
        live, _ = processor(store, key_file, "legacy-live")
        assert (await live.execute_once()).disposition is ProcessingDisposition.COMPLETED
        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        request = replay_request()
        await StartOrderedReplayHandler(access, repository, processor_clock()).execute(request)
        result = await OrderedReplayExecutor(
            access,
            repository,
            processor_clock(),
            "legacy-replay",
        ).execute(OPERATION_ID)
        assert result.state is ReplayRunState.READY
        async with store.engine.connect() as connection:
            schema_version = (
                await connection.execute(
                    text("SELECT event_schema_version FROM ordered_replay_shadow_history")
                )
            ).scalar_one()
        assert schema_version == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_interrupted_shadow_replay_recovers_cursor_without_duplicate_history(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(sequence=1))
        first_live, _ = processor(store, key_file, "resume-live-1")
        assert (await first_live.execute_once()).disposition is ProcessingDisposition.COMPLETED
        await capture.execute(event(event_id=EVENT_ID_2, sequence=2))
        second_live, _ = processor(store, key_file, "resume-live-2")
        assert (await second_live.execute_once()).disposition is ProcessingDisposition.COMPLETED

        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        request = replay_request()
        queued = await StartOrderedReplayHandler(access, repository, processor_clock()).execute(
            request
        )
        now = round(NOW.timestamp() * 1_000_000)
        building = await repository.claim(OPERATION_ID, "crashed-replay", now, now + 10)
        page = await repository.read_page(building, 1)
        source = page.records[0]
        state_sha256 = reduce_projection(
            "0" * 64,
            source.reduction,
            CANONICAL_EVENT_PROJECTION_FINGERPRINT,
        )
        event_sequence = source.reduction.event_sequence
        assert event_sequence is not None
        building = await repository.append(
            building,
            source,
            "0" * 64,
            OrderedProjectionState(
                source.reduction.ordering_key,
                event_sequence,
                state_sha256,
            ),
            state_sha256,
            now,
        )
        assert building.processed_count == 1
        assert queued.source_count == 2
        assert await repository.recover_expired(now + 10) == 1

        recovered_clock = FixedClock(NOW + timedelta(microseconds=11))
        result = await OrderedReplayExecutor(
            access,
            repository,
            recovered_clock,
            "recovered-replay",
            page_size=1,
        ).execute(OPERATION_ID)
        assert result.state is ReplayRunState.READY
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM ordered_replay_sources),"
                        "(SELECT COUNT(*) FROM ordered_replay_shadow_history),"
                        "(SELECT COUNT(DISTINCT event_id) FROM ordered_replay_shadow_history)"
                    )
                )
            ).one()
        assert tuple(counts) == (2, 2, 2)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_replay_identity_conflict_and_revoked_grant_fail_closed(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        start = StartOrderedReplayHandler(access, repository, processor_clock())
        await start.execute(replay_request())
        with pytest.raises(IngestionConflictError):
            await start.execute(replay_request(from_ingested_at_microseconds=1))
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:now WHERE id=:grant"),
                {
                    "grant": GRANT_ID,
                    "now": round((NOW - timedelta(seconds=1)).timestamp() * 1_000_000),
                },
            )
        with pytest.raises(IngestionAuthorizationError):
            await start.execute(
                replay_request(
                    operation_id="018f0000-0000-7000-8000-000000000205",
                    projection_generation="018f0000-0000-7000-8000-000000000206",
                )
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_empty_snapshot_partial_resume_and_expired_lease_recovery(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_capture_authority(store)
        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        now = round(NOW.timestamp() * 1_000_000)
        queued = await StartOrderedReplayHandler(access, repository, processor_clock()).execute(
            replay_request()
        )
        assert queued.source_count == 0
        assert queued.source_watermark_event_id == OPERATION_ID
        assert await repository.next_runnable(now) == OPERATION_ID
        with pytest.raises(IngestionIntegrityError):
            await repository.claim(OPERATION_ID, "worker", now, now)

        building = await repository.claim(OPERATION_ID, "worker", now, now + 10)
        with pytest.raises(IngestionIntegrityError):
            await repository.mark_partial(building, "", now)
        partial = await repository.mark_partial(building, "dependency_unavailable", now)
        assert partial.state is ReplayRunState.PARTIAL
        assert await repository.next_runnable(now) == OPERATION_ID

        building = await repository.claim(OPERATION_ID, "worker-2", now, now + 10)
        assert await repository.recover_expired(now + 9) == 0
        assert await repository.recover_expired(now + 10) == 1
        recovered = await repository.get(OPERATION_ID)
        assert recovered is not None
        assert recovered.state is ReplayRunState.PARTIAL
        result = await OrderedReplayExecutor(
            access,
            repository,
            FixedClock(NOW + timedelta(microseconds=11)),
            "worker-3",
        ).execute(OPERATION_ID)
        assert result.state is ReplayRunState.READY
        assert result.source_count == result.processed_count == 0
        assert await repository.next_runnable(now + 11) is None
        assert building.processed_count == 0
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_replay_source_snapshot_excludes_events_committed_after_creation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(sequence=1))
        first, _ = processor(store, key_file, "snapshot-live-1")
        assert (await first.execute_once()).disposition is ProcessingDisposition.COMPLETED

        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        queued = await StartOrderedReplayHandler(access, repository, processor_clock()).execute(
            replay_request()
        )
        assert queued.source_count == 1

        await capture.execute(event(event_id=EVENT_ID_2, sequence=2))
        building = await repository.claim(
            OPERATION_ID,
            "snapshot-reader",
            round(NOW.timestamp() * 1_000_000),
            round(NOW.timestamp() * 1_000_000) + 10,
        )
        with pytest.raises(IngestionIntegrityError):
            await repository.read_page(building, 0)
        with pytest.raises(IngestionIntegrityError):
            await repository.read_page(building, 4097)
        page = await repository.read_page(building, 4096)
        assert page.complete
        assert tuple(item.reduction.event_id for item in page.records) == (EVENT_ID,)
        with pytest.raises(IngestionIntegrityError):
            await repository.append(
                building,
                replace(page.records[0], source_ordinal=2),
                "0" * 64,
                None,
                "f" * 64,
                round(NOW.timestamp() * 1_000_000),
            )
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM ordered_replay_sources"))
            ).scalar_one() == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_replay_rejects_provider_result_changed_after_live_reduction(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        capture = capture_handler(store, key_file)
        await capture.execute(event(event_id=EVENT_ID_2, sequence=1))
        now = round(NOW.timestamp() * 1_000_000)
        await _seed_recorded_provider_evidence(store, now)
        live, _ = processor(store, key_file, "recorded-live")
        assert (await live.execute_once()).disposition is ProcessingDisposition.COMPLETED

        repository = SqliteOrderedReplayRepository(store)
        access = SqliteOrderedReplayAccessPolicy(store)
        await StartOrderedReplayHandler(access, repository, processor_clock()).execute(
            replay_request()
        )
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE provider_operation_results SET result_ref=:changed "
                    "WHERE operation_id=:operation"
                ),
                {
                    "changed": f"cas://sha256/{'e' * 64}",
                    "operation": PROVIDER_OPERATION_ID,
                },
            )
        building = await repository.claim(OPERATION_ID, "tamper-check", now, now + 10)
        with pytest.raises(IngestionIntegrityError):
            await repository.read_page(building, 1)
    finally:
        await store.close()


def processor_clock() -> FixedClock:
    return FixedClock(NOW)
