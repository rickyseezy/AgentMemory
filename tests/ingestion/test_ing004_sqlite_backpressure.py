"""ING-004 real SQLite capacity, fairness, retry, DLQ, and recovery tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, cast

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.payload_reader import InlineOnlyPayloadReader
from agentmemory.ingestion.adapters.outbound.sqlite_backpressure import (
    SqliteCaptureCapacityEnforcer,
    SqliteJobSchedulerAccessPolicy,
    SqliteJobSchedulerRepository,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAdapterCapabilityRegistry,
    SqliteAgentEventScopeResolver,
    SqliteAgentEventUnitOfWorkFactory,
)
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
from agentmemory.ingestion.application.capture_agent_event import CaptureAgentEventHandler
from agentmemory.ingestion.domain.backpressure import (
    JobErrorCode,
    JobPriority,
    JobRequest,
    JobState,
    QueueLimits,
    ReplayDeadLetterRequest,
    RetryPolicy,
)
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionCapacityError,
    IngestionConflictError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, FixedClock, digest, migrated_store, write_secret
from tests.ingestion.adp002_support import NOW as EVENT_NOW
from tests.ingestion.adp002_support import PRINCIPAL_ID, event
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority

if TYPE_CHECKING:
    from pathlib import Path

JOB_ID = "018f0000-0000-7001-8000-000000000001"
NOW_US = round(FixedClock().now().timestamp() * 1_000_000)


@dataclass
class FreeBytes:
    value: int = 10_000_000

    def free_bytes(self) -> int:
        return self.value


def limits(**changes: object) -> QueueLimits:
    value = QueueLimits(4, 10, 2, 2, 1_000_000, 500_000, 8, (50, 75, 100))
    return replace(value, **cast("Any", changes))


def request(index: int = 1, **changes: object) -> JobRequest:
    value = JobRequest(
        f"018f0000-0000-7{index:03x}-8000-{index:012x}",
        BRAIN_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        "memory-index",
        f"memory-index:event-{index}",
        digest(f"request-{index}").value,
        JobPriority.STANDARD,
        "cas://sha256/" + digest(f"input-{index}").value,
    )
    return replace(value, **cast("Any", changes))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_submit_is_concurrently_idempotent_and_hard_disk_preserves_exact_retry(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    probe = FreeBytes()
    repository = SqliteJobSchedulerRepository(store, probe)
    try:
        await seed_capture_authority(store)
        results = await asyncio.gather(
            *(repository.submit(request(), limits(), NOW_US) for _ in range(20))
        )
        assert {item.request.job_id for item in results} == {request().job_id}
        probe.value = 0
        assert (await repository.submit(request(), limits(), NOW_US)).request.job_id == JOB_ID
        with pytest.raises(IngestionCapacityError) as captured:
            await repository.submit(request(2), limits(), NOW_US)
        assert captured.value.reason_code == "disk_hard_limit"
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM job_authorizations"))
            ).scalar_one() == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_reserved_capacity_and_soft_background_delay_protect_capture_and_interactive(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteJobSchedulerRepository(store, FreeBytes())
    policy = limits(soft_pending=2, hard_pending=6, reserved_interactive=1, reserved_capture=1)
    try:
        await seed_capture_authority(store)
        await repository.submit(request(1), policy, NOW_US)
        await repository.submit(request(2), policy, NOW_US)
        background = await repository.submit(
            request(3, priority=JobPriority.BACKGROUND), policy, NOW_US
        )
        capture = await repository.submit(request(4, priority=JobPriority.CAPTURE), policy, NOW_US)
        assert background.next_attempt_at_microseconds == NOW_US + 1_000_000
        assert capture.next_attempt_at_microseconds == NOW_US
        await repository.submit(request(5, priority=JobPriority.CAPTURE), policy, NOW_US)
        with pytest.raises(IngestionCapacityError):
            await repository.submit(request(6, priority=JobPriority.STANDARD), policy, NOW_US)
        interactive = await repository.submit(
            request(7, priority=JobPriority.INTERACTIVE), policy, NOW_US
        )
        assert interactive.state is JobState.QUEUED
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_persisted_weighted_fairness_dispatches_every_nonempty_priority_queue(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteJobSchedulerRepository(store, FreeBytes())
    policy = limits(soft_pending=20, hard_pending=40, reserved_interactive=5, reserved_capture=5)
    priorities = tuple(JobPriority)
    try:
        await seed_capture_authority(store)
        for index in range(1, 17):
            await repository.submit(
                request(index, priority=priorities[(index - 1) % len(priorities)]),
                policy,
                NOW_US,
            )
        selected: list[JobPriority] = []
        for index in range(8):
            claimed = await repository.claim_next("worker-v1", NOW_US, NOW_US + 10_000_000, policy)
            assert claimed is not None
            selected.append(claimed.request.priority)
            await repository.succeed(
                claimed,
                "worker-v1",
                digest(f"result-{index}").value,
                NOW_US + index + 1,
            )
        assert set(selected) == set(JobPriority)
        assert selected.count(JobPriority.INTERACTIVE) > selected.count(JobPriority.BACKGROUND)
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT dispatch_cursor FROM scheduler_state WHERE singleton_id=1")
                )
            ).scalar_one() > 0
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_bounded_retry_enters_immutable_dlq_and_replay_is_linked_and_idempotent(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteJobSchedulerRepository(store, FreeBytes())
    policy = limits()
    retry = RetryPolicy.default()
    try:
        await seed_capture_authority(store)
        await repository.submit(request(), policy, NOW_US)
        job = await repository.claim_next("worker-v1", NOW_US, NOW_US + 10, policy)
        assert job is not None
        terminal = await repository.fail(
            job,
            "worker-v1",
            JobErrorCode.POISON_JOB,
            retry.decide(JobErrorCode.POISON_JOB, job.attempts),
            "malformed_projection_input",
            NOW_US + 1,
        )
        assert terminal.state is JobState.DEAD_LETTERED
        dead = (await repository.list_dead_letters(BRAIN_ID, maximum=10))[0]
        replay = ReplayDeadLetterRequest(
            "018f0000-0000-7000-8000-000000000401",
            dead.dead_letter_id,
            "018f0000-0000-7000-8000-000000000402",
            PRINCIPAL_ID,
            GRANT_ID,
            digest("corrected").value,
            "cas://sha256/" + digest("corrected-input").value,
        )
        replayed = await repository.replay_dead_letter(replay, policy, NOW_US + 2)
        repeated = await repository.replay_dead_letter(replay, policy, NOW_US + 3)
        assert replayed == repeated
        assert replayed.parent_job_id == job.request.job_id
        assert replayed.source_dead_letter_id == dead.dead_letter_id
        assert (await repository.list_dead_letters(BRAIN_ID, maximum=10)) == (dead,)
        with pytest.raises(IngestionConflictError):
            await repository.replay_dead_letter(
                replace(replay, corrected_request_sha256=digest("other").value),
                policy,
                NOW_US + 4,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_expired_lease_recovery_and_alert_thresholds_are_durable_and_idempotent(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteJobSchedulerRepository(store, FreeBytes())
    policy = limits(soft_pending=2, hard_pending=4, reserved_interactive=1, reserved_capture=1)
    try:
        await seed_capture_authority(store)
        await repository.submit(request(1), policy, NOW_US)
        await repository.submit(request(2, priority=JobPriority.CAPTURE), policy, NOW_US)
        claimed = await repository.claim_next("dead-worker", NOW_US, NOW_US + 10, policy)
        assert claimed is not None
        assert await repository.recover_expired(NOW_US + 11) == 1
        recovered = await repository.get(claimed.request.job_id)
        assert recovered is not None
        assert recovered.state is JobState.RETRY_SCHEDULED
        assert recovered.last_error_code is JobErrorCode.TRANSIENT_STORAGE
        assert await repository.recover_expired(NOW_US + 12) == 0
        async with store.engine.connect() as connection:
            alerts = (
                await connection.execute(
                    text(
                        "SELECT metric,threshold_percent FROM scheduler_alerts "
                        "ORDER BY metric,threshold_percent"
                    )
                )
            ).all()
        assert ("queue_pending", 50) in alerts
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_dlq_access_policy_rejects_wrong_or_expired_grant(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    access = SqliteJobSchedulerAccessPolicy(store)
    try:
        await seed_capture_authority(store)
        await access.authorize(PRINCIPAL_ID, GRANT_ID, BRAIN_ID, NOW_US)
        with pytest.raises(IngestionAuthorizationError):
            await access.authorize(
                PRINCIPAL_ID,
                "018f0000-0000-7000-8000-000000000999",
                BRAIN_ID,
                NOW_US,
            )
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:expired WHERE id=:grant"),
                {"expired": NOW_US + 1, "grant": GRANT_ID},
            )
        with pytest.raises(IngestionAuthorizationError):
            await access.authorize(PRINCIPAL_ID, GRANT_ID, BRAIN_ID, NOW_US + 2)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.resilience
async def test_capture_hard_disk_failure_is_atomic_and_acknowledged_retry_survives(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    clock = FixedClock(EVENT_NOW)
    probe = FreeBytes(value=10_000_000)
    capacity = SqliteCaptureCapacityEnforcer(probe, limits())
    handler = CaptureAgentEventHandler(
        SqliteAdapterCapabilityRegistry(store.engine),
        SqliteAgentEventScopeResolver(store.engine, clock),
        InlineOnlyPayloadReader(),
        AppendAgentEventHandler(
            CanonicalAgentEventEncoder(),
            AesGcmAgentEventEncryptor(SqliteWrappedBrainKeyProvider(store, key_file, clock)),
            SqliteAgentEventUnitOfWorkFactory(store, clock, capacity),
        ),
        clock,
    )
    try:
        await seed_capture_authority(store)
        accepted = await handler.execute(event())
        probe.value = 0
        duplicate = await handler.execute(event())
        assert accepted.disposition is AppendDisposition.ACCEPTED
        assert duplicate.disposition is AppendDisposition.DUPLICATE
        with pytest.raises(IngestionCapacityError):
            await handler.execute(
                replace(event(), event_id="018f0000-0000-7000-8000-000000000199", sequence=2)
            )
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM agent_events"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM outbox_messages"))
            ).scalar_one() == 1
    finally:
        await store.close()
