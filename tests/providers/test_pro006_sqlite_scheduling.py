"""PRO-006 real SQLite fairness, rate, lease, cancellation, and result tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.providers.adapters.sqlite_embedding_spaces import (
    SqliteEmbeddingSpaceRepository,
)
from agentmemory.providers.adapters.sqlite_scheduling import (
    SqliteProviderDispatchAuthorization,
    SqliteProviderSchedulingRepository,
)
from agentmemory.providers.domain.errors import (
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingConflictError,
)
from agentmemory.providers.domain.routing import ProviderWorkload
from agentmemory.providers.domain.scheduling import (
    ProviderBatchKey,
    ProviderBatchOutcome,
    ProviderDeadlineClass,
    ProviderItemResult,
    ProviderItemResultStatus,
    ProviderWorkState,
)
from tests.core.support import NOW, digest, migrated_store
from tests.providers.test_pro001_profiles_domain_application import PROFILE_ID, scope
from tests.providers.test_pro004_sqlite_embedding_spaces import (
    attested_descriptor,
    candidates,
    seed_active_provider,
)
from tests.providers.test_pro006_scheduling_domain import item

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.scheduling import ProviderWorkItem


async def _seed(store: SqliteCoreStore) -> ProviderBatchKey:
    attestation_id = await seed_active_provider(store)
    embedding_space, generation = candidates(
        attestation_id,
        space_descriptor=attested_descriptor(),
    )
    spaces = SqliteEmbeddingSpaceRepository(store)
    await spaces.reserve(
        scope("provider.embedding_space.ensure"),
        "pro006-space-ensure",
        digest("pro006-space-request").value,
        embedding_space,
        generation,
    )
    await spaces.complete(
        scope("provider.embedding_space.ensure"),
        "pro006-space-ensure",
        generation.generation_id,
        NOW + timedelta(seconds=3),
    )
    baseline = item(0).batch_key
    return replace(
        baseline,
        project_id=None,
        repository_id=None,
        profile_id=PROFILE_ID,
        profile_version=2,
        space_id=embedding_space.space_id,
        space_fingerprint=embedding_space.immutable_fingerprint,
        purpose=embedding_space.descriptor.purpose,
    )


def _work(
    index: int,
    batch_key: ProviderBatchKey,
    **changes: object,
) -> ProviderWorkItem:
    return item(
        index,
        batch_key=batch_key,
        enqueued_at_microseconds=round(NOW.timestamp() * 1_000_000) + index,
        deadline_at_microseconds=round(NOW.timestamp() * 1_000_000) + 120_000_000,
        **changes,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_enqueue_is_exactly_idempotent_scoped_audited_and_content_free(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderSchedulingRepository(store)
    try:
        batch_key = await _seed(store)
        work = _work(0, batch_key)
        request_digest = digest("enqueue-request").value
        created = await repository.enqueue(
            scope("provider.schedule.enqueue"),
            work.operation_id,
            request_digest,
            work,
        )
        assert created == work
        assert (
            await repository.enqueue(
                scope("provider.schedule.enqueue"),
                work.operation_id,
                request_digest,
                replace(work, item_id="018f0000-0000-7000-8000-000000000998"),
            )
            == work
        )
        loaded = await repository.get(scope("provider.schedule.read"), work.item_id)
        assert loaded == work
        with pytest.raises(ProviderSchedulingConflictError):
            await repository.enqueue(
                scope("provider.schedule.enqueue"),
                work.operation_id,
                digest("different").value,
                work,
            )
        assert (
            await repository.get(
                scope("provider.schedule.read"),
                "018f0000-0000-7000-8000-000000000997",
            )
            is None
        )
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT payload_ref,content_digest,request_digest "
                        "FROM provider_work_items JOIN provider_scheduling_operations "
                        "ON provider_scheduling_operations.operation_id="
                        "provider_work_items.operation_id"
                    )
                )
            ).one()
            audit = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_events "
                        "WHERE action='provider.schedule.enqueued'"
                    )
                )
            ).scalar_one()
        assert tuple(row) == (
            work.payload_ref,
            bytes.fromhex(work.content_digest),
            bytes.fromhex(request_digest),
        )
        assert int(audit) == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_claim_batches_only_exact_partition_and_preserves_order(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderSchedulingRepository(store)
    try:
        batch_key = await _seed(store)
        work = (
            _work(0, batch_key, token_count=4, byte_count=40),
            _work(1, batch_key, token_count=6, byte_count=60),
            _work(
                2,
                replace(
                    batch_key,
                    preprocessing_digest=digest("other-preprocessing").value,
                ),
            ),
        )
        for value in work:
            await repository.enqueue(
                scope("provider.schedule.enqueue"),
                value.operation_id,
                digest(value.operation_id).value,
                value,
            )
        now = round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000)
        first = await repository.claim_next("provider-scheduler-v1", now, now + 60_000_000)
        assert first is not None
        assert tuple(child.item_id for child in first.batch.items) == (
            work[0].item_id,
            work[1].item_id,
        )
        assert first.batch.token_count == 10
        assert first.batch.byte_count == 100
        second = await repository.claim_next("provider-scheduler-v1", now, now + 60_000_000)
        assert second is None  # Profile concurrency is conservatively one.
        await repository.release(first, "dependency_unavailable", now + 1, now)
        second = await repository.claim_next(
            "provider-scheduler-v1",
            now + 1,
            now + 60_000_001,
        )
        assert second is not None
        assert tuple(child.item_id for child in second.batch.items) == (work[2].item_id,)
        assert second.batch.key.preprocessing_digest != first.batch.key.preprocessing_digest
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_weighted_fair_claims_bound_background_and_evaluation_starvation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderSchedulingRepository(store)
    try:
        base = await _seed(store)
        created: dict[ProviderWorkload, str] = {}
        for index, workload in enumerate(ProviderWorkload):
            deadline_class = (
                ProviderDeadlineClass.INTERACTIVE
                if workload is ProviderWorkload.INTERACTIVE
                else ProviderDeadlineClass.BACKGROUND
            )
            value = _work(
                index,
                replace(base, workload=workload, deadline_class=deadline_class),
            )
            created[workload] = value.item_id
            await repository.enqueue(
                scope("provider.schedule.enqueue"),
                value.operation_id,
                digest(value.operation_id).value,
                value,
            )
        now = round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000)
        selected: list[ProviderWorkload] = []
        for offset in range(9):
            lease = await repository.claim_next(
                "provider-scheduler-v1",
                now + offset,
                now + 60_000_000 + offset,
            )
            if lease is None:
                break
            selected.append(lease.batch.key.workload)
            outcome = ProviderBatchOutcome(
                lease.batch.operation_id,
                tuple(
                    ProviderItemResult.succeeded(child.item_id, digest(child.item_id).value)
                    for child in lease.batch.items
                ),
            )
            await repository.complete(lease, outcome, now + offset)
        assert set(selected) == set(ProviderWorkload)
        assert selected[0] is ProviderWorkload.INTERACTIVE
        assert ProviderWorkload.BACKFILL in selected[:7]
        assert ProviderWorkload.EVALUATION in selected[:9]
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_partial_completion_retries_only_retryable_child_and_honors_rate_hint(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderSchedulingRepository(store)
    try:
        batch_key = await _seed(store)
        work = tuple(_work(index, batch_key) for index in range(3))
        for value in work:
            await repository.enqueue(
                scope("provider.schedule.enqueue"),
                value.operation_id,
                digest(value.operation_id).value,
                value,
            )
        now = round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000)
        lease = await repository.claim_next(
            "provider-scheduler-v1",
            now,
            now + 60_000_000,
        )
        assert lease is not None
        retry_at = now + 30_000_000
        outcome = ProviderBatchOutcome(
            lease.batch.operation_id,
            (
                ProviderItemResult.succeeded(work[0].item_id, digest("result-0").value),
                ProviderItemResult.failed(
                    work[1].item_id,
                    ProviderItemResultStatus.RETRYABLE_FAILURE,
                    "rate_limit",
                    retry_at_microseconds=retry_at,
                ),
                ProviderItemResult.failed(
                    work[2].item_id,
                    ProviderItemResultStatus.PERMANENT_FAILURE,
                    "invalid_input",
                ),
            ),
        )
        await repository.complete(lease, outcome, now + 1)
        succeeded = await repository.get(scope("provider.schedule.read"), work[0].item_id)
        retry_scheduled = await repository.get(scope("provider.schedule.read"), work[1].item_id)
        failed = await repository.get(scope("provider.schedule.read"), work[2].item_id)
        assert succeeded is not None
        assert succeeded.state is ProviderWorkState.COMPLETED
        assert retry_scheduled is not None
        assert retry_scheduled.state is ProviderWorkState.RETRY_SCHEDULED
        assert failed is not None
        assert failed.state is ProviderWorkState.FAILED
        assert (
            await repository.claim_next(
                "provider-scheduler-v1",
                retry_at - 1,
                retry_at + 60_000_000,
            )
            is None
        )
        retry = await repository.claim_next(
            "provider-scheduler-v1",
            retry_at,
            retry_at + 60_000_000,
        )
        assert retry is not None
        assert tuple(child.item_id for child in retry.batch.items) == (work[1].item_id,)
        assert retry.attempt == 2
        async with store.engine.connect() as connection:
            result_count = (
                await connection.execute(text("SELECT COUNT(*) FROM provider_item_results"))
            ).scalar_one()
        assert int(result_count) == 3
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_cancellation_and_expired_lease_recovery_are_compare_and_swap_safe(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderSchedulingRepository(store)
    try:
        batch_key = await _seed(store)
        queued = _work(0, batch_key)
        leased = _work(1, batch_key)
        for value in (queued, leased):
            await repository.enqueue(
                scope("provider.schedule.enqueue"),
                value.operation_id,
                digest(value.operation_id).value,
                value,
            )
        cancelled = await repository.cancel(
            scope("provider.schedule.cancel"),
            "cancel-pro006-queued",
            queued.item_id,
            round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000),
        )
        assert cancelled.state is ProviderWorkState.CANCELLED
        now = round((NOW + timedelta(seconds=5)).timestamp() * 1_000_000)
        lease = await repository.claim_next("provider-scheduler-v1", now, now + 10)
        assert lease is not None
        assert tuple(child.item_id for child in lease.batch.items) == (leased.item_id,)
        assert await repository.recover_expired(now + 9) == 0
        assert await repository.recover_expired(now + 10) == 1
        reclaimed = await repository.claim_next(
            "provider-scheduler-v2",
            now + 10,
            now + 100,
        )
        assert reclaimed is not None
        assert reclaimed.attempt == 2
        with pytest.raises(ProviderSchedulingConflictError):
            await repository.release(lease, "dependency_unavailable", now + 20, now + 10)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_final_dispatch_authorization_rechecks_grant_profile_space_and_payload(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderSchedulingRepository(store)
    authorizer = SqliteProviderDispatchAuthorization(store)
    try:
        batch_key = await _seed(store)
        work = _work(0, batch_key)
        await repository.enqueue(
            scope("provider.schedule.enqueue"),
            work.operation_id,
            digest(work.operation_id).value,
            work,
        )
        now = round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000)
        await authorizer.authorize(work, now)
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:now"),
                {"now": now},
            )
        with pytest.raises(ProviderSchedulingAuthorizationError):
            await authorizer.authorize(work, now)
        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="provider work identity"):
                await connection.execute(
                    text(
                        "UPDATE provider_work_items SET preprocessing_digest=:changed "
                        "WHERE item_id=:item"
                    ),
                    {"changed": bytes.fromhex(digest("tamper").value), "item": work.item_id},
                )
    finally:
        await store.close()
