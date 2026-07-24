"""ING-002 real SQLite provider idempotency, billing, and crash tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

import pytest
from sqlalchemy import text

from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.providers.adapters.sqlite_operation_cache import (
    SqliteProviderOperationCache,
)
from agentmemory.providers.application.idempotent_execution import (
    ExecuteProviderOperationHandler,
)
from agentmemory.providers.domain.errors import (
    ProviderOperationConflictError,
    ProviderOperationDependencyError,
)
from agentmemory.providers.domain.idempotency import (
    ProviderClaimDisposition,
    ProviderOperationClaim,
    ProviderOperationOutcome,
    ProviderOperationRequest,
    ProviderPrivacyClass,
    ProviderPurpose,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock, bootstrap_request, digest, migrated_store

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

PROFILE_ID = "018f0000-0000-7000-8000-000000000601"
OPERATION_ID = "018f0000-0000-7000-8000-000000000602"
OTHER_OPERATION_ID = "018f0000-0000-7000-8000-000000000603"
RESULT_DIGEST = digest("provider-result").value


def operation(**changes: object) -> ProviderOperationRequest:
    value = ProviderOperationRequest(
        operation_id=OPERATION_ID,
        idempotency_key="embed:session-1:document-1",
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        model_revision="a" * 40,
        purpose=ProviderPurpose.EMBED_DOCUMENT,
        content_sha256=(digest("provider-content").value,),
        preprocessing_revision="source-text-v1",
        privacy_class=ProviderPrivacyClass.INTERNAL,
    )
    return replace(value, **cast("Any", changes))


def outcome() -> ProviderOperationOutcome:
    return ProviderOperationOutcome(
        RESULT_DIGEST,
        f"cas://sha256/{RESULT_DIGEST}",
        11,
    )


async def bootstrap(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock(NOW))).execute(
        bootstrap_request()
    )


@dataclass
class _BillingProvider:
    delay_seconds: float = 0
    calls: int = 0
    charges: int = 0
    results: dict[str, ProviderOperationOutcome] = field(
        default_factory=dict[str, ProviderOperationOutcome]
    )
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def execute(
        self,
        operation: ProviderOperationRequest,
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        del operation
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        async with self.lock:
            cached = self.results.get(downstream_idempotency_key)
            if cached is not None:
                return cached
            self.charges += 1
            self.results[downstream_idempotency_key] = outcome()
            return outcome()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_duplicate_storm_executes_and_bills_once(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await bootstrap(store)
        backend = _BillingProvider(delay_seconds=0.005)
        handlers = tuple(
            ExecuteProviderOperationHandler(
                SqliteProviderOperationCache(store),
                backend,
                FixedClock(NOW),
                f"provider-worker-{index}",
                poll_seconds=0.001,
            )
            for index in range(32)
        )
        results = await asyncio.gather(*(handler.execute(operation()) for handler in handlers))
        assert backend.calls == 1
        assert backend.charges == 1
        assert sum(not result.cached for result in results) == 1
        assert {result.outcome for result in results} == {outcome()}
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT state,attempts,result_sha256,usage_units "
                        "FROM provider_operation_results"
                    )
                )
            ).one()
            assert tuple(row) == ("completed", 1, bytes.fromhex(RESULT_DIGEST), 11)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_same_provider_id_with_different_request_is_rejected_and_audited(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await bootstrap(store)
        cache = SqliteProviderOperationCache(store)
        backend = _BillingProvider()
        handler = ExecuteProviderOperationHandler(
            cache, backend, FixedClock(NOW), "provider-worker-1", poll_seconds=0
        )
        await handler.execute(operation())
        conflicting = operation(operation_id=OTHER_OPERATION_ID)
        with pytest.raises(ProviderOperationConflictError, match="different input"):
            await handler.execute(conflicting)
        with pytest.raises(ProviderOperationConflictError):
            await handler.execute(conflicting)
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM idempotency_conflicts"))
            ).scalar_one() == 1
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_events "
                        "WHERE action='provider.idempotency_conflict'"
                    )
                )
            ).scalar_one() == 1
        assert backend.charges == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_semantic_cache_key_replays_across_distinct_caller_key(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await bootstrap(store)
        backend = _BillingProvider()
        handler = ExecuteProviderOperationHandler(
            SqliteProviderOperationCache(store),
            backend,
            FixedClock(NOW),
            "provider-worker-1",
            poll_seconds=0,
        )
        first = await handler.execute(operation())
        second = await handler.execute(
            operation(operation_id=OTHER_OPERATION_ID, idempotency_key="embed:another-caller")
        )
        assert first.cached is False
        assert second.cached is True
        assert backend.charges == 1
    finally:
        await store.close()


@dataclass
class _FailFirstCompletion:
    delegate: SqliteProviderOperationCache
    remaining_failures: int = 1

    async def claim(
        self,
        operation: ProviderOperationRequest,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderOperationClaim:
        return await self.delegate.claim(
            operation,
            owner,
            now_microseconds,
            lease_until_microseconds,
        )

    async def complete(
        self,
        claim: ProviderOperationClaim,
        result: ProviderOperationOutcome,
        completed_at_microseconds: int,
    ) -> None:
        if self.remaining_failures:
            self.remaining_failures -= 1
            message = "simulated process death before commit"
            raise ProviderOperationDependencyError(message)
        await self.delegate.complete(claim, result, completed_at_microseconds)

    async def release_retry(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        await self.delegate.release_retry(claim, reason_code, retry_at_microseconds)

    async def fail(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        failed_at_microseconds: int,
    ) -> None:
        await self.delegate.fail(claim, reason_code, failed_at_microseconds)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_crash_after_provider_response_retries_same_billing_key_without_second_charge(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await bootstrap(store)
        backend = _BillingProvider()
        cache = _FailFirstCompletion(SqliteProviderOperationCache(store))
        with pytest.raises(ProviderOperationDependencyError, match="process death"):
            await ExecuteProviderOperationHandler(
                cache,
                backend,
                FixedClock(NOW),
                "provider-worker-1",
                poll_seconds=0,
            ).execute(operation())
        recovered = await ExecuteProviderOperationHandler(
            cache,
            backend,
            FixedClock(NOW + timedelta(seconds=61)),
            "provider-worker-2",
            poll_seconds=0,
        ).execute(operation())
        replayed = await ExecuteProviderOperationHandler(
            cache,
            backend,
            FixedClock(NOW + timedelta(seconds=62)),
            "provider-worker-3",
            poll_seconds=0,
        ).execute(operation())
        assert recovered.cached is False
        assert replayed.cached is True
        assert backend.calls == 2
        assert backend.charges == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_claim_crash_before_provider_send_is_reclaimed_after_lease(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await bootstrap(store)
        cache = SqliteProviderOperationCache(store)
        now = round(NOW.timestamp() * 1_000_000)
        abandoned = await cache.claim(operation(), "dead-worker", now, now + 10)
        assert abandoned.disposition is ProviderClaimDisposition.CLAIMED
        waiting = await cache.claim(operation(), "early-worker", now + 9, now + 20)
        assert waiting.disposition is ProviderClaimDisposition.WAIT
        reclaimed = await cache.claim(operation(), "new-worker", now + 10, now + 30)
        assert reclaimed.disposition is ProviderClaimDisposition.CLAIMED
        assert reclaimed.attempt == 2
    finally:
        await store.close()
