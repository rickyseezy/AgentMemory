"""PRO-010 real SQLite pricing, budget, telemetry, drift, and status tests."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.providers.adapters.sqlite_embedding_spaces import (
    SqliteEmbeddingSpaceRepository,
)
from agentmemory.providers.adapters.sqlite_observability import (
    SqliteProviderObservabilityRepository,
)
from agentmemory.providers.adapters.sqlite_profiles import SqliteProviderProfileRepository
from agentmemory.providers.application.observability import (
    ProviderOperationMeasurement,
    ProviderTelemetryRecorder,
    ReserveProviderBudgetCommand,
)
from agentmemory.providers.domain.embedding_spaces import IndexGenerationState
from agentmemory.providers.domain.errors import (
    ProviderDriftSuspendedError,
    ProviderErrorCode,
    ProviderObservabilityConflictError,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.observability import (
    BudgetDecision,
    BudgetExhaustionBehavior,
    DriftEvaluator,
    GenerationPinState,
    PricingSnapshot,
    ProviderBudgetPolicy,
    ProviderDriftProbeLease,
    ProviderOperationOutcome,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose, ProviderOperation
from tests.core.support import BRAIN_ID, NOW, digest, migrated_store
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    probe_result,
    scope,
)
from tests.providers.test_pro004_sqlite_embedding_spaces import (
    candidates,
    seed_active_provider,
)
from tests.providers.test_pro010_observability_domain import (
    GENERATION_ID,
    SPACE_ID,
    canary,
    observation,
    pricing,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.observability import DriftCanary


async def _seed_generation(store: SqliteCoreStore) -> DriftCanary:
    attestation_id = await seed_active_provider(store)
    embedding_space, generation = candidates(
        attestation_id,
        space_id=SPACE_ID,
        generation_id=GENERATION_ID,
    )
    spaces = SqliteEmbeddingSpaceRepository(store)
    await spaces.reserve(
        scope("provider.embedding_space.ensure"),
        "pro010-space",
        digest("pro010-space-request").value,
        embedding_space,
        generation,
    )
    await spaces.complete(
        scope("provider.embedding_space.ensure"),
        "pro010-space",
        GENERATION_ID,
        NOW + timedelta(seconds=3),
    )
    async with store.engine.begin() as connection:
        for state in (
            IndexGenerationState.VALIDATING,
            IndexGenerationState.SHADOW_READY,
            IndexGenerationState.ACTIVE,
        ):
            await connection.execute(
                text(
                    "UPDATE embedding_index_generations SET state=:state,"
                    "updated_at=updated_at+1,version=version+1 WHERE id=:generation"
                ),
                {"generation": GENERATION_ID, "state": state.value},
            )
        await connection.execute(
            text(
                "INSERT INTO active_embedding_generations "
                "(brain_id,purpose,space_id,generation_id,version,updated_at,schema_version) "
                "VALUES (:brain,'retrieval_document',:space,:generation,1,:updated,1)"
            ),
            {
                "brain": BRAIN_ID,
                "generation": GENERATION_ID,
                "space": SPACE_ID,
                "updated": round((NOW + timedelta(seconds=6)).timestamp() * 1_000_000),
            },
        )
    return canary(
        capability_attestation_id=attestation_id,
        revision_fingerprint=probe_result().revision_fingerprint,
    )


@pytest.mark.asyncio
async def test_drift_profile_source_binds_exact_generation_attestation_and_revision(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        contract = await _seed_generation(store)
        source = SqliteProviderProfileRepository(store)

        resolved = await source.get_drift_profile(contract)
        stale = await source.get_drift_profile(
            canary(
                capability_attestation_id=contract.capability_attestation_id,
                revision_fingerprint=digest("stale-revision").value,
            )
        )

        assert resolved is not None
        assert resolved[0].profile_id == contract.profile_id
        assert resolved[0].version == contract.profile_version
        assert resolved[1] is CanonicalPurpose.RETRIEVAL_DOCUMENT
        assert stale is None
    finally:
        await store.close()


def _budget(
    *,
    limit_micros: int = 1_000,
    behavior: BudgetExhaustionBehavior = BudgetExhaustionBehavior.QUEUE,
    degraded_channels: tuple[str, ...] = ("exact", "lexical", "graph"),
) -> ProviderBudgetPolicy:
    return ProviderBudgetPolicy.create(
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        version=1,
        currency="USD",
        limit_micros=limit_micros,
        behavior=behavior,
        degraded_channels=degraded_channels,
        period_start_microseconds=1_000_000,
        period_end_microseconds=2_000_000,
        created_at_microseconds=900_000,
    )


async def _publish_authority(
    repository: SqliteProviderObservabilityRepository,
    *,
    limit_micros: int = 1_000,
) -> tuple[PricingSnapshot, ProviderBudgetPolicy]:
    snapshot = pricing()
    policy = _budget(limit_micros=limit_micros)
    await repository.publish_pricing(
        scope("provider.observability.pricing.publish"),
        "pro010-pricing-publish",
        digest("pro010-pricing-publish").value,
        snapshot,
    )
    await repository.publish_budget(
        scope("provider.observability.budget.publish"),
        "pro010-budget-publish",
        digest("pro010-budget-publish").value,
        policy,
    )
    return snapshot, policy


@pytest.mark.asyncio
async def test_repository_rejects_missing_authority_and_invalid_schedule_coordinates(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.publish_pricing(
                scope("provider.observability.pricing.publish"),
                "pro010-missing-profile",
                digest("pro010-missing-profile").value,
                pricing(),
            )
        assert (
            await repository.get_canary(
                scope("provider.observability.drift.run"),
                canary().canary_id,
            )
            is None
        )
        with pytest.raises(ProviderObservabilityValidationError):
            await repository.claim_due("worker", -1, 1)
        lease = ProviderDriftProbeLease(
            canary=canary(),
            owner="worker",
            lease_until_microseconds=2_000_000,
            state_version=1,
        )
        with pytest.raises(ProviderObservabilityValidationError):
            await repository.release_probe(lease, 1, 1)
        with pytest.raises(ProviderObservabilityValidationError):
            await repository.status(
                scope("provider.observability.status.read"),
                -1,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_publication_rejects_missing_budget_catalog_and_non_monotonic_versions(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        contract = await _seed_generation(store)
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.publish_budget(
                scope("provider.observability.budget.publish"),
                "pro010-budget-without-pricing",
                digest("pro010-budget-without-pricing").value,
                _budget(),
            )

        snapshot, _ = await _publish_authority(repository)
        status = await repository.status(
            scope("provider.observability.status.read"),
            1_500_000,
        )
        assert status.health[0].status.value == "unavailable"
        non_monotonic_pricing = PricingSnapshot.create(
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            version=5,
            currency="USD",
            operation=ProviderOperation.EMBEDDING,
            request_micros=100,
            input_micros_per_million=2_000_000,
            output_micros_per_million=4_000_000,
            effective_from_microseconds=2_000_000,
            effective_until_microseconds=3_000_000,
            created_at_microseconds=1_900_000,
        )
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.publish_pricing(
                scope("provider.observability.pricing.publish"),
                "pro010-pricing-non-monotonic",
                digest("pro010-pricing-non-monotonic").value,
                non_monotonic_pricing,
            )

        non_monotonic_budget = ProviderBudgetPolicy.create(
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            version=3,
            currency="USD",
            limit_micros=1_000,
            behavior=BudgetExhaustionBehavior.QUEUE,
            degraded_channels=("exact", "lexical", "graph"),
            period_start_microseconds=1_000_000,
            period_end_microseconds=2_000_000,
            created_at_microseconds=900_000,
        )
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.publish_budget(
                scope("provider.observability.budget.publish"),
                "pro010-budget-non-monotonic",
                digest("pro010-budget-non-monotonic").value,
                non_monotonic_budget,
            )

        await repository.register_canary(
            scope("provider.observability.drift.register"),
            "pro010-canary-first",
            digest("pro010-canary-first").value,
            contract,
        )
        changed = canary(
            capability_attestation_id=contract.capability_attestation_id,
            revision_fingerprint=contract.revision_fingerprint,
            vector_fingerprint=digest("changed-baseline").value,
        )
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.register_canary(
                scope("provider.observability.drift.register"),
                "pro010-canary-conflict",
                digest("pro010-canary-conflict").value,
                changed,
            )
        assert await repository.get_pricing(snapshot.snapshot_id) == snapshot
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_pricing_and_budget_publication_are_versioned_current_and_replayable(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        await _seed_generation(store)
        snapshot, policy = await _publish_authority(repository)
        assert (
            await repository.publish_pricing(
                scope("provider.observability.pricing.publish"),
                "pro010-pricing-publish",
                digest("pro010-pricing-publish").value,
                snapshot,
            )
            == snapshot
        )
        assert (
            await repository.publish_budget(
                scope("provider.observability.budget.publish"),
                "pro010-budget-publish",
                digest("pro010-budget-publish").value,
                policy,
            )
            == policy
        )
        assert await repository.get_pricing(snapshot.snapshot_id) == snapshot
        assert (
            await repository.get_active_pricing(
                BRAIN_ID,
                PROFILE_ID,
                2,
                1_500_000,
            )
            == snapshot
        )
        assert (
            await repository.get_active_pricing(
                BRAIN_ID,
                PROFILE_ID,
                2,
                2_000_000,
            )
            is None
        )

        with pytest.raises(ProviderObservabilityConflictError):
            await repository.publish_pricing(
                scope("provider.observability.pricing.publish"),
                "pro010-pricing-publish",
                digest("different-request").value,
                snapshot,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_budget_race_serializes_reservations_without_silent_overrun(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        await _seed_generation(store)
        snapshot, _ = await _publish_authority(repository)

        def request(ordinal: int) -> ReserveProviderBudgetCommand:
            return ReserveProviderBudgetCommand(
                operation_id=f"pro010-budget-race-{ordinal}",
                brain_id=BRAIN_ID,
                profile_id=PROFILE_ID,
                profile_version=2,
                pricing_snapshot_id=snapshot.snapshot_id,
                estimated_cost_micros=600,
                requested_at_microseconds=1_500_000,
            )

        decisions = await asyncio.gather(
            repository.reserve_budget(request(1)),
            repository.reserve_budget(request(2)),
        )
        assert sorted(item.decision for item in decisions) == [
            BudgetDecision.QUEUED,
            BudgetDecision.RESERVED,
        ]
        assert sum(item.reserved_micros for item in decisions) == 600
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.reserve_budget(
                ReserveProviderBudgetCommand(
                    operation_id="pro010-budget-race-1",
                    brain_id=BRAIN_ID,
                    profile_id=PROFILE_ID,
                    profile_version=2,
                    pricing_snapshot_id=snapshot.snapshot_id,
                    estimated_cost_micros=601,
                    requested_at_microseconds=1_500_000,
                )
            )
        async with store.engine.connect() as connection:
            account = (
                (
                    await connection.execute(
                        text("SELECT spent_micros,reserved_micros FROM provider_budget_accounts")
                    )
                )
                .mappings()
                .one()
            )
        assert (int(account["spent_micros"]), int(account["reserved_micros"])) == (
            0,
            600,
        )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_degraded_budget_replay_preserves_the_exact_configured_channels(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        await _seed_generation(store)
        snapshot = pricing()
        policy = _budget(
            limit_micros=500,
            behavior=BudgetExhaustionBehavior.DEGRADE,
            degraded_channels=("exact", "graph"),
        )
        await repository.publish_pricing(
            scope("provider.observability.pricing.publish"),
            "pro010-pricing-degrade",
            digest("pro010-pricing-degrade").value,
            snapshot,
        )
        await repository.publish_budget(
            scope("provider.observability.budget.publish"),
            "pro010-budget-degrade",
            digest("pro010-budget-degrade").value,
            policy,
        )
        reservation = ReserveProviderBudgetCommand(
            operation_id="pro010-budget-degrade-reservation",
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            pricing_snapshot_id=snapshot.snapshot_id,
            estimated_cost_micros=600,
            requested_at_microseconds=1_500_000,
        )

        first = await repository.reserve_budget(reservation)
        replay = await repository.reserve_budget(reservation)

        assert first == replay
        assert first.decision is BudgetDecision.DEGRADED
        assert first.degraded_channels == ("exact", "graph")
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_telemetry_reconciles_actual_cost_once_and_status_uses_safe_aggregates(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        await _seed_generation(store)
        snapshot, _ = await _publish_authority(repository, limit_micros=2_000)
        reservation = ReserveProviderBudgetCommand(
            operation_id="pro010-telemetry-operation",
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            pricing_snapshot_id=snapshot.snapshot_id,
            estimated_cost_micros=1_000,
            requested_at_microseconds=1_500_000,
        )
        assert (await repository.reserve_budget(reservation)).decision is BudgetDecision.RESERVED
        measurement = ProviderOperationMeasurement(
            operation_id=reservation.operation_id,
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            space_id=SPACE_ID,
            generation_id=GENERATION_ID,
            pricing_snapshot_id=snapshot.snapshot_id,
            outcome=ProviderOperationOutcome.SUCCEEDED,
            error_code=None,
            request_count=1,
            item_count=2,
            input_units=100,
            output_units=0,
            request_bytes=256,
            response_bytes=512,
            attempt_count=1,
            latency_microseconds=40_000,
            estimated_cost_micros=1_000,
            cache_hit=False,
            deduplicated=False,
            occurred_at_microseconds=1_500_000,
            operation=ProviderOperation.EMBEDDING,
        )
        recorder = ProviderTelemetryRecorder(repository, repository)
        fact = await recorder.record(measurement)
        await repository.record_and_reconcile(fact)

        retry_reservation = ReserveProviderBudgetCommand(
            operation_id="pro010-telemetry-retry",
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            pricing_snapshot_id=snapshot.snapshot_id,
            estimated_cost_micros=100,
            requested_at_microseconds=1_500_001,
        )
        assert (
            await repository.reserve_budget(retry_reservation)
        ).decision is BudgetDecision.RESERVED
        retry_fact = await recorder.record(
            ProviderOperationMeasurement(
                operation_id=retry_reservation.operation_id,
                brain_id=BRAIN_ID,
                profile_id=PROFILE_ID,
                profile_version=2,
                space_id=SPACE_ID,
                generation_id=GENERATION_ID,
                pricing_snapshot_id=snapshot.snapshot_id,
                outcome=ProviderOperationOutcome.RETRY_SCHEDULED,
                error_code=ProviderErrorCode.RATE_LIMIT,
                request_count=1,
                item_count=1,
                input_units=0,
                output_units=0,
                request_bytes=1,
                response_bytes=0,
                attempt_count=1,
                latency_microseconds=50_000,
                estimated_cost_micros=100,
                cache_hit=False,
                deduplicated=False,
                occurred_at_microseconds=1_500_001,
                operation=ProviderOperation.EMBEDDING,
            )
        )

        status = await repository.status(
            scope("provider.observability.status.read"),
            1_600_000,
        )
        assert status.health[0].requests == 2
        assert status.health[0].latency_p95_microseconds == 50_000
        assert status.budgets[0].spent_micros == (
            fact.actual_cost_micros + retry_fact.actual_cost_micros
        )
        assert status.budgets[0].reserved_micros == 0
        assert status.health[0].safe_errors == ((ProviderErrorCode.RATE_LIMIT, 1),)
        assert status.generations[0].pin_state is GenerationPinState.PINNED
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_drift_mismatch_suspends_generation_and_database_rejects_new_writes(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        contract = await _seed_generation(store)
        await repository.register_canary(
            scope("provider.observability.drift.register"),
            "pro010-canary-register",
            digest("pro010-canary-register").value,
            contract,
        )
        assert (
            await repository.get_canary(
                scope("provider.observability.drift.run"),
                contract.canary_id,
            )
            == contract
        )
        stable_observation = observation(revision_fingerprint=contract.revision_fingerprint)
        stable_evaluation = DriftEvaluator.evaluate(contract, stable_observation)
        await repository.record_drift(stable_observation, stable_evaluation)
        await repository.record_drift(stable_observation, stable_evaluation)
        await repository.assert_generation_writable(
            BRAIN_ID,
            SPACE_ID,
            GENERATION_ID,
        )

        changed = observation(revision_fingerprint=digest("silent-model-change").value)
        evaluation = DriftEvaluator.evaluate(contract, changed)
        await repository.record_drift(changed, evaluation)
        changed_again = observation(
            revision_fingerprint=digest("silent-model-change-again").value,
            observed_at_microseconds=1_500_001,
        )
        await repository.record_drift(
            changed_again,
            DriftEvaluator.evaluate(contract, changed_again),
        )
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.record_drift(
                observation(canary_id="018f0000-0000-7000-8000-000000001099"),
                stable_evaluation,
            )
        with pytest.raises(ProviderDriftSuspendedError):
            await repository.assert_generation_writable(
                BRAIN_ID,
                SPACE_ID,
                GENERATION_ID,
            )
        status = await repository.status(
            scope("provider.observability.status.read"),
            1_700_000,
        )
        assert status.generations[0].write_suspended is True
        assert status.generations[0].pin_state is GenerationPinState.DRIFT_SUSPECTED
        assert status.active_alert_count == 1

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="provider generation write suspended"):
                await connection.execute(
                    text(
                        "INSERT INTO provider_work_items "
                        "(item_id,operation_id,brain_id,principal_id,grant_version,"
                        "authorization_policy_version,security_epoch,scope_fingerprint,"
                        "project_id,repository_id,profile_id,profile_version,space_id,"
                        "space_fingerprint,classification,purpose,retention_policy_digest,"
                        "preprocessing_digest,deadline_class,workload,batch_key_digest,"
                        "ordinal,payload_ref,content_digest,token_count,byte_count,"
                        "estimated_cost_micros,state,attempts,next_attempt_at,lease_owner,"
                        "lease_until,cancel_requested,last_error_code,enqueued_at,deadline_at,"
                        "updated_at,completed_at,schema_version) VALUES "
                        "(:item,:operation,:brain,:principal,1,1,1,:scope,NULL,NULL,:profile,"
                        "2,:space,:fingerprint,'internal','retrieval_document',:retention,"
                        ":preprocessing,'online','capture',:batch,0,'cas://payload',:content,"
                        "1,1,1,'queued',0,1,NULL,NULL,0,NULL,1,2,1,NULL,1)"
                    ),
                    {
                        "batch": bytes.fromhex(digest("batch").value),
                        "brain": BRAIN_ID,
                        "content": bytes.fromhex(digest("content").value),
                        "fingerprint": bytes.fromhex(digest("space").value),
                        "item": "018f0000-0000-7000-8000-000000001011",
                        "operation": "pro010-drift-blocked-work",
                        "preprocessing": bytes.fromhex(digest("preprocessing").value),
                        "principal": "018f0000-0000-7000-8000-000000000002",
                        "profile": PROFILE_ID,
                        "retention": bytes.fromhex(digest("retention").value),
                        "scope": bytes.fromhex(digest("scope").value),
                        "space": SPACE_ID,
                    },
                )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_drift_schedule_leases_once_completes_and_recovers_expired_owner(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderObservabilityRepository(store)
    try:
        contract = await _seed_generation(store)
        await repository.register_canary(
            scope("provider.observability.drift.register"),
            "pro010-canary-schedule",
            digest("pro010-canary-schedule").value,
            contract,
        )
        first, second = await asyncio.gather(
            repository.claim_due("drift-worker-a", 1_500_000, 1_600_000),
            repository.claim_due("drift-worker-b", 1_500_000, 1_600_000),
        )
        lease = first or second
        assert lease is not None
        assert (first is None) != (second is None)

        await repository.release_probe(lease, 1_700_000, 1_550_000)
        with pytest.raises(ProviderObservabilityConflictError):
            await repository.release_probe(lease, 1_700_000, 1_550_000)
        assert await repository.claim_due("drift-worker-b", 1_650_000, 1_750_000) is None
        recovered = await repository.claim_due(
            "drift-worker-b",
            1_700_000,
            1_800_000,
        )
        assert recovered is not None
        observed = observation(
            revision_fingerprint=contract.revision_fingerprint,
            observed_at_microseconds=1_700_001,
        )
        evaluation = DriftEvaluator.evaluate(contract, observed)
        await repository.complete_probe(recovered, observed, evaluation)
        assert await repository.claim_due("drift-worker-c", 1_700_001, 1_800_001) is None
    finally:
        await store.close()
