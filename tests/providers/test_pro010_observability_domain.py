"""PRO-010 pure pricing, budget, drift, telemetry, and status invariants."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from agentmemory.providers.domain import observability as observability_module
from agentmemory.providers.domain.capability_probe import ProviderProbeSuite, probe_canaries
from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.observability import (
    BudgetAdmission,
    BudgetDecision,
    BudgetExhaustionBehavior,
    DriftCanary,
    DriftEvaluation,
    DriftEvaluator,
    DriftObservation,
    DriftVerdict,
    GenerationPinState,
    PricingSnapshot,
    ProviderBudgetPolicy,
    ProviderBudgetReservationRequest,
    ProviderBudgetStatus,
    ProviderDriftProbeLease,
    ProviderGenerationStatus,
    ProviderHealth,
    ProviderHealthStatus,
    ProviderOperationFact,
    ProviderOperationOutcome,
    ProviderQueueStatus,
    ProviderStatusSnapshot,
)
from agentmemory.providers.domain.profiles import ProviderOperation
from tests.core.support import BRAIN_ID, digest
from tests.providers.test_pro001_profiles_domain_application import PROFILE_ID

GENERATION_ID = "018f0000-0000-7000-8000-000000001001"
SPACE_ID = "018f0000-0000-7000-8000-000000001002"
CANARY_ID = "018f0000-0000-7000-8000-000000001003"


def pricing(**changes: object) -> PricingSnapshot:
    """Build one immutable administrator-supplied pricing version."""
    value = PricingSnapshot.create(
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        version=3,
        currency="USD",
        operation=ProviderOperation.EMBEDDING,
        request_micros=100,
        input_micros_per_million=2_000_000,
        output_micros_per_million=4_000_000,
        effective_from_microseconds=1_000_000,
        effective_until_microseconds=2_000_000,
        created_at_microseconds=900_000,
    )
    return replace(value, **cast("Any", changes))


def budget(**changes: object) -> ProviderBudgetPolicy:
    """Build one finite monthly budget with explicit exhaustion behavior."""
    value = ProviderBudgetPolicy.create(
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        version=4,
        currency="USD",
        limit_micros=10_000,
        behavior=BudgetExhaustionBehavior.QUEUE,
        degraded_channels=("exact", "lexical", "graph"),
        period_start_microseconds=1_000_000,
        period_end_microseconds=2_000_000,
        created_at_microseconds=900_000,
    )
    return replace(value, **cast("Any", changes))


def canary(**changes: object) -> DriftCanary:
    """Build one pinned, generation-scoped canary contract."""
    fixed_ids = tuple(item.content_id for item in probe_canaries())
    value = DriftCanary.create(
        canary_id=CANARY_ID,
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        space_id=SPACE_ID,
        generation_id=GENERATION_ID,
        capability_attestation_id=digest("attestation").value,
        revision_fingerprint=digest("revision").value,
        canary_set_digest=ProviderProbeSuite().canary_digest,
        vector_fingerprint=digest("quantized-vectors").value,
        canary_item_ids=fixed_ids,
        norms_micros=(1_000_000, 999_950),
        distance_order=fixed_ids,
        norm_tolerance_ppm=100,
        maximum_order_inversions=0,
        interval_microseconds=3_600_000_000,
        next_probe_at_microseconds=1_500_000,
        created_at_microseconds=1_000_000,
    )
    return replace(value, **cast("Any", changes))


def observation(**changes: object) -> DriftObservation:
    """Build a safe aggregate observation containing no raw vector."""
    contract = canary()
    value = DriftObservation.create(
        canary=contract,
        revision_fingerprint=digest("revision").value,
        vector_fingerprint=digest("quantized-vectors").value,
        canary_item_ids=contract.canary_item_ids,
        norms_micros=(1_000_010, 999_960),
        distance_order=contract.distance_order,
        observed_at_microseconds=1_500_000,
    )
    return replace(value, **cast("Any", changes))


def test_pricing_snapshot_is_content_addressed_and_uses_integer_micro_costs() -> None:
    first = pricing()
    replay = PricingSnapshot.create(**cast("Any", first.creation_document))
    assert replay == first
    assert replay.snapshot_id == first.snapshot_id
    assert first.snapshot_id == "4a0d9b427459abb27330d1f5c9a9c5e2526a3ffe26dd3ce4c2a30c94e9b3bfea"
    assert first.cost(request_count=2, input_units=250_001, output_units=10_001) == 540_206
    assert (
        PricingSnapshot.create(**cast("Any", {**first.creation_document, "version": 4})).snapshot_id
        != first.snapshot_id
    )


def test_pricing_ceil_rate_preserves_zero_and_single_micro_boundaries() -> None:
    zero_units = PricingSnapshot.create(
        **cast(
            "Any",
            {
                **pricing().creation_document,
                "request_micros": 0,
                "input_micros_per_million": 2_000_000,
                "output_micros_per_million": 4_000_000,
            },
        )
    )
    assert zero_units.cost(request_count=0, input_units=0, output_units=0) == 0

    zero_rate = PricingSnapshot.create(
        **cast(
            "Any",
            {
                **pricing().creation_document,
                "request_micros": 0,
                "input_micros_per_million": 0,
                "output_micros_per_million": 0,
            },
        )
    )
    assert zero_rate.cost(request_count=0, input_units=1, output_units=1) == 0

    single_micro = PricingSnapshot.create(
        **cast(
            "Any",
            {
                **pricing().creation_document,
                "request_micros": 0,
                "input_micros_per_million": 1,
                "output_micros_per_million": 0,
            },
        )
    )
    assert single_micro.cost(request_count=0, input_units=1, output_units=0) == 1


def test_observability_digest_has_canonical_unicode_and_rejects_non_finite_values() -> None:
    assert (
        observability_module._digest(  # pyright: ignore[reportPrivateUsage]
            {"label": "mémoire", "ordinal": 1}
        )
        == "0b791414d794f869cd0d2663dd22408f301d18f0f14f94896318619694673f2e"
    )
    with pytest.raises(
        ProviderObservabilityValidationError,
        match=r"^provider observability input is invalid$",
    ):
        observability_module._digest(  # pyright: ignore[reportPrivateUsage]
            {"value": float("nan")}
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("snapshot_id", "bad"),
        ("profile_version", 0),
        ("version", 0),
        ("currency", "usd"),
        ("request_micros", -1),
        ("input_micros_per_million", -1),
        ("output_micros_per_million", -1),
        ("effective_until_microseconds", 1_000_000),
        ("created_at_microseconds", 1_000_001),
    ],
)
def test_pricing_snapshot_rejects_ambiguous_or_unbounded_authority(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        replace(pricing(), **cast("Any", {field: value}))


def test_budget_policy_returns_only_configured_queue_or_degrade_behavior() -> None:
    policy = budget()
    assert policy.admit(spent_micros=1_000, reserved_micros=2_000, estimate_micros=3_000) == (
        BudgetAdmission(BudgetDecision.RESERVED, 3_000, ())
    )
    assert policy.admit(spent_micros=5_000, reserved_micros=2_000, estimate_micros=3_001) == (
        BudgetAdmission(BudgetDecision.QUEUED, 0, ())
    )
    degraded = ProviderBudgetPolicy.create(
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        version=4,
        currency="USD",
        limit_micros=10_000,
        behavior=BudgetExhaustionBehavior.DEGRADE,
        degraded_channels=("exact", "lexical", "graph"),
        period_start_microseconds=1_000_000,
        period_end_microseconds=2_000_000,
        created_at_microseconds=900_000,
    )
    assert degraded.admit(
        spent_micros=10_000,
        reserved_micros=0,
        estimate_micros=1,
    ) == BudgetAdmission(
        BudgetDecision.DEGRADED,
        0,
        ("exact", "lexical", "graph"),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_id", "bad"),
        ("limit_micros", -1),
        ("degraded_channels", ("vector",)),
        ("degraded_channels", ("exact", "exact")),
        ("period_end_microseconds", 1_000_000),
        ("created_at_microseconds", 1_000_001),
    ],
)
def test_budget_policy_rejects_unsafe_or_ambiguous_configuration(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        replace(budget(), **cast("Any", {field: value}))


def test_drift_probe_accepts_tolerated_norm_noise_but_rejects_semantic_change() -> None:
    contract = canary()
    stable = DriftEvaluator.evaluate(contract, observation())
    assert stable.verdict is DriftVerdict.STABLE
    assert stable.reason_code is None
    assert stable.suspend_writes is False

    fingerprint = DriftEvaluator.evaluate(
        contract,
        observation(vector_fingerprint=digest("changed-vector").value),
    )
    assert fingerprint.verdict is DriftVerdict.DRIFTED
    assert fingerprint.reason_code == "vector_fingerprint_mismatch"
    assert fingerprint.suspend_writes is True
    assert fingerprint.requires_new_space is True

    norm = DriftEvaluator.evaluate(
        contract,
        observation(norms_micros=(1_000_101, 999_960)),
    )
    assert norm.reason_code == "vector_norm_mismatch"

    order = DriftEvaluator.evaluate(
        contract,
        observation(distance_order=tuple(reversed(contract.distance_order))),
    )
    assert order.reason_code == "distance_order_mismatch"

    revision = DriftEvaluator.evaluate(
        contract,
        observation(revision_fingerprint=digest("changed-revision").value),
    )
    assert revision.reason_code == "model_revision_mismatch"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profile_id", BRAIN_ID),
        ("profile_version", 3),
        ("space_id", CANARY_ID),
        ("generation_id", CANARY_ID),
    ],
)
def test_drift_evaluator_rejects_each_independently_mismatched_authority_coordinate(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        DriftEvaluator.evaluate(
            canary(),
            replace(observation(), **cast("Any", {field: value})),
        )


def test_drift_evaluator_rejects_foreign_canary_items_and_accepts_exact_boundaries() -> None:
    foreign_items = (digest("foreign-canary-1").value, digest("foreign-canary-2").value)
    with pytest.raises(ProviderObservabilityValidationError):
        DriftEvaluator.evaluate(
            canary(),
            observation(
                canary_item_ids=foreign_items,
                distance_order=foreign_items,
            ),
        )

    norm_boundary = DriftEvaluator.evaluate(
        canary(),
        observation(norms_micros=(1_000_100, 999_960)),
    )
    assert norm_boundary.verdict is DriftVerdict.STABLE

    order_boundary_contract = canary(maximum_order_inversions=1)
    order_boundary = DriftEvaluator.evaluate(
        order_boundary_contract,
        observation(
            distance_order=tuple(reversed(order_boundary_contract.distance_order)),
        ),
    )
    assert order_boundary.verdict is DriftVerdict.STABLE


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canary_id", "not-a-uuid"),
        ("vector_fingerprint", "bad"),
        ("norms_micros", ()),
        ("norms_micros", (1, -1)),
        ("distance_order", (digest("same").value, digest("same").value)),
        ("norm_tolerance_ppm", 1_000_001),
        ("maximum_order_inversions", 4),
        ("interval_microseconds", 0),
        ("next_probe_at_microseconds", 999_999),
    ],
)
def test_drift_contract_rejects_invalid_safe_aggregates(field: str, value: object) -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        replace(canary(), **cast("Any", {field: value}))


def test_operation_fact_exposes_only_bounded_labels_and_safe_error_taxonomy() -> None:
    fact = ProviderOperationFact.create(
        operation_id="provider-operation-10",
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        space_id=SPACE_ID,
        generation_id=GENERATION_ID,
        pricing_snapshot_id=pricing().snapshot_id,
        outcome=ProviderOperationOutcome.RETRY_SCHEDULED,
        error_code=ProviderErrorCode.RATE_LIMIT,
        request_count=1,
        item_count=8,
        input_units=200,
        output_units=0,
        request_bytes=500,
        response_bytes=0,
        attempt_count=2,
        latency_microseconds=30_000,
        estimated_cost_micros=500,
        actual_cost_micros=0,
        cache_hit=False,
        deduplicated=False,
        occurred_at_microseconds=1_500_000,
    )
    assert fact.fact_digest == fact.expected_digest
    assert set(fact.metric_labels) == {"error_code", "operation", "outcome"}
    assert "operation_id" not in fact.metric_labels
    assert "brain_id" not in fact.metric_labels

    with pytest.raises(ProviderObservabilityValidationError):
        replace(fact, error_code=None)
    with pytest.raises(ProviderObservabilityValidationError):
        replace(
            fact,
            outcome=ProviderOperationOutcome.SUCCEEDED,
            error_code=ProviderErrorCode.RATE_LIMIT,
        )


def test_status_snapshot_validates_complete_content_free_operator_view() -> None:
    snapshot = ProviderStatusSnapshot(
        brain_id=BRAIN_ID,
        observed_at_microseconds=1_600_000,
        health=(
            ProviderHealth(
                profile_id=PROFILE_ID,
                profile_version=2,
                status=ProviderHealthStatus.DEGRADED,
                circuit_counts=(2, 1, 0),
                requests=100,
                items=240,
                input_units=40_000,
                output_units=0,
                cost_micros=8_000,
                latency_p50_microseconds=25_000,
                latency_p95_microseconds=80_000,
                latency_p99_microseconds=120_000,
                safe_errors=((ProviderErrorCode.RATE_LIMIT, 2),),
            ),
        ),
        queues=ProviderQueueStatus(
            queued=8,
            leased=1,
            retry_scheduled=2,
            failed=1,
            dead_lettered=1,
            oldest_queued_at_microseconds=1_200_000,
        ),
        budgets=(
            ProviderBudgetStatus(
                profile_id=PROFILE_ID,
                policy_id=budget().policy_id,
                currency="USD",
                limit_micros=10_000,
                spent_micros=8_000,
                reserved_micros=500,
                remaining_micros=1_500,
                behavior=BudgetExhaustionBehavior.QUEUE,
            ),
        ),
        generations=(
            ProviderGenerationStatus(
                space_id=SPACE_ID,
                active_generation_id=GENERATION_ID,
                rollback_generation_id=None,
                pin_state=GenerationPinState.PINNED,
                write_suspended=False,
                suspension_reason=None,
            ),
        ),
        retry_count=2,
        dead_letter_count=1,
        active_alert_count=0,
    )
    assert snapshot.health[0].safe_errors == ((ProviderErrorCode.RATE_LIMIT, 2),)
    assert snapshot.generations[0].pin_state is GenerationPinState.PINNED

    with pytest.raises(ProviderObservabilityValidationError):
        replace(snapshot, retry_count=-1)


def test_pricing_and_budget_runtime_admission_reject_unbounded_values() -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        pricing().cost(request_count=-1, input_units=0, output_units=0)

    expensive = PricingSnapshot.create(
        **cast(
            "Any",
            {
                **pricing().creation_document,
                "request_micros": 10**15,
            },
        )
    )
    with pytest.raises(ProviderObservabilityValidationError):
        expensive.cost(request_count=10**15, input_units=0, output_units=0)

    with pytest.raises(ProviderObservabilityValidationError):
        BudgetAdmission(BudgetDecision.QUEUED, 1, ())
    with pytest.raises(ProviderObservabilityValidationError):
        budget().admit(spent_micros=-1, reserved_micros=0, estimate_micros=0)


def test_budget_drift_and_status_runtime_coordinates_fail_closed() -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        ProviderBudgetReservationRequest(
            operation_id="invalid operation",
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            profile_version=2,
            pricing_snapshot_id=pricing().snapshot_id,
            estimated_cost_micros=1,
            requested_at_microseconds=1_500_000,
        )
    with pytest.raises(ProviderObservabilityValidationError):
        DriftCanary.create()
    with pytest.raises(ProviderObservabilityValidationError):
        replace(observation(), observed_at_microseconds=-1)
    with pytest.raises(ProviderObservabilityValidationError):
        DriftObservation.create(
            canary=canary(),
            revision_fingerprint=digest("revision").value,
            vector_fingerprint=digest("quantized-vectors").value,
            canary_item_ids=canary().canary_item_ids,
            norms_micros=canary().norms_micros,
            distance_order=canary().distance_order,
            observed_at_microseconds=canary().created_at_microseconds - 1,
        )
    with pytest.raises(ProviderObservabilityValidationError):
        ProviderDriftProbeLease(
            canary=canary(),
            owner="invalid owner",
            lease_until_microseconds=2_000_000,
            state_version=1,
        )
    with pytest.raises(ProviderObservabilityValidationError):
        DriftEvaluation(
            verdict=DriftVerdict.STABLE,
            reason_code="unexpected",
            suspend_writes=False,
            requires_new_space=False,
        )
    with pytest.raises(ProviderObservabilityValidationError):
        DriftEvaluator.evaluate(canary(), observation(brain_id=PROFILE_ID))

    health = ProviderHealth(
        profile_id=PROFILE_ID,
        profile_version=2,
        status=ProviderHealthStatus.HEALTHY,
        circuit_counts=(1, 0, 0),
        requests=0,
        items=0,
        input_units=0,
        output_units=0,
        cost_micros=0,
        latency_p50_microseconds=0,
        latency_p95_microseconds=0,
        latency_p99_microseconds=0,
        safe_errors=(),
    )
    with pytest.raises(ProviderObservabilityValidationError):
        replace(health, circuit_counts=cast("Any", (1, 0)))
    with pytest.raises(ProviderObservabilityValidationError):
        ProviderQueueStatus(0, 0, 0, 0, 0, 1)
    with pytest.raises(ProviderObservabilityValidationError):
        ProviderBudgetStatus(
            profile_id=PROFILE_ID,
            policy_id=budget().policy_id,
            currency="USD",
            limit_micros=100,
            spent_micros=10,
            reserved_micros=20,
            remaining_micros=80,
            behavior=BudgetExhaustionBehavior.QUEUE,
        )
    with pytest.raises(ProviderObservabilityValidationError):
        ProviderGenerationStatus(
            space_id=SPACE_ID,
            active_generation_id=GENERATION_ID,
            rollback_generation_id=None,
            pin_state=GenerationPinState.PINNED,
            write_suspended=True,
            suspension_reason="model_revision_mismatch",
        )
