"""PRO-006 pure batching, fairness, rate, budget, and result invariants."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.domain.errors import ProviderSchedulingValidationError
from agentmemory.providers.domain.profiles import CanonicalPurpose
from agentmemory.providers.domain.routing import ProviderWorkload
from agentmemory.providers.domain.scheduling import (
    BatchPlanner,
    ProviderBatchKey,
    ProviderBatchOutcome,
    ProviderDeadlineClass,
    ProviderItemResult,
    ProviderItemResultStatus,
    ProviderRatePolicy,
    ProviderRateState,
    ProviderSchedulingLimits,
    ProviderWorkItem,
    WeightedFairProviderScheduler,
    _invalid,  # pyright: ignore[reportPrivateUsage]
)
from tests.core.support import BRAIN_ID, digest
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
)
from tests.providers.test_pro005_routing_domain import PROFILE_ID

SPACE_ID = "018f0000-0000-7000-8000-000000000603"
ITEM_ID = "018f0000-0000-7000-8000-000000000604"


def key(**changes: object) -> ProviderBatchKey:
    values: dict[str, object] = {
        "brain_id": BRAIN_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "classification": Classification.INTERNAL,
        "profile_id": PROFILE_ID,
        "profile_version": 2,
        "space_id": SPACE_ID,
        "space_fingerprint": digest("space").value,
        "purpose": CanonicalPurpose.CODE_DOCUMENT,
        "retention_policy_digest": digest("retention").value,
        "preprocessing_digest": digest("preprocessing").value,
        "deadline_class": ProviderDeadlineClass.BACKGROUND,
        "workload": ProviderWorkload.BACKFILL,
    }
    values.update(changes)
    return ProviderBatchKey(**values)  # type: ignore[arg-type]


def item(index: int, **changes: object) -> ProviderWorkItem:
    values: dict[str, object] = {
        "item_id": f"018f0000-0000-7000-8000-{index + 700:012d}",
        "operation_id": f"schedule-{index}",
        "batch_key": key(),
        "ordinal": index,
        "payload_ref": f"cas://sha256/{digest(f'payload-{index}').value}",
        "content_digest": digest(f"content-{index}").value,
        "token_count": index + 1,
        "byte_count": (index + 1) * 10,
        "estimated_cost_micros": index + 2,
        "enqueued_at_microseconds": 1_000 + index,
        "deadline_at_microseconds": 100_000,
    }
    values.update(changes)
    return ProviderWorkItem(**values)  # type: ignore[arg-type]


def limits(**changes: int) -> ProviderSchedulingLimits:
    values = {
        "max_items": 3,
        "max_item_tokens": 10,
        "max_request_tokens": 12,
        "max_input_bytes": 100,
        "max_batch_cost_micros": 100,
    }
    values.update(changes)
    return ProviderSchedulingLimits(**values)


def test_validation_sentinel_always_raises_the_content_free_error() -> None:
    """Keep the shared fail-closed validation path directly mutation-visible."""
    with pytest.raises(
        ProviderSchedulingValidationError,
        match="provider scheduling input is invalid",
    ):
        _invalid()


@given(
    token_counts=st.lists(st.integers(min_value=1, max_value=10), min_size=1, max_size=50),
    byte_counts=st.lists(st.integers(min_value=1, max_value=100), min_size=1, max_size=50),
)
def test_batch_planner_preserves_order_ids_and_never_exceeds_exact_limits(
    token_counts: list[int],
    byte_counts: list[int],
) -> None:
    count = min(len(token_counts), len(byte_counts))
    work = tuple(
        item(
            index,
            token_count=token_counts[index],
            byte_count=byte_counts[index],
            estimated_cost_micros=1,
        )
        for index in range(count)
    )
    planned = BatchPlanner.plan(
        work,
        limits(
            max_items=7,
            max_request_tokens=30,
            max_input_bytes=250,
            max_batch_cost_micros=20,
        ),
    )

    flattened = tuple(child.item_id for batch in planned for child in batch.items)
    assert flattened == tuple(child.item_id for child in work)
    assert all(len(batch.items) <= 7 for batch in planned)
    assert all(batch.token_count <= 30 for batch in planned)
    assert all(batch.byte_count <= 250 for batch in planned)
    assert all(batch.estimated_cost_micros <= 20 for batch in planned)
    assert len({batch.operation_id for batch in planned}) == len(planned)


def test_batch_planner_splits_on_exact_item_token_byte_and_cost_boundaries() -> None:
    work = (
        item(0, token_count=4, byte_count=40, estimated_cost_micros=5),
        item(1, token_count=6, byte_count=60, estimated_cost_micros=5),
        item(2, token_count=1, byte_count=1, estimated_cost_micros=1),
    )
    planned = BatchPlanner.plan(
        work,
        limits(
            max_items=2,
            max_request_tokens=10,
            max_input_bytes=100,
            max_batch_cost_micros=10,
        ),
    )
    assert tuple(len(batch.items) for batch in planned) == (2, 1)
    assert planned[0].token_count == 10
    assert planned[0].byte_count == 100
    assert planned[0].estimated_cost_micros == 10


@pytest.mark.parametrize(
    "changed_key",
    [
        {"brain_id": "018f0000-0000-7000-8000-000000000699"},
        {"classification": Classification.CONFIDENTIAL},
        {"profile_version": 3},
        {"space_fingerprint": digest("other-space").value},
        {"purpose": CanonicalPurpose.CODE_QUERY},
        {"retention_policy_digest": digest("other-retention").value},
        {"preprocessing_digest": digest("other-preprocessing").value},
        {"deadline_class": ProviderDeadlineClass.ONLINE},
        {"workload": ProviderWorkload.EVALUATION},
    ],
)
def test_batch_planner_rejects_every_semantic_or_privacy_mixture(
    changed_key: dict[str, object],
) -> None:
    with pytest.raises(ProviderSchedulingValidationError, match="homogeneous"):
        BatchPlanner.plan(
            (item(0), item(1, batch_key=key(**changed_key))),
            limits(),
        )


def test_batch_key_and_batch_operation_digests_are_canonical_and_stable() -> None:
    """Protect durable partition and operation identities across processes/releases."""
    expected_key_digest = "2fd3a31cc3386f909f612e1be39766c756e3fac287bb586259adf10ade0acbbf"
    expected_operation_id = "provider-batch-925207d29592c7b3cfab310cccb95450"

    assert key().digest == expected_key_digest
    assert BatchPlanner.plan((item(0), item(1)), limits())[0].operation_id == expected_operation_id


@pytest.mark.parametrize(
    "changed",
    [
        {"token_count": 11},
        {"byte_count": 101},
        {"estimated_cost_micros": 101},
    ],
)
def test_one_oversized_item_is_rejected_instead_of_silently_truncated(
    changed: dict[str, int],
) -> None:
    with pytest.raises(ProviderSchedulingValidationError, match="limit"):
        BatchPlanner.plan((item(0, **changed),), limits())


def test_interactive_batches_cannot_contain_backfill_or_evaluation() -> None:
    interactive = key(
        deadline_class=ProviderDeadlineClass.INTERACTIVE,
        workload=ProviderWorkload.INTERACTIVE,
    )
    BatchPlanner.plan((item(0, batch_key=interactive),), limits())
    with pytest.raises(ProviderSchedulingValidationError, match="deadline"):
        key(
            deadline_class=ProviderDeadlineClass.INTERACTIVE,
            workload=ProviderWorkload.BACKFILL,
        )


def test_weighted_fair_scheduler_prioritizes_interactive_but_bounds_starvation() -> None:
    scheduler = WeightedFairProviderScheduler()
    available = frozenset(ProviderWorkload)
    cursor = 0
    selected: list[ProviderWorkload] = []
    for _ in range(scheduler.cycle_length):
        workload, cursor = scheduler.select(available, cursor)
        assert workload is not None
        selected.append(workload)
    assert selected.count(ProviderWorkload.INTERACTIVE) > selected.count(ProviderWorkload.BACKFILL)
    assert set(selected) == set(ProviderWorkload)
    assert (
        max(
            next(
                offset
                for offset in range(1, scheduler.cycle_length + 1)
                if selected[(start + offset) % scheduler.cycle_length]
                is ProviderWorkload.EVALUATION
            )
            for start in range(scheduler.cycle_length)
        )
        <= scheduler.cycle_length
    )


def test_weighted_fair_scheduler_skips_empty_queues_without_losing_cursor_progress() -> None:
    scheduler = WeightedFairProviderScheduler()
    available = frozenset({ProviderWorkload.BACKFILL, ProviderWorkload.EVALUATION})
    cursor = 0
    sequence: list[ProviderWorkload] = []
    for _ in range(4):
        selected, cursor = scheduler.select(available, cursor)
        assert selected is not None
        sequence.append(selected)
    assert set(sequence) == available
    assert scheduler.select(frozenset(), cursor)[0] is None


def test_dual_token_bucket_honors_rate_hint_concurrency_and_monthly_budget() -> None:
    policy = ProviderRatePolicy(
        request_capacity=2,
        requests_per_minute=2,
        token_capacity=10,
        tokens_per_minute=10,
        max_concurrency=1,
        monthly_cost_budget_micros=20,
    )
    state = ProviderRateState.full(policy, period_start_microseconds=0)
    admitted = state.admit(
        policy,
        now_microseconds=0,
        token_count=7,
        estimated_cost_micros=12,
    )
    assert admitted.allowed
    assert admitted.state.in_flight == 1
    assert admitted.state.cost_spent_micros == 12

    concurrency = admitted.state.admit(
        policy,
        now_microseconds=0,
        token_count=1,
        estimated_cost_micros=1,
    )
    assert not concurrency.allowed
    assert concurrency.reason == "concurrency_limit"

    released = admitted.state.release()
    rate_limited = released.admit(
        policy,
        now_microseconds=0,
        token_count=7,
        estimated_cost_micros=1,
    )
    assert not rate_limited.allowed
    assert rate_limited.reason == "token_rate"
    assert rate_limited.retry_at_microseconds == 24_000_000

    budget = released.admit(
        policy,
        now_microseconds=60_000_000,
        token_count=1,
        estimated_cost_micros=9,
    )
    assert not budget.allowed
    assert budget.reason == "cost_budget"
    assert budget.retry_at_microseconds is None

    hinted = replace(released, blocked_until_microseconds=90_000_000).admit(
        policy,
        now_microseconds=60_000_000,
        token_count=1,
        estimated_cost_micros=1,
    )
    assert not hinted.allowed
    assert hinted.reason == "provider_rate_hint"
    assert hinted.retry_at_microseconds == 90_000_000


def test_partial_response_retries_only_retryable_children_in_original_order() -> None:
    work = (item(0), item(1), item(2))
    batch = BatchPlanner.plan(work, limits())[0]
    outcome = ProviderBatchOutcome(
        batch_operation_id=batch.operation_id,
        results=(
            ProviderItemResult.succeeded(work[0].item_id, digest("result-0").value),
            ProviderItemResult.failed(
                work[1].item_id,
                ProviderItemResultStatus.RETRYABLE_FAILURE,
                "rate_limit",
                retry_at_microseconds=55_000,
            ),
            ProviderItemResult.failed(
                work[2].item_id,
                ProviderItemResultStatus.PERMANENT_FAILURE,
                "invalid_input",
            ),
        ),
    )
    outcome.validate_for(batch)
    assert outcome.retryable_item_ids == (work[1].item_id,)
    assert outcome.retry_at_microseconds == 55_000


@pytest.mark.parametrize(
    "results",
    [
        (),
        (
            ProviderItemResult.succeeded(item(0).item_id, digest("a").value),
            ProviderItemResult.succeeded(item(0).item_id, digest("b").value),
            ProviderItemResult.succeeded(item(2).item_id, digest("c").value),
        ),
        (
            ProviderItemResult.succeeded(item(1).item_id, digest("a").value),
            ProviderItemResult.succeeded(item(0).item_id, digest("b").value),
            ProviderItemResult.succeeded(item(2).item_id, digest("c").value),
        ),
    ],
)
def test_partial_response_requires_every_child_exactly_once_and_in_order(
    results: tuple[ProviderItemResult, ...],
) -> None:
    batch = BatchPlanner.plan((item(0), item(1), item(2)), limits())[0]
    with pytest.raises(ProviderSchedulingValidationError, match="result"):
        ProviderBatchOutcome(batch.operation_id, results).validate_for(batch)
