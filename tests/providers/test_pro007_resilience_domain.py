"""PRO-007 canonical error, retry, equivalence, and circuit invariants."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderResilienceValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)
from agentmemory.providers.domain.resilience import (
    EquivalentEndpointSet,
    ProviderCircuitPolicy,
    ProviderCircuitSnapshot,
    ProviderCircuitState,
    ProviderEndpointAttestation,
    ProviderErrorPolicy,
    ProviderOutputContract,
    ProviderRetryAction,
    ProviderRetryContext,
    ProviderRetryDecision,
    ProviderRetryPolicy,
    _digest,  # pyright: ignore[reportPrivateUsage]
    _invalid,  # pyright: ignore[reportPrivateUsage]
    retry_jitter_seed,
)
from tests.core.support import digest
from tests.providers.test_pro005_routing_domain import PROFILE_ID
from tests.providers.test_pro006_scheduling_domain import SPACE_ID

FALLBACK_PROFILE_ID = "018f0000-0000-7000-8000-000000000701"
PRIMARY_ENDPOINT = digest("primary-endpoint").value
FALLBACK_ENDPOINT = digest("fallback-endpoint").value


def output_contract(**changes: object) -> ProviderOutputContract:
    values: dict[str, object] = {
        "space_id": SPACE_ID,
        "space_fingerprint": digest("space").value,
        "model_revision": "a" * 40,
        "revision_fingerprint": digest("model-revision").value,
        "operation": ProviderOperation.EMBEDDING,
        "purpose": CanonicalPurpose.CODE_DOCUMENT,
        "preprocessing_digest": digest("source-text-v1").value,
        "dimension": 1_024,
        "dtype": VectorDtype.FLOAT32,
        "normalization": VectorNormalization.L2,
        "similarity": SimilarityMetric.COSINE,
        "suite_digest": digest("suite").value,
        "canary_digest": digest("canary").value,
        "validation_digest": digest("validation").value,
    }
    values.update(changes)
    return ProviderOutputContract(**values)  # type: ignore[arg-type]


def endpoint(
    *,
    profile_id: str = PROFILE_ID,
    endpoint_fingerprint: str = PRIMARY_ENDPOINT,
    contract: ProviderOutputContract | None = None,
) -> ProviderEndpointAttestation:
    return ProviderEndpointAttestation(
        profile_id=profile_id,
        profile_version=2,
        capability_attestation_id=digest(f"attestation-{profile_id}").value,
        endpoint_fingerprint=endpoint_fingerprint,
        configuration_digest=digest(f"configuration-{profile_id}").value,
        adapter_digest=digest(f"adapter-{profile_id}").value,
        output_contract=contract or output_contract(),
    )


def equivalent_endpoints() -> EquivalentEndpointSet:
    return EquivalentEndpointSet(
        endpoint(),
        (
            endpoint(
                profile_id=FALLBACK_PROFILE_ID,
                endpoint_fingerprint=FALLBACK_ENDPOINT,
            ),
        ),
    )


def test_validation_sentinel_uses_one_content_free_error() -> None:
    with pytest.raises(
        ProviderResilienceValidationError,
        match="provider resilience input is invalid",
    ):
        _invalid()


def test_canonical_digest_has_a_locked_unicode_sorted_compact_json_vector() -> None:
    assert (
        _digest({"z": 1, "a": "café"})
        == "79ab3e11fc70c4b67c474b34ff77941ed7eba4d33b123ac3e2bedd2e98dbe2bc"
    )
    with pytest.raises(
        ProviderResilienceValidationError,
        match=r"^provider resilience input is invalid$",
    ):
        _digest({"not_finite": float("nan")})


@pytest.mark.parametrize(
    ("operation_key", "endpoint_fingerprint", "attempt"),
    [
        ("", "a" * 64, 1),
        ("x" * 513, "a" * 64, 1),
        ("operation", "not-a-digest", 1),
        ("operation", "a" * 64, 0),
        ("operation", "a" * 64, 101),
    ],
)
def test_retry_jitter_seed_rejects_each_coordinate_independently(
    operation_key: str,
    endpoint_fingerprint: str,
    attempt: int,
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        retry_jitter_seed(operation_key, endpoint_fingerprint, attempt)


def test_retry_jitter_seed_accepts_exact_upper_bounds_and_has_a_locked_vector() -> None:
    assert (
        retry_jitter_seed("operation", "a" * 64, 100)
        == "88e2111ed6d4f4d8f931ea40979b9c83be22866ce092ab7d50c8d759be2b2705"
    )
    assert len(retry_jitter_seed("x" * 512, "a" * 64, 1)) == 64


def test_error_taxonomy_is_exhaustive_and_has_the_reviewed_full_matrix() -> None:
    ProviderErrorPolicy.verify_complete()
    expected = {
        ProviderErrorCode.AUTHENTICATION: (False, False, False),
        ProviderErrorCode.PERMISSION: (False, False, False),
        ProviderErrorCode.INVALID_CONFIGURATION: (False, False, False),
        ProviderErrorCode.UNSUPPORTED_CAPABILITY: (False, False, False),
        ProviderErrorCode.MISSING_MODEL: (False, False, False),
        ProviderErrorCode.OVERSIZED_INPUT: (False, False, False),
        ProviderErrorCode.RATE_LIMIT: (True, True, False),
        ProviderErrorCode.QUOTA: (False, False, False),
        ProviderErrorCode.TIMEOUT: (True, True, True),
        ProviderErrorCode.CANCELLATION: (False, False, False),
        ProviderErrorCode.TRANSIENT_UPSTREAM: (True, True, True),
        ProviderErrorCode.MALFORMED_RESPONSE: (False, False, True),
        ProviderErrorCode.DIMENSION_MISMATCH: (False, False, True),
        ProviderErrorCode.MODEL_DRIFT: (False, False, True),
        ProviderErrorCode.PRIVACY_DENIAL: (False, False, False),
        ProviderErrorCode.ADAPTER_CRASH: (True, True, True),
    }
    actual = {
        code: (
            ProviderErrorPolicy.traits(code).retryable,
            ProviderErrorPolicy.traits(code).fallback_safe,
            ProviderErrorPolicy.traits(code).counts_toward_circuit,
        )
        for code in ProviderErrorCode
    }
    assert actual == expected


@pytest.mark.parametrize(
    "code",
    [
        ProviderErrorCode.AUTHENTICATION,
        ProviderErrorCode.PERMISSION,
        ProviderErrorCode.INVALID_CONFIGURATION,
        ProviderErrorCode.UNSUPPORTED_CAPABILITY,
        ProviderErrorCode.MISSING_MODEL,
        ProviderErrorCode.OVERSIZED_INPUT,
        ProviderErrorCode.QUOTA,
        ProviderErrorCode.CANCELLATION,
        ProviderErrorCode.MALFORMED_RESPONSE,
        ProviderErrorCode.DIMENSION_MISMATCH,
        ProviderErrorCode.MODEL_DRIFT,
        ProviderErrorCode.PRIVACY_DENIAL,
    ],
)
def test_nonretryable_errors_fail_immediately(code: ProviderErrorCode) -> None:
    policy = ProviderRetryPolicy.production()
    assert policy.decide(
        code,
        ProviderRetryContext(
            attempt=1,
            now_microseconds=1_000,
            deadline_at_microseconds=100_000_000,
            jitter_seed="0" * 64,
        ),
    ) == ProviderRetryDecision(ProviderRetryAction.FAIL, None)


@pytest.mark.parametrize(
    "code",
    [
        ProviderErrorCode.RATE_LIMIT,
        ProviderErrorCode.TIMEOUT,
        ProviderErrorCode.TRANSIENT_UPSTREAM,
        ProviderErrorCode.ADAPTER_CRASH,
    ],
)
def test_retryable_errors_get_bounded_deterministic_jitter(
    code: ProviderErrorCode,
) -> None:
    policy = ProviderRetryPolicy.production()
    seed = retry_jitter_seed("provider-operation", PRIMARY_ENDPOINT, 1)
    first = policy.decide(
        code,
        ProviderRetryContext(
            attempt=1,
            now_microseconds=1_000,
            deadline_at_microseconds=100_000_000,
            jitter_seed=seed,
        ),
    )
    repeated = policy.decide(
        code,
        ProviderRetryContext(
            attempt=1,
            now_microseconds=1_000,
            deadline_at_microseconds=100_000_000,
            jitter_seed=seed,
        ),
    )
    maximum = 1_000_000 if code is ProviderErrorCode.RATE_LIMIT else 100_000
    assert first == repeated
    assert first.action is ProviderRetryAction.RETRY
    assert first.retry_at_microseconds is not None
    assert 1_001 <= first.retry_at_microseconds <= 1_000 + maximum


def test_retry_after_is_a_minimum_and_attempt_or_deadline_exhaustion_never_loops() -> None:
    policy = ProviderRetryPolicy.production()
    assert policy.max_attempts == 3
    hint = 5_000_000
    assert policy.decide(
        ProviderErrorCode.RATE_LIMIT,
        ProviderRetryContext(
            attempt=1,
            now_microseconds=1_000,
            deadline_at_microseconds=10_000_000,
            jitter_seed="0" * 64,
            retry_after_microseconds=hint,
        ),
    ) == ProviderRetryDecision(ProviderRetryAction.RETRY, hint)
    assert (
        policy.decide(
            ProviderErrorCode.TIMEOUT,
            ProviderRetryContext(
                attempt=policy.max_attempts,
                now_microseconds=1_000,
                deadline_at_microseconds=10_000_000,
                jitter_seed="0" * 64,
            ),
        ).action
        is ProviderRetryAction.EXHAUSTED
    )
    assert (
        policy.decide(
            ProviderErrorCode.TIMEOUT,
            ProviderRetryContext(
                attempt=1,
                now_microseconds=1_000,
                deadline_at_microseconds=1_001,
                jitter_seed="0" * 64,
            ),
        ).action
        is ProviderRetryAction.EXHAUSTED
    )


@pytest.mark.parametrize(
    ("action", "retry_at_microseconds"),
    [
        (ProviderRetryAction.RETRY, None),
        (ProviderRetryAction.FAIL, 1),
        (ProviderRetryAction.EXHAUSTED, 1),
        (ProviderRetryAction.RETRY, -1),
    ],
)
def test_retry_decision_rejects_incoherent_or_negative_retry_times(
    action: ProviderRetryAction,
    retry_at_microseconds: int | None,
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        ProviderRetryDecision(action, retry_at_microseconds)


@pytest.mark.parametrize(
    "changed",
    [
        {"attempt": 0},
        {"attempt": 101},
        {"now_microseconds": -1},
        {"deadline_at_microseconds": 1_000},
        {"jitter_seed": "not-a-digest"},
        {"retry_after_microseconds": 999},
    ],
)
def test_retry_context_rejects_each_invalid_timing_coordinate(
    changed: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "attempt": 1,
        "now_microseconds": 1_000,
        "deadline_at_microseconds": 2_000,
        "jitter_seed": "0" * 64,
    }
    values.update(changed)
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        ProviderRetryContext(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changed",
    [
        {"max_attempts": 0},
        {"max_attempts": 101},
        {"transient_base_delay_microseconds": 0},
        {"throttle_base_delay_microseconds": 0},
        {"max_delay_microseconds": 99_999},
    ],
)
def test_retry_policy_rejects_every_unbounded_or_zero_delay_shape(
    changed: dict[str, int],
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        replace(ProviderRetryPolicy.production(), **changes_as_any(changed))


@pytest.mark.parametrize(
    "changed",
    [
        {"space_id": "not-a-uuid"},
        {"space_id": "018F0000-0000-7000-8000-000000000501"},
        {"space_id": "018f0000-0000-4000-8000-000000000501"},
        {"space_fingerprint": "not-a-digest"},
        {"model_revision": ""},
        {"revision_fingerprint": "not-a-digest"},
        {"preprocessing_digest": "not-a-digest"},
        {"dimension": 0},
        {"dtype": None},
        {"normalization": None},
        {"similarity": None},
        {"suite_digest": "not-a-digest"},
        {"canary_digest": "not-a-digest"},
        {"validation_digest": "not-a-digest"},
    ],
)
def test_output_contract_rejects_every_incomplete_embedding_coordinate(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        output_contract(**changed)


def test_reranking_contract_forbids_embedding_shape_fields() -> None:
    valid = output_contract(
        operation=ProviderOperation.RERANKING,
        dimension=None,
        dtype=None,
        normalization=None,
        similarity=None,
    )
    assert valid.dimension is None
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        replace(valid, dimension=1)


@pytest.mark.parametrize(
    "contract_change",
    [
        {"space_fingerprint": digest("different-space").value},
        {"model_revision": "b" * 40},
        {"revision_fingerprint": digest("different-revision").value},
        {"purpose": CanonicalPurpose.CODE_QUERY},
        {"preprocessing_digest": digest("different-preprocessing").value},
        {"dimension": 768},
        {"dtype": VectorDtype.FLOAT64},
        {"normalization": VectorNormalization.NONE},
        {"similarity": SimilarityMetric.DOT_PRODUCT},
        {"suite_digest": digest("different-suite").value},
        {"canary_digest": digest("different-canary").value},
        {"validation_digest": digest("different-validation").value},
    ],
)
def test_fallback_rejects_every_semantic_output_contract_delta(
    contract_change: dict[str, object],
) -> None:
    with pytest.raises(
        ProviderResilienceValidationError,
        match="not proven equivalent",
    ):
        EquivalentEndpointSet(
            endpoint(),
            (
                endpoint(
                    profile_id=FALLBACK_PROFILE_ID,
                    endpoint_fingerprint=FALLBACK_ENDPOINT,
                    contract=output_contract(**contract_change),
                ),
            ),
        )


def test_equivalence_identity_is_ordered_stable_and_rejects_duplicate_endpoints() -> None:
    endpoints = equivalent_endpoints()
    assert endpoints.endpoints[0].profile_id == PROFILE_ID
    assert endpoints.set_id == equivalent_endpoints().set_id
    assert endpoints.primary.output_contract.digest == endpoints.fallbacks[0].output_contract.digest
    with pytest.raises(ProviderResilienceValidationError, match="not proven equivalent"):
        EquivalentEndpointSet(endpoint(), (endpoint(),))


def test_equivalence_set_rejects_unbounded_fallback_fanout() -> None:
    fallbacks = tuple(
        endpoint(
            profile_id=f"018f0000-0000-7{index:03x}-8000-{index:012x}",
            endpoint_fingerprint=digest(f"fallback-{index}").value,
        )
        for index in range(100)
    )
    with pytest.raises(ProviderResilienceValidationError, match="not proven equivalent"):
        EquivalentEndpointSet(endpoint(), fallbacks)


@pytest.mark.parametrize(
    "changed",
    [
        {"profile_id": "not-a-uuid"},
        {"profile_version": 0},
        {"capability_attestation_id": "not-a-digest"},
        {"endpoint_fingerprint": "not-a-digest"},
        {"configuration_digest": "not-a-digest"},
        {"adapter_digest": "not-a-digest"},
    ],
)
def test_endpoint_attestation_rejects_unbound_evidence(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        replace(endpoint(), **cast("Any", changed))


def test_circuit_opens_at_threshold_allows_one_half_open_probe_and_resets() -> None:
    policy = ProviderCircuitPolicy(
        failure_threshold=2,
        failure_window_microseconds=100,
        open_microseconds=50,
    )
    initial = ProviderCircuitSnapshot.initial(PRIMARY_ENDPOINT)
    assert policy.acquire(initial, 0).allowed

    first = policy.after_failure(initial, ProviderErrorCode.TIMEOUT, 10)
    assert first.state is ProviderCircuitState.CLOSED
    assert first.consecutive_failures == 1
    opened = policy.after_failure(first, ProviderErrorCode.TRANSIENT_UPSTREAM, 20)
    assert opened.state is ProviderCircuitState.OPEN
    assert opened.open_until_microseconds == 70
    assert not policy.acquire(opened, 69).allowed

    probe = policy.acquire(opened, 70)
    assert probe.allowed
    assert probe.snapshot.state is ProviderCircuitState.HALF_OPEN
    assert not policy.acquire(probe.snapshot, 70).allowed
    closed = policy.after_success(probe.snapshot, 71)
    assert closed == ProviderCircuitSnapshot(
        endpoint_fingerprint=PRIMARY_ENDPOINT,
        state=ProviderCircuitState.CLOSED,
        consecutive_failures=0,
        window_started_at_microseconds=None,
        open_until_microseconds=None,
        probe_in_flight=False,
        version=probe.snapshot.version + 1,
    )


def test_half_open_failure_reopens_and_noncounted_failures_do_not_poison_circuit() -> None:
    policy = ProviderCircuitPolicy(
        failure_threshold=2,
        failure_window_microseconds=100,
        open_microseconds=50,
    )
    opened = ProviderCircuitSnapshot(
        endpoint_fingerprint=PRIMARY_ENDPOINT,
        state=ProviderCircuitState.OPEN,
        consecutive_failures=2,
        window_started_at_microseconds=0,
        open_until_microseconds=50,
        probe_in_flight=False,
        version=2,
    )
    probe = policy.acquire(opened, 50).snapshot
    rate_limited = policy.after_failure(probe, ProviderErrorCode.RATE_LIMIT, 51)
    assert rate_limited.state is ProviderCircuitState.OPEN
    assert rate_limited.consecutive_failures == 2
    assert rate_limited.open_until_microseconds == 101

    reopened = policy.after_failure(
        policy.acquire(rate_limited, 101).snapshot,
        ProviderErrorCode.ADAPTER_CRASH,
        102,
    )
    assert reopened.state is ProviderCircuitState.OPEN
    assert reopened.consecutive_failures == 1
    assert reopened.window_started_at_microseconds == 102
    assert reopened.open_until_microseconds == 152


def test_failure_window_resets_and_jitter_seed_binds_all_coordinates() -> None:
    policy = ProviderCircuitPolicy(
        failure_threshold=2,
        failure_window_microseconds=10,
        open_microseconds=5,
    )
    first = policy.after_failure(
        ProviderCircuitSnapshot.initial(PRIMARY_ENDPOINT),
        ProviderErrorCode.TIMEOUT,
        1,
    )
    reset = policy.after_failure(first, ProviderErrorCode.TIMEOUT, 12)
    assert reset.consecutive_failures == 1
    assert reset.window_started_at_microseconds == 12

    one = retry_jitter_seed("operation", PRIMARY_ENDPOINT, 1)
    assert one == retry_jitter_seed("operation", PRIMARY_ENDPOINT, 1)
    assert one != retry_jitter_seed("operation", PRIMARY_ENDPOINT, 2)
    assert one != retry_jitter_seed("other-operation", PRIMARY_ENDPOINT, 1)
    assert one != retry_jitter_seed("operation", FALLBACK_ENDPOINT, 1)


@pytest.mark.parametrize(
    "changed",
    [
        {"endpoint_fingerprint": "not-a-digest"},
        {"consecutive_failures": -1},
        {"version": -1},
        {"window_started_at_microseconds": -1},
        {"open_until_microseconds": -1},
        {"open_until_microseconds": 1},
        {
            "state": ProviderCircuitState.CLOSED,
            "probe_in_flight": True,
        },
        {
            "state": ProviderCircuitState.OPEN,
            "open_until_microseconds": None,
        },
        {
            "state": ProviderCircuitState.OPEN,
            "open_until_microseconds": 1,
            "probe_in_flight": True,
        },
        {
            "state": ProviderCircuitState.HALF_OPEN,
            "open_until_microseconds": None,
            "probe_in_flight": True,
        },
        {
            "state": ProviderCircuitState.HALF_OPEN,
            "open_until_microseconds": 1,
            "probe_in_flight": False,
        },
    ],
)
def test_circuit_snapshot_rejects_each_incoherent_persisted_shape(
    changed: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "endpoint_fingerprint": PRIMARY_ENDPOINT,
        "state": ProviderCircuitState.CLOSED,
        "consecutive_failures": 0,
        "window_started_at_microseconds": None,
        "open_until_microseconds": None,
        "probe_in_flight": False,
        "version": 0,
    }
    values.update(changed)
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        ProviderCircuitSnapshot(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changed",
    [
        {"failure_threshold": 0},
        {"failure_threshold": 101},
        {"failure_window_microseconds": 0},
        {"failure_window_microseconds": 3_600_000_001},
        {"open_microseconds": 0},
        {"open_microseconds": 3_600_000_001},
    ],
)
def test_circuit_policy_rejects_unbounded_or_zero_thresholds(
    changed: dict[str, int],
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        replace(ProviderCircuitPolicy.production(), **changes_as_any(changed))


def test_circuit_transitions_reject_negative_time() -> None:
    policy = ProviderCircuitPolicy.production()
    snapshot = ProviderCircuitSnapshot.initial(PRIMARY_ENDPOINT)
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        policy.acquire(snapshot, -1)
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        policy.after_failure(snapshot, ProviderErrorCode.TIMEOUT, -1)
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        policy.after_success(snapshot, -1)
    with pytest.raises(ProviderResilienceValidationError, match="input is invalid"):
        policy.after_abandon(snapshot, -1)


def changes_as_any(values: dict[str, int]) -> Any:
    """Keep parametrized dataclass replacements strict-type-checker friendly."""
    return cast("Any", values)
