"""ING-004 queue admission, fairness, retry, and dead-letter domain tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from agentmemory.ingestion.domain.backpressure import (
    AdmissionDecision,
    AdmissionDisposition,
    CapacitySnapshot,
    DeadLetter,
    JobErrorCode,
    JobPriority,
    JobRequest,
    JobState,
    QueueLimits,
    ReplayDeadLetterRequest,
    RetryDecision,
    RetryDisposition,
    RetryMode,
    RetryPolicy,
    RetryRule,
    ScheduledJob,
    select_dispatch_priority,
)
from agentmemory.ingestion.domain.errors import FieldViolation, IngestionValidationError
from tests.core.support import BRAIN_ID, GRANT_ID, digest
from tests.ingestion.adp002_support import PRINCIPAL_ID

JOB_ID = "018f0000-0000-7000-8000-000000000301"
DEAD_LETTER_ID = "018f0000-0000-7000-8000-000000000302"
REPLAY_OPERATION_ID = "018f0000-0000-7000-8000-000000000303"
REPLAY_JOB_ID = "018f0000-0000-7000-8000-000000000304"


def limits(**changes: object) -> QueueLimits:
    value = QueueLimits(
        soft_pending=100,
        hard_pending=200,
        reserved_interactive=20,
        reserved_capture=30,
        soft_free_bytes=1_000_000,
        hard_free_bytes=500_000,
        soft_background_stride=16,
        alert_percentages=(70, 85, 100),
    )
    return replace(value, **cast("Any", changes))


def snapshot(  # noqa: PLR0913 -- Fixture exposes each independent capacity dimension.
    *,
    total: int = 0,
    interactive: int = 0,
    capture: int = 0,
    standard: int = 0,
    background: int = 0,
    free_bytes: int = 2_000_000,
    existing: bool = False,
) -> CapacitySnapshot:
    return CapacitySnapshot(
        total_pending=total,
        interactive_pending=interactive,
        capture_pending=capture,
        standard_pending=standard,
        background_pending=background,
        free_bytes=free_bytes,
        existing_identity=existing,
    )


def request(**changes: object) -> JobRequest:
    value = JobRequest(
        job_id=JOB_ID,
        brain_id=BRAIN_ID,
        actor_id=PRINCIPAL_ID,
        grant_id=GRANT_ID,
        kind="memory-index",
        idempotency_key="memory-index:event-301",
        request_sha256=digest("request").value,
        priority=JobPriority.STANDARD,
        input_ref="cas://sha256/" + digest("input").value,
    )
    return replace(value, **cast("Any", changes))


def job(**changes: object) -> ScheduledJob:
    value = ScheduledJob(
        request=request(),
        state=JobState.QUEUED,
        attempts=0,
        next_attempt_at_microseconds=10,
        lease_owner=None,
        lease_until_microseconds=None,
        last_error_code=None,
        result_sha256=None,
        completed_at_microseconds=None,
        parent_job_id=None,
        source_dead_letter_id=None,
        created_at_microseconds=1,
        updated_at_microseconds=1,
    )
    return replace(value, **cast("Any", changes))


def test_hard_capacity_rejects_only_new_work_and_preserves_reserved_slots() -> None:
    policy = limits()
    assert policy.admit(JobPriority.BACKGROUND, snapshot(total=200)).disposition is (
        AdmissionDisposition.REJECT_CAPACITY
    )
    assert (
        policy.admit(JobPriority.INTERACTIVE, snapshot(total=200, existing=True)).disposition
        is AdmissionDisposition.ADMIT
    )

    normal_ceiling = 200 - 20 - 30
    assert (
        policy.admit(JobPriority.STANDARD, snapshot(total=normal_ceiling)).disposition
        is AdmissionDisposition.REJECT_CAPACITY
    )
    assert (
        policy.admit(JobPriority.CAPTURE, snapshot(total=normal_ceiling)).disposition
        is AdmissionDisposition.ADMIT
    )

    capture_ceiling = 200 - 20
    assert (
        policy.admit(JobPriority.CAPTURE, snapshot(total=capture_ceiling)).disposition
        is AdmissionDisposition.REJECT_CAPACITY
    )
    assert (
        policy.admit(JobPriority.INTERACTIVE, snapshot(total=capture_ceiling)).disposition
        is AdmissionDisposition.ADMIT
    )


def test_disk_hard_limit_rejects_new_capture_but_exact_existing_identity_is_admitted() -> None:
    policy = limits()
    assert (
        policy.admit(
            JobPriority.CAPTURE,
            snapshot(free_bytes=500_000),
        ).disposition
        is AdmissionDisposition.REJECT_CAPACITY
    )
    assert (
        policy.admit(
            JobPriority.CAPTURE,
            snapshot(free_bytes=0, existing=True),
        ).disposition
        is AdmissionDisposition.ADMIT
    )


def test_soft_pressure_throttles_background_without_blocking_capture_or_interactive() -> None:
    policy = limits()
    pressure = snapshot(total=100, free_bytes=1_000_000)
    assert policy.admit(JobPriority.BACKGROUND, pressure).disposition is (
        AdmissionDisposition.THROTTLE
    )
    assert policy.admit(JobPriority.CAPTURE, pressure).disposition is (AdmissionDisposition.ADMIT)
    assert policy.admit(JobPriority.INTERACTIVE, pressure).disposition is (
        AdmissionDisposition.ADMIT
    )


@pytest.mark.parametrize("soft_limited", [False, True])
def test_dispatch_cycle_is_deterministic_and_never_starves_an_available_queue(
    soft_limited: object,
) -> None:
    assert isinstance(soft_limited, bool)
    available = frozenset(JobPriority)
    cursor = 0
    selected: list[JobPriority] = []
    rounds = 64 if soft_limited else 32
    for _ in range(rounds):
        priority, cursor = select_dispatch_priority(
            available,
            cursor,
            soft_limited=soft_limited,
            background_stride=16,
        )
        assert priority is not None
        selected.append(priority)
    assert set(selected) == set(JobPriority)
    assert selected.count(JobPriority.INTERACTIVE) > selected.count(JobPriority.BACKGROUND)
    if soft_limited:
        assert selected.count(JobPriority.BACKGROUND) == rounds // 16


def test_dispatch_skips_empty_queues_without_resetting_persisted_fairness_cursor() -> None:
    priority, cursor = select_dispatch_priority(
        frozenset({JobPriority.BACKGROUND}),
        cursor=5,
        soft_limited=False,
        background_stride=16,
    )
    assert priority is JobPriority.BACKGROUND
    assert cursor > 5
    assert select_dispatch_priority(
        frozenset(),
        cursor,
        soft_limited=False,
        background_stride=16,
    ) == (None, cursor)


@pytest.mark.parametrize(
    ("cursor", "background_stride", "expected"),
    [
        (-1, 16, FieldViolation("dispatch_cursor", "out_of_range")),
        (0, 0, FieldViolation("background_stride", "out_of_range")),
    ],
)
def test_dispatch_rejects_invalid_cycle_state_with_canonical_evidence(
    cursor: int,
    background_stride: int,
    expected: FieldViolation,
) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        select_dispatch_priority(
            frozenset(JobPriority),
            cursor,
            soft_limited=False,
            background_stride=background_stride,
        )
    assert captured.value.violations == (expected,)


@pytest.mark.parametrize("background_stride", [2, 1024])
def test_dispatch_accepts_each_configured_background_stride_boundary(
    background_stride: int,
) -> None:
    priority, cursor = select_dispatch_priority(
        frozenset(JobPriority),
        0,
        soft_limited=True,
        background_stride=background_stride,
    )
    assert priority is JobPriority.INTERACTIVE
    assert cursor == 1


def test_dispatch_preserves_the_canonical_soft_pressure_sequence_and_direction() -> None:
    cursor = 0
    selected: list[JobPriority] = []
    for _ in range(8):
        priority, cursor = select_dispatch_priority(
            frozenset(JobPriority),
            cursor,
            soft_limited=True,
            background_stride=8,
        )
        assert priority is not None
        selected.append(priority)
    assert selected == [
        JobPriority.INTERACTIVE,
        JobPriority.CAPTURE,
        JobPriority.INTERACTIVE,
        JobPriority.STANDARD,
        JobPriority.CAPTURE,
        JobPriority.INTERACTIVE,
        JobPriority.STANDARD,
        JobPriority.BACKGROUND,
    ]
    assert select_dispatch_priority(
        frozenset({JobPriority.STANDARD}),
        0,
        soft_limited=False,
        background_stride=16,
    ) == (JobPriority.STANDARD, 4)


def test_retry_policy_maps_nonretryable_bounded_and_backoff_errors() -> None:
    policy = RetryPolicy.default()
    assert policy.decide(JobErrorCode.INVALID_INPUT, attempts=1).disposition is (
        RetryDisposition.DEAD_LETTER
    )
    bounded = policy.decide(JobErrorCode.RATE_LIMITED, attempts=1)
    assert bounded.disposition is RetryDisposition.RETRY
    assert bounded.delay_microseconds == 5_000_000
    assert policy.decide(JobErrorCode.RATE_LIMITED, attempts=5).disposition is (
        RetryDisposition.DEAD_LETTER
    )

    assert [
        policy.decide(JobErrorCode.DEPENDENCY_UNAVAILABLE, attempts=value).delay_microseconds
        for value in (1, 2, 3, 4, 5)
    ] == [1_000_000, 2_000_000, 4_000_000, 8_000_000, 16_000_000]
    assert policy.decide(JobErrorCode.DEPENDENCY_UNAVAILABLE, attempts=9).disposition is (
        RetryDisposition.DEAD_LETTER
    )


def test_custom_retry_rules_are_closed_complete_and_validated() -> None:
    with pytest.raises(IngestionValidationError):
        RetryPolicy(
            (
                RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.NONE, 1, 0, 0),
                RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.NONE, 1, 0, 0),
            )
        )
    with pytest.raises(IngestionValidationError):
        RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.EXPONENTIAL_BACKOFF, 2, 0, 1)
    with pytest.raises(IngestionValidationError):
        RetryPolicy((RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.NONE, 1, 0, 0),))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: CapacitySnapshot(-1, 0, 0, 0, 0, 0, existing_identity=False),
        lambda: CapacitySnapshot(0, 1, 0, 0, 0, 0, existing_identity=False),
        lambda: AdmissionDecision(AdmissionDisposition.ADMIT, "unexpected_reason"),
        lambda: AdmissionDecision(AdmissionDisposition.THROTTLE, None),
        lambda: AdmissionDecision(AdmissionDisposition.THROTTLE, "Unsafe Reason"),
        lambda: RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.NONE, 0, 0, 0),
        lambda: RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.NONE, 1, 1, 0),
        lambda: RetryRule(JobErrorCode.INTERNAL_ERROR, RetryMode.BOUNDED, 2, 1, 2),
        lambda: RetryDecision(RetryDisposition.RETRY, None),
        lambda: RetryDecision(RetryDisposition.DEAD_LETTER, 1),
        lambda: RetryDecision(RetryDisposition.RETRY, 0),
    ],
)
def test_policy_evidence_rejects_ambiguous_shapes(factory: object) -> None:
    with pytest.raises(IngestionValidationError):
        cast("Any", factory)()


def test_retry_decision_rejects_nonpositive_attempt_number() -> None:
    with pytest.raises(IngestionValidationError):
        RetryPolicy.default().decide(JobErrorCode.INTERNAL_ERROR, attempts=0)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"job_id": "bad"}, FieldViolation("job_id", "invalid_id")),
        ({"kind": "bad kind"}, FieldViolation("kind", "invalid")),
        ({"idempotency_key": ""}, FieldViolation("idempotency_key", "invalid")),
        ({"request_sha256": "bad"}, FieldViolation("request_sha256", "invalid_digest")),
        (
            {"input_ref": "https://user:secret@example.test/input"},
            FieldViolation("input_ref", "unsafe"),
        ),
    ],
)
def test_job_request_rejects_ambiguous_identity_or_unsafe_input_reference(
    changes: dict[str, object],
    expected: FieldViolation,
) -> None:
    with pytest.raises(IngestionValidationError) as captured:
        request(**changes)
    assert captured.value.violations == (expected,)


@pytest.mark.parametrize(
    "changes",
    [
        {"attempts": -1},
        {"next_attempt_at_microseconds": -1},
        {"state": JobState.LEASED},
        {"last_error_code": JobErrorCode.INTERNAL_ERROR},
        {
            "state": JobState.SUCCEEDED,
            "result_sha256": digest("result").value,
        },
        {"parent_job_id": "bad"},
    ],
)
def test_scheduled_job_rejects_ambiguous_state_and_history(changes: dict[str, object]) -> None:
    with pytest.raises(IngestionValidationError):
        job(**changes)


def test_dead_letter_and_replay_request_are_immutable_content_free_evidence() -> None:
    dead = DeadLetter(
        dead_letter_id=DEAD_LETTER_ID,
        original_job_id=JOB_ID,
        brain_id=BRAIN_ID,
        priority=JobPriority.STANDARD,
        kind="memory-index",
        request_sha256=digest("request").value,
        attempts=3,
        error_code=JobErrorCode.INTEGRITY_VIOLATION,
        diagnostic_code="projection_digest_mismatch",
        failed_at_microseconds=20,
        created_at_microseconds=20,
    )
    replay = ReplayDeadLetterRequest(
        operation_id=REPLAY_OPERATION_ID,
        dead_letter_id=dead.dead_letter_id,
        new_job_id=REPLAY_JOB_ID,
        actor_id=PRINCIPAL_ID,
        grant_id=GRANT_ID,
        corrected_request_sha256=digest("corrected").value,
        corrected_input_ref="cas://sha256/" + digest("corrected-input").value,
    )
    assert replay.request_sha256 != dead.request_sha256
    assert dead.diagnostic_code == "projection_digest_mismatch"
    with pytest.raises(IngestionValidationError):
        replace(dead, diagnostic_code="contains secret text")


@pytest.mark.parametrize(
    "changes",
    [
        {"soft_pending": 0},
        {"hard_pending": 99},
        {"reserved_interactive": 100},
        {"reserved_capture": 200},
        {"soft_free_bytes": 499_999},
        {"hard_free_bytes": -1},
        {"soft_background_stride": 1},
        {"alert_percentages": (85, 70)},
    ],
)
def test_queue_limits_reject_unsafe_or_nonmonotonic_thresholds(
    changes: dict[str, object],
) -> None:
    with pytest.raises(IngestionValidationError):
        limits(**changes)
