"""PF-004 degradation policy and circuit-state tests."""

from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest

from agentmemory.resilience.domain.errors import (
    RecallAuthorizationError,
    RecallIntegrityError,
    ResilienceValidationError,
)
from agentmemory.resilience.domain.models import (
    ChannelFailure,
    ChannelFailureKind,
    ChannelName,
    ChannelOutcome,
    ChannelStatus,
    CircuitPolicy,
    CircuitSnapshot,
    CircuitState,
    DegradationPolicy,
    DependencyName,
    RecallExecutionPolicy,
    RecallResponse,
)
from agentmemory.resilience.infrastructure.system_clock import SystemRecallClock

NOW = datetime(2026, 7, 22, 16, 0, tzinfo=UTC)


def test_pf004_policy_degrades_optional_failures_but_escalates_authority_and_integrity() -> None:
    policy = DegradationPolicy()

    outcome = policy.channel_failure(
        ChannelName.VECTOR,
        ChannelFailure(ChannelFailureKind.DEPENDENCY, "AM_DEPENDENCY_UNAVAILABLE"),
        NOW,
    )

    assert outcome.channel is ChannelName.VECTOR
    assert outcome.degraded is True
    assert outcome.code == "AM_DEPENDENCY_UNAVAILABLE"
    assert outcome.status.value == "unavailable"
    assert outcome.freshness == NOW
    with pytest.raises(RecallAuthorizationError, match="fatal"):
        policy.channel_failure(
            ChannelName.EXACT,
            ChannelFailure(ChannelFailureKind.AUTHORIZATION, "fatal"),
            NOW,
        )
    with pytest.raises(RecallIntegrityError, match="fatal"):
        policy.channel_failure(
            ChannelName.EXACT,
            ChannelFailure(ChannelFailureKind.CANONICAL_INTEGRITY, "fatal"),
            NOW,
        )


def test_pf004_circuit_policy_transitions_closed_open_half_open_and_closed() -> None:
    policy = CircuitPolicy.production()
    closed = CircuitSnapshot.initial(DependencyName.EMBEDDING)
    snapshot = closed
    for offset in range(5):
        snapshot = policy.after_failure(snapshot, NOW + timedelta(seconds=offset))
    assert snapshot.state is CircuitState.OPEN
    assert policy.permit(snapshot, NOW + timedelta(seconds=29)).allowed is False

    probe = policy.permit(snapshot, NOW + timedelta(seconds=34))
    assert probe.allowed is True
    assert probe.snapshot.state is CircuitState.HALF_OPEN
    assert policy.permit(probe.snapshot, NOW + timedelta(seconds=34)).allowed is False

    recovered = policy.after_success(probe.snapshot, NOW + timedelta(seconds=35))
    assert recovered == CircuitSnapshot.initial(DependencyName.EMBEDDING, recovered.version)


def test_pf004_circuit_discards_failures_outside_window_and_rejects_invalid_time() -> None:
    policy = CircuitPolicy.production()
    snapshot = policy.after_failure(CircuitSnapshot.initial(DependencyName.NEO4J), NOW)
    reset = policy.after_failure(snapshot, NOW + timedelta(seconds=31))
    assert reset.consecutive_failures == 1
    with pytest.raises(ResilienceValidationError, match="UTC"):
        policy.after_failure(reset, NOW.replace(tzinfo=None))
    with pytest.raises(ResilienceValidationError, match="UTC"):
        policy.after_failure(reset, NOW.astimezone(timezone(timedelta(hours=1))))


def test_pf004_execution_policy_copies_deadlines_and_rejects_unbounded_values() -> None:
    deadlines = {ChannelName.EXACT: 1.0}
    policy = RecallExecutionPolicy(deadlines, 1, CircuitPolicy.production())
    deadlines[ChannelName.EXACT] = 20.0
    assert policy.channel_deadlines[ChannelName.EXACT] == 1.0

    with pytest.raises(ResilienceValidationError, match="execution policy"):
        RecallExecutionPolicy({}, 1, CircuitPolicy.production())


def test_pf004_cancelled_half_open_probe_reopens_without_counting_failure() -> None:
    policy = CircuitPolicy(failure_threshold=1, failure_window_seconds=30, open_seconds=30)
    opened = policy.after_failure(CircuitSnapshot.initial(DependencyName.EMBEDDING), NOW)
    probe = policy.permit(opened, NOW + timedelta(seconds=30)).snapshot

    abandoned = policy.after_abandon(probe, NOW + timedelta(seconds=31))

    assert abandoned.state is CircuitState.OPEN
    assert abandoned.consecutive_failures == opened.consecutive_failures
    assert abandoned.probe_in_flight is False


def test_pf004_system_clock_supplies_utc_time() -> None:
    assert SystemRecallClock().now().utcoffset() == UTC.utcoffset(None)


def test_pf004_outcome_and_response_reject_ambiguous_runtime_values() -> None:
    with pytest.raises(ResilienceValidationError, match="response"):
        ChannelOutcome(
            cast("ChannelName", "invalid"),
            ChannelStatus.AVAILABLE,
            "AM_OK",
            NOW,
        )
    outcome = ChannelOutcome(ChannelName.EXACT, ChannelStatus.AVAILABLE, "AM_OK", NOW)
    with pytest.raises(ResilienceValidationError, match="response"):
        RecallResponse((), (outcome, outcome))
