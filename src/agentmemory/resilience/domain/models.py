"""PF-004 circuit, channel-outcome, and explicit degradation models."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from agentmemory.resilience.domain.errors import (
    RecallAuthorizationError,
    RecallIntegrityError,
    ResilienceValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SCOPE_DIGEST = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_CODE_LENGTH = 128
_MAX_FAILURE_THRESHOLD = 100
_MAX_POLICY_SECONDS = 3_600
_MAX_SCORE_BASIS_POINTS = 10_000
_MAX_CHANNEL_CANDIDATES = 1_000
_MAX_BULKHEAD_LIMIT = 64
_MAX_CHANNEL_DEADLINE_SECONDS = 30.0
_ERR_CHANNEL_FAILURE = "channel failure code is invalid"
_ERR_CIRCUIT_COUNTER = "circuit counters are invalid"
_ERR_CIRCUIT_OPEN = "open circuit requires open_until"
_ERR_CIRCUIT_HALF_OPEN = "half-open circuit requires one probe"
_ERR_CIRCUIT_POLICY = "circuit policy is invalid"
_ERR_CANDIDATE = "recall candidate is invalid"
_ERR_QUERY = "recall query is invalid"
_ERR_CHANNEL_CANDIDATES = "channel candidates are invalid"
_ERR_RESPONSE = "recall response is invalid"
_ERR_EXECUTION_POLICY = "recall execution policy is invalid"
_ERR_AUTHORIZATION = "fatal authorization failure"
_ERR_INTEGRITY = "fatal canonical integrity failure"
_ERR_TIME = "time must be UTC"


class DependencyName(StrEnum):
    """Closed PF-004 local dependency identities."""

    CANONICAL_LEDGER = "canonical_ledger"
    NEO4J = "neo4j"
    EMBEDDING = "embedding"
    RERANKING = "reranking"
    EXTRACTION = "extraction"
    NONCANONICAL_WORKER = "noncanonical_worker"


class ChannelName(StrEnum):
    """Independent recall channels exposed in degradation evidence."""

    EXACT = "exact"
    LEXICAL = "lexical"
    VECTOR = "vector"
    GRAPH = "graph"


class CircuitState(StrEnum):
    """Closed circuit-breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ChannelStatus(StrEnum):
    """Typed outcome for every requested recall channel."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    CIRCUIT_OPEN = "circuit_open"


class ChannelFailureKind(StrEnum):
    """Security-significant classification supplied to DegradationPolicy."""

    AUTHORIZATION = "authorization"
    CANONICAL_INTEGRITY = "canonical_integrity"
    DEPENDENCY = "dependency"
    DEADLINE = "deadline"
    CIRCUIT_OPEN = "circuit_open"


@dataclass(frozen=True, slots=True)
class ChannelFailure:
    """Content-free typed channel failure."""

    kind: ChannelFailureKind
    code: str

    def __post_init__(self) -> None:
        """Require a bounded stable diagnostic code."""
        if not self.code or len(self.code) > _MAX_CODE_LENGTH:
            raise ResilienceValidationError(_ERR_CHANNEL_FAILURE)


@dataclass(frozen=True, slots=True)
class CircuitSnapshot:
    """One versioned dependency circuit snapshot."""

    dependency: DependencyName
    state: CircuitState
    consecutive_failures: int
    window_started_at: datetime | None
    open_until: datetime | None
    probe_in_flight: bool
    version: int

    @classmethod
    def initial(cls, dependency: DependencyName, version: int = 0) -> CircuitSnapshot:
        """Create the initial closed snapshot for one dependency."""
        return cls(
            dependency=dependency,
            state=CircuitState.CLOSED,
            consecutive_failures=0,
            window_started_at=None,
            open_until=None,
            probe_in_flight=False,
            version=version,
        )

    def __post_init__(self) -> None:
        """Validate the closed circuit state machine representation."""
        if self.consecutive_failures < 0 or self.version < 0:
            raise ResilienceValidationError(_ERR_CIRCUIT_COUNTER)
        for value in (self.window_started_at, self.open_until):
            if value is not None:
                _utc(value)
        if self.state is CircuitState.OPEN and self.open_until is None:
            raise ResilienceValidationError(_ERR_CIRCUIT_OPEN)
        if self.state is CircuitState.HALF_OPEN and not self.probe_in_flight:
            raise ResilienceValidationError(_ERR_CIRCUIT_HALF_OPEN)


@dataclass(frozen=True, slots=True)
class CircuitPermit:
    """Atomic before-call decision and resulting snapshot."""

    allowed: bool
    snapshot: CircuitSnapshot


@dataclass(frozen=True, slots=True)
class CircuitPolicy:
    """Pure reviewed circuit transition policy."""

    failure_threshold: int
    failure_window_seconds: int
    open_seconds: int

    @classmethod
    def production(cls) -> CircuitPolicy:
        """Return the reviewed production circuit thresholds."""
        return cls(failure_threshold=5, failure_window_seconds=30, open_seconds=30)

    def __post_init__(self) -> None:
        """Reject unsafe circuit thresholds at composition time."""
        if (
            not 1 <= self.failure_threshold <= _MAX_FAILURE_THRESHOLD
            or not 1 <= self.failure_window_seconds <= _MAX_POLICY_SECONDS
            or not 1 <= self.open_seconds <= _MAX_POLICY_SECONDS
        ):
            raise ResilienceValidationError(_ERR_CIRCUIT_POLICY)

    def permit(self, snapshot: CircuitSnapshot, now: datetime) -> CircuitPermit:
        """Atomically decide whether a call or sole half-open probe may run."""
        _utc(now)
        if snapshot.state is CircuitState.CLOSED:
            return CircuitPermit(allowed=True, snapshot=snapshot)
        if snapshot.state is CircuitState.HALF_OPEN:
            return CircuitPermit(allowed=False, snapshot=snapshot)
        if snapshot.open_until is None or now < snapshot.open_until:
            return CircuitPermit(allowed=False, snapshot=snapshot)
        half_open = CircuitSnapshot(
            dependency=snapshot.dependency,
            state=CircuitState.HALF_OPEN,
            consecutive_failures=snapshot.consecutive_failures,
            window_started_at=snapshot.window_started_at,
            open_until=snapshot.open_until,
            probe_in_flight=True,
            version=snapshot.version + 1,
        )
        return CircuitPermit(allowed=True, snapshot=half_open)

    def after_failure(self, snapshot: CircuitSnapshot, now: datetime) -> CircuitSnapshot:
        """Count one failed call and open the circuit at its threshold."""
        _utc(now)
        started = snapshot.window_started_at
        outside = started is None or now - started > timedelta(seconds=self.failure_window_seconds)
        failures = 1 if outside else snapshot.consecutive_failures + 1
        started = now if outside else started
        should_open = snapshot.state is CircuitState.HALF_OPEN or failures >= self.failure_threshold
        return CircuitSnapshot(
            dependency=snapshot.dependency,
            state=CircuitState.OPEN if should_open else CircuitState.CLOSED,
            consecutive_failures=failures,
            window_started_at=started,
            open_until=now + timedelta(seconds=self.open_seconds) if should_open else None,
            probe_in_flight=False,
            version=snapshot.version + 1,
        )

    def after_success(self, snapshot: CircuitSnapshot, now: datetime) -> CircuitSnapshot:
        """Reset a healthy dependency to a closed circuit."""
        _utc(now)
        return CircuitSnapshot.initial(snapshot.dependency, snapshot.version + 1)

    def after_abandon(self, snapshot: CircuitSnapshot, now: datetime) -> CircuitSnapshot:
        """Release a cancelled permit without counting a dependency failure."""
        _utc(now)
        if snapshot.state is not CircuitState.HALF_OPEN:
            return snapshot
        return CircuitSnapshot(
            dependency=snapshot.dependency,
            state=CircuitState.OPEN,
            consecutive_failures=snapshot.consecutive_failures,
            window_started_at=snapshot.window_started_at,
            open_until=now + timedelta(seconds=self.open_seconds),
            probe_in_flight=False,
            version=snapshot.version + 1,
        )


@dataclass(frozen=True, slots=True)
class RecallExecutionPolicy:
    """Immutable channel deadlines, bulkhead, and circuit policy."""

    channel_deadlines: Mapping[ChannelName, float]
    bulkhead_limit: int
    circuit: CircuitPolicy

    def __post_init__(self) -> None:
        """Freeze and validate all bounded execution controls."""
        deadlines = dict(self.channel_deadlines)
        if (
            not deadlines
            or not 1 <= self.bulkhead_limit <= _MAX_BULKHEAD_LIMIT
            or any(not 0 < value <= _MAX_CHANNEL_DEADLINE_SECONDS for value in deadlines.values())
        ):
            raise ResilienceValidationError(_ERR_EXECUTION_POLICY)
        object.__setattr__(self, "channel_deadlines", MappingProxyType(deadlines))


@dataclass(frozen=True, slots=True)
class RecallCandidate:
    """Content-free candidate identity and deterministic channel score."""

    candidate_id: str
    score_basis_points: int

    def __post_init__(self) -> None:
        """Require a stable identity and normalized score."""
        if not self.candidate_id or not 0 <= self.score_basis_points <= _MAX_SCORE_BASIS_POINTS:
            raise ResilienceValidationError(_ERR_CANDIDATE)


@dataclass(frozen=True, slots=True)
class RecallQuery:
    """Authorized-scope coordinate and caller deadline shared by every channel."""

    operation_id: str
    requested_at: datetime
    deadline_at: datetime
    scope_fingerprint: str

    def __post_init__(self) -> None:
        """Validate operation, authorization scope, and caller deadline."""
        _utc(self.requested_at)
        _utc(self.deadline_at)
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or _SCOPE_DIGEST.fullmatch(self.scope_fingerprint) is None
            or self.deadline_at <= self.requested_at
        ):
            raise ResilienceValidationError(_ERR_QUERY)


@dataclass(frozen=True, slots=True)
class RecallChannelSuccess:
    """One bounded successful channel result with an explicit watermark."""

    channel: ChannelName
    candidates: tuple[RecallCandidate, ...]
    freshness: datetime

    def __post_init__(self) -> None:
        """Require bounded deduplicated candidates and a UTC watermark."""
        _utc(self.freshness)
        if len(self.candidates) > _MAX_CHANNEL_CANDIDATES or len(
            {item.candidate_id for item in self.candidates}
        ) != len(self.candidates):
            raise ResilienceValidationError(_ERR_CHANNEL_CANDIDATES)


@dataclass(frozen=True, slots=True)
class ChannelOutcome:
    """First-class available or degraded channel evidence."""

    channel: ChannelName
    status: ChannelStatus
    code: str
    freshness: datetime

    def __post_init__(self) -> None:
        """Require closed enum identities, bounded code, and UTC failure evidence."""
        if not _valid_outcome_types(self.channel, self.status):
            raise ResilienceValidationError(_ERR_RESPONSE)
        ChannelFailure(ChannelFailureKind.DEPENDENCY, self.code)
        _utc(self.freshness)

    @property
    def degraded(self) -> bool:
        """Return whether this channel did not produce an available result."""
        return self.status is not ChannelStatus.AVAILABLE


@dataclass(frozen=True, slots=True)
class RecallResponse:
    """Partial-success response that never hides unavailable channels."""

    candidates: tuple[RecallCandidate, ...]
    channel_outcomes: tuple[ChannelOutcome, ...]

    def __post_init__(self) -> None:
        """Reject ambiguous duplicate channel and candidate identities."""
        if len({item.channel for item in self.channel_outcomes}) != len(
            self.channel_outcomes
        ) or len({item.candidate_id for item in self.candidates}) != len(self.candidates):
            raise ResilienceValidationError(_ERR_RESPONSE)

    @property
    def outcomes(self) -> dict[ChannelName, ChannelOutcome]:
        """Index channel outcomes by their closed identity."""
        return {item.channel: item for item in self.channel_outcomes}

    @property
    def degraded_channels(self) -> tuple[ChannelName, ...]:
        """Expose every unavailable channel in deterministic source order."""
        return tuple(item.channel for item in self.channel_outcomes if item.degraded)

    @property
    def freshness(self) -> dict[ChannelName, datetime]:
        """Expose the explicit source or failure observation watermark per channel."""
        return {item.channel: item.freshness for item in self.channel_outcomes}


class DegradationPolicy:
    """Fail closed for authority/integrity and degrade only optional dependency work."""

    def channel_failure(
        self,
        channel: ChannelName,
        failure: ChannelFailure,
        observed_at: datetime,
    ) -> ChannelOutcome:
        """Convert optional failures while raising fatal authority and integrity failures."""
        _utc(observed_at)
        if failure.kind is ChannelFailureKind.AUTHORIZATION:
            raise RecallAuthorizationError(_ERR_AUTHORIZATION)
        if failure.kind is ChannelFailureKind.CANONICAL_INTEGRITY:
            raise RecallIntegrityError(_ERR_INTEGRITY)
        status = {
            ChannelFailureKind.DEPENDENCY: ChannelStatus.UNAVAILABLE,
            ChannelFailureKind.DEADLINE: ChannelStatus.TIMED_OUT,
            ChannelFailureKind.CIRCUIT_OPEN: ChannelStatus.CIRCUIT_OPEN,
        }[failure.kind]
        return ChannelOutcome(channel, status, failure.code, observed_at)


def _utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ResilienceValidationError(_ERR_TIME)


def _valid_outcome_types(channel: object, status: object) -> bool:
    """Defend runtime construction boundaries despite statically closed annotations."""
    return isinstance(channel, ChannelName) and isinstance(status, ChannelStatus)
