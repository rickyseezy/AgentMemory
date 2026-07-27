"""PRO-010 pure provider pricing, budget, telemetry, drift, and status contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Never
from uuid import UUID

from agentmemory.providers.domain.capability_probe import ProviderProbeSuite, probe_canaries
from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.profiles import ProviderOperation

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_OPERATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_WORKER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_UUID_VERSION = 7
_MAX_MONEY = 10**15
_MAX_COUNT = 10**15
_MAX_LATENCY_MICROSECONDS = 3_600_000_000
_MIN_CANARY_ITEMS = 2
_MAX_CANARY_ITEMS = 100
_MAX_NORM_MICROS = 10**15
_MAX_TOLERANCE_PPM = 1_000_000
_MAX_INTERVAL_MICROSECONDS = 31 * 24 * 60 * 60 * 1_000_000
_MICRO_UNITS = 1_000_000
_CIRCUIT_STATE_COUNT = 3
_DEGRADED_CHANNELS = frozenset({"exact", "lexical", "graph"})
_ERR_INPUT = "provider observability input is invalid"


class BudgetExhaustionBehavior(StrEnum):
    """Closed operator-selected behavior when a monetary period is exhausted."""

    QUEUE = "queue"
    DEGRADE = "degrade"


class BudgetDecision(StrEnum):
    """Closed pre-dispatch budget admission result."""

    RESERVED = "reserved"
    QUEUED = "queued"
    DEGRADED = "degraded"


class ProviderOperationOutcome(StrEnum):
    """Bounded canonical outcome labels accepted by provider telemetry."""

    SUCCEEDED = "succeeded"
    RETRY_SCHEDULED = "retry_scheduled"
    PERMANENT_FAILURE = "permanent_failure"
    CANCELLED = "cancelled"
    PRIVACY_DENIED = "privacy_denied"
    BUDGET_QUEUED = "budget_queued"
    BUDGET_DEGRADED = "budget_degraded"


class DriftVerdict(StrEnum):
    """Closed result of comparing one scheduled canary observation."""

    STABLE = "stable"
    DRIFTED = "drifted"


class ProviderHealthStatus(StrEnum):
    """Closed aggregate operator health state."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    SUSPENDED = "suspended"


class GenerationPinState(StrEnum):
    """Operator-visible model pin state for one semantic generation."""

    PINNED = "pinned"
    UNPINNED = "unpinned"
    DRIFT_SUSPECTED = "drift_suspected"


@dataclass(frozen=True, slots=True)
class PricingSnapshot:
    """Immutable administrator-supplied cost catalog for one profile revision."""

    snapshot_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    version: int
    currency: str
    operation: ProviderOperation
    request_micros: int
    input_micros_per_million: int
    output_micros_per_million: int
    effective_from_microseconds: int
    effective_until_microseconds: int
    created_at_microseconds: int

    def __post_init__(self) -> None:
        """Require a content-addressed, finite, non-overlapping price authority."""
        if (
            _DIGEST.fullmatch(self.snapshot_id) is None
            or not _uuid7(self.brain_id)
            or not _uuid7(self.profile_id)
            or not 1 <= self.profile_version <= 2**31 - 1
            or not 1 <= self.version <= 2**31 - 1
            or _CURRENCY.fullmatch(self.currency) is None
            or min(
                self.request_micros,
                self.input_micros_per_million,
                self.output_micros_per_million,
                self.effective_from_microseconds,
                self.created_at_microseconds,
            )
            < 0
            or max(
                self.request_micros,
                self.input_micros_per_million,
                self.output_micros_per_million,
            )
            > _MAX_MONEY
            or self.effective_until_microseconds <= self.effective_from_microseconds
            or self.created_at_microseconds > self.effective_from_microseconds
            or self.snapshot_id != _digest(self.creation_document)
        ):
            _invalid()

    @classmethod
    def create(  # noqa: PLR0913 -- The price identity binds every independent rate coordinate.
        cls,
        *,
        brain_id: str,
        profile_id: str,
        profile_version: int,
        version: int,
        currency: str,
        operation: ProviderOperation,
        request_micros: int,
        input_micros_per_million: int,
        output_micros_per_million: int,
        effective_from_microseconds: int,
        effective_until_microseconds: int,
        created_at_microseconds: int,
    ) -> PricingSnapshot:
        """Construct the content identity from the complete versioned catalog."""
        document: dict[str, object] = {
            "brain_id": brain_id,
            "created_at_microseconds": created_at_microseconds,
            "currency": currency,
            "effective_from_microseconds": effective_from_microseconds,
            "effective_until_microseconds": effective_until_microseconds,
            "input_micros_per_million": input_micros_per_million,
            "operation": operation.value,
            "output_micros_per_million": output_micros_per_million,
            "profile_id": profile_id,
            "profile_version": profile_version,
            "request_micros": request_micros,
            "version": version,
        }
        return cls(
            snapshot_id=_digest(document),
            brain_id=brain_id,
            profile_id=profile_id,
            profile_version=profile_version,
            version=version,
            currency=currency,
            operation=operation,
            request_micros=request_micros,
            input_micros_per_million=input_micros_per_million,
            output_micros_per_million=output_micros_per_million,
            effective_from_microseconds=effective_from_microseconds,
            effective_until_microseconds=effective_until_microseconds,
            created_at_microseconds=created_at_microseconds,
        )

    @property
    def creation_document(self) -> dict[str, object]:
        """Return the exact constructor fields without the derived identity."""
        return {
            "brain_id": self.brain_id,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "version": self.version,
            "currency": self.currency,
            "operation": self.operation,
            "request_micros": self.request_micros,
            "input_micros_per_million": self.input_micros_per_million,
            "output_micros_per_million": self.output_micros_per_million,
            "effective_from_microseconds": self.effective_from_microseconds,
            "effective_until_microseconds": self.effective_until_microseconds,
            "created_at_microseconds": self.created_at_microseconds,
        }

    @property
    def document(self) -> dict[str, object]:
        """Return deterministic persistence fields."""
        return {
            **self.creation_document,
            "operation": self.operation.value,
            "snapshot_id": self.snapshot_id,
        }

    def cost(
        self,
        *,
        request_count: int,
        input_units: int,
        output_units: int,
    ) -> int:
        """Calculate one conservative integer-micro charge without floating point."""
        if (
            min(request_count, input_units, output_units) < 0
            or max(
                request_count,
                input_units,
                output_units,
            )
            > _MAX_COUNT
        ):
            _invalid()
        cost = (
            request_count * self.request_micros
            + _ceil_rate(input_units, self.input_micros_per_million)
            + _ceil_rate(output_units, self.output_micros_per_million)
        )
        if cost > _MAX_MONEY:
            _invalid()
        return cost


@dataclass(frozen=True, slots=True)
class BudgetAdmission:
    """Pure decision carrying either an exact reservation or safe degraded channels."""

    decision: BudgetDecision
    reserved_micros: int
    degraded_channels: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require mutually exclusive reserve, queue, and degrade shapes."""
        if (
            not 0 <= self.reserved_micros <= _MAX_MONEY
            or len(set(self.degraded_channels)) != len(self.degraded_channels)
            or any(channel not in _DEGRADED_CHANNELS for channel in self.degraded_channels)
            or (
                self.decision is BudgetDecision.RESERVED
                and (self.reserved_micros < 0 or self.degraded_channels)
            )
            or (
                self.decision is BudgetDecision.QUEUED
                and (self.reserved_micros != 0 or self.degraded_channels)
            )
            or (
                self.decision is BudgetDecision.DEGRADED
                and (self.reserved_micros != 0 or not self.degraded_channels)
            )
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderBudgetPolicy:
    """Versioned finite spend policy with an explicit exhaustion action."""

    policy_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    version: int
    currency: str
    limit_micros: int
    behavior: BudgetExhaustionBehavior
    degraded_channels: tuple[str, ...]
    period_start_microseconds: int
    period_end_microseconds: int
    created_at_microseconds: int

    def __post_init__(self) -> None:
        """Reject implicit unlimited budgets and vector-based degradation."""
        if (
            _DIGEST.fullmatch(self.policy_id) is None
            or not _uuid7(self.brain_id)
            or not _uuid7(self.profile_id)
            or not 1 <= self.profile_version <= 2**31 - 1
            or not 1 <= self.version <= 2**31 - 1
            or _CURRENCY.fullmatch(self.currency) is None
            or not 0 <= self.limit_micros <= _MAX_MONEY
            or len(set(self.degraded_channels)) != len(self.degraded_channels)
            or any(channel not in _DEGRADED_CHANNELS for channel in self.degraded_channels)
            or not self.degraded_channels
            or self.period_start_microseconds < 0
            or self.period_end_microseconds <= self.period_start_microseconds
            or not 0 <= self.created_at_microseconds <= self.period_start_microseconds
            or self.policy_id != _digest(self.creation_document)
        ):
            _invalid()

    @classmethod
    def create(  # noqa: PLR0913 -- The policy identity binds every budget authority coordinate.
        cls,
        *,
        brain_id: str,
        profile_id: str,
        profile_version: int,
        version: int,
        currency: str,
        limit_micros: int,
        behavior: BudgetExhaustionBehavior,
        degraded_channels: tuple[str, ...],
        period_start_microseconds: int,
        period_end_microseconds: int,
        created_at_microseconds: int,
    ) -> ProviderBudgetPolicy:
        """Construct one content-addressed administrator budget."""
        document: dict[str, object] = {
            "behavior": behavior.value,
            "brain_id": brain_id,
            "created_at_microseconds": created_at_microseconds,
            "currency": currency,
            "degraded_channels": list(degraded_channels),
            "limit_micros": limit_micros,
            "period_end_microseconds": period_end_microseconds,
            "period_start_microseconds": period_start_microseconds,
            "profile_id": profile_id,
            "profile_version": profile_version,
            "version": version,
        }
        return cls(
            policy_id=_digest(document),
            brain_id=brain_id,
            profile_id=profile_id,
            profile_version=profile_version,
            version=version,
            currency=currency,
            limit_micros=limit_micros,
            behavior=behavior,
            degraded_channels=degraded_channels,
            period_start_microseconds=period_start_microseconds,
            period_end_microseconds=period_end_microseconds,
            created_at_microseconds=created_at_microseconds,
        )

    @property
    def creation_document(self) -> dict[str, object]:
        """Return exact content-addressed fields."""
        return {
            "behavior": self.behavior.value,
            "brain_id": self.brain_id,
            "created_at_microseconds": self.created_at_microseconds,
            "currency": self.currency,
            "degraded_channels": list(self.degraded_channels),
            "limit_micros": self.limit_micros,
            "period_end_microseconds": self.period_end_microseconds,
            "period_start_microseconds": self.period_start_microseconds,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "version": self.version,
        }

    def admit(
        self,
        *,
        spent_micros: int,
        reserved_micros: int,
        estimate_micros: int,
    ) -> BudgetAdmission:
        """Reserve only if the serialized total remains within the exact limit."""
        if (
            min(spent_micros, reserved_micros, estimate_micros) < 0
            or max(
                spent_micros,
                reserved_micros,
                estimate_micros,
            )
            > _MAX_MONEY
        ):
            _invalid()
        if spent_micros + reserved_micros + estimate_micros <= self.limit_micros:
            return BudgetAdmission(BudgetDecision.RESERVED, estimate_micros, ())
        if self.behavior is BudgetExhaustionBehavior.QUEUE:
            return BudgetAdmission(BudgetDecision.QUEUED, 0, ())
        return BudgetAdmission(
            BudgetDecision.DEGRADED,
            0,
            self.degraded_channels,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderBudgetReservationRequest:
    """Exact pre-dispatch identity used for serialized budget admission."""

    operation_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    pricing_snapshot_id: str
    estimated_cost_micros: int
    requested_at_microseconds: int

    def __post_init__(self) -> None:
        """Require stable profile, pricing, cost, and period coordinates."""
        if (
            _OPERATION_ID.fullmatch(self.operation_id) is None
            or not _uuid7(self.brain_id)
            or not _uuid7(self.profile_id)
            or not 1 <= self.profile_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.pricing_snapshot_id) is None
            or not 0 <= self.estimated_cost_micros <= _MAX_MONEY
            or self.requested_at_microseconds < 0
        ):
            _invalid()

    @property
    def request_digest(self) -> str:
        """Bind idempotency to every admission coordinate."""
        return _digest(
            {
                "brain_id": self.brain_id,
                "estimated_cost_micros": self.estimated_cost_micros,
                "operation_id": self.operation_id,
                "pricing_snapshot_id": self.pricing_snapshot_id,
                "profile_id": self.profile_id,
                "profile_version": self.profile_version,
                "requested_at_microseconds": self.requested_at_microseconds,
            }
        )


@dataclass(frozen=True, slots=True)
class DriftCanary:
    """Pinned safe canary aggregates for one exact semantic generation."""

    canary_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    space_id: str
    generation_id: str
    capability_attestation_id: str
    revision_fingerprint: str
    canary_set_digest: str
    vector_fingerprint: str
    canary_item_ids: tuple[str, ...]
    norms_micros: tuple[int, ...]
    distance_order: tuple[str, ...]
    norm_tolerance_ppm: int
    maximum_order_inversions: int
    interval_microseconds: int
    next_probe_at_microseconds: int
    created_at_microseconds: int

    def __post_init__(self) -> None:
        """Require bounded content-free aggregates and exact generation coordinates."""
        item_count = len(self.norms_micros)
        maximum_inversions = item_count * (item_count - 1) // 2
        fixed_ids = tuple(item.content_id for item in probe_canaries())
        if (
            any(
                not _uuid7(value)
                for value in (
                    self.canary_id,
                    self.brain_id,
                    self.profile_id,
                    self.space_id,
                    self.generation_id,
                )
            )
            or not 1 <= self.profile_version <= 2**31 - 1
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.capability_attestation_id,
                    self.revision_fingerprint,
                    self.canary_set_digest,
                    self.vector_fingerprint,
                )
            )
            or not _MIN_CANARY_ITEMS <= item_count <= _MAX_CANARY_ITEMS
            or len(self.canary_item_ids) != item_count
            or len(set(self.canary_item_ids)) != item_count
            or any(_DIGEST.fullmatch(value) is None for value in self.canary_item_ids)
            or self.canary_set_digest != ProviderProbeSuite().canary_digest
            or self.canary_item_ids != fixed_ids
            or len(self.distance_order) != item_count
            or len(set(self.distance_order)) != item_count
            or any(_DIGEST.fullmatch(value) is None for value in self.distance_order)
            or set(self.distance_order) != set(self.canary_item_ids)
            or any(not 1 <= value <= _MAX_NORM_MICROS for value in self.norms_micros)
            or not 0 <= self.norm_tolerance_ppm <= _MAX_TOLERANCE_PPM
            or not 0 <= self.maximum_order_inversions <= maximum_inversions
            or not 1 <= self.interval_microseconds <= _MAX_INTERVAL_MICROSECONDS
            or self.created_at_microseconds < 0
            or self.next_probe_at_microseconds < self.created_at_microseconds
        ):
            _invalid()

    @classmethod
    def create(cls, **values: object) -> DriftCanary:
        """Build the strict immutable canary contract."""
        try:
            return cls(**values)  # type: ignore[arg-type]
        except TypeError as error:
            raise ProviderObservabilityValidationError(_ERR_INPUT) from error

    @property
    def document(self) -> dict[str, object]:
        """Return safe persistence fields; raw canary content and vectors do not fit."""
        return {
            "brain_id": self.brain_id,
            "canary_id": self.canary_id,
            "canary_item_ids": list(self.canary_item_ids),
            "canary_set_digest": self.canary_set_digest,
            "capability_attestation_id": self.capability_attestation_id,
            "created_at_microseconds": self.created_at_microseconds,
            "distance_order": list(self.distance_order),
            "generation_id": self.generation_id,
            "interval_microseconds": self.interval_microseconds,
            "maximum_order_inversions": self.maximum_order_inversions,
            "next_probe_at_microseconds": self.next_probe_at_microseconds,
            "norm_tolerance_ppm": self.norm_tolerance_ppm,
            "norms_micros": list(self.norms_micros),
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "revision_fingerprint": self.revision_fingerprint,
            "space_id": self.space_id,
            "vector_fingerprint": self.vector_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class DriftObservation:
    """One scheduled probe result reduced to bounded non-vector aggregates."""

    canary_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    space_id: str
    generation_id: str
    revision_fingerprint: str
    vector_fingerprint: str
    canary_item_ids: tuple[str, ...]
    norms_micros: tuple[int, ...]
    distance_order: tuple[str, ...]
    observed_at_microseconds: int

    def __post_init__(self) -> None:
        """Reject malformed or unbounded adapter observations."""
        if (
            any(
                not _uuid7(value)
                for value in (
                    self.canary_id,
                    self.brain_id,
                    self.profile_id,
                    self.space_id,
                    self.generation_id,
                )
            )
            or not 1 <= self.profile_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.revision_fingerprint) is None
            or _DIGEST.fullmatch(self.vector_fingerprint) is None
            or not _MIN_CANARY_ITEMS <= len(self.norms_micros) <= _MAX_CANARY_ITEMS
            or len(self.canary_item_ids) != len(self.norms_micros)
            or len(set(self.canary_item_ids)) != len(self.canary_item_ids)
            or any(_DIGEST.fullmatch(value) is None for value in self.canary_item_ids)
            or len(self.distance_order) != len(self.norms_micros)
            or len(set(self.distance_order)) != len(self.distance_order)
            or any(_DIGEST.fullmatch(value) is None for value in self.distance_order)
            or set(self.distance_order) != set(self.canary_item_ids)
            or any(not 1 <= value <= _MAX_NORM_MICROS for value in self.norms_micros)
            or self.observed_at_microseconds < 0
        ):
            _invalid()

    @classmethod
    def create(  # noqa: PLR0913 -- Observation coordinates are explicit and independently bound.
        cls,
        *,
        canary: DriftCanary,
        revision_fingerprint: str,
        vector_fingerprint: str,
        canary_item_ids: tuple[str, ...],
        norms_micros: tuple[int, ...],
        distance_order: tuple[str, ...],
        observed_at_microseconds: int,
    ) -> DriftObservation:
        """Bind untrusted safe aggregates to the exact claimed canary coordinates."""
        if observed_at_microseconds < canary.created_at_microseconds:
            _invalid()
        return cls(
            canary_id=canary.canary_id,
            brain_id=canary.brain_id,
            profile_id=canary.profile_id,
            profile_version=canary.profile_version,
            space_id=canary.space_id,
            generation_id=canary.generation_id,
            revision_fingerprint=revision_fingerprint,
            vector_fingerprint=vector_fingerprint,
            canary_item_ids=canary_item_ids,
            norms_micros=norms_micros,
            distance_order=distance_order,
            observed_at_microseconds=observed_at_microseconds,
        )

    @property
    def digest(self) -> str:
        """Content-address the safe observation for append-only persistence."""
        return _digest(
            {
                "brain_id": self.brain_id,
                "canary_id": self.canary_id,
                "canary_item_ids": list(self.canary_item_ids),
                "distance_order": list(self.distance_order),
                "generation_id": self.generation_id,
                "norms_micros": list(self.norms_micros),
                "observed_at_microseconds": self.observed_at_microseconds,
                "profile_id": self.profile_id,
                "profile_version": self.profile_version,
                "revision_fingerprint": self.revision_fingerprint,
                "space_id": self.space_id,
                "vector_fingerprint": self.vector_fingerprint,
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderDriftProbeLease:
    """One owner-bound scheduled canary lease."""

    canary: DriftCanary
    owner: str
    lease_until_microseconds: int
    state_version: int

    def __post_init__(self) -> None:
        """Require a bounded owner, future lease, and optimistic state version."""
        if (
            _WORKER.fullmatch(self.owner) is None
            or self.lease_until_microseconds <= self.canary.created_at_microseconds
            or not 1 <= self.state_version <= 2**31 - 1
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class DriftEvaluation:
    """Pure comparison result used for atomic write suspension."""

    verdict: DriftVerdict
    reason_code: str | None
    suspend_writes: bool
    requires_new_space: bool

    def __post_init__(self) -> None:
        """Require stable or drifted fields to agree exactly."""
        drifted = self.verdict is DriftVerdict.DRIFTED
        if (
            drifted != (self.reason_code is not None)
            or drifted != self.suspend_writes
            or drifted != self.requires_new_space
            or (self.reason_code is not None and _SAFE_CODE.fullmatch(self.reason_code) is None)
        ):
            _invalid()


class DriftEvaluator:
    """Compare tolerant safe aggregates without accepting raw vectors."""

    @staticmethod
    def evaluate(
        canary: DriftCanary,
        observation: DriftObservation,
    ) -> DriftEvaluation:
        """Return the first closed mismatch in semantic-corruption priority order."""
        if (
            observation.canary_id != canary.canary_id
            or observation.brain_id != canary.brain_id
            or observation.profile_id != canary.profile_id
            or observation.profile_version != canary.profile_version
            or observation.space_id != canary.space_id
            or observation.generation_id != canary.generation_id
            or observation.canary_item_ids != canary.canary_item_ids
            or len(observation.norms_micros) != len(canary.norms_micros)
            or set(observation.distance_order) != set(canary.distance_order)
        ):
            _invalid()
        if observation.revision_fingerprint != canary.revision_fingerprint:
            return _drift("model_revision_mismatch")
        if observation.vector_fingerprint != canary.vector_fingerprint:
            return _drift("vector_fingerprint_mismatch")
        if any(
            abs(actual - expected) * _MICRO_UNITS > expected * canary.norm_tolerance_ppm
            for expected, actual in zip(
                canary.norms_micros,
                observation.norms_micros,
                strict=True,
            )
        ):
            return _drift("vector_norm_mismatch")
        if _inversions(canary.distance_order, observation.distance_order) > (
            canary.maximum_order_inversions
        ):
            return _drift("distance_order_mismatch")
        return DriftEvaluation(
            verdict=DriftVerdict.STABLE,
            reason_code=None,
            suspend_writes=False,
            requires_new_space=False,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderOperationFact:
    """Immutable privacy-bounded canonical provider operation outcome."""

    fact_digest: str
    operation_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    space_id: str | None
    generation_id: str | None
    pricing_snapshot_id: str
    operation: ProviderOperation
    outcome: ProviderOperationOutcome
    error_code: ProviderErrorCode | None
    request_count: int
    item_count: int
    input_units: int
    output_units: int
    request_bytes: int
    response_bytes: int
    attempt_count: int
    latency_microseconds: int
    estimated_cost_micros: int
    actual_cost_micros: int
    cache_hit: bool
    deduplicated: bool
    occurred_at_microseconds: int

    def __post_init__(self) -> None:
        """Require bounded fields, canonical errors, and a valid evidence digest."""
        error_required = self.outcome in {
            ProviderOperationOutcome.RETRY_SCHEDULED,
            ProviderOperationOutcome.PERMANENT_FAILURE,
            ProviderOperationOutcome.CANCELLED,
            ProviderOperationOutcome.PRIVACY_DENIED,
        }
        if (
            _DIGEST.fullmatch(self.fact_digest) is None
            or _OPERATION_ID.fullmatch(self.operation_id) is None
            or not _uuid7(self.brain_id)
            or not _uuid7(self.profile_id)
            or not 1 <= self.profile_version <= 2**31 - 1
            or (self.space_id is not None and not _uuid7(self.space_id))
            or (self.generation_id is not None and not _uuid7(self.generation_id))
            or ((self.space_id is None) != (self.generation_id is None))
            or _DIGEST.fullmatch(self.pricing_snapshot_id) is None
            or error_required != (self.error_code is not None)
            or (self.outcome is ProviderOperationOutcome.SUCCEEDED and self.error_code is not None)
            or any(
                not 0 <= value <= _MAX_COUNT
                for value in (
                    self.request_count,
                    self.item_count,
                    self.input_units,
                    self.output_units,
                    self.request_bytes,
                    self.response_bytes,
                    self.attempt_count,
                )
            )
            or not 0 <= self.latency_microseconds <= _MAX_LATENCY_MICROSECONDS
            or not 0 <= self.estimated_cost_micros <= _MAX_MONEY
            or not 0 <= self.actual_cost_micros <= _MAX_MONEY
            or not _boolean(self.cache_hit)
            or not _boolean(self.deduplicated)
            or self.occurred_at_microseconds < 0
            or self.fact_digest != self.expected_digest
        ):
            _invalid()

    @classmethod
    def create(  # noqa: PLR0913 -- Canonical telemetry deliberately has an explicit closed schema.
        cls,
        *,
        operation_id: str,
        brain_id: str,
        profile_id: str,
        profile_version: int,
        space_id: str | None,
        generation_id: str | None,
        pricing_snapshot_id: str,
        outcome: ProviderOperationOutcome,
        error_code: ProviderErrorCode | None,
        request_count: int,
        item_count: int,
        input_units: int,
        output_units: int,
        request_bytes: int,
        response_bytes: int,
        attempt_count: int,
        latency_microseconds: int,
        estimated_cost_micros: int,
        actual_cost_micros: int,
        cache_hit: bool,
        deduplicated: bool,
        occurred_at_microseconds: int,
        operation: ProviderOperation = ProviderOperation.EMBEDDING,
    ) -> ProviderOperationFact:
        """Create one digest-bound telemetry fact."""
        values: dict[str, object] = {
            "actual_cost_micros": actual_cost_micros,
            "attempt_count": attempt_count,
            "brain_id": brain_id,
            "cache_hit": cache_hit,
            "deduplicated": deduplicated,
            "error_code": None if error_code is None else error_code.value,
            "estimated_cost_micros": estimated_cost_micros,
            "generation_id": generation_id,
            "input_units": input_units,
            "item_count": item_count,
            "latency_microseconds": latency_microseconds,
            "occurred_at_microseconds": occurred_at_microseconds,
            "operation": operation.value,
            "operation_id": operation_id,
            "outcome": outcome.value,
            "output_units": output_units,
            "pricing_snapshot_id": pricing_snapshot_id,
            "profile_id": profile_id,
            "profile_version": profile_version,
            "request_bytes": request_bytes,
            "request_count": request_count,
            "response_bytes": response_bytes,
            "space_id": space_id,
        }
        return cls(
            fact_digest=_digest(values),
            operation_id=operation_id,
            brain_id=brain_id,
            profile_id=profile_id,
            profile_version=profile_version,
            space_id=space_id,
            generation_id=generation_id,
            pricing_snapshot_id=pricing_snapshot_id,
            operation=operation,
            outcome=outcome,
            error_code=error_code,
            request_count=request_count,
            item_count=item_count,
            input_units=input_units,
            output_units=output_units,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            attempt_count=attempt_count,
            latency_microseconds=latency_microseconds,
            estimated_cost_micros=estimated_cost_micros,
            actual_cost_micros=actual_cost_micros,
            cache_hit=cache_hit,
            deduplicated=deduplicated,
            occurred_at_microseconds=occurred_at_microseconds,
        )

    @property
    def expected_digest(self) -> str:
        """Recompute the immutable fact identity."""
        return _digest(
            {
                "actual_cost_micros": self.actual_cost_micros,
                "attempt_count": self.attempt_count,
                "brain_id": self.brain_id,
                "cache_hit": self.cache_hit,
                "deduplicated": self.deduplicated,
                "error_code": None if self.error_code is None else self.error_code.value,
                "estimated_cost_micros": self.estimated_cost_micros,
                "generation_id": self.generation_id,
                "input_units": self.input_units,
                "item_count": self.item_count,
                "latency_microseconds": self.latency_microseconds,
                "occurred_at_microseconds": self.occurred_at_microseconds,
                "operation": self.operation.value,
                "operation_id": self.operation_id,
                "outcome": self.outcome.value,
                "output_units": self.output_units,
                "pricing_snapshot_id": self.pricing_snapshot_id,
                "profile_id": self.profile_id,
                "profile_version": self.profile_version,
                "request_bytes": self.request_bytes,
                "request_count": self.request_count,
                "response_bytes": self.response_bytes,
                "space_id": self.space_id,
            }
        )

    @property
    def metric_labels(self) -> dict[str, str]:
        """Return only fixed bounded metric dimensions."""
        return {
            "error_code": "none" if self.error_code is None else self.error_code.value,
            "operation": self.operation.value,
            "outcome": self.outcome.value,
        }


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    """One profile-level aggregate with bounded labels and safe error counts."""

    profile_id: str
    profile_version: int
    status: ProviderHealthStatus
    circuit_counts: tuple[int, int, int]
    requests: int
    items: int
    input_units: int
    output_units: int
    cost_micros: int
    latency_p50_microseconds: int
    latency_p95_microseconds: int
    latency_p99_microseconds: int
    safe_errors: tuple[tuple[ProviderErrorCode, int], ...]

    def __post_init__(self) -> None:
        """Validate monotonic percentiles and unique closed error groups."""
        codes = tuple(code for code, _ in self.safe_errors)
        if (
            not _uuid7(self.profile_id)
            or not 1 <= self.profile_version <= 2**31 - 1
            or len(self.circuit_counts) != _CIRCUIT_STATE_COUNT
            or any(value < 0 for value in self.circuit_counts)
            or any(
                not 0 <= value <= _MAX_COUNT
                for value in (
                    self.requests,
                    self.items,
                    self.input_units,
                    self.output_units,
                    self.cost_micros,
                )
            )
            or not (
                0
                <= self.latency_p50_microseconds
                <= self.latency_p95_microseconds
                <= self.latency_p99_microseconds
                <= _MAX_LATENCY_MICROSECONDS
            )
            or len(set(codes)) != len(codes)
            or tuple(sorted(codes, key=str)) != codes
            or any(count < 1 for _, count in self.safe_errors)
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderQueueStatus:
    """Content-free aggregate provider queue/retry/dead-letter state."""

    queued: int
    leased: int
    retry_scheduled: int
    failed: int
    dead_lettered: int
    oldest_queued_at_microseconds: int | None

    def __post_init__(self) -> None:
        """Reject negative counts and ambiguous oldest-item time."""
        if (
            any(
                not 0 <= value <= _MAX_COUNT
                for value in (
                    self.queued,
                    self.leased,
                    self.retry_scheduled,
                    self.failed,
                    self.dead_lettered,
                )
            )
            or (
                self.oldest_queued_at_microseconds is not None
                and self.oldest_queued_at_microseconds < 0
            )
            or ((self.queued == 0) != (self.oldest_queued_at_microseconds is None))
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderBudgetStatus:
    """One exact current budget balance."""

    profile_id: str
    policy_id: str
    currency: str
    limit_micros: int
    spent_micros: int
    reserved_micros: int
    remaining_micros: int
    behavior: BudgetExhaustionBehavior

    def __post_init__(self) -> None:
        """Require an arithmetically consistent nonnegative balance."""
        if (
            not _uuid7(self.profile_id)
            or _DIGEST.fullmatch(self.policy_id) is None
            or _CURRENCY.fullmatch(self.currency) is None
            or any(
                not 0 <= value <= _MAX_MONEY
                for value in (
                    self.limit_micros,
                    self.spent_micros,
                    self.reserved_micros,
                    self.remaining_micros,
                )
            )
            or self.remaining_micros
            != max(0, self.limit_micros - self.spent_micros - self.reserved_micros)
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderGenerationStatus:
    """Active/rollback generation and model pin/write state."""

    space_id: str
    active_generation_id: str
    rollback_generation_id: str | None
    pin_state: GenerationPinState
    write_suspended: bool
    suspension_reason: str | None

    def __post_init__(self) -> None:
        """Require suspension to be visible as drift-suspected with a safe reason."""
        if (
            not _uuid7(self.space_id)
            or not _uuid7(self.active_generation_id)
            or (self.rollback_generation_id is not None and not _uuid7(self.rollback_generation_id))
            or not _boolean(self.write_suspended)
            or self.write_suspended != (self.suspension_reason is not None)
            or (
                self.suspension_reason is not None
                and _SAFE_CODE.fullmatch(self.suspension_reason) is None
            )
            or (self.write_suspended and self.pin_state is not GenerationPinState.DRIFT_SUSPECTED)
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderStatusSnapshot:
    """Complete Brain-scoped operator status assembled from canonical evidence."""

    brain_id: str
    observed_at_microseconds: int
    health: tuple[ProviderHealth, ...]
    queues: ProviderQueueStatus
    budgets: tuple[ProviderBudgetStatus, ...]
    generations: tuple[ProviderGenerationStatus, ...]
    retry_count: int
    dead_letter_count: int
    active_alert_count: int

    def __post_init__(self) -> None:
        """Require unique, sorted, bounded aggregate identities."""
        health_ids = tuple(item.profile_id for item in self.health)
        budget_ids = tuple(item.profile_id for item in self.budgets)
        space_ids = tuple(item.space_id for item in self.generations)
        if (
            not _uuid7(self.brain_id)
            or self.observed_at_microseconds < 0
            or len(set(health_ids)) != len(health_ids)
            or len(set(budget_ids)) != len(budget_ids)
            or len(set(space_ids)) != len(space_ids)
            or any(
                not 0 <= value <= _MAX_COUNT
                for value in (
                    self.retry_count,
                    self.dead_letter_count,
                    self.active_alert_count,
                )
            )
        ):
            _invalid()


def _ceil_rate(units: int, rate: int) -> int:
    return 0 if units == 0 or rate == 0 else (units * rate + _MICRO_UNITS - 1) // _MICRO_UNITS


def _boolean(value: object) -> bool:
    return type(value) is bool


def _inversions(expected: tuple[str, ...], actual: tuple[str, ...]) -> int:
    rank = {value: index for index, value in enumerate(expected)}
    positions = tuple(rank[value] for value in actual)
    return sum(
        positions[left] > positions[right]
        for left in range(len(positions))
        for right in range(left + 1, len(positions))
    )


def _drift(reason: str) -> DriftEvaluation:
    return DriftEvaluation(
        verdict=DriftVerdict.DRIFTED,
        reason_code=reason,
        suspend_writes=True,
        requires_new_space=True,
    )


def _uuid7(value: object) -> bool:
    try:
        return isinstance(value, str) and UUID(value).version == _UUID_VERSION
    except TypeError, ValueError:
        return False


def _digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderObservabilityValidationError(_ERR_INPUT) from error
    return hashlib.sha256(payload).hexdigest()


def _invalid() -> Never:
    raise ProviderObservabilityValidationError(_ERR_INPUT)
