"""PRO-010 authorized pricing, budget, telemetry, drift, and status use cases."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.domain.errors import (
    ProviderBudgetExhaustedError,
    ProviderErrorCode,
    ProviderObservabilityAuthorizationError,
    ProviderObservabilityConflictError,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.observability import (
    BudgetAdmission,
    BudgetDecision,
    DriftCanary,
    DriftEvaluation,
    DriftEvaluator,
    PricingSnapshot,
    ProviderBudgetPolicy,
    ProviderBudgetReservationRequest,
    ProviderOperationFact,
    ProviderOperationOutcome,
    ProviderStatusSnapshot,
)
from agentmemory.providers.domain.profiles import ProviderOperation
from agentmemory.providers.domain.scheduling import (
    ProviderBatch,
    ProviderBatchOutcome,
    ProviderItemResultStatus,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.observability_ports import (
        ProviderBudgetRepository,
        ProviderDriftProbe,
        ProviderDriftRepository,
        ProviderDriftScheduleRepository,
        ProviderObservabilityAdministrationRepository,
        ProviderPricingQuery,
        ProviderStatusRepository,
    )
    from agentmemory.providers.domain.scheduling_ports import ProviderBatchGateway
    from agentmemory.shared.clock import Clock

_OPERATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ADMIN_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})
_STATUS_ROLES = _ADMIN_ROLES | frozenset({RetrievalRole.AUDITOR})
_ERR_INPUT = "provider observability request is invalid"
_ERR_ACTION = "provider observability action is not authorized"
_ERR_CONFLICT = "provider observability authority is missing or stale"
_DRIFT_LEASE_MICROSECONDS = 60_000_000
_DRIFT_RETRY_MICROSECONDS = 60_000_000
_MAX_POLL_SECONDS = 1.0
_UUID_VERSION = 7


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishPricingSnapshotCommand:
    """Publish one immutable administrator-supplied catalog version."""

    operation_id: str
    scope: AuthorizedScope
    snapshot: PricingSnapshot

    def __post_init__(self) -> None:
        """Require stable idempotency and matching Brain authority."""
        _validate_command(self.operation_id, self.scope, self.snapshot.brain_id)

    @property
    def request_digest(self) -> str:
        """Bind operation replay to the exact snapshot identity and scope."""
        return _digest(
            {
                "brain_id": self.scope.brain_id.value,
                "scope_fingerprint": self.scope.scope_fingerprint,
                "snapshot_id": self.snapshot.snapshot_id,
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishBudgetPolicyCommand:
    """Publish one finite explicit budget period and exhaustion behavior."""

    operation_id: str
    scope: AuthorizedScope
    policy: ProviderBudgetPolicy

    def __post_init__(self) -> None:
        """Require stable idempotency and matching Brain authority."""
        _validate_command(self.operation_id, self.scope, self.policy.brain_id)

    @property
    def request_digest(self) -> str:
        """Bind operation replay to the exact policy identity and scope."""
        return _digest(
            {
                "brain_id": self.scope.brain_id.value,
                "policy_id": self.policy.policy_id,
                "scope_fingerprint": self.scope.scope_fingerprint,
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RegisterDriftCanaryCommand:
    """Register one pinned canary baseline for one exact generation."""

    operation_id: str
    scope: AuthorizedScope
    canary: DriftCanary

    def __post_init__(self) -> None:
        """Require stable idempotency and matching Brain authority."""
        _validate_command(self.operation_id, self.scope, self.canary.brain_id)

    @property
    def request_digest(self) -> str:
        """Bind operation replay to the complete canary document and scope."""
        return _digest(
            {
                "brain_id": self.scope.brain_id.value,
                "canary": self.canary.document,
                "scope_fingerprint": self.scope.scope_fingerprint,
            }
        )


ReserveProviderBudgetCommand = ProviderBudgetReservationRequest


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderOperationMeasurement:
    """Validated pre-telemetry measurement before exact pricing is applied."""

    operation_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    space_id: str | None
    generation_id: str | None
    pricing_snapshot_id: str
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
    cache_hit: bool
    deduplicated: bool
    occurred_at_microseconds: int
    operation: ProviderOperation = ProviderOperation.EMBEDDING

    def __post_init__(self) -> None:
        """Use the canonical fact validator before accepting a measurement."""
        self.to_fact(actual_cost_micros=0)

    def to_fact(self, *, actual_cost_micros: int) -> ProviderOperationFact:
        """Build the canonical digest-bound fact with reconciled actual cost."""
        return ProviderOperationFact.create(
            operation_id=self.operation_id,
            brain_id=self.brain_id,
            profile_id=self.profile_id,
            profile_version=self.profile_version,
            space_id=self.space_id,
            generation_id=self.generation_id,
            pricing_snapshot_id=self.pricing_snapshot_id,
            outcome=self.outcome,
            error_code=self.error_code,
            request_count=self.request_count,
            item_count=self.item_count,
            input_units=self.input_units,
            output_units=self.output_units,
            request_bytes=self.request_bytes,
            response_bytes=self.response_bytes,
            attempt_count=self.attempt_count,
            latency_microseconds=self.latency_microseconds,
            estimated_cost_micros=self.estimated_cost_micros,
            actual_cost_micros=actual_cost_micros,
            cache_hit=self.cache_hit,
            deduplicated=self.deduplicated,
            occurred_at_microseconds=self.occurred_at_microseconds,
            operation=self.operation,
        )

    @property
    def document(self) -> dict[str, object]:
        """Return exact fact constructor fields excluding reconciled actual cost."""
        return {
            "operation_id": self.operation_id,
            "brain_id": self.brain_id,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "space_id": self.space_id,
            "generation_id": self.generation_id,
            "pricing_snapshot_id": self.pricing_snapshot_id,
            "outcome": self.outcome,
            "error_code": self.error_code,
            "request_count": self.request_count,
            "item_count": self.item_count,
            "input_units": self.input_units,
            "output_units": self.output_units,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "attempt_count": self.attempt_count,
            "latency_microseconds": self.latency_microseconds,
            "estimated_cost_micros": self.estimated_cost_micros,
            "cache_hit": self.cache_hit,
            "deduplicated": self.deduplicated,
            "occurred_at_microseconds": self.occurred_at_microseconds,
            "operation": self.operation,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class RunDriftProbeCommand:
    """Run one registered canary under current administrative authority."""

    scope: AuthorizedScope
    canary_id: str

    def __post_init__(self) -> None:
        """Require one exact UUIDv7 canary identity."""
        try:
            valid = UUID(self.canary_id).version == _UUID_VERSION
        except TypeError, ValueError:
            valid = False
        if not valid:
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class GetProviderStatusQuery:
    """Read one complete current operator snapshot."""

    scope: AuthorizedScope
    observed_at: datetime

    def __post_init__(self) -> None:
        """Require a trusted UTC observation time."""
        if not _is_utc(self.observed_at):
            _invalid()


@dataclass(frozen=True, slots=True)
class PublishPricingSnapshotHandler:
    """Authorize and persist immutable pricing authority."""

    repository: ProviderObservabilityAdministrationRepository

    async def execute(self, command: PublishPricingSnapshotCommand) -> PricingSnapshot:
        """Publish only with Brain owner/administrator authority."""
        _authorize(
            command.scope,
            "provider.observability.pricing.publish",
            _ADMIN_ROLES,
        )
        return await self.repository.publish_pricing(
            command.scope,
            command.operation_id,
            command.request_digest,
            command.snapshot,
        )


@dataclass(frozen=True, slots=True)
class PublishBudgetPolicyHandler:
    """Authorize and persist one exact finite budget."""

    repository: ProviderObservabilityAdministrationRepository

    async def execute(self, command: PublishBudgetPolicyCommand) -> ProviderBudgetPolicy:
        """Publish only with Brain owner/administrator authority."""
        _authorize(
            command.scope,
            "provider.observability.budget.publish",
            _ADMIN_ROLES,
        )
        return await self.repository.publish_budget(
            command.scope,
            command.operation_id,
            command.request_digest,
            command.policy,
        )


@dataclass(frozen=True, slots=True)
class RegisterDriftCanaryHandler:
    """Authorize and persist one pinned generation canary."""

    repository: ProviderObservabilityAdministrationRepository

    async def execute(self, command: RegisterDriftCanaryCommand) -> DriftCanary:
        """Register only with Brain owner/administrator authority."""
        _authorize(
            command.scope,
            "provider.observability.drift.register",
            _ADMIN_ROLES,
        )
        return await self.repository.register_canary(
            command.scope,
            command.operation_id,
            command.request_digest,
            command.canary,
        )


@dataclass(frozen=True, slots=True)
class ReserveProviderBudgetHandler:
    """Reserve estimated cost before any provider dispatch."""

    repository: ProviderBudgetRepository

    async def execute(self, command: ReserveProviderBudgetCommand) -> BudgetAdmission:
        """Return the atomic configured reserve/queue/degrade decision."""
        return await self.repository.reserve_budget(command)


@dataclass(frozen=True, slots=True)
class ProviderTelemetryRecorder:
    """Price canonical operation usage and atomically reconcile its reservation."""

    pricing: ProviderPricingQuery
    repository: ProviderBudgetRepository

    async def record(
        self,
        measurement: ProviderOperationMeasurement,
    ) -> ProviderOperationFact:
        """Resolve one immutable catalog version before persisting actual usage."""
        snapshot = await self.pricing.get_pricing(measurement.pricing_snapshot_id)
        if (
            snapshot is None
            or snapshot.brain_id != measurement.brain_id
            or snapshot.profile_id != measurement.profile_id
            or snapshot.profile_version != measurement.profile_version
            or snapshot.operation is not measurement.operation
            or not snapshot.effective_from_microseconds
            <= measurement.occurred_at_microseconds
            < snapshot.effective_until_microseconds
        ):
            raise ProviderObservabilityConflictError(_ERR_CONFLICT)
        actual = snapshot.cost(
            request_count=measurement.request_count,
            input_units=measurement.input_units,
            output_units=measurement.output_units,
        )
        fact = measurement.to_fact(actual_cost_micros=actual)
        await self.repository.record_and_reconcile(fact)
        return fact


@dataclass(frozen=True, slots=True)
class BudgetedTelemetryProviderBatchGateway:
    """Reserve before dispatch and reconcile canonical batch usage after response."""

    gateway: ProviderBatchGateway
    pricing: ProviderPricingQuery
    budget: ProviderBudgetRepository
    telemetry: ProviderTelemetryRecorder
    clock: Clock
    elapsed_microseconds: Callable[[], int]

    async def execute(
        self,
        batch: ProviderBatch,
        payloads: Sequence[bytearray],
    ) -> ProviderBatchOutcome:
        """Never dispatch without exact pricing and a serialized reservation."""
        requested_at = _microseconds(self.clock.now())
        snapshot = await self.pricing.get_active_pricing(
            batch.key.brain_id,
            batch.key.profile_id,
            batch.key.profile_version,
            requested_at,
        )
        if snapshot is None or snapshot.operation is not ProviderOperation.EMBEDDING:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT)
        admission = await self.budget.reserve_budget(
            ProviderBudgetReservationRequest(
                operation_id=batch.operation_id,
                brain_id=batch.key.brain_id,
                profile_id=batch.key.profile_id,
                profile_version=batch.key.profile_version,
                pricing_snapshot_id=snapshot.snapshot_id,
                estimated_cost_micros=batch.estimated_cost_micros,
                requested_at_microseconds=requested_at,
            )
        )
        if admission.decision is not BudgetDecision.RESERVED:
            raise ProviderBudgetExhaustedError(
                admission.decision.value,
                admission.degraded_channels,
            )
        started = self.elapsed_microseconds()
        outcome = await self.gateway.execute(batch, payloads)
        outcome.validate_for(batch)
        elapsed = self.elapsed_microseconds() - started
        if elapsed < 0:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT)
        canonical_outcome, error_code = _batch_outcome(outcome)
        await self.telemetry.record(
            ProviderOperationMeasurement(
                operation_id=batch.operation_id,
                brain_id=batch.key.brain_id,
                profile_id=batch.key.profile_id,
                profile_version=batch.key.profile_version,
                space_id=None,
                generation_id=None,
                pricing_snapshot_id=snapshot.snapshot_id,
                outcome=canonical_outcome,
                error_code=error_code,
                request_count=1,
                item_count=len(batch.items),
                input_units=batch.token_count,
                output_units=0,
                request_bytes=batch.byte_count,
                response_bytes=0,
                attempt_count=1,
                latency_microseconds=elapsed,
                estimated_cost_micros=batch.estimated_cost_micros,
                cache_hit=False,
                deduplicated=False,
                occurred_at_microseconds=requested_at,
                operation=ProviderOperation.EMBEDDING,
            )
        )
        return outcome


@dataclass(frozen=True, slots=True)
class RunDriftProbeHandler:
    """Execute, compare, and atomically persist one safe canary observation."""

    repository: ProviderDriftRepository
    probe: ProviderDriftProbe

    async def execute(self, command: RunDriftProbeCommand) -> DriftEvaluation:
        """Suspend writes on mismatch; never expose a raw vector."""
        _authorize(
            command.scope,
            "provider.observability.drift.run",
            _ADMIN_ROLES,
        )
        canary = await self.repository.get_canary(command.scope, command.canary_id)
        if canary is None:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT)
        observation = await self.probe.observe(canary)
        evaluation = DriftEvaluator.evaluate(canary, observation)
        await self.repository.record_drift(observation, evaluation)
        return evaluation


@dataclass(frozen=True, slots=True)
class GetProviderStatusHandler:
    """Authorize and assemble one complete provider operator status."""

    repository: ProviderStatusRepository

    async def execute(self, query: GetProviderStatusQuery) -> ProviderStatusSnapshot:
        """Allow only owner, administrator, or auditor status access."""
        _authorize(
            query.scope,
            "provider.observability.status.read",
            _STATUS_ROLES,
        )
        return await self.repository.status(
            query.scope,
            _microseconds(query.observed_at),
        )


@dataclass(frozen=True, slots=True)
class ScheduledDriftProbeWorker:
    """Lease and isolate recurring provider drift probes."""

    repository: ProviderDriftScheduleRepository
    probe: ProviderDriftProbe
    clock: Clock
    owner: str
    poll_seconds: float = 0.05

    def __post_init__(self) -> None:
        """Bound idle polling; lease owner is validated by the claimed lease."""
        if (
            _OPERATION_ID.fullmatch(self.owner) is None
            or not 0 <= self.poll_seconds <= _MAX_POLL_SECONDS
        ):
            _invalid()

    async def run(self, stop: asyncio.Event) -> None:
        """Continuously isolate probe failures until graceful shutdown."""
        while not stop.is_set():
            try:
                claimed = await self.run_once()
            except Exception:  # noqa: BLE001 -- One provider probe cannot kill the worker.
                claimed = False
            if not claimed:
                await _wait_or_stop(stop, self.poll_seconds)

    async def run_once(self) -> bool:
        """Execute at most one due canary and report whether work was claimed."""
        now = _microseconds(self.clock.now())
        lease = await self.repository.claim_due(
            self.owner,
            now,
            now + _DRIFT_LEASE_MICROSECONDS,
        )
        if lease is None:
            return False
        try:
            observation = await self.probe.observe(lease.canary)
            evaluation = DriftEvaluator.evaluate(lease.canary, observation)
            await self.repository.complete_probe(lease, observation, evaluation)
        except asyncio.CancelledError:
            released = _microseconds(self.clock.now())
            await self.repository.release_probe(
                lease,
                released + _DRIFT_RETRY_MICROSECONDS,
                released,
            )
            raise
        except Exception:  # noqa: BLE001 -- Adapter details are intentionally discarded.
            released = _microseconds(self.clock.now())
            await self.repository.release_probe(
                lease,
                released + _DRIFT_RETRY_MICROSECONDS,
                released,
            )
        return True


def _validate_command(
    operation_id: str,
    scope: AuthorizedScope,
    brain_id: str,
) -> None:
    if _OPERATION_ID.fullmatch(operation_id) is None or scope.brain_id.value != brain_id:
        _invalid()


def _batch_outcome(
    outcome: ProviderBatchOutcome,
) -> tuple[ProviderOperationOutcome, ProviderErrorCode | None]:
    failed = tuple(
        item for item in outcome.results if item.status is not ProviderItemResultStatus.SUCCEEDED
    )
    if not failed:
        return ProviderOperationOutcome.SUCCEEDED, None
    first = failed[0]
    try:
        code = (
            ProviderErrorCode.ADAPTER_CRASH
            if first.error_code is None
            else ProviderErrorCode(first.error_code)
        )
    except ValueError:
        code = ProviderErrorCode.ADAPTER_CRASH
    if any(item.status is ProviderItemResultStatus.RETRYABLE_FAILURE for item in failed):
        return ProviderOperationOutcome.RETRY_SCHEDULED, code
    if any(item.status is ProviderItemResultStatus.CANCELLED for item in failed):
        return ProviderOperationOutcome.CANCELLED, code
    return ProviderOperationOutcome.PERMANENT_FAILURE, code


def _authorize(
    scope: AuthorizedScope,
    action: str,
    roles: frozenset[RetrievalRole],
) -> None:
    if scope.action != action or scope.role not in roles:
        raise ProviderObservabilityAuthorizationError(_ERR_ACTION)


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)


def _microseconds(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    if seconds == 0:
        await asyncio.sleep(0)
        return
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return


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
    result = hashlib.sha256(payload).hexdigest()
    if _DIGEST.fullmatch(result) is None:
        _invalid()
    return result


def _invalid() -> Never:
    raise ProviderObservabilityValidationError(_ERR_INPUT)
