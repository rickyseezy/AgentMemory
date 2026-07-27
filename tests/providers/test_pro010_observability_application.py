"""PRO-010 authorization, pricing, telemetry, budget, drift, and status orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, RetrievalRole
from agentmemory.providers.application.observability import (
    BudgetedTelemetryProviderBatchGateway,
    GetProviderStatusHandler,
    GetProviderStatusQuery,
    ProviderOperationMeasurement,
    ProviderTelemetryRecorder,
    PublishBudgetPolicyCommand,
    PublishBudgetPolicyHandler,
    PublishPricingSnapshotCommand,
    PublishPricingSnapshotHandler,
    RegisterDriftCanaryCommand,
    RegisterDriftCanaryHandler,
    ReserveProviderBudgetCommand,
    ReserveProviderBudgetHandler,
    RunDriftProbeCommand,
    RunDriftProbeHandler,
    ScheduledDriftProbeWorker,
)
from agentmemory.providers.domain.errors import (
    ProviderBudgetExhaustedError,
    ProviderObservabilityAuthorizationError,
    ProviderObservabilityConflictError,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.observability import (
    BudgetAdmission,
    BudgetDecision,
    DriftCanary,
    DriftEvaluation,
    DriftObservation,
    PricingSnapshot,
    ProviderBudgetPolicy,
    ProviderDriftProbeLease,
    ProviderOperationFact,
    ProviderOperationOutcome,
    ProviderQueueStatus,
    ProviderStatusSnapshot,
)
from agentmemory.providers.domain.scheduling import (
    BatchPlanner,
    ProviderBatch,
    ProviderBatchOutcome,
    ProviderItemResult,
    ProviderItemResultStatus,
)
from tests.core.support import NOW, FixedClock, digest
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro006_scheduling_domain import item, limits
from tests.providers.test_pro010_observability_domain import (
    budget,
    canary,
    observation,
    pricing,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(slots=True)
class _Repository:
    """Record every application call without weakening the port contract."""

    pricing_value: PricingSnapshot = field(default_factory=pricing)
    budget_value: ProviderBudgetPolicy = field(default_factory=budget)
    canary_value: DriftCanary | None = field(default_factory=canary)
    status_value: ProviderStatusSnapshot | None = None
    active_pricing_available: bool = True
    admission: BudgetAdmission = field(
        default_factory=lambda: BudgetAdmission(BudgetDecision.RESERVED, 500, ())
    )
    pricing_publications: list[tuple[AuthorizedScope, str, str, PricingSnapshot]] = field(
        default_factory=list[tuple[AuthorizedScope, str, str, PricingSnapshot]]
    )
    budget_publications: list[tuple[AuthorizedScope, str, str, ProviderBudgetPolicy]] = field(
        default_factory=list[tuple[AuthorizedScope, str, str, ProviderBudgetPolicy]]
    )
    canary_registrations: list[tuple[AuthorizedScope, str, str, DriftCanary]] = field(
        default_factory=list[tuple[AuthorizedScope, str, str, DriftCanary]]
    )
    reservations: list[ReserveProviderBudgetCommand] = field(
        default_factory=list[ReserveProviderBudgetCommand]
    )
    facts: list[ProviderOperationFact] = field(default_factory=list[ProviderOperationFact])
    observations: list[tuple[DriftObservation, DriftEvaluation]] = field(
        default_factory=list[tuple[DriftObservation, DriftEvaluation]]
    )

    async def publish_pricing(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        snapshot: PricingSnapshot,
    ) -> PricingSnapshot:
        self.pricing_publications.append((scope, operation_id, request_digest, snapshot))
        return snapshot

    async def publish_budget(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        policy: ProviderBudgetPolicy,
    ) -> ProviderBudgetPolicy:
        self.budget_publications.append((scope, operation_id, request_digest, policy))
        return policy

    async def register_canary(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        canary: DriftCanary,
    ) -> DriftCanary:
        self.canary_registrations.append((scope, operation_id, request_digest, canary))
        return canary

    async def reserve_budget(
        self,
        request: ReserveProviderBudgetCommand,
    ) -> BudgetAdmission:
        self.reservations.append(request)
        return self.admission

    async def get_pricing(self, snapshot_id: str) -> PricingSnapshot | None:
        return self.pricing_value if snapshot_id == self.pricing_value.snapshot_id else None

    async def get_active_pricing(
        self,
        brain_id: str,
        profile_id: str,
        profile_version: int,
        at_microseconds: int,
    ) -> PricingSnapshot | None:
        del at_microseconds
        value = self.pricing_value
        if (
            self.active_pricing_available
            and value.brain_id == brain_id
            and value.profile_id == profile_id
            and value.profile_version == profile_version
        ):
            return value
        return None

    async def record_and_reconcile(self, fact: ProviderOperationFact) -> None:
        self.facts.append(fact)

    async def get_canary(
        self,
        scope: AuthorizedScope,
        canary_id: str,
    ) -> DriftCanary | None:
        del scope
        value = self.canary_value
        return value if value is not None and canary_id == value.canary_id else None

    async def record_drift(
        self,
        observation: DriftObservation,
        evaluation: DriftEvaluation,
    ) -> None:
        self.observations.append((observation, evaluation))

    async def status(
        self,
        scope: AuthorizedScope,
        observed_at_microseconds: int,
    ) -> ProviderStatusSnapshot:
        del scope, observed_at_microseconds
        if self.status_value is None:
            msg = "status fixture was not configured"
            raise AssertionError(msg)
        return self.status_value


@dataclass(slots=True)
class _Probe:
    result: DriftObservation = field(default_factory=observation)
    calls: list[DriftCanary] = field(default_factory=list[DriftCanary])

    async def observe(self, canary: DriftCanary) -> DriftObservation:
        self.calls.append(canary)
        return self.result


@dataclass(slots=True)
class _Schedule:
    lease: ProviderDriftProbeLease | None

    async def claim_due(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderDriftProbeLease | None:
        del owner, now_microseconds, lease_until_microseconds
        claimed, self.lease = self.lease, None
        return claimed

    async def complete_probe(
        self,
        lease: ProviderDriftProbeLease,
        observation: DriftObservation,
        evaluation: DriftEvaluation,
    ) -> None:
        del lease, observation, evaluation

    async def release_probe(
        self,
        lease: ProviderDriftProbeLease,
        retry_at_microseconds: int,
        released_at_microseconds: int,
    ) -> None:
        del lease, retry_at_microseconds, released_at_microseconds


@dataclass(slots=True)
class _BatchGateway:
    calls: list[ProviderBatch] = field(default_factory=list[ProviderBatch])
    status: ProviderItemResultStatus | None = None
    error_code: str = "adapter_crash"

    async def execute(
        self,
        batch: ProviderBatch,
        payloads: Sequence[bytearray],
    ) -> ProviderBatchOutcome:
        assert len(payloads) == len(batch.items)
        self.calls.append(batch)
        if self.status is not None:
            first, *remaining = batch.items
            return ProviderBatchOutcome(
                batch.operation_id,
                (
                    ProviderItemResult.failed(
                        first.item_id,
                        self.status,
                        self.error_code,
                    ),
                    *(
                        ProviderItemResult.succeeded(
                            value.item_id,
                            digest(value.item_id).value,
                        )
                        for value in remaining
                    ),
                ),
            )
        return ProviderBatchOutcome(
            batch.operation_id,
            tuple(
                ProviderItemResult.succeeded(value.item_id, digest(value.item_id).value)
                for value in batch.items
            ),
        )


@pytest.mark.asyncio
async def test_administration_handlers_publish_exact_versioned_authority() -> None:
    repository = _Repository()
    price_command = PublishPricingSnapshotCommand(
        operation_id="publish-pricing-3",
        scope=scope("provider.observability.pricing.publish"),
        snapshot=pricing(),
    )
    budget_command = PublishBudgetPolicyCommand(
        operation_id="publish-budget-4",
        scope=scope("provider.observability.budget.publish"),
        policy=budget(),
    )
    canary_command = RegisterDriftCanaryCommand(
        operation_id="register-canary-1",
        scope=scope("provider.observability.drift.register"),
        canary=canary(),
    )

    assert await PublishPricingSnapshotHandler(repository).execute(price_command) == pricing()
    assert await PublishBudgetPolicyHandler(repository).execute(budget_command) == budget()
    assert await RegisterDriftCanaryHandler(repository).execute(canary_command) == canary()
    assert repository.pricing_publications[0][2] == price_command.request_digest
    assert repository.budget_publications[0][2] == budget_command.request_digest
    assert repository.canary_registrations[0][2] == canary_command.request_digest


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "command"),
    [
        (
            PublishPricingSnapshotHandler,
            PublishPricingSnapshotCommand(
                operation_id="publish-pricing-denied",
                scope=scope(
                    "provider.observability.pricing.publish",
                    role=RetrievalRole.READER,
                ),
                snapshot=pricing(),
            ),
        ),
        (
            PublishBudgetPolicyHandler,
            PublishBudgetPolicyCommand(
                operation_id="publish-budget-denied",
                scope=scope(
                    "provider.observability.budget.publish",
                    role=RetrievalRole.AUDITOR,
                ),
                policy=budget(),
            ),
        ),
        (
            RegisterDriftCanaryHandler,
            RegisterDriftCanaryCommand(
                operation_id="register-canary-denied",
                scope=scope(
                    "provider.observability.drift.register",
                    role=RetrievalRole.READER,
                ),
                canary=canary(),
            ),
        ),
    ],
)
async def test_observability_administration_rejects_non_admin_roles(
    handler: type[object],
    command: object,
) -> None:
    repository = _Repository()
    with pytest.raises(ProviderObservabilityAuthorizationError):
        await handler(repository).execute(command)  # type: ignore[attr-defined,call-arg]


@pytest.mark.asyncio
async def test_budget_reservation_occurs_before_dispatch_and_returns_closed_behavior() -> None:
    repository = _Repository()
    command = ReserveProviderBudgetCommand(
        operation_id="provider-operation-budget-1",
        brain_id=pricing().brain_id,
        profile_id=pricing().profile_id,
        profile_version=2,
        pricing_snapshot_id=pricing().snapshot_id,
        estimated_cost_micros=500,
        requested_at_microseconds=1_500_000,
    )
    result = await ReserveProviderBudgetHandler(repository).execute(command)
    assert result == BudgetAdmission(BudgetDecision.RESERVED, 500, ())
    assert repository.reservations == [command]

    repository.admission = BudgetAdmission(BudgetDecision.QUEUED, 0, ())
    assert (
        await ReserveProviderBudgetHandler(repository).execute(command)
    ).decision is BudgetDecision.QUEUED


@pytest.mark.asyncio
async def test_budgeted_gateway_reserves_before_dispatch_and_reconciles_usage() -> None:
    repository = _Repository()
    key = replace(item(0).batch_key, profile_id=pricing().profile_id)
    work = (item(0, batch_key=key), item(1, batch_key=key))
    batch = BatchPlanner.plan(work, limits())[0]
    gateway = _BatchGateway()
    elapsed = iter((100, 350))
    guarded = BudgetedTelemetryProviderBatchGateway(
        gateway=gateway,
        pricing=repository,
        budget=repository,
        telemetry=ProviderTelemetryRecorder(repository, repository),
        clock=FixedClock(datetime.fromtimestamp(1.5, tz=UTC)),
        elapsed_microseconds=lambda: next(elapsed),
    )

    outcome = await guarded.execute(
        batch,
        tuple(bytearray(b"safe") for _ in batch.items),
    )

    assert outcome.batch_operation_id == batch.operation_id
    assert repository.reservations[0].operation_id == batch.operation_id
    assert gateway.calls == [batch]
    assert repository.facts[0].latency_microseconds == 250
    assert repository.facts[0].item_count == 2

    repository.admission = BudgetAdmission(BudgetDecision.QUEUED, 0, ())
    denied_gateway = _BatchGateway()
    denied = replace(guarded, gateway=denied_gateway)
    with pytest.raises(ProviderBudgetExhaustedError) as captured:
        await denied.execute(batch, tuple(bytearray(b"safe") for _ in batch.items))
    assert captured.value.decision == "queued"
    assert denied_gateway.calls == []


@pytest.mark.asyncio
async def test_telemetry_recorder_uses_exact_pricing_version_and_reconciles_actual() -> None:
    repository = _Repository()
    measurement = ProviderOperationMeasurement(
        operation_id="provider-operation-telemetry-1",
        brain_id=pricing().brain_id,
        profile_id=pricing().profile_id,
        profile_version=2,
        space_id=canary().space_id,
        generation_id=canary().generation_id,
        pricing_snapshot_id=pricing().snapshot_id,
        outcome=ProviderOperationOutcome.SUCCEEDED,
        error_code=None,
        request_count=1,
        item_count=2,
        input_units=100,
        output_units=0,
        request_bytes=200,
        response_bytes=300,
        attempt_count=1,
        latency_microseconds=20_000,
        estimated_cost_micros=500,
        cache_hit=False,
        deduplicated=False,
        occurred_at_microseconds=1_500_000,
    )
    fact = await ProviderTelemetryRecorder(repository, repository).record(measurement)
    assert fact.actual_cost_micros == pricing().cost(
        request_count=1,
        input_units=100,
        output_units=0,
    )
    assert fact.pricing_snapshot_id == pricing().snapshot_id
    assert repository.facts == [fact]

    with pytest.raises(ProviderObservabilityConflictError):
        await ProviderTelemetryRecorder(repository, repository).record(
            replace(
                measurement,
                pricing_snapshot_id=digest("unknown-pricing").value,
            )
        )


@pytest.mark.asyncio
async def test_drift_handler_compares_and_atomically_records_write_suspension() -> None:
    repository = _Repository()
    probe = _Probe()
    command = RunDriftProbeCommand(
        scope=scope("provider.observability.drift.run"),
        canary_id=canary().canary_id,
    )
    stable = await RunDriftProbeHandler(repository, probe).execute(command)
    assert stable.verdict.value == "stable"
    assert probe.calls == [canary()]
    assert repository.observations[-1][1] == stable

    probe.result = observation(revision_fingerprint=digest("silently-changed-model").value)
    drifted = await RunDriftProbeHandler(repository, probe).execute(command)
    assert drifted.suspend_writes is True
    assert drifted.requires_new_space is True
    assert repository.observations[-1][1] == drifted


@pytest.mark.asyncio
async def test_status_requires_operator_authority_and_returns_repository_snapshot() -> None:
    repository = _Repository()
    repository.status_value = ProviderStatusSnapshot(
        brain_id=pricing().brain_id,
        observed_at_microseconds=round(NOW.timestamp() * 1_000_000),
        health=(),
        queues=ProviderQueueStatus(0, 0, 0, 0, 0, None),
        budgets=(),
        generations=(),
        retry_count=0,
        dead_letter_count=0,
        active_alert_count=0,
    )
    query = GetProviderStatusQuery(
        scope=scope(
            "provider.observability.status.read",
            role=RetrievalRole.AUDITOR,
        ),
        observed_at=NOW,
    )
    assert await GetProviderStatusHandler(repository).execute(query) == (repository.status_value)
    with pytest.raises(ProviderObservabilityAuthorizationError):
        await GetProviderStatusHandler(repository).execute(
            GetProviderStatusQuery(
                scope=scope(
                    "provider.observability.status.read",
                    role=RetrievalRole.READER,
                ),
                observed_at=NOW,
            )
        )


def test_commands_workers_and_queries_reject_invalid_runtime_coordinates() -> None:
    with pytest.raises(ProviderObservabilityValidationError):
        RunDriftProbeCommand(
            scope=scope("provider.observability.drift.run"),
            canary_id="not-a-uuid",
        )
    with pytest.raises(ProviderObservabilityValidationError):
        GetProviderStatusQuery(
            scope=scope("provider.observability.status.read"),
            observed_at=datetime(2026, 1, 1),  # noqa: DTZ001 -- Deliberately invalid naive UTC.
        )
    with pytest.raises(ProviderObservabilityValidationError):
        ScheduledDriftProbeWorker(
            _Schedule(None),
            _Probe(),
            FixedClock(),
            "invalid worker",
        )


@pytest.mark.asyncio
async def test_budgeted_gateway_fails_closed_on_missing_pricing_or_invalid_elapsed_time() -> None:
    repository = _Repository(active_pricing_available=False)
    key = replace(item(0).batch_key, profile_id=pricing().profile_id)
    batch = BatchPlanner.plan((item(0, batch_key=key),), limits())[0]
    guarded = BudgetedTelemetryProviderBatchGateway(
        gateway=_BatchGateway(),
        pricing=repository,
        budget=repository,
        telemetry=ProviderTelemetryRecorder(repository, repository),
        clock=FixedClock(datetime.fromtimestamp(1.5, tz=UTC)),
        elapsed_microseconds=lambda: 0,
    )
    with pytest.raises(ProviderObservabilityConflictError):
        await guarded.execute(batch, (bytearray(b"safe"),))

    repository.active_pricing_available = True
    elapsed = iter((200, 100))
    with pytest.raises(ProviderObservabilityConflictError):
        await replace(
            guarded,
            elapsed_microseconds=lambda: next(elapsed),
        ).execute(batch, (bytearray(b"safe"),))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error_code", "expected"),
    [
        (
            ProviderItemResultStatus.RETRYABLE_FAILURE,
            "rate_limit",
            ProviderOperationOutcome.RETRY_SCHEDULED,
        ),
        (
            ProviderItemResultStatus.CANCELLED,
            "cancelled",
            ProviderOperationOutcome.CANCELLED,
        ),
        (
            ProviderItemResultStatus.PERMANENT_FAILURE,
            "unknown_provider_code",
            ProviderOperationOutcome.PERMANENT_FAILURE,
        ),
    ],
)
async def test_budgeted_gateway_maps_every_closed_child_outcome(
    status: ProviderItemResultStatus,
    error_code: str,
    expected: ProviderOperationOutcome,
) -> None:
    repository = _Repository()
    key = replace(item(0).batch_key, profile_id=pricing().profile_id)
    batch = BatchPlanner.plan((item(0, batch_key=key),), limits())[0]
    elapsed = iter((100, 200))
    guarded = BudgetedTelemetryProviderBatchGateway(
        gateway=_BatchGateway(status=status, error_code=error_code),
        pricing=repository,
        budget=repository,
        telemetry=ProviderTelemetryRecorder(repository, repository),
        clock=FixedClock(datetime.fromtimestamp(1.5, tz=UTC)),
        elapsed_microseconds=lambda: next(elapsed),
    )

    await guarded.execute(batch, (bytearray(b"safe"),))

    assert repository.facts[-1].outcome is expected


@pytest.mark.asyncio
async def test_drift_handler_hides_missing_canary_and_worker_idles_safely() -> None:
    repository = _Repository(canary_value=None)
    with pytest.raises(ProviderObservabilityConflictError):
        await RunDriftProbeHandler(repository, _Probe()).execute(
            RunDriftProbeCommand(
                scope=scope("provider.observability.drift.run"),
                canary_id=canary().canary_id,
            )
        )

    worker = ScheduledDriftProbeWorker(
        _Schedule(None),
        _Probe(),
        FixedClock(),
        "provider-drift-worker-v1",
        poll_seconds=0,
    )
    assert await worker.run_once() is False
    stop = asyncio.Event()
    run = asyncio.create_task(worker.run(stop))
    await asyncio.sleep(0)
    stop.set()
    await run

    timed_stop = asyncio.Event()
    timed_worker = replace(worker, poll_seconds=0.0001)
    timed_run = asyncio.create_task(timed_worker.run(timed_stop))
    await asyncio.sleep(0.001)
    timed_stop.set()
    await asyncio.wait_for(timed_run, timeout=1)
