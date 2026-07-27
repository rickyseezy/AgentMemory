"""PRO-010 safe vector drift probe and scheduled worker tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters.drift_probe import (
    ConfiguredDriftVectorGateway,
    MutableAdapterVectorResult,
    MutableDriftVectorBatch,
    ProviderDriftVectorAdapter,
    ProviderVectorDriftProbe,
)
from agentmemory.providers.application.observability import ScheduledDriftProbeWorker
from agentmemory.providers.domain.capability_probe import ProviderProbeSuite, probe_canaries
from agentmemory.providers.domain.errors import ProviderObservabilityDependencyError
from agentmemory.providers.domain.observability import (
    DriftCanary,
    DriftEvaluation,
    DriftEvaluator,
    DriftObservation,
    DriftVerdict,
    ProviderDriftProbeLease,
)
from tests.core.support import NOW, FixedClock, digest
from tests.providers.test_pro001_profiles_domain_application import (
    probe_evidence,
    profile,
)
from tests.providers.test_pro010_observability_domain import canary, observation

if TYPE_CHECKING:
    from agentmemory.providers.domain.profiles import CanonicalPurpose, ProviderProfile


@dataclass(slots=True)
class _Gateway:
    batch: MutableDriftVectorBatch
    calls: list[DriftCanary] = field(default_factory=list[DriftCanary])

    async def execute(self, canary: DriftCanary) -> MutableDriftVectorBatch:
        self.calls.append(canary)
        return self.batch


@dataclass(slots=True)
class _ProfileSource:
    result: tuple[ProviderProfile, CanonicalPurpose] | None

    async def get_drift_profile(
        self,
        canary: DriftCanary,
    ) -> tuple[ProviderProfile, CanonicalPurpose] | None:
        del canary
        return self.result


@dataclass(slots=True)
class _DriftAdapter:
    result: MutableAdapterVectorResult

    async def observe_drift_vectors(
        self,
        profile: ProviderProfile,
        purpose: CanonicalPurpose,
    ) -> MutableAdapterVectorResult:
        del profile, purpose
        return self.result


@dataclass(slots=True)
class _Registry:
    adapter: _DriftAdapter

    def get_drift(self, adapter_id: str) -> ProviderDriftVectorAdapter:
        assert adapter_id == "openai"
        return self.adapter


def _batch(
    vectors: list[list[float]] | None = None,
    *,
    content_ids: tuple[str, ...] | None = None,
) -> MutableDriftVectorBatch:
    contract = canary()
    return MutableDriftVectorBatch(
        canary_set_digest=contract.canary_set_digest,
        content_ids=content_ids or contract.canary_item_ids,
        vectors=vectors
        or [
            [1.0, 0.0, 0.0],
            [0.8, 0.6, 0.0],
        ],
        revision_fingerprint=contract.revision_fingerprint,
        observed_at_microseconds=1_500_000,
    )


@pytest.mark.asyncio
async def test_configured_gateway_binds_shipped_corpus_profile_and_revision() -> None:
    evidence = probe_evidence()
    active = profile().activate(evidence)
    corpus = probe_canaries()
    contract = canary(
        profile_version=active.version,
        capability_attestation_id=evidence.evidence_id,
        revision_fingerprint=evidence.result.revision_fingerprint,
        canary_set_digest=ProviderProbeSuite().canary_digest,
        canary_item_ids=tuple(item.content_id for item in corpus),
        distance_order=tuple(item.content_id for item in corpus),
        norms_micros=(1_000_000, 1_000_000),
    )
    adapter_result = MutableAdapterVectorResult(
        content_ids=contract.canary_item_ids,
        vectors=[[1.0, 0.0], [0.0, 1.0]],
        revision_fingerprint=contract.revision_fingerprint,
    )
    gateway = ConfiguredDriftVectorGateway(
        profiles=_ProfileSource(
            (active, active.configuration.purposes[0]),
        ),
        adapters=_Registry(_DriftAdapter(adapter_result)),
        now_microseconds=lambda: contract.created_at_microseconds + 1,
    )

    result = await gateway.execute(contract)

    assert result.content_ids == contract.canary_item_ids
    assert result.revision_fingerprint == contract.revision_fingerprint
    assert result.vectors == [[1.0, 0.0], [0.0, 1.0]]

    unavailable = replace(gateway, profiles=_ProfileSource(None))
    with pytest.raises(ProviderObservabilityDependencyError):
        await unavailable.execute(contract)


@pytest.mark.asyncio
async def test_vector_probe_reduces_vectors_to_safe_tolerant_aggregates_and_zeroes() -> None:
    batch = _batch()
    gateway = _Gateway(batch)
    observed = await ProviderVectorDriftProbe(gateway).observe(canary())
    assert observed.canary_item_ids == canary().canary_item_ids
    assert observed.norms_micros == (1_000_000, 1_000_000)
    assert set(observed.distance_order) == set(canary().canary_item_ids)
    assert len(observed.vector_fingerprint) == 64
    assert batch.vectors == [[0.0, 0.0, 0.0]] * 2
    assert "1.0" not in repr(batch)

    baseline = replace(
        canary(),
        vector_fingerprint=observed.vector_fingerprint,
        norms_micros=observed.norms_micros,
        distance_order=observed.distance_order,
    )
    assert DriftEvaluator.evaluate(baseline, observed).verdict is DriftVerdict.STABLE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "batch",
    [
        _batch([[1.0, 0.0], [1.0]]),
        _batch([[1.0, 0.0], [float("nan"), 1.0]]),
        _batch([[0.0, 0.0], [1.0, 0.0]]),
        _batch(content_ids=(digest("foreign").value,) * 2),
    ],
)
async def test_vector_probe_rejects_malformed_output_and_always_zeroes(
    batch: MutableDriftVectorBatch,
) -> None:
    with pytest.raises(ProviderObservabilityDependencyError):
        await ProviderVectorDriftProbe(_Gateway(batch)).observe(canary())
    assert all(all(value == 0.0 for value in vector) for vector in batch.vectors)


@dataclass(slots=True)
class _Schedule:
    lease: ProviderDriftProbeLease | None
    completed: list[tuple[ProviderDriftProbeLease, DriftObservation, DriftEvaluation]] = field(
        default_factory=list[tuple[ProviderDriftProbeLease, DriftObservation, DriftEvaluation]]
    )
    released: list[tuple[ProviderDriftProbeLease, int, int]] = field(
        default_factory=list[tuple[ProviderDriftProbeLease, int, int]]
    )

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
        self.completed.append((lease, observation, evaluation))

    async def release_probe(
        self,
        lease: ProviderDriftProbeLease,
        retry_at_microseconds: int,
        released_at_microseconds: int,
    ) -> None:
        self.released.append((lease, retry_at_microseconds, released_at_microseconds))


@dataclass(slots=True)
class _SafeProbe:
    observed: DriftObservation
    error: BaseException | None = None

    async def observe(self, canary: DriftCanary) -> DriftObservation:
        del canary
        if self.error is not None:
            raise self.error
        return self.observed


def _lease() -> ProviderDriftProbeLease:
    return ProviderDriftProbeLease(
        canary=canary(),
        owner="provider-drift-worker-v1",
        lease_until_microseconds=round(NOW.timestamp() * 1_000_000) + 60_000_000,
        state_version=2,
    )


@pytest.mark.asyncio
async def test_scheduled_worker_completes_one_due_probe() -> None:
    baseline_batch = _batch()
    baseline = await ProviderVectorDriftProbe(_Gateway(baseline_batch)).observe(canary())
    contract = replace(
        canary(),
        vector_fingerprint=baseline.vector_fingerprint,
        norms_micros=baseline.norms_micros,
        distance_order=baseline.distance_order,
    )
    observed = replace(baseline, canary_id=contract.canary_id)
    lease = replace(_lease(), canary=contract)
    schedule = _Schedule(lease)
    worker = ScheduledDriftProbeWorker(
        schedule,
        _SafeProbe(observed),
        FixedClock(),
        "provider-drift-worker-v1",
        poll_seconds=0,
    )
    assert await worker.run_once() is True
    assert schedule.completed[0][2].verdict is DriftVerdict.STABLE
    assert schedule.released == []


@pytest.mark.asyncio
async def test_scheduled_worker_releases_probe_on_failure_or_cancellation() -> None:
    schedule = _Schedule(_lease())
    worker = ScheduledDriftProbeWorker(
        schedule,
        _SafeProbe(
            observed=observation(),
            error=RuntimeError("must not leak"),
        ),
        FixedClock(),
        "provider-drift-worker-v1",
        poll_seconds=0,
    )
    assert await worker.run_once() is True
    assert schedule.completed == []
    assert len(schedule.released) == 1
    assert schedule.released[0][1] > schedule.released[0][2]

    cancelled = _Schedule(_lease())
    cancelled_worker = ScheduledDriftProbeWorker(
        cancelled,
        _SafeProbe(
            observed=observation(),
            error=asyncio.CancelledError(),
        ),
        FixedClock(),
        "provider-drift-worker-v1",
        poll_seconds=0,
    )
    with pytest.raises(asyncio.CancelledError):
        await cancelled_worker.run_once()
    assert len(cancelled.released) == 1
