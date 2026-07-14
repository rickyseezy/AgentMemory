"""Bounded-cadence full certification and cheap recurrent readiness tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from agentmemory.operations.application.commands.verify_readiness import (
    ReadinessFailure,
    ReadinessVerification,
)
from agentmemory.operations.application.runtime_readiness import (
    FAILED_CERTIFICATION_RETRY,
    FULL_CERTIFICATION_TTL,
    RUNTIME_PROBE_ORDER,
    RuntimeReadinessCoordinator,
)
from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    evidence_digest,
)
from tests.core.support import NOW, receipt


@dataclass(slots=True)
class _MutableClock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


@dataclass(slots=True)
class _FullGate:
    clock: _MutableClock
    passes: bool = True
    calls: int = 0

    async def verify_live(self, binding: ReadinessBinding) -> ReadinessVerification:
        self.calls += 1
        if not self.passes:
            return ReadinessVerification(
                ready=False,
                receipt=None,
                failures=(ReadinessFailure(ReadinessProbe.LOCAL_PROVIDERS, "probe_failed"),),
            )
        return ReadinessVerification(
            ready=True,
            receipt=receipt(binding, self.clock.now()),
            failures=(),
        )


class _RuntimeProbe:
    def __init__(self, probe: ReadinessProbe, clock: _MutableClock, *, passes: bool = True) -> None:
        self._probe = probe
        self._clock = clock
        self._passes = passes
        self.calls = 0

    @property
    def probe(self) -> ReadinessProbe:
        return self._probe

    async def execute(self, binding: ReadinessBinding) -> ProbeEvidence:
        self.calls += 1
        return ProbeEvidence(
            probe=self._probe,
            status=ProbeStatus.PASSED if self._passes else ProbeStatus.FAILED,
            binding=binding,
            evidence_digest=evidence_digest(self._probe, binding, "runtime"),
            observed_at=self._clock.now(),
        )


def _runtime_probes(
    clock: _MutableClock,
    failed: ReadinessProbe | None = None,
) -> tuple[_RuntimeProbe, ...]:
    return tuple(
        _RuntimeProbe(probe, clock, passes=probe is not failed) for probe in RUNTIME_PROBE_ORDER
    )


@pytest.mark.asyncio
async def test_fresh_full_anchor_runs_only_cheap_live_probes() -> None:
    clock = _MutableClock()
    full = _FullGate(clock)
    probes = _runtime_probes(clock)
    anchor = receipt()
    result = await RuntimeReadinessCoordinator(full, probes, clock).verify(anchor)
    assert result == anchor
    assert full.calls == 0
    assert all(probe.calls == 1 for probe in probes)


@pytest.mark.asyncio
async def test_stale_anchor_recertifies_once_then_reuses_fresh_certificate() -> None:
    clock = _MutableClock()
    full = _FullGate(clock)
    probes = _runtime_probes(clock)
    anchor = receipt(evaluated_at=NOW - FULL_CERTIFICATION_TTL - timedelta(seconds=1))
    coordinator = RuntimeReadinessCoordinator(full, probes, clock)
    first = await coordinator.verify(anchor)
    second = await coordinator.verify(anchor)
    assert first is not None
    assert first.evaluated_at == NOW
    assert second == first
    assert full.calls == 1
    assert all(probe.calls == 2 for probe in probes)


@pytest.mark.asyncio
async def test_failed_full_gate_uses_backoff_instead_of_hammering_models() -> None:
    clock = _MutableClock()
    full = _FullGate(clock, passes=False)
    anchor = receipt(evaluated_at=NOW - FULL_CERTIFICATION_TTL - timedelta(seconds=1))
    coordinator = RuntimeReadinessCoordinator(full, _runtime_probes(clock), clock)
    assert await coordinator.verify(anchor) is None
    assert await coordinator.verify(anchor) is None
    assert full.calls == 1
    clock.value += FAILED_CERTIFICATION_RETRY
    assert await coordinator.verify(anchor) is None
    assert full.calls == 2


@pytest.mark.asyncio
async def test_cheap_dependency_failure_denies_ready_with_fresh_full_anchor() -> None:
    clock = _MutableClock()
    coordinator = RuntimeReadinessCoordinator(
        _FullGate(clock),
        _runtime_probes(clock, failed=ReadinessProbe.GRAPH_COMPATIBILITY),
        clock,
    )
    assert await coordinator.verify(receipt()) is None


def test_runtime_readiness_rejects_missing_or_reordered_cheap_probes() -> None:
    clock = _MutableClock()
    with pytest.raises(DomainValidationError):
        RuntimeReadinessCoordinator(_FullGate(clock), _runtime_probes(clock)[:-1], clock)
