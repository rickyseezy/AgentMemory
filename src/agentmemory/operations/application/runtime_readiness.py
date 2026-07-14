"""Bounded-cadence full certification plus cheap recurrent runtime readiness."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Final, Protocol

from agentmemory.operations.domain.errors import DomainValidationError, OperationError
from agentmemory.operations.domain.readiness import (
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
)
from agentmemory.operations.domain.value_objects import require_utc_microseconds

if TYPE_CHECKING:
    from agentmemory.operations.application.commands.verify_readiness import (
        ReadinessVerification,
    )
    from agentmemory.operations.domain.ports import ReadinessProbePort
    from agentmemory.shared.clock import Clock

FULL_CERTIFICATION_TTL: Final = timedelta(minutes=30)
FAILED_CERTIFICATION_RETRY: Final = timedelta(minutes=5)
RUNTIME_PROBE_ORDER: Final = (
    ReadinessProbe.SQLITE_INTEGRITY,
    ReadinessProbe.MIGRATION_HEAD,
    ReadinessProbe.WRITABLE_VOLUMES,
    ReadinessProbe.GRAPH_COMPATIBILITY,
    ReadinessProbe.KEY_ACCESS,
    ReadinessProbe.LOCAL_PROVIDERS,
    ReadinessProbe.DEFAULT_EGRESS_DENIED,
)


class FullReadinessPort(Protocol):
    """Execute the complete eleven-probe gate without persisting a new anchor."""

    async def verify_live(self, binding: ReadinessBinding) -> ReadinessVerification:
        """Return one full current certificate or exact negative gates."""
        ...


class RuntimeReadinessCoordinator:
    """Prevent health polling from continuously invoking models or mutating canaries."""

    def __init__(
        self,
        full_gate: FullReadinessPort,
        runtime_probes: tuple[ReadinessProbePort, ...],
        clock: Clock,
    ) -> None:
        """Require the closed cheap-probe set in deterministic order."""
        identities = tuple(probe.probe for probe in runtime_probes)
        if identities != RUNTIME_PROBE_ORDER:
            msg = "runtime readiness ports must match the closed cheap-probe order"
            raise DomainValidationError(msg)
        self._full_gate = full_gate
        self._runtime_probes = runtime_probes
        self._clock = clock
        self._lock = asyncio.Lock()
        self._certificate: ReadinessReceipt | None = None
        self._last_full_attempt_at: datetime | None = None
        self._binding: ReadinessBinding | None = None

    async def verify(self, anchor: ReadinessReceipt) -> ReadinessReceipt | None:
        """Return Ready only with a fresh full gate and current cheap live dependencies."""
        async with self._lock:
            now = require_utc_microseconds(self._clock.now())
            self._select_binding(anchor)
            certificate = self._certificate or anchor
            if certificate.evaluated_at > now:
                return None
            if now - certificate.evaluated_at > FULL_CERTIFICATION_TTL:
                recertified = await self._recertify(anchor.binding, now)
                if recertified is None:
                    return None
                certificate = recertified
            if not await self._runtime_dependencies_pass(certificate.binding):
                return None
            return certificate

    def _select_binding(self, anchor: ReadinessReceipt) -> None:
        if self._binding == anchor.binding:
            return
        self._binding = anchor.binding
        self._certificate = anchor
        self._last_full_attempt_at = None

    async def _recertify(
        self,
        binding: ReadinessBinding,
        now: datetime,
    ) -> ReadinessReceipt | None:
        observed_now = require_utc_microseconds(now)
        if self._last_full_attempt_at is not None:
            elapsed = observed_now - self._last_full_attempt_at
            if timedelta(0) <= elapsed < FAILED_CERTIFICATION_RETRY:
                return None
        self._last_full_attempt_at = observed_now
        try:
            verification = await self._full_gate.verify_live(binding)
        except DomainValidationError, OperationError:
            return None
        if not verification.ready or verification.receipt is None:
            return None
        self._certificate = verification.receipt
        return verification.receipt

    async def _runtime_dependencies_pass(self, binding: ReadinessBinding) -> bool:
        try:
            results = await asyncio.gather(
                *(probe.execute(binding) for probe in self._runtime_probes)
            )
        except DomainValidationError, OperationError:
            return False
        return all(
            result.probe is expected
            and result.binding == binding
            and result.status is ProbeStatus.PASSED
            for expected, result in zip(RUNTIME_PROBE_ORDER, results, strict=True)
        )
