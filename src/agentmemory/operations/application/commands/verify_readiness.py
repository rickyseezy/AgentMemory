"""Execute the all-or-nothing PF-001 Core readiness gate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import (
    DomainValidationError,
    ErrorCode,
    OperationError,
)
from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
)

if TYPE_CHECKING:
    from agentmemory.operations.domain.ports import (
        CoreUnitOfWorkFactory,
        ReadinessProbePort,
    )
    from agentmemory.shared.clock import Clock


@dataclass(frozen=True, slots=True)
class ReadinessFailure:
    """A privacy-safe negative probe outcome."""

    probe: ReadinessProbe
    code: str


@dataclass(frozen=True, slots=True)
class ReadinessVerification:
    """Return either one complete receipt or ordered negative probes."""

    ready: bool
    receipt: ReadinessReceipt | None
    failures: tuple[ReadinessFailure, ...]


class VerifyReadinessHandler:
    """Run every Core readiness capability in normative order."""

    def __init__(
        self,
        probes: tuple[ReadinessProbePort, ...],
        unit_of_work: CoreUnitOfWorkFactory,
        clock: Clock,
    ) -> None:
        """Reject missing, duplicate, or out-of-order capabilities at composition."""
        identities = tuple(probe.probe for probe in probes)
        if identities != tuple(ReadinessProbe):
            msg = "readiness ports must exactly match the closed probe order"
            raise DomainValidationError(msg)
        self._probes = probes
        self._unit_of_work = unit_of_work
        self._clock = clock

    async def execute(self, binding: ReadinessBinding) -> ReadinessVerification:
        """Run all probes, persisting a receipt only after complete success."""
        verification = await self.verify_live(binding)
        if verification.receipt is None:
            return verification
        await self._persist(verification.receipt)
        return verification

    async def verify_live(self, binding: ReadinessBinding) -> ReadinessVerification:
        """Run every dependency without treating a historical receipt as live readiness."""
        results: list[ProbeEvidence] = []
        failures: list[ReadinessFailure] = []
        for expected_probe, port in zip(ReadinessProbe, self._probes, strict=True):
            try:
                result = await port.execute(binding)
            except OperationError:
                raise
            except Exception as error:
                raise OperationError(
                    ErrorCode.DEPENDENCY_UNAVAILABLE,
                    f"readiness dependency unavailable: {expected_probe.evidence_key}",
                    retryable=True,
                ) from error
            if result.probe is not expected_probe or result.binding != binding:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "readiness evidence binding was inconsistent",
                    retryable=False,
                )
            results.append(result)
            if result.status is ProbeStatus.FAILED:
                failures.append(ReadinessFailure(result.probe, "probe_failed"))
        if failures:
            return ReadinessVerification(
                ready=False,
                receipt=None,
                failures=tuple(failures),
            )
        try:
            receipt = ReadinessReceipt.create(binding, self._clock.now(), tuple(results))
        except DomainValidationError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "readiness evidence failed the complete gate",
                retryable=False,
            ) from error
        return ReadinessVerification(ready=True, receipt=receipt, failures=())

    async def _persist(self, receipt: ReadinessReceipt) -> None:
        try:
            async with self._unit_of_work() as unit_of_work:
                await unit_of_work.receipts.add(receipt)
                await unit_of_work.commit()
        except OperationError:
            raise
        except Exception as error:
            raise OperationError(
                ErrorCode.INTERNAL,
                "readiness receipt did not commit",
                retryable=False,
            ) from error
