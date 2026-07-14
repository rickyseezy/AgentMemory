"""Core application-command and readiness-probe tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

import pytest

from agentmemory.operations.adapters.outbound.probes import (
    FunctionalReadinessProbe,
    ProbeCheckFailedError,
)
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.application.commands.verify_readiness import VerifyReadinessHandler
from agentmemory.operations.domain.bootstrap import (
    BootstrapDisposition,
    BootstrapRequest,
)
from agentmemory.operations.domain.errors import DomainValidationError, ErrorCode, OperationError
from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
    evidence_digest,
)
from tests.core.support import NOW, FixedClock, binding, bootstrap_request

if TYPE_CHECKING:
    from types import TracebackType


@dataclass(slots=True)
class _ReceiptRepository:
    values: list[ReadinessReceipt] = field(default_factory=list[ReadinessReceipt])

    async def add(self, receipt: ReadinessReceipt) -> None:
        self.values.append(receipt)

    async def latest(self) -> ReadinessReceipt | None:
        return self.values[-1] if self.values else None


@dataclass(slots=True)
class _BootstrapRepository:
    disposition: BootstrapDisposition = BootstrapDisposition.CREATED
    values: list[BootstrapRequest] = field(default_factory=list[BootstrapRequest])

    async def ensure(self, request: BootstrapRequest) -> BootstrapDisposition:
        self.values.append(request)
        return self.disposition


@dataclass(slots=True)
class _AuditRepository:
    values: list[tuple[BootstrapRequest, BootstrapDisposition]] = field(
        default_factory=list[tuple[BootstrapRequest, BootstrapDisposition]]
    )

    async def append_bootstrap(
        self,
        request: BootstrapRequest,
        disposition: BootstrapDisposition,
    ) -> None:
        self.values.append((request, disposition))


@dataclass(slots=True)
class _UnitOfWork:
    receipts: _ReceiptRepository = field(default_factory=_ReceiptRepository)
    bootstrap: _BootstrapRepository = field(default_factory=_BootstrapRepository)
    audit: _AuditRepository = field(default_factory=_AuditRepository)
    committed: bool = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    async def commit(self) -> None:
        self.committed = True


@dataclass(frozen=True, slots=True)
class _Factory:
    value: _UnitOfWork

    def __call__(self) -> _UnitOfWork:
        return self.value


class _Probe:
    def __init__(
        self,
        probe: ReadinessProbe,
        *,
        status: ProbeStatus = ProbeStatus.PASSED,
        returned_binding: ReadinessBinding | None = None,
        explode: bool = False,
    ) -> None:
        self._probe = probe
        self._status = status
        self._returned_binding = returned_binding
        self._explode = explode

    @property
    def probe(self) -> ReadinessProbe:
        return self._probe

    async def execute(self, binding: ReadinessBinding) -> ProbeEvidence:
        if self._explode:
            msg = "dependency exploded"
            raise RuntimeError(msg)
        resolved = self._returned_binding or binding
        return ProbeEvidence(
            probe=self._probe,
            status=self._status,
            binding=resolved,
            evidence_digest=evidence_digest(self._probe, resolved, "proof"),
            observed_at=NOW,
        )


def _probes(
    failed: ReadinessProbe | None = None,
    *,
    mismatch: ReadinessProbe | None = None,
    explode: ReadinessProbe | None = None,
) -> tuple[_Probe, ...]:
    return tuple(
        _Probe(
            probe,
            status=ProbeStatus.FAILED if probe is failed else ProbeStatus.PASSED,
            returned_binding=binding("mismatch") if probe is mismatch else None,
            explode=probe is explode,
        )
        for probe in ReadinessProbe
    )


@pytest.mark.asyncio
async def test_bootstrap_handler_commits_exact_aggregate_and_audit() -> None:
    unit_of_work = _UnitOfWork()
    request = bootstrap_request()
    result = await BootstrapLocalBrainHandler(_Factory(unit_of_work)).execute(request)
    assert unit_of_work.bootstrap.values == [request]
    assert unit_of_work.audit.values == [(request, BootstrapDisposition.CREATED)]
    assert unit_of_work.committed
    assert result.installation_id == request.installation_id.value
    assert result.brain_id == request.brain_id.value
    assert result.disposition is BootstrapDisposition.CREATED


@pytest.mark.asyncio
async def test_readiness_handler_persists_only_complete_receipt() -> None:
    unit_of_work = _UnitOfWork()
    verification = await VerifyReadinessHandler(
        _probes(),
        _Factory(unit_of_work),
        FixedClock(),
    ).execute(binding())
    assert verification.ready
    assert verification.receipt is not None
    assert verification.failures == ()
    assert unit_of_work.receipts.values == [verification.receipt]
    assert unit_of_work.committed


@pytest.mark.asyncio
async def test_readiness_handler_returns_ordered_failure_without_committing() -> None:
    unit_of_work = _UnitOfWork()
    verification = await VerifyReadinessHandler(
        _probes(ReadinessProbe.KEY_ACCESS),
        _Factory(unit_of_work),
        FixedClock(),
    ).execute(binding())
    assert not verification.ready
    assert verification.receipt is None
    assert [failure.probe for failure in verification.failures] == [ReadinessProbe.KEY_ACCESS]
    assert unit_of_work.receipts.values == []
    assert not unit_of_work.committed


def test_readiness_handler_rejects_incomplete_composition() -> None:
    with pytest.raises(DomainValidationError):
        VerifyReadinessHandler(_probes()[:-1], _Factory(_UnitOfWork()), FixedClock())


@pytest.mark.asyncio
async def test_readiness_handler_fails_closed_on_bad_evidence_binding() -> None:
    handler = VerifyReadinessHandler(
        _probes(mismatch=ReadinessProbe.SQLITE_INTEGRITY),
        _Factory(_UnitOfWork()),
        FixedClock(),
    )
    with pytest.raises(OperationError) as raised:
        await handler.execute(binding())
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION


@pytest.mark.asyncio
async def test_readiness_handler_maps_untyped_dependency_failure() -> None:
    handler = VerifyReadinessHandler(
        _probes(explode=ReadinessProbe.SQLITE_INTEGRITY),
        _Factory(_UnitOfWork()),
        FixedClock(),
    )
    with pytest.raises(OperationError) as raised:
        await handler.execute(binding())
    assert raised.value.code is ErrorCode.DEPENDENCY_UNAVAILABLE
    assert raised.value.retryable


@pytest.mark.asyncio
async def test_functional_probe_hashes_positive_and_expected_negative_proof() -> None:
    async def pass_check(readiness_binding: ReadinessBinding) -> str:
        assert readiness_binding == binding()
        return "validated"

    async def fail_check(readiness_binding: ReadinessBinding) -> str:
        del readiness_binding
        msg = "migration_head_mismatch"
        raise ProbeCheckFailedError(msg)

    positive = await FunctionalReadinessProbe(
        ReadinessProbe.MIGRATION_HEAD,
        pass_check,
        FixedClock(),
    ).execute(binding())
    negative = await FunctionalReadinessProbe(
        ReadinessProbe.MIGRATION_HEAD,
        fail_check,
        FixedClock(),
    ).execute(binding())
    assert positive.status is ProbeStatus.PASSED
    assert negative.status is ProbeStatus.FAILED
    assert positive.evidence_digest != negative.evidence_digest
