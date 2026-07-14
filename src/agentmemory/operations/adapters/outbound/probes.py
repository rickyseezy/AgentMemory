"""Generic adapter from one narrow live check to domain readiness evidence."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    evidence_digest,
)

if TYPE_CHECKING:
    from agentmemory.shared.clock import Clock


class ProbeCheckFailedError(RuntimeError):
    """Report one expected, privacy-safe negative readiness observation."""

    def __init__(self, safe_code: str) -> None:
        """Keep only a stable code suitable for evidence hashing."""
        super().__init__(safe_code)
        self.safe_code = safe_code


type Check = Callable[[ReadinessBinding], Awaitable[str]]


class FunctionalReadinessProbe:
    """Implement one probe without merging unrelated dependency capabilities."""

    def __init__(self, identity: ReadinessProbe, check: Check, clock: Clock) -> None:
        """Bind the adapter to one closed identity and injected policy clock."""
        self._identity = identity
        self._check = check
        self._clock = clock

    @property
    def probe(self) -> ReadinessProbe:
        """Return the sole probe identity implemented by this adapter."""
        return self._identity

    async def execute(self, binding: ReadinessBinding) -> ProbeEvidence:
        """Convert live proof into immutable bound evidence."""
        try:
            proof = await self._check(binding)
            status = ProbeStatus.PASSED
        except ProbeCheckFailedError as error:
            proof = error.safe_code
            status = ProbeStatus.FAILED
        return ProbeEvidence(
            probe=self._identity,
            status=status,
            binding=binding,
            evidence_digest=evidence_digest(self._identity, binding, proof),
            observed_at=self._clock.now(),
        )
