"""Execute billable provider work behind a persistent idempotency reservation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import ProviderOperationDependencyError
from agentmemory.providers.domain.idempotency import (
    ProviderClaimDisposition,
    ProviderExecutionResult,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.idempotency import ProviderOperationRequest
    from agentmemory.providers.domain.ports import (
        BillableProviderBackend,
        ProviderOperationCache,
    )
    from agentmemory.shared.clock import Clock

_LEASE_MICROSECONDS = 60 * 1_000_000
_RETRY_MICROSECONDS = 1 * 1_000_000
_MAX_OWNER_LENGTH = 128
_MAX_POLL_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class ExecuteProviderOperationHandler:
    """Serialize semantic duplicates and replay committed provider results."""

    cache: ProviderOperationCache
    backend: BillableProviderBackend
    clock: Clock
    owner: str
    poll_seconds: float = 0.01

    def __post_init__(self) -> None:
        """Bound cache contention waits and the stable worker identity."""
        if not self.owner or len(self.owner) > _MAX_OWNER_LENGTH:
            msg = "provider operation worker owner is invalid"
            raise ValueError(msg)
        if not 0 <= self.poll_seconds <= _MAX_POLL_SECONDS:
            msg = "provider operation poll interval is invalid"
            raise ValueError(msg)

    async def execute(self, operation: ProviderOperationRequest) -> ProviderExecutionResult:
        """Return one result while forwarding the same downstream key on every retry."""
        while True:
            now = _microseconds(self.clock)
            claim = await self.cache.claim(
                operation,
                self.owner,
                now,
                now + _LEASE_MICROSECONDS,
            )
            if claim.disposition is ProviderClaimDisposition.CACHED:
                if claim.cached_outcome is None:
                    msg = "provider cache returned incomplete replay evidence"
                    raise ProviderOperationDependencyError(msg)
                return ProviderExecutionResult(claim.cached_outcome, cached=True)
            if claim.disposition is ProviderClaimDisposition.WAIT:
                await asyncio.sleep(self.poll_seconds)
                continue
            try:
                outcome = await self.backend.execute(
                    operation,
                    operation.downstream_idempotency_key,
                )
            except ProviderOperationDependencyError:
                await self.cache.release_retry(
                    claim,
                    "provider_dependency_unavailable",
                    now + _RETRY_MICROSECONDS,
                )
                raise
            await self.cache.complete(claim, outcome, _microseconds(self.clock))
            return ProviderExecutionResult(outcome, cached=False)


def _microseconds(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)
