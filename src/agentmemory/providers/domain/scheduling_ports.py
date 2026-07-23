"""PRO-006 repository, authorization, payload, and gateway ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.scheduling import (
        ProviderBatch,
        ProviderBatchLease,
        ProviderBatchOutcome,
        ProviderWorkItem,
    )


class ProviderSchedulingRepository(Protocol):
    """Persist exact work identities, fair leases, and immutable child outcomes."""

    async def enqueue(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        work: ProviderWorkItem,
    ) -> ProviderWorkItem:
        """Queue or exactly replay one authorized provider item."""
        ...

    async def get(
        self,
        scope: AuthorizedScope,
        item_id: str,
    ) -> ProviderWorkItem | None:
        """Read one exact Brain-scoped work item."""
        ...

    async def cancel(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        item_id: str,
        cancelled_at_microseconds: int,
    ) -> ProviderWorkItem:
        """Cancel queued/retry work or replay an existing cancellation."""
        ...

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderBatchLease | None:
        """Atomically apply fairness/rate/budget limits and lease one batch."""
        ...

    async def complete(
        self,
        lease: ProviderBatchLease,
        outcome: ProviderBatchOutcome,
        completed_at_microseconds: int,
    ) -> None:
        """Persist every child once and retry only retryable children."""
        ...

    async def release(
        self,
        lease: ProviderBatchLease,
        reason: str,
        retry_at_microseconds: int | None,
        released_at_microseconds: int,
    ) -> None:
        """Release an exact lease after safe authorization/dependency failure."""
        ...

    async def recover_expired(self, now_microseconds: int) -> int:
        """Return only expired nonterminal leases to their prior queues."""
        ...


class ProviderSchedulingIdentityGenerator(Protocol):
    """Generate unpredictable RFC 9562 UUIDv7 item identities."""

    def new(self) -> str:
        """Return one fresh work-item identity."""
        ...


class ProviderDispatchAuthorizationPort(Protocol):
    """Reauthorize exact egress/local execution immediately before payload access."""

    async def authorize(
        self,
        work: ProviderWorkItem,
        now_microseconds: int,
    ) -> None:
        """Deny before payload materialization or provider socket acquisition."""
        ...


class ProviderPayloadMaterializer(Protocol):
    """Resolve one protected payload only after final dispatch authorization."""

    async def materialize(self, work: ProviderWorkItem) -> bytearray:
        """Return caller-owned mutable bytes so the worker can zero them."""
        ...


class ProviderBatchGateway(Protocol):
    """Execute one homogeneous batch through the exact selected provider."""

    async def execute(
        self,
        batch: ProviderBatch,
        payloads: Sequence[bytearray],
    ) -> ProviderBatchOutcome:
        """Return every child exactly once and in original order."""
        ...
