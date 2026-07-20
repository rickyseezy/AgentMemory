"""Narrow model-runtime port owned by the provider domain."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationClaim,
        ProviderOperationOutcome,
        ProviderOperationRequest,
    )


class InferenceBackend(Protocol):
    """Capabilities required from the pinned local inference runtime."""

    async def health(self) -> None:
        """Require the exact model process to be loaded and responsive."""
        ...

    async def verify_cancellation(self) -> None:
        """Prove an in-flight backend request can be cancelled."""
        ...

    async def embed(self, contents: tuple[str, ...]) -> tuple[tuple[float, ...], ...]:
        """Generate one vector for every input in original order."""
        ...

    async def rerank(self, query: str, documents: tuple[str, ...]) -> tuple[float, ...]:
        """Return one score per document in original order."""
        ...

    async def extract_subject(self, content: str) -> str:
        """Produce one schema-constrained subject."""
        ...


class BillableProviderBackend(Protocol):
    """Invoke one provider while preserving its stable downstream idempotency key."""

    async def execute(
        self,
        operation: ProviderOperationRequest,
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        """Return content-addressed output or a typed dependency failure."""
        ...


class ProviderOperationCache(Protocol):
    """Persistently arbitrate, cache, and recover potentially billable operations."""

    async def claim(
        self,
        operation: ProviderOperationRequest,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderOperationClaim:
        """Claim new/expired work, replay completed work, or request a bounded wait."""
        ...

    async def complete(
        self,
        claim: ProviderOperationClaim,
        result: ProviderOperationOutcome,
        completed_at_microseconds: int,
    ) -> None:
        """Commit one result against the exact active claim."""
        ...

    async def release_retry(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        """Release the exact active claim without fabricating a cached result."""
        ...
