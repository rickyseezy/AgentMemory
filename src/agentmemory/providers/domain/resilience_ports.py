"""PRO-007 endpoint, circuit, equivalence, and dispatch evidence ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.errors import ProviderErrorCode
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationOutcome,
        ProviderOperationRequest,
    )
    from agentmemory.providers.domain.resilience import (
        EquivalentEndpointSet,
        ProviderCircuitPermit,
        ProviderCircuitPolicy,
        ProviderDispatchFact,
        ProviderEndpointAttestation,
    )


class ProviderEndpointGateway(Protocol):
    """Invoke one exact attested endpoint with a stable downstream identity."""

    async def execute(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        """Return content-addressed output or raise one safe ProviderAdapterError."""
        ...


class ProviderCircuitRepository(Protocol):
    """Atomically arbitrate durable endpoint circuit transitions."""

    async def acquire(
        self,
        endpoint: ProviderEndpointAttestation,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> ProviderCircuitPermit:
        """Allow a closed call or reserve the sole due half-open probe."""
        ...

    async def success(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        """Close the exact acquired circuit after success."""
        ...

    async def failure(
        self,
        permit: ProviderCircuitPermit,
        code: ProviderErrorCode,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        """Record a canonical failure against the exact acquired circuit."""
        ...

    async def abandon(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        """Release a cancelled or otherwise unclassified acquired probe."""
        ...


class EquivalentEndpointRepository(Protocol):
    """Persist immutable profile-attestation equivalence evidence."""

    async def put(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        endpoints: EquivalentEndpointSet,
        created_at_microseconds: int,
    ) -> EquivalentEndpointSet:
        """Insert or exactly replay one complete endpoint set."""
        ...

    async def get(
        self,
        scope: AuthorizedScope,
        set_id: str,
    ) -> EquivalentEndpointSet | None:
        """Return one complete immutable set by its content identity."""
        ...

    async def resolve(
        self,
        brain_id: str,
        primary_profile_id: str,
        primary_profile_version: int,
        space_id: str,
    ) -> EquivalentEndpointSet | None:
        """Resolve the sole attested set for one exact provider/space revision."""
        ...


class ProviderDispatchEvidenceRecorder(Protocol):
    """Append content-free endpoint attempt and fallback evidence."""

    async def record(self, fact: ProviderDispatchFact) -> None:
        """Persist one idempotent content-free dispatch fact."""
        ...
