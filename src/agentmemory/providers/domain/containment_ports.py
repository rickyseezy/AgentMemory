"""PRO-009 egress authority, socket, supervisor, and evidence ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.containment import (
        AdapterOperationResult,
        AdapterOperationSandbox,
        ExecuteProviderEgress,
        PreparedProviderWireRequest,
        ProviderEgressDecisionFact,
        ProviderEgressHttpResponse,
        ProviderEgressOperationContext,
        ProviderEgressPermit,
        ProviderEgressPolicy,
        ProviderEgressRequest,
        ProviderGatewayCredential,
        ProviderRuntimeFact,
    )
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationOutcome,
        ProviderOperationRequest,
    )
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation


class ProviderEgressRequestFactory(Protocol):
    """Resolve content-free policy coordinates for one attested endpoint."""

    async def create(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
    ) -> ProviderEgressRequest:
        """Build one complete request without acquiring an external socket."""
        ...


class ProviderEgressOperationContextResolver(Protocol):
    """Resolve current profile, policy, content-taint, quota, and budget coordinates."""

    async def resolve(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
    ) -> ProviderEgressOperationContext:
        """Return content-free current authorization context without a socket."""
        ...


class ProviderEgressAuthority(Protocol):
    """Atomically reauthorize and persist one exact short-lived permit."""

    async def authorize(
        self,
        request: ProviderEgressRequest,
        now_microseconds: int,
    ) -> ProviderEgressPermit:
        """Deny or return one exact permit immediately before gateway invocation."""
        ...


class AuthorizedProviderSocketGateway(Protocol):
    """Acquire one pinned provider socket using an exact live permit."""

    async def execute(
        self,
        permit: ProviderEgressPermit,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        """Perform only the authenticated embedding/reranking operation."""
        ...


class ProviderGatewayUsageAuthority(Protocol):
    """Independently reserve gateway rate, token, budget, and replay capacity."""

    async def authorize(
        self,
        permit: ProviderEgressPermit,
        now_microseconds: int,
    ) -> None:
        """Deny or atomically consume one exact live permit."""
        ...


class ProviderPermitDecoder(Protocol):
    """Authenticate and strictly decode one opaque internal gateway permit."""

    def decode(self, token: bytes) -> ProviderEgressPermit:
        """Return a verified exact permit or deny."""
        ...


class ProviderPermitCodec(ProviderPermitDecoder, Protocol):
    """Sign and verify an exact content-free permit across the process boundary."""

    def encode(self, permit: ProviderEgressPermit) -> bytes:
        """Return one opaque authenticated permit token."""
        ...


class ProviderGatewayEnvelopeClient(Protocol):
    """Send an authenticated operation envelope to the internal gateway."""

    async def execute(
        self,
        command: ExecuteProviderEgress,
    ) -> ProviderEgressHttpResponse:
        """Return one bounded raw provider response."""
        ...


class ProviderWireOperationCodec(Protocol):
    """Deterministically translate canonical operations to/from vendor wire bytes."""

    def prepare(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> PreparedProviderWireRequest:
        """Build one exact request without a credential or socket."""
        ...

    def parse(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        response: ProviderEgressHttpResponse,
    ) -> ProviderOperationOutcome:
        """Validate and persist one exact content-addressed outcome."""
        ...


class ProviderCredentialBroker(Protocol):
    """Resolve a profile-bound credential only inside the gateway."""

    async def resolve(self, permit: ProviderEgressPermit) -> ProviderGatewayCredential:
        """Return one mutable credential header without exposing its secret reference."""
        ...


class ProviderPinnedTransport(Protocol):
    """Execute only a permit-bound direct HTTPS request."""

    async def execute(  # noqa: PLR0913 -- Every socket-bound limit is explicit.
        self,
        permit_value: ProviderEgressPermit,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        maximum_response_bytes: int,
        timeout_milliseconds: int,
    ) -> ProviderEgressHttpResponse:
        """Return one bounded response without proxy or redirect behavior."""
        ...


class AdapterRuntimeSupervisor(Protocol):
    """Execute one untrusted adapter in a closed operation-scoped sandbox."""

    async def execute(
        self,
        sandbox: AdapterOperationSandbox,
        inputs: Sequence[bytearray],
    ) -> AdapterOperationResult:
        """Create, bound, execute, and remove exactly one operation container."""
        ...


class ProviderRuntimeTelemetryRecorder(Protocol):
    """Persist only closed content-free provider runtime facts."""

    async def record(self, fact: ProviderRuntimeFact) -> None:
        """Append one immutable runtime outcome."""
        ...


class ProviderEgressTelemetryRecorder(Protocol):
    """Append only closed content-free provider gateway decisions."""

    async def record_egress(self, fact: ProviderEgressDecisionFact) -> None:
        """Persist an allowed or denied gateway result."""
        ...


class ProviderContainmentRepository(
    ProviderEgressAuthority,
    ProviderRuntimeTelemetryRecorder,
    ProviderEgressTelemetryRecorder,
    Protocol,
):
    """Canonical policy publication, lookup, authorization, and evidence authority."""

    async def publish(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        policy: ProviderEgressPolicy,
        published_at_microseconds: int,
    ) -> ProviderEgressPolicy:
        """Publish or exactly replay one Brain-owned immutable policy."""
        ...

    async def get(
        self,
        scope: AuthorizedScope,
        requested_at_microseconds: int,
    ) -> ProviderEgressPolicy | None:
        """Return the active policy after current Brain-wide authorization."""
        ...
