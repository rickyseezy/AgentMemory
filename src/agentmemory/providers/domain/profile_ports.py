"""PRO-001 ports for profiles, certified adapters, probes, and gateway transport."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.profiles import (
        ProviderManifest,
        ProviderProbeEvidence,
        ProviderProbeResult,
        ProviderProfile,
        ProviderProfileConfiguration,
    )


@dataclass(frozen=True, slots=True)
class ProviderGatewayRequest:
    """Credential-reference-only request authorized by the local provider gateway."""

    adapter_id: str
    endpoint_policy_ref: str
    secret_ref: str
    method: str
    path: str
    body: bytes
    timeout_milliseconds: int
    max_response_bytes: int


@dataclass(frozen=True, slots=True)
class ProviderGatewayResponse:
    """Bounded response plus gateway-attested immutable model revision evidence."""

    status_code: int
    body: bytes
    model_revision: str
    revision_fingerprint: str
    endpoint_fingerprint: str
    cancellation_verified: bool


class ProviderProfileRepository(Protocol):
    """Persist provider snapshots, immutable revisions, probes, and operations."""

    async def create(  # noqa: PLR0913 -- Port binds authority, identity, manifest, and time.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        profile_id: str,
        configuration: ProviderProfileConfiguration,
        manifest_digest: str,
        created_at: datetime,
    ) -> ProviderProfile:
        """Create or exactly replay one draft profile."""
        ...

    async def get(
        self,
        scope: AuthorizedScope,
        profile_id: str,
        requested_at: datetime,
    ) -> ProviderProfile | None:
        """Load one profile after current Brain-wide authorization."""
        ...

    async def find_operation(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        operation_kind: str,
        profile_id: str | None,
        requested_at: datetime,
    ) -> ProviderProfile | None:
        """Replay one completed create/probe operation before external work."""
        ...

    async def activate(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        expected_version: int,
        evidence: ProviderProbeEvidence,
    ) -> ProviderProfile:
        """Atomically persist evidence and activate the exact expected snapshot."""
        ...


class ProviderAdapterPort(Protocol):
    """Common conformance contract implemented by every certified built-in."""

    @property
    def manifest(self) -> ProviderManifest:
        """Return the immutable certified manifest."""
        ...

    async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
        """Perform a live, bounded protocol probe without returning credentials."""
        ...


class ProviderAdapterRegistry(Protocol):
    """Resolve only installed/certified adapter implementations."""

    def get(self, adapter_id: str) -> ProviderAdapterPort:
        """Return one exact adapter or fail closed."""
        ...


class ProviderProfileIdentityGenerator(Protocol):
    """Generate an unpredictable RFC 9562 UUIDv7 profile identity."""

    def new(self) -> str:
        """Return one fresh provider profile ID."""
        ...


class ProviderGatewayTransport(Protocol):
    """Execute remote calls only through the independently authorized gateway."""

    async def execute(self, request: ProviderGatewayRequest) -> ProviderGatewayResponse:
        """Return a bounded response without exposing credential values."""
        ...


class LocalProviderProbe(Protocol):
    """Probe an already release-verified local inference sidecar."""

    async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
        """Return exact loaded-model capability evidence."""
        ...
