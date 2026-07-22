"""PF-003 clean-architecture ports for governed adapter registration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from agentmemory.extensions.domain.models import (
        AdapterAuthorizationRequest,
        AdapterManifest,
        AdapterProbeEvidence,
        AdapterRegistration,
        ProtocolVersion,
    )


@dataclass(frozen=True, slots=True)
class AdapterProbeTransportResponse:
    """Bounded response bytes plus independently observed runtime package digest."""

    body: bytes
    runtime_digest: str


@dataclass(frozen=True, slots=True)
class AdapterRegistrationEvent:
    """Content-free audit/outbox event emitted atomically with registration."""

    event_id: str
    event_type: str
    registration_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    adapter_id: str
    adapter_kind: str
    manifest_digest: str
    package_digest: str
    evidence_digest: str
    registration_digest: str
    occurred_at: datetime


class AdapterRegistrationRepository(Protocol):
    """Persist operation receipts and immutable adapter versions."""

    async def replay(self, operation_id: str, request_digest: str) -> AdapterRegistration | None:
        """Return an exact replay or reject conflicting operation reuse."""
        ...

    async def get_version(
        self,
        brain_id: str,
        adapter_id: str,
        adapter_version: str,
    ) -> AdapterRegistration | None:
        """Return one immutable registered version within the authorized Brain."""
        ...

    async def save(
        self,
        operation_id: str,
        request_digest: str,
        registration: AdapterRegistration,
    ) -> None:
        """Stage one operation-bound active registration."""
        ...

    async def link_operation(
        self,
        operation_id: str,
        request_digest: str,
        registration: AdapterRegistration,
    ) -> None:
        """Stage a new exact receipt for an already registered immutable version."""
        ...


class AdapterEventSink(Protocol):
    """Stage one content-free audit or integration event."""

    async def append(self, event: AdapterRegistrationEvent) -> None:
        """Append idempotently inside the current unit of work."""
        ...


class AdapterRegistrationUnitOfWork(Protocol):
    """Atomic registry, audit, and outbox transaction."""

    @property
    def repository(self) -> AdapterRegistrationRepository:
        """Return the transaction-scoped repository."""
        ...

    @property
    def audit(self) -> AdapterEventSink:
        """Return the transaction-scoped audit sink."""
        ...

    @property
    def outbox(self) -> AdapterEventSink:
        """Return the transaction-scoped integration-event sink."""
        ...

    async def __aenter__(self) -> Self:
        """Enter one isolated transaction."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Roll back unless commit completed."""
        ...

    async def commit(self) -> None:
        """Atomically make registry, audit, and outbox facts durable."""
        ...


class AdapterRegistrationUnitOfWorkFactory(Protocol):
    """Create one isolated registration transaction."""

    def __call__(self) -> AdapterRegistrationUnitOfWork:
        """Return a fresh unit of work."""
        ...


class AdapterRegistrationAuthorization(Protocol):
    """Authorize current actor/grant/Brain before candidate access."""

    async def authorize(self, request: AdapterAuthorizationRequest) -> None:
        """Permit owner/admin adapter registration or raise a closed denial."""
        ...


class AdapterPackageTrust(Protocol):
    """Verify exact package digest, signature, and approved publisher."""

    async def verify(self, manifest: AdapterManifest) -> None:
        """Return only after offline trust evidence binds the exact package."""
        ...


class AdapterPackageSignatureVerifier(Protocol):
    """Verify an offline signature bundle through the approved trust implementation."""

    async def verify(
        self,
        package_digest: str,
        signature_digest: str,
        signer_identity: str,
    ) -> None:
        """Raise when exact signed subject or publisher authority is invalid."""
        ...


class AdapterPermissionPolicy(Protocol):
    """Evaluate least-authority package permission requests."""

    async def approve(self, manifest: AdapterManifest) -> None:
        """Reject unapproved or kind-incompatible permission authority."""
        ...


class AdapterCapabilityProbe(Protocol):
    """Run live protocol/capability conformance outside the domain."""

    async def probe(
        self,
        manifest: AdapterManifest,
        negotiated_protocol: ProtocolVersion,
    ) -> AdapterProbeEvidence:
        """Return exact package- and manifest-bound live evidence."""
        ...


class AdapterProbeTransport(Protocol):
    """Exchange one bounded live conformance challenge with an isolated runtime."""

    async def exchange(
        self,
        manifest: AdapterManifest,
        request: bytes,
        timeout_milliseconds: int,
        max_response_bytes: int,
    ) -> AdapterProbeTransportResponse:
        """Return bounded bytes and the runtime's independently observed digest."""
        ...


class AdapterChallengeGenerator(Protocol):
    """Generate an unpredictable one-use live-probe challenge."""

    def new(self) -> str:
        """Return one opaque bounded challenge token."""
        ...


class AdapterClock(Protocol):
    """Supply canonical UTC policy time."""

    def now(self) -> datetime:
        """Return the current UTC instant."""
        ...


class AdapterIdentityGenerator(Protocol):
    """Generate unpredictable RFC 9562 UUIDv7 identities."""

    def new(self) -> str:
        """Return one fresh canonical UUIDv7 string."""
        ...
