"""Capability-specific ports for canonical event translation and admission."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, TypeVar

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.ingestion.domain.adapter_capability import (
        CapabilityChangeResult,
        CapabilityCompatibilityWarning,
        RegisteredAdapterCapabilities,
    )
    from agentmemory.ingestion.domain.agent_event import (
        AgentEvent,
        AgentEventIdentity,
        AgentEventProvenance,
        PayloadReference,
        ResolvedAgentEventIdentity,
    )
    from agentmemory.ingestion.domain.capture import (
        AdmittedAgentEvent,
        AppendAgentEventResult,
        EncryptedAgentEvent,
    )

NativeEventT_contra = TypeVar("NativeEventT_contra", contravariant=True)


class NativeEventTranslator(Protocol[NativeEventT_contra]):
    """Translate one typed host-native observation into AgentEvent v1."""

    def translate(self, observation: NativeEventT_contra) -> AgentEvent:
        """Return one fully validated immutable canonical event."""
        ...


class AgentEventScopeResolver(Protocol):
    """Resolve untrusted event claims through authenticated daemon identity state."""

    async def resolve(
        self,
        claim: AgentEventIdentity,
        provenance: AgentEventProvenance,
    ) -> ResolvedAgentEventIdentity:
        """Return authoritative scope or raise a typed authorization failure."""
        ...


class AdapterCapabilityRegistry(Protocol):
    """Resolve immutable declaration and effective evidence from daemon-owned state."""

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
    ) -> RegisteredAdapterCapabilities:
        """Return exact declared and effective capability evidence or deny capture."""
        ...


class AdapterCapabilityRepository(Protocol):
    """Persist immutable manifests, observations, warnings, and command receipts."""

    async def replay(
        self,
        operation_id: str,
        request_sha256: str,
    ) -> CapabilityChangeResult | None:
        """Return an exact prior result, None, or reject conflicting operation reuse."""
        ...

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> RegisteredAdapterCapabilities | None:
        """Return the exact version with its latest effective observation."""
        ...

    async def latest(self, adapter_id: str) -> RegisteredAdapterCapabilities | None:
        """Return the most recently registered version for compatibility comparison."""
        ...

    async def persist(
        self,
        result: CapabilityChangeResult,
        operation_id: str,
        request_sha256: str,
    ) -> None:
        """Atomically append new facts and a content-free idempotency receipt."""
        ...


class AdapterCapabilityUnitOfWork(Protocol):
    """Transaction for adapter manifest/observation command persistence."""

    capabilities: AdapterCapabilityRepository

    async def __aenter__(self) -> Self:
        """Open one serialized capability transaction."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless explicitly committed."""
        ...

    async def commit(self) -> None:
        """Durably commit once."""
        ...


class AdapterCapabilityUnitOfWorkFactory(Protocol):
    """Create one fresh adapter capability command transaction."""

    def __call__(self) -> AdapterCapabilityUnitOfWork:
        """Return an unopened transaction."""
        ...


class AdapterCapabilityQueryRepository(Protocol):
    """Read-only capability matrix projection for policies and operator display."""

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> RegisteredAdapterCapabilities | None:
        """Return current effective evidence for one exact registered version."""
        ...

    async def list_active(self) -> tuple[RegisteredAdapterCapabilities, ...]:
        """Return every active version in deterministic display order."""
        ...

    async def warnings(
        self,
        adapter_id: str,
        adapter_version: str,
        *,
        maximum: int = 100,
    ) -> tuple[CapabilityCompatibilityWarning, ...]:
        """Return bounded newest warnings for one exact adapter version."""
        ...


class IngestionIdentityGenerator(Protocol):
    """Generate opaque UUIDv7 identities for append-only ingestion facts."""

    def new(self) -> str:
        """Return a lowercase UUIDv7 string."""
        ...


class PayloadContentReader(Protocol):
    """Read authorized CAS bytes so the daemon can independently verify them."""

    async def read(self, reference: PayloadReference) -> bytes:
        """Return exact plaintext bytes after CAS authorization and decryption."""
        ...


class AgentEventEncoder(Protocol):
    """Encode a validated event into its stable canonical transport bytes."""

    def encode(self, event: AgentEvent) -> bytes:
        """Return deterministic bytes suitable for hashing and encryption."""
        ...


class AgentEventEnvelopeEncryptor(Protocol):
    """Encrypt a canonical event with a Brain-scoped key hierarchy."""

    async def encrypt(
        self,
        *,
        event_id: str,
        brain_id: str,
        classification: str,
        plaintext: bytes,
    ) -> EncryptedAgentEvent:
        """Return an authenticated envelope without retaining plaintext."""
        ...


class AgentEventRepository(Protocol):
    """Append the canonical event and required derivative facts atomically."""

    async def append(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> AppendAgentEventResult:
        """Insert or identify an exact idempotent retry."""
        ...


class AgentEventUnitOfWork(Protocol):
    """Transaction containing event, outbox, and audit writes."""

    events: AgentEventRepository

    async def __aenter__(self) -> Self:
        """Open the transaction and bind its repositories."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back any transaction that was not explicitly committed."""
        ...

    async def commit(self) -> None:
        """Durably commit exactly once."""
        ...


class AgentEventUnitOfWorkFactory(Protocol):
    """Create a fresh event transaction for one append command."""

    def __call__(self) -> AgentEventUnitOfWork:
        """Return one unopened transaction."""
        ...
