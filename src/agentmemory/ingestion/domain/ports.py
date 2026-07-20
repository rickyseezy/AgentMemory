"""Capability-specific ports for canonical event translation and admission."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, TypeVar

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.ingestion.domain.agent_event import (
        AdapterCapabilityDescriptor,
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


class AdapterDescriptorRegistry(Protocol):
    """Resolve an active immutable adapter descriptor from daemon-owned state."""

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
    ) -> AdapterCapabilityDescriptor:
        """Return an exact active descriptor or deny capture."""
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
