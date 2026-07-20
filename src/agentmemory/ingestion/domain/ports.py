"""Capability-specific ports for canonical event translation and admission."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, TypeVar

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path
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
    from agentmemory.ingestion.domain.generic_adapter import (
        DecodedTranscriptRecord,
        GitState,
        ProcessExecutionResult,
        TranscriptEncoding,
        TranscriptFormat,
        WorkspaceSnapshot,
    )
    from agentmemory.ingestion.domain.spool_reconciliation import (
        SpoolAcknowledgement,
        SpoolRecord,
        SpoolUploadResult,
    )

NativeEventT_contra = TypeVar("NativeEventT_contra", contravariant=True)


class NativeEventTranslator(Protocol[NativeEventT_contra]):
    """Translate one typed host-native observation into AgentEvent v1."""

    def translate(self, observation: NativeEventT_contra) -> AgentEvent:
        """Return one fully validated immutable canonical event."""
        ...


class AgentAdapterPort(Protocol):
    """Vendor-neutral daemon capture boundary used by every host adapter."""

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        """Admit and durably append one canonical adapter event."""
        ...


class TranscriptDecoder(Protocol):
    """Decode one supported transcript without guessing its encoding or structure."""

    def decode(
        self,
        source: bytes,
        transcript_format: TranscriptFormat,
        encoding: TranscriptEncoding,
        default_occurred_at: datetime,
    ) -> tuple[DecodedTranscriptRecord, ...]:
        """Return stable byte ranges and explicit source fields."""
        ...


class SensitiveTextRedactor(Protocol):
    """Remove configured sensitive tokens before canonical payload creation."""

    def redact(self, value: str) -> str:
        """Return safe text that contains no matched source secret."""
        ...


class WorkspaceObserver(Protocol):
    """Read a privacy-filtered workspace snapshot without following links."""

    def snapshot(self, root: Path) -> WorkspaceSnapshot:
        """Return deterministic authorized file metadata and digests."""
        ...


class GitObserver(Protocol):
    """Read directly observable Git state using fixed argv operations."""

    async def observe(self, root: Path) -> GitState | None:
        """Return repository state or None when the directory is not Git-backed."""
        ...


class ProcessExecutor(Protocol):
    """Execute an argv vector without a command shell."""

    async def execute(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        stdin: bytes | None,
        timeout_seconds: float | None,
    ) -> ProcessExecutionResult:
        """Return bounded output and explicit normal/abrupt completion."""
        ...


class OfflineSpoolRepository(Protocol):
    """Durable host-side queue, lease, watermark, and ciphertext-erasure boundary."""

    async def try_acquire_lease(
        self,
        owner: str,
        acquired_at_microseconds: int,
        expires_at_microseconds: int,
    ) -> bool:
        """Acquire the singleton recovery lease or return False while another owner is live."""
        ...

    async def pending(
        self,
        *,
        maximum_items: int,
        maximum_bytes: int,
    ) -> tuple[SpoolRecord, ...]:
        """Return one bounded deterministic batch without mutating queue state."""
        ...

    async def acknowledge(
        self,
        owner: str,
        acknowledgements: tuple[SpoolAcknowledgement, ...],
        acknowledged_at_microseconds: int,
    ) -> int:
        """Erase only the owner's contiguous durable prefixes and advance watermarks atomically."""
        ...

    async def count_pending(self) -> int:
        """Return a content-free pending count for bounded recovery scheduling."""
        ...

    async def release_lease(self, owner: str) -> None:
        """Release only a lease held by the exact owner."""
        ...


class SpoolBatchUploader(Protocol):
    """Recovered Core boundary for one bounded per-item upload batch."""

    async def upload(self, records: tuple[SpoolRecord, ...]) -> tuple[SpoolUploadResult, ...]:
        """Return exactly one content-free durable/retry/rejection result per record."""
        ...


class RecoveryScheduler(Protocol):
    """Cancellation-aware retry delay owned by the launcher boundary."""

    async def wait(self, seconds: float) -> bool:
        """Wait for the delay or return True when launcher shutdown was requested."""
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
