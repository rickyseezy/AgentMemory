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
    from agentmemory.ingestion.domain.backpressure import (
        CapacitySnapshot,
        DeadLetter,
        JobErrorCode,
        JobRequest,
        QueueLimits,
        ReplayDeadLetterRequest,
        RetryDecision,
        ScheduledJob,
    )
    from agentmemory.ingestion.domain.capture import (
        AdmittedAgentEvent,
        AppendAgentEventResult,
        EncryptedAgentEvent,
    )
    from agentmemory.ingestion.domain.durable_processing import (
        ClaimedOutboxMessage,
        InboxReceiptClaim,
        VerifiedEventProjection,
    )
    from agentmemory.ingestion.domain.generic_adapter import (
        DecodedTranscriptRecord,
        GitState,
        ProcessExecutionResult,
        TranscriptEncoding,
        TranscriptFormat,
        WorkspaceSnapshot,
    )
    from agentmemory.ingestion.domain.ordered_replay import (
        OrderedEventClaim,
        OrderedProjectionState,
        OrderedReplayRun,
        ReplayRunRequest,
        ReplaySourcePage,
        ReplaySourceRecord,
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
    """Append only the canonical event index and authenticated envelope."""

    async def append(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
        artifact_id: str | None,
    ) -> AppendAgentEventResult:
        """Insert or identify an exact idempotent retry."""
        ...


class ArtifactRepository(Protocol):
    """Persist a content-addressed reference used by one canonical event."""

    async def ensure_reference(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> str | None:
        """Return a Brain-scoped artifact identity or None for inline content."""
        ...


class OutboxRepository(Protocol):
    """Persist immutable local dispatch intent for an accepted event."""

    async def enqueue(self, admitted: AdmittedAgentEvent) -> None:
        """Append one checksum-bound ready message without committing."""
        ...


class IngestionAuditRepository(Protocol):
    """Append tamper-evident audit evidence for ingestion mutations."""

    async def append_agent_event(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> None:
        """Append one content-free event acceptance fact without committing."""
        ...

    async def append_agent_event_conflict(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> None:
        """Append one deduplicated content-free identity conflict without committing."""
        ...


class AgentEventUnitOfWork(Protocol):
    """Transaction containing event, outbox, and audit writes."""

    events: AgentEventRepository
    artifacts: ArtifactRepository
    outbox: OutboxRepository
    audit: IngestionAuditRepository

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


class CanonicalEventProjectionVerifier(Protocol):
    """Authenticate one canonical event and derive its terminal processing digest."""

    async def verify(self, message: ClaimedOutboxMessage) -> VerifiedEventProjection:
        """Return verified receipt material or a typed dependency/integrity failure."""
        ...


class DurableEventProcessingRepository(Protocol):
    """Lease and atomically finish acknowledged event processing."""

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ClaimedOutboxMessage | None:
        """Claim the oldest ready or expired message in a short durable transaction."""
        ...

    async def claim_inbox(
        self,
        message: ClaimedOutboxMessage,
        consumer: str,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> InboxReceiptClaim:
        """Claim/replay the consumer receipt or reject divergent message content."""
        ...

    async def complete(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim,
        projection: VerifiedEventProjection,
        completed_at_microseconds: int,
    ) -> None:
        """Commit the terminal receipt and completed outbox state atomically."""
        ...

    async def claim_order(  # noqa: PLR0913 -- Port carries exact lease/gap evidence.
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
        gap_timeout_microseconds: int,
    ) -> OrderedEventClaim:
        """Claim the next causal sequence, wait on a gap, or identify late replay work."""
        ...

    async def complete_replay(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        completed_at_microseconds: int,
    ) -> None:
        """Finish a repeated outbox delivery only after validating its committed receipt."""
        ...

    async def require_repair(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim,
        reason_code: str,
        detected_at_microseconds: int,
    ) -> None:
        """Commit a content-free repair alert and terminal queue state atomically."""
        ...

    async def release_retry(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim | None,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        """Release only the exact lease for a later safe retry."""
        ...

    async def defer_replay(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim,
        detected_at_microseconds: int,
    ) -> None:
        """Atomically hold one late event and record the required shadow replay."""
        ...

    async def recover_expired_leases(self, now_microseconds: int) -> int:
        """Return every expired processing lease to the ready state at startup."""
        ...

    async def alert_unprocessed_events(self, detected_at_microseconds: int) -> int:
        """Alert on committed events whose atomic outbox intent is absent."""
        ...


class JobSchedulerRepository(Protocol):
    """Durable priority queues, leases, retries, and immutable dead letters."""

    async def submit(
        self,
        request: JobRequest,
        limits: QueueLimits,
        now_microseconds: int,
    ) -> ScheduledJob:
        """Idempotently admit one authorized job or raise a typed capacity error."""
        ...

    async def get(self, job_id: str) -> ScheduledJob | None:
        """Return one scheduler-owned job or None without exposing job input."""
        ...

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
        limits: QueueLimits,
    ) -> ScheduledJob | None:
        """Fairly lease one due job from an independently prioritized queue."""
        ...

    async def succeed(
        self,
        job: ScheduledJob,
        owner: str,
        result_sha256: str,
        completed_at_microseconds: int,
    ) -> ScheduledJob:
        """Atomically complete only the exact live lease."""
        ...

    async def fail(  # noqa: PLR0913 -- Lease CAS requires complete typed failure evidence.
        self,
        job: ScheduledJob,
        owner: str,
        error_code: JobErrorCode,
        decision: RetryDecision,
        diagnostic_code: str,
        failed_at_microseconds: int,
    ) -> ScheduledJob:
        """Apply the typed retry policy or append an immutable dead letter."""
        ...

    async def recover_expired(self, now_microseconds: int) -> int:
        """Release expired leases to deterministic retry state."""
        ...

    async def capacity_snapshot(
        self,
        *,
        kind: str,
        idempotency_key: str,
    ) -> CapacitySnapshot:
        """Return a content-free atomic view of scheduler and disk capacity."""
        ...

    async def list_dead_letters(
        self,
        brain_id: str,
        *,
        maximum: int,
    ) -> tuple[DeadLetter, ...]:
        """Return bounded newest immutable dead letters for one Brain."""
        ...

    async def get_dead_letter(self, dead_letter_id: str) -> DeadLetter | None:
        """Return one immutable dead letter or None."""
        ...

    async def replay_dead_letter(
        self,
        request: ReplayDeadLetterRequest,
        limits: QueueLimits,
        now_microseconds: int,
    ) -> ScheduledJob:
        """Idempotently create a corrected job linked to immutable failure history."""
        ...


class JobSchedulerAccessPolicy(Protocol):
    """Authorize current actor/grant access to scheduler state."""

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        now_microseconds: int,
    ) -> None:
        """Raise unless the exact current Brain grant is active."""
        ...


class ScheduledJobExecutor(Protocol):
    """Execute one typed scheduler job behind an adapter-owned boundary."""

    async def execute(self, job: ScheduledJob) -> str:
        """Return the immutable result SHA-256 or raise a typed job failure."""
        ...


class LocalStorageCapacityProbe(Protocol):
    """Read content-free free-space evidence for the canonical local volume."""

    def free_bytes(self) -> int:
        """Return currently available bytes or raise a typed dependency error."""
        ...


class OrderedReplayAccessPolicy(Protocol):
    """Authorize replay scope against current canonical grants."""

    async def authorize(self, request: ReplayRunRequest, now_microseconds: int) -> None:
        """Raise unless the actor's exact Brain grant remains active."""
        ...


class OrderedReplayRepository(Protocol):
    """Persist immutable selection, isolated shadow state, and validation evidence."""

    async def create(
        self,
        request: ReplayRunRequest,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Idempotently capture a source watermark and create one queued shadow run."""
        ...

    async def get(self, operation_id: str) -> OrderedReplayRun | None:
        """Return content-free durable status for one operation."""
        ...

    async def claim(
        self,
        operation_id: str,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> OrderedReplayRun:
        """Claim queued/partial/expired work with an exact durable lease."""
        ...

    async def read_page(self, run: OrderedReplayRun, limit: int) -> ReplaySourcePage:
        """Read the next bounded immutable source page in causal order."""
        ...

    async def shadow_state(
        self,
        operation_id: str,
        ordering_key: str,
    ) -> OrderedProjectionState | None:
        """Return the last state inside only this shadow generation."""
        ...

    async def append(  # noqa: PLR0913 -- CAS requires complete immutable replay evidence.
        self,
        run: OrderedReplayRun,
        source: ReplaySourceRecord,
        prior_state_sha256: str,
        state: OrderedProjectionState | None,
        state_sha256: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Atomically append history/state and advance the durable source cursor."""
        ...

    async def begin_validation(
        self,
        run: OrderedReplayRun,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> OrderedReplayRun:
        """Transition a complete building run to leased validation."""
        ...

    async def shadow_states(
        self,
        operation_id: str,
    ) -> tuple[OrderedProjectionState, ...]:
        """Return final isolated states in deterministic key order."""
        ...

    async def live_states(self, run: OrderedReplayRun) -> tuple[OrderedProjectionState, ...]:
        """Return comparable live states for the replay's touched keys."""
        ...

    async def finish_validation(
        self,
        run: OrderedReplayRun,
        shadow_digest: str,
        live_digest: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Commit matching ready or divergent superseded evidence without activation."""
        ...

    async def mark_partial(
        self,
        run: OrderedReplayRun,
        failure_code: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Release the exact lease with a bounded resumable reason."""
        ...

    async def next_runnable(self, now_microseconds: int) -> str | None:
        """Return the oldest queued, partial, or expired replay operation."""
        ...

    async def recover_expired(self, now_microseconds: int) -> int:
        """Release stale replay leases without touching committed shadow state."""
        ...
