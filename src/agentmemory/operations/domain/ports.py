"""Capability-specific ports owned by the Core operations context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from agentmemory.operations.domain.active_release import ActiveReleasePointer
    from agentmemory.operations.domain.bootstrap import BootstrapDisposition, BootstrapRequest
    from agentmemory.operations.domain.mcp_session import (
        McpSession,
        McpSessionRegistration,
        McpWorkspaceScope,
    )
    from agentmemory.operations.domain.projection_rebuild import (
        ProjectionRebuild,
        ProjectionType,
        ProjectionValidation,
        RebuildManifest,
        SourcePage,
        SourceRecord,
        StartProjectionRebuildCommand,
    )
    from agentmemory.operations.domain.readiness import (
        ProbeEvidence,
        ReadinessBinding,
        ReadinessProbe,
        ReadinessReceipt,
    )
    from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest, Uuid7Id
    from agentmemory.operations.domain.workspace_checkpoint import (
        WorkspaceCheckpointBatch,
        WorkspaceCheckpointIngestionResult,
        WorkspaceIndexCoverage,
    )


class ReadinessProbePort(Protocol):
    """Execute exactly one independently evidenced readiness capability."""

    @property
    def probe(self) -> ReadinessProbe:
        """Return the one closed probe implemented by this capability."""
        ...

    async def execute(self, binding: ReadinessBinding) -> ProbeEvidence:
        """Return a bound positive or negative observation."""
        ...


class ReadinessReceiptRepository(Protocol):
    """Persist complete readiness receipts idempotently within one UoW."""

    async def add(self, receipt: ReadinessReceipt) -> None:
        """Add a new receipt or accept the exact previously stored receipt."""
        ...

    async def latest(self) -> ReadinessReceipt | None:
        """Return the latest verified receipt without mutating state."""
        ...


class ReadinessStatusPort(Protocol):
    """Read-only optimized readiness receipt query."""

    async def latest(self) -> ReadinessReceipt | None:
        """Return the latest verified receipt without mutating state."""
        ...


class RuntimeReadinessPort(Protocol):
    """Bound full-gate cadence while proving cheap dependencies live on every check."""

    async def verify(self, anchor: ReadinessReceipt) -> ReadinessReceipt | None:
        """Return a current trusted certificate only while runtime dependencies pass."""
        ...


class BootstrapRepository(Protocol):
    """Own the atomic first-install identity aggregate creation."""

    async def ensure(self, request: BootstrapRequest) -> BootstrapDisposition:
        """Create exact bootstrap state or return an exact idempotent match."""
        ...


class AuditRepository(Protocol):
    """Append governed non-content Core bootstrap facts."""

    async def append_bootstrap(
        self,
        request: BootstrapRequest,
        disposition: BootstrapDisposition,
    ) -> None:
        """Append one hash-chained audit fact inside the owning UoW."""
        ...


class ActiveReleaseRepository(Protocol):
    """Own the staged intent and exact active pointer mirror in one transaction."""

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> tuple[Sha256Digest, bool]:
        """Persist or verify an exact readiness-authorized stage."""
        ...

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        """Mirror the exact staged pointer under anti-rollback policy."""
        ...

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        """Return equality only after authenticating every durable mirror."""
        ...


class ActiveReleaseUnitOfWork(Protocol):
    """Own one canonical transaction containing active-release persistence."""

    @property
    def active_releases(self) -> ActiveReleaseRepository:
        """Return transaction-scoped active-release persistence."""
        ...

    async def __aenter__(self) -> Self:
        """Open the active-release transaction scope."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless the handler explicitly committed."""
        ...

    async def commit(self) -> None:
        """Commit the active-release mutation atomically."""
        ...


class ActiveReleaseUnitOfWorkFactory(Protocol):
    """Construct one fresh active-release transaction scope."""

    def __call__(self) -> ActiveReleaseUnitOfWork:
        """Return an unopened active-release Unit of Work."""
        ...


class CoreUnitOfWork(Protocol):
    """Own one canonical SQLite transaction and aggregate repositories."""

    @property
    def receipts(self) -> ReadinessReceiptRepository:
        """Return transaction-scoped readiness receipt persistence."""
        ...

    @property
    def bootstrap(self) -> BootstrapRepository:
        """Return transaction-scoped bootstrap aggregate persistence."""
        ...

    @property
    def audit(self) -> AuditRepository:
        """Return transaction-scoped governed audit persistence."""
        ...

    async def __aenter__(self) -> Self:
        """Open one transaction-scoped repository set."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless the handler explicitly committed."""
        ...

    async def commit(self) -> None:
        """Commit all canonical mutations atomically."""
        ...


class CoreUnitOfWorkFactory(Protocol):
    """Construct one fresh explicit Core transaction scope."""

    def __call__(self) -> CoreUnitOfWork:
        """Return an unopened Unit of Work."""
        ...


class McpSessionRepository(Protocol):
    """Persist append-only PF-005 credential and lease state."""

    async def register(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        """Create exact registration or return its idempotent prior value."""
        ...

    async def get(self, session_id: Uuid7Id) -> McpSession | None:
        """Load one complete aggregate from authenticated append-only state."""
        ...

    async def get_by_credential(self, digest: Sha256Digest) -> McpSession | None:
        """Resolve one opaque credential digest without content access."""
        ...

    async def save(self, previous: McpSession, current: McpSession) -> None:
        """Append exactly one optimistic lifecycle revision and audit fact."""
        ...

    async def expired(self, now: datetime, limit: int) -> tuple[McpSession, ...]:
        """Return a bounded deterministic set of expired active leases."""
        ...

    async def authorize(
        self,
        digest: Sha256Digest,
        session_id: Uuid7Id,
        now: datetime,
    ) -> McpSession | None:
        """Resolve only current unrevoked authority under the active security epoch."""
        ...


class McpWorkspaceScopeResolver(Protocol):
    """Resolve only previously governed canonical identity from opaque host evidence."""

    async def resolve(self, registration: McpSessionRegistration) -> McpWorkspaceScope | None:
        """Return one exact scope, absence, or raise on ambiguity/integrity failure."""
        ...


class McpWorkspaceScopeProvisioner(Protocol):
    """Create only the missing governed identity needed by an authorized session."""

    async def ensure(
        self,
        registration: McpSessionRegistration,
        resolved: McpWorkspaceScope | None,
    ) -> McpWorkspaceScope:
        """Return an exact existing or newly provisioned Project/Repository/Checkout."""
        ...


class WorkspaceCheckpointRepository(Protocol):
    """Persist encrypted PF-005 workspace batches before launcher acknowledgement."""

    async def stage(self, batch: WorkspaceCheckpointBatch) -> bool:
        """Create one exact encrypted batch or return its idempotent prior value."""
        ...

    async def pending(self, limit: int) -> tuple[WorkspaceCheckpointBatch, ...]:
        """Decrypt a deterministic bounded set without exposing storage envelopes."""
        ...

    async def acknowledge(
        self,
        batch_digest: Sha256Digest,
        result: WorkspaceCheckpointIngestionResult,
    ) -> bool:
        """Append a terminal exact receipt or return its idempotent prior value."""
        ...


class WorkspaceCheckpointIngestor(Protocol):
    """Translate one staged workspace delta through canonical ingestion contracts."""

    async def ingest(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> WorkspaceCheckpointIngestionResult:
        """Return only after every derived event is durably accepted or replayed."""
        ...


class WorkspaceCheckpointProjector(Protocol):
    """Queue durable derived work from one fully ingested workspace checkpoint."""

    async def project(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> None:
        """Return only after the checkpoint's derived work is durably queued."""
        ...


class WorkspaceCheckpointCoverageRepository(Protocol):
    """Read content-free indexing coverage for one authenticated MCP session."""

    async def coverage(self, session_id: Uuid7Id) -> WorkspaceIndexCoverage:
        """Return current durable coverage without exposing file identities."""
        ...


class CanonicalProjectionSourcePort(Protocol):
    """Read immutable pages from canonical SQL events and authorized artifacts."""

    async def latest_watermark(self, brain_id: Uuid7Id) -> int:
        """Capture the last committed source sequence for one Brain."""
        ...

    async def read_page(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        after_cursor: int,
        watermark: int,
        limit: int,
    ) -> SourcePage:
        """Read only records at or below the fixed rebuild watermark."""
        ...


class ProjectionAccessPolicyPort(Protocol):
    """Re-evaluate authorization and deletion state during every replay page."""

    async def authorize(self, brain_id: Uuid7Id, actor_id: Uuid7Id, grant_id: Uuid7Id) -> None:
        """Reject absent, expired, revoked, or wrong-Brain grants."""
        ...

    async def is_tombstoned(self, brain_id: Uuid7Id, source: SourceRecord) -> bool:
        """Return true when authoritative SQL forbids materialization."""
        ...


class ProjectionGenerationPort(Protocol):
    """Write and validate isolated derived records without changing query visibility."""

    async def prepare(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> None:
        """Create or verify one exact immutable shadow generation."""
        ...

    async def put(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        record: SourceRecord,
        manifest: RebuildManifest,
    ) -> bool:
        """Insert once, accept an exact replay, and reject divergent duplicates."""
        ...

    async def validate(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> ProjectionValidation:
        """Run counts, lineage, integrity, policy, tombstone, and golden-query gates."""
        ...


class ProjectionRebuildRepository(Protocol):
    """Persist durable rebuild jobs and the sole canonical activation pointers."""

    async def create(
        self,
        command: StartProjectionRebuildCommand,
        source_watermark: int,
        rebuild_key: Sha256Digest,
        generation_id: Sha256Digest,
    ) -> ProjectionRebuild:
        """Create or return the exact idempotent rebuild operation."""
        ...

    async def get(self, operation_id: str) -> ProjectionRebuild | None:
        """Return one rebuild without exposing projected content."""
        ...

    async def next_runnable(self) -> str | None:
        """Return the oldest queued/partial or expired-lease operation without claiming it."""
        ...

    async def claim(self, operation_id: str) -> ProjectionRebuild:
        """Claim queued or partial work and move it to building."""
        ...

    async def checkpoint(
        self,
        operation_id: str,
        cursor: int,
        inserted: int,
        skipped_tombstones: int,
    ) -> ProjectionRebuild:
        """Persist monotonic replay progress after idempotent projection writes."""
        ...

    async def mark_partial(self, operation_id: str, reason: str) -> ProjectionRebuild:
        """Pause at the last committed cursor with a typed safe reason."""
        ...

    async def begin_validation(self, operation_id: str) -> ProjectionRebuild:
        """Close replay and enter the non-visible validation stage."""
        ...

    async def mark_ready(
        self,
        operation_id: str,
        validation: ProjectionValidation,
    ) -> ProjectionRebuild:
        """Persist passing validation evidence before activation."""
        ...

    async def activate(self, operation_id: str) -> ProjectionRebuild:
        """Atomically compare-and-swap the active generation pointer."""
        ...

    async def fail(self, operation_id: str, reason: str) -> ProjectionRebuild:
        """Quarantine failed work without changing the active pointer."""
        ...
