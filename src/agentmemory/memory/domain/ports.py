"""Capability-specific ports owned by the memory bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from agentmemory.memory.domain.consolidation import (
        ConsolidationCommit,
        ConsolidationResult,
        ExtractorIdentity,
        ExtractorRequest,
        ExtractorResponse,
        MemoryScope,
        TaskEvidenceBundle,
    )
    from agentmemory.memory.domain.lineage_backfill import (
        TaskLineageBackfillOutcome,
        TaskLineageBackfillProgress,
    )
    from agentmemory.memory.domain.work import (
        MemoryConsolidationWork,
        MemoryWorkErrorCode,
        MemoryWorkRetryDecision,
    )


class TaskEvidenceQuery(Protocol):
    """Load one authorized, terminal, bounded task evidence snapshot."""

    async def load(
        self,
        task_id: str,
        terminal_event_id: str,
        scope: MemoryScope,
        maximum_items: int,
        maximum_bytes: int,
    ) -> TaskEvidenceBundle | None:
        """Return exact indexed evidence or None without cross-scope disclosure."""
        ...


class MemoryConsolidationAccessPolicy(Protocol):
    """Authorize one current actor/grant tuple for an exact memory scope."""

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        scope: MemoryScope,
        at: datetime,
    ) -> None:
        """Reject inactive, expired, read-only, or narrower authority."""
        ...


class CanonicalTaskEventReader(Protocol):
    """Authenticate and decrypt one immutable canonical task event."""

    async def read(self, event_id: str) -> bytes:
        """Return exact canonical bytes or fail with a typed integrity error."""
        ...


class MemoryCandidateExtractor(Protocol):
    """Produce untrusted structured candidates without persistence authority."""

    async def extract(self, request: ExtractorRequest) -> ExtractorResponse:
        """Return one hash-bound response for the exact bounded operation."""
        ...


class MemoryConsolidationRepository(Protocol):
    """Stage one complete consolidation inside an existing Unit of Work."""

    async def get(self, idempotency_key: str) -> ConsolidationResult | None:
        """Return an existing content-free result for an exact identity."""
        ...

    async def add(self, consolidation: ConsolidationCommit) -> None:
        """Stage memories, lineage, events, outbox, audit, and receipt."""
        ...


class MemoryConsolidationReceiptQuery(Protocol):
    """Read authenticated content-free idempotency receipts without mutation."""

    async def get(self, idempotency_key: str) -> ConsolidationResult | None:
        """Return an existing exact receipt or None."""
        ...


class MemoryConsolidationUnitOfWork(Protocol):
    """Own one short canonical memory mutation transaction."""

    @property
    def access(self) -> MemoryConsolidationAccessPolicy:
        """Return transaction-bound current authorization."""
        ...

    @property
    def repository(self) -> MemoryConsolidationRepository:
        """Return the transaction-bound aggregate repository."""
        ...

    async def __aenter__(self) -> Self:
        """Open and exclusively own the transaction."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Rollback unless commit completed."""
        ...

    async def commit(self) -> None:
        """Commit all staged changes exactly once."""
        ...


class MemoryConsolidationUnitOfWorkFactory(Protocol):
    """Create unopened memory consolidation Units of Work."""

    def __call__(self) -> MemoryConsolidationUnitOfWork:
        """Return an unopened Unit of Work."""
        ...


class MemoryConsolidationWorkRepository(Protocol):
    """Discover, lease, retry, and complete automatic terminal-task work."""

    async def claim_next(
        self,
        extractor: ExtractorIdentity,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> MemoryConsolidationWork | None:
        """Lease one due exact snapshot or discover one new terminal snapshot."""
        ...

    async def succeed(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        result_sha256: str,
        completed_at_microseconds: int,
    ) -> None:
        """Complete only the exact active lease."""
        ...

    async def fail(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        error_code: MemoryWorkErrorCode,
        decision: MemoryWorkRetryDecision,
        failed_at_microseconds: int,
    ) -> None:
        """Schedule a bounded retry or retain terminal dead-letter evidence."""
        ...

    async def recover_expired(self, now_microseconds: int) -> int:
        """Release exact expired leases for retry."""
        ...


class TaskLineageBackfillRepository(Protocol):
    """Capture a historical watermark and checkpoint derived lineage atomically."""

    async def start_or_resume(self) -> TaskLineageBackfillProgress:
        """Capture the immutable source watermark or resume exact prior progress."""
        ...

    async def load_after(
        self,
        progress: TaskLineageBackfillProgress,
        limit: int,
    ) -> tuple[TaskLineageBackfillOutcome, ...]:
        """Authenticate and derive one bounded ordered page after the cursor."""
        ...

    async def checkpoint(
        self,
        progress: TaskLineageBackfillProgress,
        outcome: TaskLineageBackfillOutcome,
    ) -> TaskLineageBackfillProgress:
        """Store exact lineage if present and advance one source atomically."""
        ...

    async def complete(
        self,
        progress: TaskLineageBackfillProgress,
    ) -> TaskLineageBackfillProgress:
        """Complete only after the exact captured source count was scanned."""
        ...

    async def interrupt(
        self,
        progress: TaskLineageBackfillProgress,
        reason_code: str,
    ) -> TaskLineageBackfillProgress:
        """Retain cursor and safe reason for automatic resume."""
        ...
