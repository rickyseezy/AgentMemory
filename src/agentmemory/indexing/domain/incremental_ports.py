"""IDX-002 ports for repository inspection, durable runs, and bounded projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.code_entities import IndexedFile, SourceSnapshot
    from agentmemory.indexing.domain.incremental import (
        IndexFingerprint,
        IndexOperation,
        IndexPlan,
        IndexProjectionEvent,
        IndexRun,
        PriorIndexedUnit,
        VcsDelta,
    )
    from agentmemory.indexing.domain.ports import SourceArtifact
    from agentmemory.operations.domain.dependency_ports import EmbeddingVector


@dataclass(frozen=True, slots=True)
class RepositoryManifestEntry:
    """One content-addressed current file discovered without retaining source text."""

    relative_path: str
    content_digest: str
    byte_length: int
    generated: bool


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
    """Complete current repository manifest and normalized VCS delta evidence."""

    target_commit_id: str | None
    working_digest: str
    files: tuple[RepositoryManifestEntry, ...]
    vcs_deltas: tuple[VcsDelta, ...]


@dataclass(frozen=True, slots=True)
class CompletedIndexManifest:
    """Previous completed snapshot and its currently bound semantic units."""

    snapshot: SourceSnapshot
    units: tuple[PriorIndexedUnit, ...]


@dataclass(frozen=True, slots=True)
class IndexWork:
    """One durably claimed run with its immutable plan and target snapshot."""

    run: IndexRun
    snapshot: SourceSnapshot
    plan: IndexPlan


@dataclass(frozen=True, slots=True)
class ProjectionImpact:
    """Reverse dependency closure for changed or deleted semantic units."""

    dependent_fact_ids: tuple[str, ...]
    assertion_evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IndexOperationCommit:
    """Atomic canonical result and outbox event for one plan operation."""

    operation: IndexOperation
    indexed_file: IndexedFile | None
    projection_event: IndexProjectionEvent | None


class IncrementalRepositorySource(Protocol):
    """Inspect Git state and read only exact changed artifacts at execution time."""

    async def inspect(
        self,
        repository_id: str,
        base_commit_id: str | None,
        target_commit_id: str | None,
        previous: tuple[PriorIndexedUnit, ...],
    ) -> RepositoryInspection:
        """Return all current hashes plus VCS rename/copy/delete observations."""
        ...

    async def read(
        self,
        repository_id: str,
        target_commit_id: str | None,
        relative_path: str,
        expected_digest: str,
    ) -> SourceArtifact:
        """Return exact current bytes only when they still match the planned digest."""
        ...


class IndexFingerprintProvider(Protocol):
    """Resolve exact parser/extractor/privacy cache coordinates by file path."""

    @property
    def implementation_digest(self) -> str:
        """Return the global reviewed implementation manifest digest."""
        ...

    def for_path(self, relative_path: str) -> IndexFingerprint:
        """Return deterministic cache coordinates without opening source content."""
        ...


class IncrementalIndexRepository(Protocol):
    """Authorize and persist append-only index plans, checkpoints, and bindings."""

    async def latest_completed(self, scope: AuthorizedScope) -> CompletedIndexManifest | None:
        """Return the latest currently authorized completed snapshot."""
        ...

    async def find_by_operation(self, scope: AuthorizedScope, operation_id: str) -> IndexRun | None:
        """Return an existing idempotency operation before source reinspection."""
        ...

    async def start(
        self,
        scope: AuthorizedScope,
        run: IndexRun,
        snapshot: SourceSnapshot,
        plan: IndexPlan,
    ) -> IndexRun:
        """Append the exact queued run and immutable plan or replay it."""
        ...

    async def get(self, scope: AuthorizedScope, run_id: str) -> IndexRun | None:
        """Return one run after current repository authorization."""
        ...

    async def request_cancel(
        self,
        scope: AuthorizedScope,
        run_id: str,
        operation_id: str,
        requested_at: datetime,
    ) -> IndexRun:
        """Append an idempotent cancellation request and lifecycle snapshot."""
        ...


class IncrementalIndexWorkRepository(Protocol):
    """Trusted worker capability over durable run checkpoints and projection outbox."""

    async def claim_next(self, claimed_at: datetime) -> IndexWork | None:
        """Claim the oldest queued run after revalidating its recorded authority."""
        ...

    async def current(self, run_id: str) -> IndexRun:
        """Reload current state to observe cancellation between operations."""
        ...

    async def impact(self, semantic_ids: tuple[str, ...]) -> ProjectionImpact:
        """Return the bounded transitive reverse dependency closure."""
        ...

    async def commit_operation(
        self,
        previous: IndexRun,
        current: IndexRun,
        commit: IndexOperationCommit,
    ) -> IndexRun:
        """Atomically append evidence, binding, lineage, event, and run checkpoint."""
        ...

    async def save_state(self, previous: IndexRun, current: IndexRun) -> IndexRun:
        """Append a cancellation, completion, or failure lifecycle snapshot."""
        ...

    async def next_projection(self, claimed_at: datetime) -> IndexProjectionEvent | None:
        """Claim the oldest undelivered projection event with a bounded lease."""
        ...

    async def projection_succeeded(self, event_id: str, delivered_at: datetime) -> None:
        """Append an idempotent delivery receipt for one exact event."""
        ...


class IndexProjectionConsumer(Protocol):
    """Apply one idempotent invalidation/re-embedding event to derived channels."""

    async def consume(self, event: IndexProjectionEvent) -> None:
        """Invalidate affected current facts and enqueue exact changed semantic units."""
        ...


class SemanticEmbeddingPort(Protocol):
    """Embed one canonical code semantic document in the configured local vector space."""

    async def embed_document(self, content_id: str, content: str) -> EmbeddingVector:
        """Return a model-identified finite vector for one exact semantic identity."""
        ...
