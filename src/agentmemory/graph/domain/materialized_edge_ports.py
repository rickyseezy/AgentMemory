"""GRA-003 segregated canonical, projection, integrity, and traversal ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertions import Assertion
    from agentmemory.graph.domain.materialized_edges import (
        EdgeIntegrityFinding,
        MaterializedAssertionEdge,
        MaterializedEdgeProjectionJob,
        MaterializedEdgeWriteResult,
        ProjectionEdgeStatus,
        ProjectionJobFailureCode,
        TraversalEdgeExplanation,
    )
    from agentmemory.graph.domain.models import GraphRelationshipType
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


class CanonicalAssertionProjectionSource(Protocol):
    """Resolve current canonical assertion state for a projection event."""

    async def current_for_event(
        self,
        scope: AuthorizedScope,
        source_event_id: str,
        assertion_id: str,
    ) -> tuple[Assertion, str, datetime]:
        """Validate the trigger and return current assertion, latest event ID, and event time."""
        ...

    async def expected_edges(
        self,
        scope: AuthorizedScope,
        generation_id: str,
        projected_at: datetime,
    ) -> tuple[MaterializedAssertionEdge, ...]:
        """Build every currently expected edge from canonical lifecycle state."""
        ...


class MaterializedEdgeProjection(Protocol):
    """Project, inspect, quarantine, repair, and traverse assertion-bound edges."""

    async def project(self, edge: MaterializedAssertionEdge) -> MaterializedEdgeWriteResult:
        """Apply only the same or a newer canonical aggregate version."""
        ...

    async def list_edges(self, generation_id: str) -> tuple[MaterializedAssertionEdge, ...]:
        """Return all scoped managed edges, including retired and quarantined rows."""
        ...

    async def quarantine(
        self,
        assertion_id: str,
        generation_id: str,
        reason: str,
        at: datetime,
    ) -> None:
        """Exclude one mismatched edge without deleting projection history."""
        ...

    async def traverse(
        self,
        subject_id: str,
        relationship_types: tuple[GraphRelationshipType, ...],
        generation_id: str,
        limit: int,
    ) -> tuple[TraversalEdgeExplanation, ...]:
        """Traverse only active, non-quarantined, authorized edges."""
        ...


class MaterializedEdgeIntegrityJournal(Protocol):
    """Persist immutable content-free integrity findings and repair outcomes."""

    async def record(
        self,
        scope: AuthorizedScope,
        findings: tuple[EdgeIntegrityFinding, ...],
    ) -> None:
        """Append exact idempotent findings before projection repair."""
        ...

    async def repaired(
        self,
        scope: AuthorizedScope,
        finding: EdgeIntegrityFinding,
        repaired_at: datetime,
    ) -> None:
        """Append an immutable repair transition for one finding."""
        ...


class ScopedMaterializedEdgeProjectionFactory(Protocol):
    """Create one operation-scoped projection capability."""

    def projection(self, scope: AuthorizedScope) -> MaterializedEdgeProjection:
        """Bind every graph operation to one immutable authorization scope."""
        ...


class MaterializedEdgeProjectionWorkRepository(Protocol):
    """Lease and finalize durable assertion-edge projection work."""

    async def claim_next(
        self,
        owner: str,
        now: datetime,
        lease_until: datetime,
    ) -> MaterializedEdgeProjectionJob | None:
        """Claim one ready or expired item through an atomic compare-and-swap."""
        ...

    async def complete(
        self,
        job: MaterializedEdgeProjectionJob,
        generation_id: str,
        projection_digest: str,
        status: ProjectionEdgeStatus,
        completed_at: datetime,
    ) -> None:
        """Atomically append a receipt and complete the exact current lease."""
        ...

    async def retry(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        not_before: datetime,
        attempted_at: datetime,
    ) -> None:
        """Release the exact lease for a bounded delayed retry."""
        ...

    async def quarantine(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        at: datetime,
    ) -> None:
        """Permanently exclude malformed or unauthorized work from automatic replay."""
        ...


class MaterializedEdgeProjectionAuthorization(Protocol):
    """Resolve fresh least-privilege scope for one durable projection item."""

    async def authorize(
        self,
        job: MaterializedEdgeProjectionJob,
        action: str,
        at: datetime,
    ) -> AuthorizedScope:
        """Reauthorize canonical coordinates without trusting the original scope snapshot."""
        ...


class MaterializedEdgeGenerationResolver(Protocol):
    """Resolve the current graph generation selected by canonical SQLite state."""

    async def active_generation(self, brain_id: str) -> str | None:
        """Return the active graph generation digest or no value when not initialized."""
        ...


class MaterializedEdgeIntegrityScopeSource(Protocol):
    """Resolve bounded current authorization scopes for periodic integrity checks."""

    async def integrity_scopes(
        self,
        at: datetime,
        limit: int,
    ) -> tuple[tuple[AuthorizedScope, str], ...]:
        """Return at most limit Brain scopes paired with active graph generations."""
        ...
