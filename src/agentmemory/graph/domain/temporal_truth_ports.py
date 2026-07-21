"""GRA-004 application ports for canonical temporal truth and VCS evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.temporal_truth import (
        EvidenceRevisionAnchor,
        ResolvedVcsRevision,
        RevisionEvidenceProof,
        TemporalAssertionCandidate,
        TemporalAssertionCriteria,
        VcsRevisionBatch,
        VcsRevisionSelector,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


class TemporalAssertionRepository(Protocol):
    """Read canonical assertion lifecycle snapshots under an exact AuthorizedScope."""

    async def query(
        self, scope: AuthorizedScope, criteria: TemporalAssertionCriteria
    ) -> tuple[TemporalAssertionCandidate, ...]:
        """Return active-at-snapshot canonical candidates in deterministic order."""
        ...


class VcsRevisionPort(Protocol):
    """Resolve mutable refs and prove evidence reachability against immutable commits."""

    async def resolve(
        self,
        scope: AuthorizedScope,
        selector: VcsRevisionSelector,
        recorded_at: datetime,
    ) -> ResolvedVcsRevision:
        """Resolve a branch/commit selector at the requested recorded-time watermark."""
        ...

    async def prove(
        self,
        scope: AuthorizedScope,
        evidence_id: str,
        anchor: EvidenceRevisionAnchor | None,
        resolved: ResolvedVcsRevision,
        recorded_at: datetime,
    ) -> RevisionEvidenceProof:
        """Return a bounded reachability and invalidation proof for one evidence item."""
        ...


class VcsRevisionBatchRepository(Protocol):
    """Append authorized commit DAG, ref, and evidence-impact observations atomically."""

    async def append(self, scope: AuthorizedScope, batch: VcsRevisionBatch) -> str:
        """Persist or exactly replay one immutable batch and return its digest."""
        ...
