"""IDX-005 capability-specific ports for artifact topology."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.artifact_topology import (
        ArtifactTopologyBatch,
        ArtifactTopologySnapshot,
        ArtifactTopologySourceArtifact,
        TopologyRelationCandidate,
    )


class ArtifactParserPort(Protocol):
    """Own exactly one deterministic artifact format family."""

    def supports(self, relative_path: str) -> bool:
        """Return whether this parser exclusively owns the normalized path."""
        ...

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Return complete canonical observations without retaining raw source."""
        ...


class ArtifactTopologyRepository(Protocol):
    """Persist append-only batches and query authorized temporal snapshots."""

    async def find_batch_by_operation(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ArtifactTopologyBatch | None:
        """Return an exact registration replay when present."""
        ...

    async def register_batch(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        registered_at: datetime,
    ) -> ArtifactTopologyBatch:
        """Append a complete output and supersede only its prior current source output."""
        ...

    async def snapshot(self, scope: AuthorizedScope, cutoff: datetime) -> ArtifactTopologySnapshot:
        """Return latest-per-source observations without overwriting cross-source conflicts."""
        ...


class ArtifactTopologyProjectionPort(Protocol):
    """Project topology entities and temporal assertions through canonical graph boundaries."""

    async def project(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        projected_at: datetime,
    ) -> tuple[str, ...]:
        """Idempotently project all candidates and relations and return assertion identities."""
        ...


class ArtifactTopologyLineagePort(Protocol):
    """Register relation assertion evidence in branch-aware source lineage."""

    async def register(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        relation: TopologyRelationCandidate,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        """Append an exact relation/evidence/assertion dependency."""
        ...
