"""IDX-004 ports for topology plugins, persistence, and canonical assertions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.api_topology import (
        ApiTopologyCandidateBatch,
        ApiTopologyLinkDecision,
        ApiTopologyMatch,
        ClientCallCandidate,
        ContractBindingCandidate,
        EndpointCandidate,
        ServiceOwnershipCandidate,
    )


class ApiTopologyPluginPort(Protocol):
    """Extract one complete bounded candidate batch from a supported source artifact."""

    def supports(self, relative_path: str) -> bool:
        """Return whether this pinned plugin owns the artifact format."""
        ...

    def extract(self, artifact: object) -> ApiTopologyCandidateBatch:
        """Return deterministic candidates without persisting raw source."""
        ...


class ApiTopologyRepository(Protocol):
    """Persist immutable candidates, current source replacement, and link decisions."""

    async def find_batch_by_operation(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ApiTopologyCandidateBatch | None:
        """Resolve exact registration replay before caller-visible mutation."""
        ...

    async def register_batch(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ApiTopologyCandidateBatch,
        registered_at: datetime,
    ) -> ApiTopologyCandidateBatch:
        """Append or replay a complete source revision candidate batch."""
        ...

    async def load_link_universe(
        self,
        scope: AuthorizedScope,
        client_call_id: str,
        linked_at: datetime,
    ) -> tuple[
        ClientCallCandidate,
        tuple[EndpointCandidate, ...],
        tuple[ContractBindingCandidate, ...],
        tuple[ServiceOwnershipCandidate, ...],
    ]:
        """Load only authorized latest candidate batches across scope members."""
        ...

    async def find_link_decision(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ApiTopologyLinkDecision | None:
        """Return exact durable command replay if present."""
        ...

    async def record_link_decision(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        decision: ApiTopologyLinkDecision,
        assertion_ids: tuple[str, ...],
        linked_at: datetime,
    ) -> ApiTopologyLinkDecision:
        """Atomically append the complete decision and assertion receipts."""
        ...


class ConsumesAssertionPort(Protocol):
    """Materialize one qualified or authoritative canonical CONSUMES assertion."""

    async def record(
        self,
        scope: AuthorizedScope,
        match: ApiTopologyMatch,
        occurred_at: datetime,
    ) -> str:
        """Return the deterministic canonical assertion identity."""
        ...


class TopologyEvidenceLineagePort(Protocol):
    """Bind source revision contexts and semantic dependencies to assertion evidence."""

    async def register(  # noqa: PLR0913 -- Exact lineage coordinates are security-relevant.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        source_revision_context_id: str,
        source_semantic_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        """Append or replay exact reverse lineage for later branch-aware staleness."""
        ...
