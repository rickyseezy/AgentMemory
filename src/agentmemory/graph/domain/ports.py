"""Capability-specific ports owned by the graph bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.graph.domain.models import (
        GraphEntity,
        GraphEntityQuery,
        GraphRelationship,
        GraphWriteResult,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


class GraphProjectionWriter(Protocol):
    """Write validated graph projections idempotently."""

    async def merge_entity(self, entity: GraphEntity) -> GraphWriteResult:
        """Create one effective stable entity/version or verify an exact retry."""
        ...

    async def merge_relationship(self, relationship: GraphRelationship) -> GraphWriteResult:
        """Create one effective typed relationship/version or verify an exact retry."""
        ...


class AuthorizedGraphQuery(Protocol):
    """Run closed query objects within one immutable authorization scope."""

    async def get_entity(self, query: GraphEntityQuery) -> GraphEntity | None:
        """Return one exact authorized graph entity without accepting raw Cypher."""
        ...


class ScopedGraphRepositoryFactory(Protocol):
    """Create a new operation-scoped graph capability from an AuthorizedScope."""

    def writer(self, scope: AuthorizedScope) -> GraphProjectionWriter:
        """Bind a projection writer to one immutable scope."""
        ...

    def query(self, scope: AuthorizedScope) -> AuthorizedGraphQuery:
        """Bind a query capability to one immutable scope."""
        ...
