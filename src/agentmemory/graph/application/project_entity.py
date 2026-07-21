"""GRA-001 operation-scoped graph projection and exact query handlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.graph.domain.errors import GraphAuthorizationError
from agentmemory.graph.domain.models import GraphEntityQuery

if TYPE_CHECKING:
    from agentmemory.graph.domain.models import GraphEntity, GraphEntityType, GraphWriteResult
    from agentmemory.graph.domain.ports import ScopedGraphRepositoryFactory
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_ERR_ACTION = "graph scope action is not authorized"
_ERR_SCOPE = "graph projection is outside authorized scope"


@dataclass(frozen=True, slots=True)
class ProjectGraphEntityCommand:
    """Project one validated effective graph entity under worker authority."""

    scope: AuthorizedScope
    entity: GraphEntity


@dataclass(frozen=True, slots=True)
class ProjectGraphEntityHandler:
    """Open one scoped writer and execute the idempotent graph projection."""

    repositories: ScopedGraphRepositoryFactory

    async def execute(self, command: ProjectGraphEntityCommand) -> GraphWriteResult:
        """Reject scope drift before the graph adapter receives any data."""
        _authorize_entity(command.scope, command.entity, "graph.project")
        return await self.repositories.writer(command.scope).merge_entity(command.entity)


@dataclass(frozen=True, slots=True)
class GetGraphEntityQuery:
    """Public exact graph query with immutable authorization."""

    scope: AuthorizedScope
    entity_type: GraphEntityType
    entity_id: str


@dataclass(frozen=True, slots=True)
class GetGraphEntityHandler:
    """Open one scoped query capability without exposing arbitrary Cypher."""

    repositories: ScopedGraphRepositoryFactory

    async def execute(self, query: GetGraphEntityQuery) -> GraphEntity | None:
        """Execute one closed exact query within the caller's Brain scope."""
        if query.scope.action != "graph.read":
            raise GraphAuthorizationError(_ERR_ACTION)
        return await self.repositories.query(query.scope).get_entity(
            GraphEntityQuery(query.entity_type, query.entity_id)
        )


def _authorize_entity(scope: AuthorizedScope, entity: GraphEntity, action: str) -> None:
    if scope.action != action or entity.brain_id != scope.brain_id.value:
        raise GraphAuthorizationError(_ERR_SCOPE)
    member = next(
        (value for value in scope.members if value.project_id.value == entity.project_id),
        None,
    )
    if member is None or entity.repository_id not in {
        repository.value for repository in member.repository_ids
    }:
        raise GraphAuthorizationError(_ERR_SCOPE)
