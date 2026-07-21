"""GRA-003 scoped Neo4j materialized-edge projection and traversal adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

from neo4j import Query, RoutingControl
from neo4j.exceptions import ConstraintError, DriverError, Neo4jError

from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
    GraphValidationError,
)
from agentmemory.graph.domain.materialized_edges import (
    MaterializedAssertionEdge,
    MaterializedEdgeWriteResult,
    ProjectionEdgeStatus,
    TraversalEdgeExplanation,
)
from agentmemory.graph.domain.models import GraphRelationshipType

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from neo4j import AsyncDriver

    from agentmemory.graph.domain.materialized_edge_ports import MaterializedEdgeProjection
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_MAX_DATABASE_NAME_LENGTH = 63
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_ACTIONS = frozenset(
    {
        "graph.assertion.materialize",
        "graph.assertion.edge.integrity",
        "graph.assertion.traverse",
    }
)
_MATERIALIZED_TYPES = tuple(
    item.value
    for item in (
        GraphRelationshipType.CALLS,
        GraphRelationshipType.IMPORTS,
        GraphRelationshipType.CONSUMES,
        GraphRelationshipType.IMPLEMENTS,
        GraphRelationshipType.DEPENDS_ON,
        GraphRelationshipType.PRODUCES,
        GraphRelationshipType.DEPLOYED_AS,
    )
)
_ERR_ACTION = "materialized edge scope action is not authorized"
_ERR_CONFLICT = "materialized edge projection conflicts with canonical state"
_ERR_DATABASE = "Neo4j database identity is invalid"
_ERR_INTEGRITY = "materialized edge projection returned malformed evidence"
_ERR_SCOPE = "materialized assertion edge is outside authorized scope"
_ERR_UNAVAILABLE = "materialized edge storage is unavailable"

_PROJECT_ACTIVE = """CYPHER 25
// gra003:project-active
MATCH (subject:GraphEntity {brain_id: $brain_id, id: $subject_id})
MATCH (object:GraphEntity {brain_id: $brain_id, id: $object_id})
WHERE subject.project_id IN $project_ids AND object.project_id IN $project_ids
  AND subject.repository_id IN $repository_ids AND object.repository_id IN $repository_ids
  AND subject.classification IN $classifications AND object.classification IN $classifications
WITH subject, object, $edge AS candidate
MERGE (subject)-[edge:$($relationship_type) {
  brain_id: $brain_id, id: $edge_id
}]->(object)
ON CREATE SET edge._created_by = $operation_nonce
WITH edge, candidate, coalesce(edge._created_by = $operation_nonce, false) AS created,
     edge.aggregate_version IS NULL
       OR edge.aggregate_version < candidate.aggregate_version
       OR (edge.aggregate_version = candidate.aggregate_version
           AND (edge.projection_digest = candidate.projection_digest OR $allow_repair)) AS apply
FOREACH (_ IN CASE WHEN apply THEN [1] ELSE [] END | SET edge = candidate)
REMOVE edge._created_by
RETURN properties(edge) AS edge, apply AS applied, created
"""

_PROJECT_RETIRED = """CYPHER 25
// gra003:project-retired
OPTIONAL MATCH ()-[edge]->()
WHERE type(edge) = $relationship_type
  AND edge.brain_id = $brain_id AND edge.assertion_id = $assertion_id
  AND edge.generation_id = $edge.generation_id
  AND edge.project_id IN $project_ids AND edge.repository_id IN $repository_ids
  AND edge.classification IN $classifications
WITH edge, $edge AS candidate,
     edge IS NOT NULL AND (edge.aggregate_version < candidate.aggregate_version
       OR (edge.aggregate_version = candidate.aggregate_version
           AND (edge.projection_digest = candidate.projection_digest OR $allow_repair))) AS apply
FOREACH (_ IN CASE WHEN apply THEN [1] ELSE [] END | SET edge = candidate)
RETURN CASE WHEN edge IS NULL THEN NULL ELSE properties(edge) END AS edge,
       apply AS applied, false AS created
"""

_LIST_EDGES = """CYPHER 25
// gra003:list
MATCH (subject:GraphEntity)-[edge]->(object:GraphEntity)
WHERE type(edge) IN $materialized_types
  AND edge.brain_id = $brain_id AND edge.generation_id = $generation_id
  AND edge.project_id IN $project_ids AND edge.repository_id IN $repository_ids
  AND (edge.checkout_id IS NULL OR size($checkout_ids) = 0 OR edge.checkout_id IN $checkout_ids)
  AND edge.classification IN $classifications
  AND subject.brain_id = $brain_id AND object.brain_id = $brain_id
RETURN properties(edge) AS edge, type(edge) AS actual_relationship_type
ORDER BY edge.assertion_id
"""

_QUARANTINE_EDGE = """CYPHER 25
// gra003:quarantine
MATCH ()-[edge]->()
WHERE type(edge) IN $materialized_types
  AND edge.brain_id = $brain_id AND edge.assertion_id = $assertion_id
  AND edge.generation_id = $generation_id
  AND edge.project_id IN $project_ids AND edge.repository_id IN $repository_ids
  AND edge.classification IN $classifications
SET edge.quarantined = true, edge.quarantine_reason = $reason,
    edge.quarantined_at = $quarantined_at
RETURN count(edge) AS changed
"""

_TRAVERSE = """CYPHER 25
// gra003:traverse
MATCH (subject:GraphEntity {brain_id: $brain_id, id: $subject_id})-[edge]->
      (object:GraphEntity {brain_id: $brain_id})
WHERE type(edge) IN $relationship_types
  AND edge.brain_id = $brain_id AND edge.generation_id = $generation_id
  AND edge.projection_status = 'active' AND edge.quarantined = false
  AND edge.recorded_to IS NULL
  AND edge.project_id IN $project_ids AND edge.repository_id IN $repository_ids
  AND (edge.checkout_id IS NULL OR size($checkout_ids) = 0 OR edge.checkout_id IN $checkout_ids)
  AND edge.classification IN $classifications
  AND object.project_id IN $project_ids AND object.repository_id IN $repository_ids
  AND object.classification IN $classifications
RETURN properties(edge) AS edge, type(edge) AS actual_relationship_type
ORDER BY edge.relationship_type, edge.object_id, edge.assertion_id
LIMIT $limit
"""

EDGE_QUERY_TEMPLATES = (
    _PROJECT_ACTIVE,
    _PROJECT_RETIRED,
    _LIST_EDGES,
    _QUARANTINE_EDGE,
    _TRAVERSE,
)


class Neo4jMaterializedEdgeProjection:
    """Bind every materialized-edge operation to one immutable AuthorizedScope."""

    def __init__(self, driver: AsyncDriver, database: str, scope: AuthorizedScope) -> None:
        """Reject ambient database names and unrecognized capabilities."""
        if (
            not database
            or len(database) > _MAX_DATABASE_NAME_LENGTH
            or not database.replace("_", "").isalnum()
        ):
            raise ValueError(_ERR_DATABASE)
        if scope.action not in _ACTIONS:
            raise GraphAuthorizationError(_ERR_ACTION)
        self._driver = driver
        self._database = database
        self._scope = scope

    async def project(self, edge: MaterializedAssertionEdge) -> MaterializedEdgeWriteResult:
        """Apply one exact same/newer canonical version or reject a divergent retry."""
        self._require_action({"graph.assertion.materialize", "graph.assertion.edge.integrity"})
        self._require_scope(edge)
        parameters = {
            **self._scope_parameters(),
            "assertion_id": edge.assertion_id,
            "edge_id": edge.id,
            "subject_id": edge.subject_id,
            "object_id": edge.object_id,
            "relationship_type": edge.relationship_type.value,
            "edge": _persistence_document(edge.document()),
            "operation_nonce": self._scope.scope_fingerprint,
            "allow_repair": self._scope.action == "graph.assertion.edge.integrity",
        }
        query = (
            _PROJECT_ACTIVE
            if edge.projection_status is ProjectionEdgeStatus.ACTIVE
            else _PROJECT_RETIRED
        )
        rows = await self._execute(query, parameters, RoutingControl.WRITE)
        if not rows and edge.projection_status is ProjectionEdgeStatus.RETIRED:
            return MaterializedEdgeWriteResult(
                assertion_id=edge.assertion_id,
                projection_digest=edge.projection_digest,
                applied=False,
                created=False,
            )
        return _write_result(rows, edge)

    async def list_edges(self, generation_id: str) -> tuple[MaterializedAssertionEdge, ...]:
        """Return scoped managed edges after defensive document validation."""
        self._require_action({"graph.assertion.edge.integrity"})
        rows = await self._execute(
            _LIST_EDGES,
            {**self._scope_parameters(), "generation_id": generation_id},
            RoutingControl.READ,
        )
        edges = tuple(_decode_edge(row) for row in rows)
        for edge in edges:
            self._require_scope(edge)
            if edge.generation_id != generation_id:
                raise GraphIntegrityError(_ERR_INTEGRITY)
        return edges

    async def quarantine(
        self,
        assertion_id: str,
        generation_id: str,
        reason: str,
        at: datetime,
    ) -> None:
        """Mark exactly one scoped edge non-retrievable without deleting it."""
        self._require_action({"graph.assertion.edge.integrity"})
        rows = await self._execute(
            _QUARANTINE_EDGE,
            {
                **self._scope_parameters(),
                "assertion_id": assertion_id,
                "generation_id": generation_id,
                "reason": reason,
                "quarantined_at": at,
            },
            RoutingControl.WRITE,
        )
        if len(rows) != 1 or not isinstance(rows[0].get("changed"), int):
            raise GraphIntegrityError(_ERR_INTEGRITY)
        if rows[0]["changed"] != 1:
            raise GraphConflictError(_ERR_CONFLICT)

    async def traverse(
        self,
        subject_id: str,
        relationship_types: tuple[GraphRelationshipType, ...],
        generation_id: str,
        limit: int,
    ) -> tuple[TraversalEdgeExplanation, ...]:
        """Return only active, non-quarantined edges with authority pointers."""
        self._require_action({"graph.assertion.traverse"})
        rows = await self._execute(
            _TRAVERSE,
            {
                **self._scope_parameters(),
                "subject_id": subject_id,
                "relationship_types": [item.value for item in relationship_types],
                "generation_id": generation_id,
                "limit": limit,
            },
            RoutingControl.READ,
        )
        edges = tuple(_decode_edge(row) for row in rows)
        explanations: list[TraversalEdgeExplanation] = []
        for edge in edges:
            self._require_scope(edge)
            if (
                edge.subject_id != subject_id
                or edge.relationship_type not in relationship_types
                or edge.generation_id != generation_id
                or not edge.retrieval_visible
            ):
                raise GraphIntegrityError(_ERR_INTEGRITY)
            explanations.append(TraversalEdgeExplanation.from_edge(edge))
        return tuple(explanations)

    def _require_action(self, allowed: set[str]) -> None:
        if self._scope.action not in allowed:
            raise GraphAuthorizationError(_ERR_ACTION)

    def _require_scope(self, edge: MaterializedAssertionEdge) -> None:
        member = next(
            (item for item in self._scope.members if item.project_id.value == edge.project_id),
            None,
        )
        if (
            edge.brain_id != self._scope.brain_id.value
            or member is None
            or edge.repository_id not in {item.value for item in member.repository_ids}
            or (
                edge.checkout_id is not None
                and member.checkout_ids
                and edge.checkout_id not in {item.value for item in member.checkout_ids}
            )
            or edge.classification.value not in self._allowed_classifications()
        ):
            raise GraphAuthorizationError(_ERR_SCOPE)

    def _scope_parameters(self) -> dict[str, object]:
        return {
            "brain_id": self._scope.brain_id.value,
            "project_ids": [item.value for item in self._scope.project_ids],
            "repository_ids": [item.value for item in self._scope.repository_ids],
            "checkout_ids": [item.value for item in self._scope.checkout_ids],
            "classifications": list(self._allowed_classifications()),
            "materialized_types": list(_MATERIALIZED_TYPES),
        }

    def _allowed_classifications(self) -> tuple[str, ...]:
        ceiling = _CLASSIFICATIONS.index(self._scope.classification_ceiling.value)
        return _CLASSIFICATIONS[: ceiling + 1]

    async def _execute(
        self,
        query: str,
        parameters: Mapping[str, object],
        routing: RoutingControl,
    ) -> list[dict[str, object]]:
        try:
            result = await self._driver.execute_query(
                Query(query),  # pyright: ignore[reportArgumentType]
                parameters_=dict(parameters),
                database_=self._database,
                routing_=routing,
            )
        except ConstraintError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except (DriverError, Neo4jError) as error:
            raise GraphUnavailableError(_ERR_UNAVAILABLE) from error
        records = cast("Sequence[Mapping[str, object]]", result[0])
        return [dict(record) for record in records]


class Neo4jMaterializedEdgeProjectionFactory:
    """Create operation-scoped GRA-003 projection capabilities."""

    def __init__(self, driver: AsyncDriver, database: str) -> None:
        """Retain only shared immutable Neo4j driver configuration."""
        self._driver = driver
        self._database = database

    def projection(self, scope: AuthorizedScope) -> MaterializedEdgeProjection:
        """Return a fresh scope-bound projection capability."""
        return Neo4jMaterializedEdgeProjection(self._driver, self._database, scope)


def _write_result(
    rows: list[dict[str, object]], edge: MaterializedAssertionEdge
) -> MaterializedEdgeWriteResult:
    if len(rows) != 1:
        raise GraphUnavailableError(_ERR_UNAVAILABLE)
    row = rows[0]
    raw = row.get("edge")
    applied = row.get("applied")
    created = row.get("created")
    if raw is None and edge.projection_status is ProjectionEdgeStatus.RETIRED:
        return MaterializedEdgeWriteResult(
            assertion_id=edge.assertion_id,
            projection_digest=edge.projection_digest,
            applied=False,
            created=False,
        )
    if (
        not isinstance(raw, Mapping)
        or not isinstance(applied, bool)
        or not isinstance(created, bool)
    ):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    current = _decode_document(cast("Mapping[str, object]", raw))
    if current.assertion_id != edge.assertion_id:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    if current.projection_digest != edge.projection_digest:
        raise GraphConflictError(_ERR_CONFLICT)
    return MaterializedEdgeWriteResult(edge.assertion_id, edge.projection_digest, applied, created)


def _decode_edge(row: Mapping[str, object]) -> MaterializedAssertionEdge:
    raw = row.get("edge")
    actual_relationship_type = row.get("actual_relationship_type")
    if not isinstance(raw, Mapping) or not isinstance(actual_relationship_type, str):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    edge = _decode_document(cast("Mapping[str, object]", raw))
    if edge.relationship_type.value != actual_relationship_type:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return edge


def _decode_document(document: Mapping[str, object]) -> MaterializedAssertionEdge:
    normalized = dict(document)
    normalized.setdefault("checkout_id", None)
    normalized.setdefault("valid_to", None)
    normalized.setdefault("recorded_to", None)
    normalized.setdefault("quarantine_reason", None)
    if normalized.get("created_at") != normalized.get("recorded_from") or normalized.get(
        "revision_id"
    ) != normalized.get("assertion_revision_id"):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    try:
        return MaterializedAssertionEdge.from_document(normalized)
    except GraphValidationError as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


def _persistence_document(document: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in document.items() if value is not None}
