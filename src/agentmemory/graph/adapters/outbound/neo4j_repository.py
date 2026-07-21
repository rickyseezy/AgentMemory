"""GRA-001 operation-scoped official-driver Neo4j repository."""

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
from agentmemory.graph.domain.models import GraphEntity, GraphWriteResult

if TYPE_CHECKING:
    from collections.abc import Sequence

    from neo4j import AsyncDriver

    from agentmemory.graph.domain.models import GraphEntityQuery, GraphRelationship
    from agentmemory.graph.domain.ports import AuthorizedGraphQuery, GraphProjectionWriter
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_MAX_DATABASE_NAME_LENGTH = 63
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_ACTIONS = frozenset({"graph.project", "graph.read"})
_ERR_DATABASE = "Neo4j database identity is invalid"
_ERR_ACTION = "graph scope action is not authorized"
_ERR_QUERY_CARDINALITY = "graph query returned invalid cardinality"
_ERR_QUERY_MALFORMED = "graph query returned malformed entity"
_ERR_QUERY_MISMATCH = "graph query returned mismatched entity"
_ERR_ENTITY_SCOPE = "graph entity is outside authorized scope"
_ERR_RELATIONSHIP_SCOPE = "graph relationship is outside authorized scope"
_ERR_CONFLICT = "stable graph identity already has another version"
_ERR_UNAVAILABLE = "graph storage is unavailable"
_ERR_WRITE_SCOPE = "graph write did not match its authorized scope"
_ERR_WRITE_EVIDENCE = "graph write returned malformed evidence"

_MERGE_ENTITY = """CYPHER 25
WITH $entity AS candidate
WHERE candidate.brain_id = $brain_id
  AND candidate.project_id IN $project_ids
  AND candidate.repository_id IN $repository_ids
  AND candidate.classification IN $classifications
MERGE (entity:GraphEntity:$($entity_label) {brain_id: $brain_id, id: $id})
ON CREATE SET entity += candidate, entity._created_by = $operation_nonce
WITH entity, candidate, coalesce(entity._created_by = $operation_nonce, false) AS created
REMOVE entity._created_by
RETURN properties(entity) AS entity,
       all(key IN keys(candidate) WHERE entity[key] = candidate[key])
         AND size(keys(entity)) = size(keys(candidate)) AS exact,
       created
"""

_MERGE_RELATIONSHIP = """CYPHER 25
MATCH (subject:GraphEntity {brain_id: $brain_id, id: $subject_id})
MATCH (object:GraphEntity {brain_id: $brain_id, id: $object_id})
WHERE subject.project_id IN $project_ids
  AND object.project_id IN $project_ids
  AND subject.repository_id IN $repository_ids
  AND object.repository_id IN $repository_ids
  AND subject.classification IN $classifications
  AND object.classification IN $classifications
WITH subject, object, $relationship AS candidate
WHERE candidate.brain_id = $brain_id
  AND candidate.project_id IN $project_ids
  AND candidate.repository_id IN $repository_ids
  AND candidate.classification IN $classifications
MERGE (subject)-[relationship:$($relationship_type) {brain_id: $brain_id, id: $id}]->(object)
ON CREATE SET relationship += candidate, relationship._created_by = $operation_nonce
WITH relationship, candidate,
     coalesce(relationship._created_by = $operation_nonce, false) AS created
REMOVE relationship._created_by
RETURN properties(relationship) AS relationship,
       all(key IN keys(candidate) WHERE relationship[key] = candidate[key])
         AND size(keys(relationship)) = size(keys(candidate)) AS exact,
       created
"""

_GET_ENTITY = """CYPHER 25
MATCH (entity:GraphEntity:$($entity_label))
WHERE entity.brain_id = $brain_id
  AND entity.id = $id
  AND entity.project_id IN $project_ids
  AND entity.repository_id IN $repository_ids
  AND (entity['checkout_id'] IS NULL OR size($checkout_ids) = 0
       OR entity['checkout_id'] IN $checkout_ids)
  AND entity.classification IN $classifications
RETURN properties(entity) AS entity
LIMIT 2
"""

GRAPH_QUERY_TEMPLATES = (_MERGE_ENTITY, _MERGE_RELATIONSHIP, _GET_ENTITY)


class Neo4jGraphRepository:
    """Bind every closed graph query to one immutable AuthorizedScope."""

    def __init__(self, driver: AsyncDriver, database: str, scope: AuthorizedScope) -> None:
        """Reject ambient database names and unsupported operation authority."""
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

    async def merge_entity(self, entity: GraphEntity) -> GraphWriteResult:
        """MERGE on constrained stable keys and reject divergent retries."""
        self._require_action("graph.project")
        self._require_entity_scope(entity)
        parameters = {
            **self._scope_parameters(),
            "id": entity.id,
            "entity_label": entity.entity_type.value,
            "entity": _persistence_document(entity.document()),
            "operation_nonce": self._scope.scope_fingerprint,
        }
        rows = await self._execute(_MERGE_ENTITY, parameters, RoutingControl.WRITE)
        return _write_result(rows, entity.id, entity.revision_id, "entity")

    async def merge_relationship(self, relationship: GraphRelationship) -> GraphWriteResult:
        """MERGE one closed relationship type after endpoint and scope matching."""
        self._require_action("graph.project")
        self._require_relationship_scope(relationship)
        parameters = {
            **self._scope_parameters(),
            "id": relationship.id,
            "subject_id": relationship.subject_id,
            "object_id": relationship.object_id,
            "relationship_type": relationship.relationship_type.value,
            "relationship": _persistence_document(relationship.document()),
            "operation_nonce": self._scope.scope_fingerprint,
        }
        rows = await self._execute(_MERGE_RELATIONSHIP, parameters, RoutingControl.WRITE)
        return _write_result(rows, relationship.id, relationship.revision_id, "relationship")

    async def get_entity(self, query: GraphEntityQuery) -> GraphEntity | None:
        """Return one exact entity after indexed scope filtering and defensive recheck."""
        self._require_action("graph.read")
        parameters = {
            **self._scope_parameters(),
            "id": query.entity_id,
            "entity_label": query.entity_type.value,
        }
        rows = await self._execute(_GET_ENTITY, parameters, RoutingControl.READ)
        if not rows:
            return None
        if len(rows) != 1:
            raise GraphIntegrityError(_ERR_QUERY_CARDINALITY)
        raw = rows[0].get("entity")
        if not isinstance(raw, Mapping):
            raise GraphIntegrityError(_ERR_QUERY_MALFORMED)
        try:
            entity = GraphEntity.from_document(
                _normalize_entity_document(cast("Mapping[str, object]", raw))
            )
        except GraphValidationError as error:
            raise GraphIntegrityError(_ERR_QUERY_MALFORMED) from error
        if entity.entity_type is not query.entity_type or entity.id != query.entity_id:
            raise GraphIntegrityError(_ERR_QUERY_MISMATCH)
        try:
            self._require_entity_scope(entity)
        except GraphAuthorizationError as error:
            raise GraphIntegrityError(_ERR_QUERY_MISMATCH) from error
        return entity

    def _require_action(self, expected: str) -> None:
        if self._scope.action != expected:
            raise GraphAuthorizationError(_ERR_ACTION)

    def _require_entity_scope(self, entity: GraphEntity) -> None:
        if entity.brain_id != self._scope.brain_id.value:
            raise GraphAuthorizationError(_ERR_ENTITY_SCOPE)
        member = next(
            (item for item in self._scope.members if item.project_id.value == entity.project_id),
            None,
        )
        repositories = () if member is None else member.repository_ids
        if member is None or entity.repository_id not in {item.value for item in repositories}:
            raise GraphAuthorizationError(_ERR_ENTITY_SCOPE)
        if (
            entity.checkout_id is not None
            and member.checkout_ids
            and entity.checkout_id not in {item.value for item in member.checkout_ids}
        ):
            raise GraphAuthorizationError(_ERR_ENTITY_SCOPE)
        if entity.classification.value not in self._allowed_classifications():
            raise GraphAuthorizationError(_ERR_ENTITY_SCOPE)

    def _require_relationship_scope(self, relationship: GraphRelationship) -> None:
        if relationship.brain_id != self._scope.brain_id.value:
            raise GraphAuthorizationError(_ERR_RELATIONSHIP_SCOPE)
        member = next(
            (
                item
                for item in self._scope.members
                if item.project_id.value == relationship.project_id
            ),
            None,
        )
        if member is None or relationship.repository_id not in {
            item.value for item in member.repository_ids
        }:
            raise GraphAuthorizationError(_ERR_RELATIONSHIP_SCOPE)
        if relationship.classification.value not in self._allowed_classifications():
            raise GraphAuthorizationError(_ERR_RELATIONSHIP_SCOPE)

    def _scope_parameters(self) -> dict[str, object]:
        return {
            "brain_id": self._scope.brain_id.value,
            "project_ids": [item.value for item in self._scope.project_ids],
            "repository_ids": [item.value for item in self._scope.repository_ids],
            "checkout_ids": [item.value for item in self._scope.checkout_ids],
            "classifications": list(self._allowed_classifications()),
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


class Neo4jGraphRepositoryFactory:
    """Create operation-scoped graph adapters from the shared immutable driver."""

    def __init__(self, driver: AsyncDriver, database: str) -> None:
        """Retain only process-safe immutable driver configuration."""
        self._driver = driver
        self._database = database

    def writer(self, scope: AuthorizedScope) -> GraphProjectionWriter:
        """Return a new scope-bound writer capability."""
        return Neo4jGraphRepository(self._driver, self._database, scope)

    def query(self, scope: AuthorizedScope) -> AuthorizedGraphQuery:
        """Return a new scope-bound exact-query capability."""
        return Neo4jGraphRepository(self._driver, self._database, scope)


def _write_result(
    rows: list[dict[str, object]],
    stable_id: str,
    revision_id: str,
    field: str,
) -> GraphWriteResult:
    if len(rows) != 1:
        raise GraphAuthorizationError(_ERR_WRITE_SCOPE)
    row = rows[0]
    raw = row.get(field)
    if not isinstance(raw, Mapping) or not isinstance(row.get("exact"), bool):
        raise GraphIntegrityError(_ERR_WRITE_EVIDENCE)
    document = cast("Mapping[str, object]", raw)
    if row["exact"] is not True or document.get("revision_id") != revision_id:
        raise GraphConflictError(_ERR_CONFLICT)
    created = row.get("created")
    if not isinstance(created, bool):
        raise GraphIntegrityError(_ERR_WRITE_EVIDENCE)
    return GraphWriteResult(stable_id, revision_id, created)


def _persistence_document(document: Mapping[str, object]) -> dict[str, object]:
    """Represent nullable Neo4j properties by absence, as required by Cypher."""
    return {key: value for key, value in document.items() if value is not None}


def _normalize_entity_document(document: Mapping[str, object]) -> dict[str, object]:
    """Restore nullable keys and convert official-driver temporal values to stdlib values."""
    normalized = dict(document)
    normalized.setdefault("checkout_id", None)
    normalized.setdefault("recorded_to", None)
    for key in ("created_at", "recorded_from", "recorded_to"):
        value = normalized[key]
        convert = getattr(value, "to_native", None)
        if callable(convert):
            normalized[key] = convert()
    return normalized
