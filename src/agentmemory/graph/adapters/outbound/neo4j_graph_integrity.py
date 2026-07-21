"""GRA-006 fixed-Cypher Neo4j migration, integrity scan, and repair adapter."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from neo4j import Query, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError

from agentmemory.graph.domain.errors import GraphIntegrityError, GraphUnavailableError
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityFinding,
    GraphIntegrityObservation,
    GraphMigrationBatch,
    GraphMigrationRun,
    GraphProjectionKind,
    GraphRepairAction,
    GraphRepairPlan,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from neo4j import AsyncDriver

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_MAX_SCAN = 10_000
_DATABASE_MAX = 63
_ERR_DATABASE = "graph integrity database identity is invalid"
_ERR_MIGRATION = "graph migration implementation is not registered"
_ERR_RESULT = "graph integrity query returned malformed evidence"
_ERR_UNAVAILABLE = "graph integrity dependency is unavailable"
_MIGRATION_ID = "gra006-integrity-v1"

_WATERMARK = """CYPHER 25
MATCH (projection)
WHERE projection.brain_id = $brain_id
  AND (projection:GraphEntity OR projection:Embedding)
  AND NOT projection:GraphMigrationShadow
RETURN count(projection) AS count
"""

_MIGRATE_BATCH = """CYPHER 25
MATCH (projection)
WHERE projection.brain_id = $brain_id
  AND (projection:GraphEntity OR projection:Embedding)
  AND NOT projection:GraphMigrationShadow
WITH projection ORDER BY projection.id SKIP $cursor LIMIT $batch_size
MERGE (shadow:GraphMigrationShadow {
  brain_id: $brain_id, migration_id: $migration_id, projection_id: projection.id
})
ON CREATE SET shadow.id = randomUUID(), shadow.migration_checksum = $migration_checksum,
              shadow.source_digest = coalesce(projection.projection_digest,
                                              projection.content_fingerprint,
                                              projection.revision_id),
              shadow.created_marker = $operation_id
WITH shadow, coalesce(shadow.created_marker = $operation_id, false) AS created
REMOVE shadow.created_marker
RETURN count(shadow) AS scanned, count(CASE WHEN created THEN 1 END) AS changed
"""

_VALIDATE_MIGRATION = """CYPHER 25
MATCH (shadow:GraphMigrationShadow {brain_id: $brain_id, migration_id: $migration_id})
RETURN count(shadow) AS count,
       count(CASE WHEN shadow.migration_checksum = $migration_checksum THEN 1 END) AS exact
"""

_SCAN = """CYPHER 25
CALL {
  MATCH (projection:Assertion)
  WHERE projection.brain_id = $brain_id AND projection.generation_id IS NOT NULL
    AND projection.project_id IN $project_ids AND projection.repository_id IN $repository_ids
  OPTIONAL MATCH (projection)-[:SUPPORTED_BY]->(evidence:Evidence)
  WITH projection, count(evidence) AS evidence_count
  RETURN projection.id AS projection_id, 'assertion' AS projection_kind,
         projection.brain_id AS brain_id, projection.project_id AS project_id,
         projection.repository_id AS repository_id, projection.id AS canonical_id,
         evidence_count > 0 AS canonical_supported,
         (projection.valid_to IS NULL OR projection.valid_to > projection.valid_from)
           AND (projection.recorded_to IS NULL OR projection.recorded_to > projection.recorded_from)
           AS temporal_valid,
         true AS scope_matches, projection.generation_id AS generation_id,
         projection.projection_digest AS projection_digest
  UNION ALL
  MATCH (source)-[projection]->(target)
  WHERE projection.brain_id = $brain_id AND projection.generation_id IS NOT NULL
    AND projection.project_id IN $project_ids AND projection.repository_id IN $repository_ids
  OPTIONAL MATCH (assertion:Assertion {brain_id: $brain_id, id: projection.assertion_id})
  RETURN projection.id AS projection_id, 'edge' AS projection_kind,
         projection.brain_id AS brain_id, projection.project_id AS project_id,
         projection.repository_id AS repository_id, projection.assertion_id AS canonical_id,
         assertion IS NOT NULL AS canonical_supported,
         (projection.valid_to IS NULL OR projection.valid_to > projection.valid_from)
           AND (projection.recorded_to IS NULL OR projection.recorded_to > projection.recorded_from)
           AS temporal_valid,
         source.brain_id = projection.brain_id AND target.brain_id = projection.brain_id
           AND source.project_id = projection.project_id
           AND target.project_id = projection.project_id AS scope_matches,
         projection.generation_id AS generation_id,
         projection.projection_digest AS projection_digest
  UNION ALL
  MATCH (projection:Embedding)
  WHERE projection.brain_id = $brain_id AND projection.generation_id IS NOT NULL
    AND projection.project_id IN $project_ids AND projection.repository_id IN $repository_ids
  OPTIONAL MATCH (canonical {brain_id: $brain_id, id: projection.source_id})
  RETURN projection.id AS projection_id, 'vector' AS projection_kind,
         projection.brain_id AS brain_id, projection.project_id AS project_id,
         projection.repository_id AS repository_id, projection.source_id AS canonical_id,
         canonical IS NOT NULL AS canonical_supported, true AS temporal_valid,
         canonical IS NULL OR (canonical.project_id = projection.project_id
           AND canonical.repository_id = projection.repository_id) AS scope_matches,
         projection.generation_id AS generation_id,
         projection.projection_digest AS projection_digest
}
RETURN projection_id, projection_kind, brain_id, project_id, repository_id, canonical_id,
       canonical_supported, temporal_valid, scope_matches, generation_id, projection_digest
ORDER BY projection_id LIMIT $limit
"""

_SHADOW_REPAIR = """CYPHER 25
MERGE (shadow:GraphRepairShadow {brain_id: $brain_id, finding_id: $finding_id})
ON CREATE SET shadow.id = randomUUID(), shadow.projection_id = $projection_id,
              shadow.action = $action, shadow.projection_digest = $projection_digest,
              shadow.repaired_at = $repaired_at
RETURN count(shadow) AS count
"""

_QUARANTINE_EDGE = """CYPHER 25
MATCH ()-[projection]->()
WHERE projection.brain_id = $brain_id AND projection.id = $projection_id
  AND projection.project_id IN $project_ids AND projection.repository_id IN $repository_ids
SET projection.quarantined = true, projection.quarantine_reason = $finding_id
RETURN count(projection) AS count
"""

_QUARANTINE_NODE = """CYPHER 25
MATCH (projection)
WHERE projection.brain_id = $brain_id AND projection.id = $projection_id
  AND projection.project_id IN $project_ids AND projection.repository_id IN $repository_ids
SET projection.quarantined = true, projection.quarantine_reason = $finding_id
RETURN count(projection) AS count
"""

GRAPH_INTEGRITY_QUERIES = (
    _WATERMARK,
    _MIGRATE_BATCH,
    _VALIDATE_MIGRATION,
    _SCAN,
    _SHADOW_REPAIR,
    _QUARANTINE_EDGE,
    _QUARANTINE_NODE,
)
REGISTERED_GRAPH_MIGRATION_CHECKSUM = hashlib.sha256(
    f"{_MIGRATE_BATCH}\n{_VALIDATE_MIGRATION}".encode()
).hexdigest()


class Neo4jGraphIntegrityAdapter:
    """Operate on authorized derived graph state without dynamic Cypher identifiers."""

    def __init__(self, driver: AsyncDriver, database: str) -> None:
        """Bind the official async driver and a validated static database name."""
        if not database or len(database) > _DATABASE_MAX or not database.replace("_", "").isalnum():
            raise ValueError(_ERR_DATABASE)
        self._driver = driver
        self._database = database

    async def source_watermark(
        self, scope: AuthorizedScope, migration_id: str, migration_checksum: str
    ) -> int:
        """Count the fixed source set for the registered migration."""
        _require_migration(migration_id, migration_checksum)
        rows = await self._execute(_WATERMARK, _scope(scope), RoutingControl.READ)
        return _one_count(rows)

    async def apply_batch(
        self, scope: AuthorizedScope, run: GraphMigrationRun
    ) -> GraphMigrationBatch:
        """MERGE one shadow batch so replay never duplicates effective state."""
        _require_migration(run.migration_id, run.migration_checksum)
        if run.brain_id != scope.brain_id.value:
            raise GraphIntegrityError(_ERR_RESULT)
        rows = await self._execute(
            _MIGRATE_BATCH,
            {
                **_scope(scope),
                "cursor": run.cursor,
                "batch_size": run.batch_size,
                "migration_id": run.migration_id,
                "migration_checksum": run.migration_checksum,
                "operation_id": run.operation_id,
            },
            RoutingControl.WRITE,
        )
        row = _one(rows)
        scanned = _integer(row, "scanned")
        changed = _integer(row, "changed")
        if scanned < 1:
            raise GraphIntegrityError(_ERR_RESULT)
        return GraphMigrationBatch(
            min(run.cursor + scanned, run.source_watermark), scanned, changed, 0
        )

    async def validate(self, scope: AuthorizedScope, run: GraphMigrationRun) -> bool:
        """Require one exact checksum-bound shadow per source projection."""
        _require_migration(run.migration_id, run.migration_checksum)
        if run.brain_id != scope.brain_id.value:
            raise GraphIntegrityError(_ERR_RESULT)
        rows = await self._execute(
            _VALIDATE_MIGRATION,
            {
                **_scope(scope),
                "migration_id": run.migration_id,
                "migration_checksum": run.migration_checksum,
            },
            RoutingControl.READ,
        )
        row = _one(rows)
        return _integer(row, "count") == run.source_watermark == _integer(row, "exact")

    async def scan(self, scope: AuthorizedScope) -> tuple[GraphIntegrityObservation, ...]:
        """Return bounded content-free metadata for all managed edges and vectors."""
        rows = await self._execute(
            _SCAN, {**_scope(scope), "limit": _MAX_SCAN + 1}, RoutingControl.READ
        )
        if len(rows) > _MAX_SCAN:
            raise GraphIntegrityError(_ERR_RESULT)
        try:
            observations = tuple(_observation(row) for row in rows)
        except (KeyError, TypeError, ValueError) as error:
            raise GraphIntegrityError(_ERR_RESULT) from error
        if any(not _observation_in_scope(scope, item) for item in observations):
            raise GraphIntegrityError(_ERR_RESULT)
        return observations

    async def execute(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        plan: GraphRepairPlan,
        repaired_at: datetime,
    ) -> None:
        """Write a shadow repair or quarantine; never delete graph or canonical history."""
        if not _finding_in_scope(scope, finding):
            raise GraphIntegrityError(_ERR_RESULT)
        if plan.action is GraphRepairAction.DESTRUCTIVE_REBUILD:
            raise GraphIntegrityError(_ERR_RESULT)
        if plan.action is GraphRepairAction.SHADOW_WRITE:
            query = _SHADOW_REPAIR
        elif finding.projection_kind is GraphProjectionKind.EDGE:
            query = _QUARANTINE_EDGE
        else:
            query = _QUARANTINE_NODE
        rows = await self._execute(
            query,
            {
                **_scope(scope),
                "finding_id": finding.id,
                "projection_id": finding.projection_id,
                "projection_digest": finding.projection_digest,
                "action": plan.action.value,
                "repaired_at": repaired_at,
            },
            RoutingControl.WRITE,
        )
        if _one_count(rows) != 1:
            raise GraphIntegrityError(_ERR_RESULT)

    async def _execute(
        self, query: str, parameters: Mapping[str, object], routing: RoutingControl
    ) -> list[dict[str, object]]:
        try:
            result = await self._driver.execute_query(
                Query(query),  # pyright: ignore[reportArgumentType]
                parameters_=dict(parameters),
                database_=self._database,
                routing_=routing,
            )
        except (DriverError, Neo4jError) as error:
            raise GraphUnavailableError(_ERR_UNAVAILABLE) from error
        records = cast("Sequence[Mapping[str, object]]", result[0])
        return [dict(record) for record in records]


def _scope(scope: AuthorizedScope) -> dict[str, object]:
    return {
        "brain_id": scope.brain_id.value,
        "project_ids": [item.value for item in scope.project_ids],
        "repository_ids": [item.value for item in scope.repository_ids],
    }


def _observation_in_scope(scope: AuthorizedScope, observation: GraphIntegrityObservation) -> bool:
    return (
        observation.brain_id == scope.brain_id.value
        and observation.project_id in {item.value for item in scope.project_ids}
        and observation.repository_id in {item.value for item in scope.repository_ids}
    )


def _finding_in_scope(scope: AuthorizedScope, finding: GraphIntegrityFinding) -> bool:
    return (
        finding.brain_id == scope.brain_id.value
        and finding.project_id in {item.value for item in scope.project_ids}
        and finding.repository_id in {item.value for item in scope.repository_ids}
    )


def _require_migration(migration_id: str, checksum: str) -> None:
    if migration_id != _MIGRATION_ID or checksum != REGISTERED_GRAPH_MIGRATION_CHECKSUM:
        raise GraphIntegrityError(_ERR_MIGRATION)


def _one(rows: list[dict[str, object]]) -> dict[str, object]:
    if len(rows) != 1:
        raise GraphIntegrityError(_ERR_RESULT)
    return rows[0]


def _one_count(rows: list[dict[str, object]]) -> int:
    return _integer(_one(rows), "count")


def _integer(row: Mapping[str, object], key: str) -> int:
    value = row.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GraphIntegrityError(_ERR_RESULT)
    return value


def _observation(row: Mapping[str, object]) -> GraphIntegrityObservation:
    canonical = row["canonical_id"]
    return GraphIntegrityObservation(
        projection_id=str(row["projection_id"]),
        projection_kind=GraphProjectionKind(str(row["projection_kind"])),
        brain_id=str(row["brain_id"]),
        project_id=str(row["project_id"]),
        repository_id=str(row["repository_id"]),
        canonical_id=None if canonical is None else str(canonical),
        canonical_supported=_boolean(row, "canonical_supported"),
        temporal_valid=_boolean(row, "temporal_valid"),
        scope_matches=_boolean(row, "scope_matches"),
        generation_id=str(row["generation_id"]),
        projection_digest=str(row["projection_digest"]),
    )


def _boolean(row: Mapping[str, object], key: str) -> bool:
    value = row.get(key)
    if not isinstance(value, bool):
        raise GraphIntegrityError(_ERR_RESULT)
    return value
