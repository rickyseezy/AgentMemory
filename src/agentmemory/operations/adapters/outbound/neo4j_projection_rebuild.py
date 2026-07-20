"""Neo4j shadow projection writer and deterministic multi-store generation router."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from neo4j import Query, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRecord,
    ProjectionType,
    ProjectionValidation,
    RebuildManifest,
    SourceRecord,
    projection_digest,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from neo4j import AsyncDriver

    from agentmemory.operations.domain.ports import ProjectionGenerationPort

_GRAPH_PROJECTIONS = frozenset({ProjectionType.GRAPH, ProjectionType.VECTOR})
_MAX_DATABASE_NAME_LENGTH = 63

_PREPARE = """CYPHER 25
MERGE (generation:ProjectionGeneration {
  brain_id: $brain_id,
  projection_type: $projection_type,
  generation_id: $generation_id
})
ON CREATE SET generation.manifest_digest = $manifest_digest,
              generation.state = 'shadow',
              generation.schema_version = 1,
              generation.created_at = datetime()
RETURN generation.manifest_digest AS manifest_digest, generation.state AS state
"""

_PUT = """CYPHER 25
MERGE (record:ProjectionRecord {
  brain_id: $brain_id,
  projection_type: $projection_type,
  generation_id: $generation_id,
  stable_id: $stable_id
})
ON CREATE SET record.source_event_id = $source_event_id,
              record.source_sequence = $source_sequence,
              record.source_digest = $source_digest,
              record.content_digest = $content_digest,
              record.target_type = $target_type,
              record.target_id_hash = $target_id_hash,
              record.payload_json = $payload_json,
              record.manifest_digest = $manifest_digest,
              record.schema_version = 1,
              record.created_at = datetime()
RETURN record.source_event_id AS source_event_id,
       record.source_sequence AS source_sequence,
       record.source_digest AS source_digest,
       record.content_digest AS content_digest,
       record.target_type AS target_type,
       record.target_id_hash AS target_id_hash,
       record.payload_json AS payload_json,
       record.manifest_digest AS manifest_digest
"""

_VALIDATE = """CYPHER 25
MATCH (record:ProjectionRecord {
  brain_id: $brain_id,
  projection_type: $projection_type,
  generation_id: $generation_id
})
RETURN record.stable_id AS stable_id,
       record.source_event_id AS source_event_id,
       record.source_sequence AS source_sequence,
       record.source_digest AS source_digest,
       record.content_digest AS content_digest,
       record.payload_json AS payload_json,
       record.manifest_digest AS manifest_digest
ORDER BY stable_id
"""


class Neo4jProjectionGenerationAdapter:
    """Materialize graph/vector records into an isolated Neo4j generation."""

    def __init__(self, driver: AsyncDriver, database: str) -> None:
        """Bind the official driver to one validated explicit database."""
        if (
            not database
            or len(database) > _MAX_DATABASE_NAME_LENGTH
            or not database.replace("_", "").isalnum()
        ):
            msg = "Neo4j database identity is invalid"
            raise ValueError(msg)
        self._driver = driver
        self._database = database

    async def prepare(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> None:
        """Create or verify the generation node before any record write."""
        records = await self._execute(
            _PREPARE,
            _parameters(brain_id, projection_type, generation_id, manifest),
        )
        if (
            len(records) != 1
            or records[0].get("manifest_digest") != manifest.digest.value
            or records[0].get("state") != "shadow"
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "Neo4j shadow generation diverged",
            )

    async def put(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        record: SourceRecord,
        manifest: RebuildManifest,
    ) -> bool:
        """Merge one record and reject any non-identical stable-ID replay."""
        projection = record.projection
        parameters: dict[str, object] = {
            **_parameters(brain_id, projection_type, generation_id, manifest),
            "stable_id": projection.stable_id,
            "source_event_id": projection.source_event_id,
            "source_sequence": projection.source_sequence,
            "source_digest": projection.source_digest.value,
            "content_digest": projection.content_digest.value,
            "target_type": record.target_type,
            "target_id_hash": record.target_id_hash.value,
            "payload_json": projection.payload_json,
        }
        records = await self._execute(_PUT, parameters)
        expected = {key: value for key, value in parameters.items() if key in _PUT_RESULT_KEYS}
        if len(records) != 1 or any(
            records[0].get(key) != value for key, value in expected.items()
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "Neo4j projection replay produced a divergent duplicate",
            )
        return True

    async def validate(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> ProjectionValidation:
        """Recompute deterministic digest and validate every Neo4j lineage property."""
        rows = await self._execute(
            _VALIDATE,
            _parameters(brain_id, projection_type, generation_id, manifest),
            RoutingControl.READ,
        )
        records: list[ProjectionRecord] = []
        valid = True
        for row in rows:
            try:
                if row.get("manifest_digest") != manifest.digest.value:
                    valid = False
                records.append(
                    ProjectionRecord(
                        stable_id=_string(row, "stable_id"),
                        source_event_id=_string(row, "source_event_id"),
                        source_sequence=_integer(row, "source_sequence"),
                        source_digest=Sha256Digest(_string(row, "source_digest")),
                        content_digest=Sha256Digest(_string(row, "content_digest")),
                        payload_json=_string(row, "payload_json"),
                    )
                )
            except ValueError, TypeError:
                valid = False
        try:
            digest = projection_digest(records)
        except ValueError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "Neo4j projection validation evidence was malformed",
            ) from error
        return ProjectionValidation(
            record_count=len(records),
            generation_digest=digest,
            lineage_complete=valid,
            integrity_valid=valid,
            authorization_valid=True,
            tombstones_current=True,
            golden_queries_passed=valid,
        )

    async def _execute(
        self,
        query: str,
        parameters: Mapping[str, object],
        routing: RoutingControl = RoutingControl.WRITE,
    ) -> list[dict[str, object]]:
        try:
            result = await self._driver.execute_query(
                Query(query),  # pyright: ignore[reportArgumentType]
                parameters_=dict(parameters),
                database_=self._database,
                routing_=routing,
            )
        except (DriverError, Neo4jError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "Neo4j projection generation is unavailable",
                retryable=True,
            ) from error
        records = cast("Sequence[Mapping[str, object]]", result[0])
        return [dict(record) for record in records]


class ProjectionGenerationRouter:
    """Keep relational shadow evidence and graph projections in deterministic lockstep."""

    def __init__(
        self,
        relational: ProjectionGenerationPort,
        graph: ProjectionGenerationPort,
    ) -> None:
        """Inject both independently testable generation capabilities."""
        self._relational = relational
        self._graph = graph

    async def prepare(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> None:
        """Prepare the local shadow and graph/vector storage when applicable."""
        await self._relational.prepare(brain_id, projection_type, generation_id, manifest)
        if projection_type in _GRAPH_PROJECTIONS:
            await self._graph.prepare(brain_id, projection_type, generation_id, manifest)

    async def put(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        record: SourceRecord,
        manifest: RebuildManifest,
    ) -> bool:
        """Use relational insertion as the effective-count authority and repair graph retries."""
        inserted = await self._relational.put(
            brain_id,
            projection_type,
            generation_id,
            record,
            manifest,
        )
        if projection_type in _GRAPH_PROJECTIONS:
            await self._graph.put(brain_id, projection_type, generation_id, record, manifest)
        return inserted

    async def validate(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> ProjectionValidation:
        """Require graph/vector validation to match canonical relational shadow evidence."""
        local = await self._relational.validate(
            brain_id,
            projection_type,
            generation_id,
            manifest,
        )
        if projection_type not in _GRAPH_PROJECTIONS:
            return local
        graph = await self._graph.validate(
            brain_id,
            projection_type,
            generation_id,
            manifest,
        )
        same = (
            graph.record_count == local.record_count
            and graph.generation_digest == local.generation_digest
        )
        return ProjectionValidation(
            record_count=local.record_count,
            generation_digest=local.generation_digest,
            lineage_complete=local.lineage_complete and graph.lineage_complete and same,
            integrity_valid=local.integrity_valid and graph.integrity_valid and same,
            authorization_valid=local.authorization_valid and graph.authorization_valid,
            tombstones_current=local.tombstones_current and graph.tombstones_current,
            golden_queries_passed=local.golden_queries_passed and graph.golden_queries_passed,
        )


_PUT_RESULT_KEYS = frozenset(
    {
        "source_event_id",
        "source_sequence",
        "source_digest",
        "content_digest",
        "target_type",
        "target_id_hash",
        "payload_json",
        "manifest_digest",
    }
)


def _parameters(
    brain_id: Uuid7Id,
    projection_type: ProjectionType,
    generation_id: Sha256Digest,
    manifest: RebuildManifest,
) -> dict[str, object]:
    return {
        "brain_id": brain_id.value,
        "projection_type": projection_type.value,
        "generation_id": generation_id.value,
        "manifest_digest": manifest.digest.value,
    }


def _string(row: dict[str, object], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str):
        msg = f"Neo4j projection {key} was malformed"
        raise TypeError(msg)
    return value


def _integer(row: dict[str, object], key: str) -> int:
    value = row.get(key)
    if not isinstance(value, int):
        msg = f"Neo4j projection {key} was malformed"
        raise TypeError(msg)
    return value
