"""Official-driver Neo4j schema probe and filtered semantic canary index."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, cast

import neo4j
from neo4j import AsyncDriver, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.domain.dependency_ports import ActiveBrainPort, EmbeddingVector
    from agentmemory.operations.domain.readiness import ReadinessBinding

NEO4J_SCHEMA_HEAD = "0003_gra001_brain_scoped_schema"
VECTOR_INDEX_NAME = "am_pf001_vectors"
MINIMUM_NEO4J_VERSION = (2026, 6, 0)
EXPECTED_DRIVER_VERSION = "6.2.0"
_MAX_DATABASE_NAME_LENGTH = 63
_EMBEDDING_DIMENSION = 1024
_MINIMUM_VERSION_PARTS = 3
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_UUID7_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_DIGEST_PATTERN = "^[0-9a-f]{64}$"

GRA001_CONSTRAINT_NAMES = (
    "am_graph_entity_identity",
    "am_brain_identity",
    "am_project_identity",
    "am_repository_identity",
    "am_checkout_identity",
    "am_branch_identity",
    "am_commit_identity",
    "am_agent_identity",
    "am_session_identity",
    "am_task_identity",
    "am_turn_identity",
    "am_event_identity",
    "am_artifact_identity",
    "am_file_identity",
    "am_file_revision_identity",
    "am_symbol_identity",
    "am_symbol_revision_identity",
    "am_package_identity",
    "am_service_identity",
    "am_endpoint_identity",
    "am_contract_identity",
    "am_dependency_identity",
    "am_environment_identity",
    "am_memory_identity",
    "am_decision_identity",
    "am_constraint_identity",
    "am_preference_identity",
    "am_procedure_identity",
    "am_lesson_identity",
    "am_failure_identity",
    "am_outcome_identity",
    "am_assertion_identity",
    "am_evidence_identity",
    "am_contradiction_identity",
    "am_causal_hypothesis_identity",
    "am_evaluation_identity",
    "am_procedure_revision_identity",
    "am_deployment_identity",
    "am_embedding_space_identity",
    "am_index_generation_identity",
    "am_vector_record_identity",
    "am_subject_of_identity",
    "am_object_of_identity",
    "am_supported_by_identity",
    "am_contradicted_by_identity",
    "am_invalidated_by_identity",
    "am_calls_identity",
    "am_imports_identity",
    "am_consumes_identity",
    "am_implements_identity",
    "am_depends_on_identity",
    "am_produces_identity",
    "am_deployed_as_identity",
)

_GRAPH_ENTITY_TYPES = (
    "Brain",
    "Project",
    "Repository",
    "Checkout",
    "Branch",
    "Commit",
    "Agent",
    "Session",
    "Task",
    "Turn",
    "Event",
    "Artifact",
    "File",
    "FileRevision",
    "Symbol",
    "SymbolRevision",
    "Package",
    "Service",
    "Endpoint",
    "Contract",
    "Dependency",
    "Environment",
    "Memory",
    "Decision",
    "Constraint",
    "Preference",
    "Procedure",
    "Lesson",
    "Failure",
    "Outcome",
    "Assertion",
    "Evidence",
    "Contradiction",
    "CausalHypothesis",
    "Evaluation",
    "ProcedureRevision",
    "Deployment",
    "EmbeddingSpace",
    "IndexGeneration",
    "VectorRecord",
)
_GRAPH_RELATIONSHIP_TYPES = (
    "SUBJECT_OF",
    "OBJECT_OF",
    "SUPPORTED_BY",
    "CONTRADICTED_BY",
    "INVALIDATED_BY",
    "CALLS",
    "IMPORTS",
    "CONSUMES",
    "IMPLEMENTS",
    "DEPENDS_ON",
    "PRODUCES",
    "DEPLOYED_AS",
)
_GLOBAL_GRAPH_ENTITY_TYPES = ("Brain", "EmbeddingSpace", "IndexGeneration")

_GRAPH_ENTITY_INTEGRITY_QUERY = """CYPHER 25
MATCH (entity:GraphEntity)
WHERE NOT (entity.id IS :: STRING NOT NULL)
   OR NOT entity.id =~ $uuid7_pattern
   OR NOT (entity.brain_id IS :: STRING NOT NULL)
   OR NOT entity.brain_id =~ $uuid7_pattern
   OR NOT (entity.entity_type IS :: STRING NOT NULL)
   OR NOT entity.entity_type IN $entity_types
   OR NOT entity.entity_type IN labels(entity)
   OR NOT (entity.project_id IS NULL
           OR (entity.project_id IS :: STRING NOT NULL
               AND entity.project_id =~ $uuid7_pattern))
   OR NOT (entity.repository_id IS NULL
           OR (entity.repository_id IS :: STRING NOT NULL
               AND entity.repository_id =~ $uuid7_pattern))
   OR NOT (entity.checkout_id IS NULL
           OR (entity.checkout_id IS :: STRING NOT NULL
               AND entity.checkout_id =~ $uuid7_pattern))
   OR (entity.entity_type IN $global_entity_types
       AND (entity.project_id IS NOT NULL
            OR entity.repository_id IS NOT NULL
            OR entity.checkout_id IS NOT NULL))
   OR (NOT entity.entity_type IN $global_entity_types AND entity.project_id IS NULL)
   OR (entity.entity_type = 'Project'
       AND (entity.project_id <> entity.id OR entity.repository_id IS NOT NULL))
   OR (NOT entity.entity_type IN $global_entity_types
       AND entity.entity_type <> 'Project'
       AND entity.repository_id IS NULL)
   OR (entity.entity_type = 'Repository' AND entity.repository_id <> entity.id)
   OR (entity.entity_type = 'Checkout' AND entity.checkout_id <> entity.id)
   OR NOT (entity.schema_version IS :: INTEGER NOT NULL)
   OR entity.schema_version < 1
   OR NOT (entity.created_at IS :: ZONED DATETIME NOT NULL)
   OR NOT (entity.recorded_from IS :: ZONED DATETIME NOT NULL)
   OR entity.created_at > entity.recorded_from
   OR NOT (entity.recorded_to IS NULL OR entity.recorded_to IS :: ZONED DATETIME NOT NULL)
   OR (entity.recorded_to IS NOT NULL AND entity.recorded_to <= entity.recorded_from)
   OR NOT (entity.classification IS :: STRING NOT NULL)
   OR NOT entity.classification IN $classifications
   OR NOT (entity.content_fingerprint IS :: STRING NOT NULL)
   OR NOT entity.content_fingerprint =~ $digest_pattern
   OR entity.content_fingerprint = $zero_digest
   OR NOT (entity.revision_id IS :: STRING NOT NULL)
   OR NOT entity.revision_id =~ $digest_pattern
RETURN count(entity) AS invalid
"""

_GRAPH_RELATIONSHIP_INTEGRITY_QUERY = """CYPHER 25
MATCH (subject)-[relationship]->(object)
WHERE type(relationship) IN $relationship_types
  AND (NOT subject:GraphEntity
    OR NOT object:GraphEntity
    OR NOT (relationship.id IS :: STRING NOT NULL)
    OR NOT relationship.id =~ $uuid7_pattern
    OR NOT (relationship.brain_id IS :: STRING NOT NULL)
    OR NOT relationship.brain_id =~ $uuid7_pattern
    OR relationship.brain_id <> subject.brain_id
    OR relationship.brain_id <> object.brain_id
    OR NOT (relationship.relationship_type IS :: STRING NOT NULL)
    OR relationship.relationship_type <> type(relationship)
    OR NOT (relationship.subject_id IS :: STRING NOT NULL)
    OR relationship.subject_id <> subject.id
    OR NOT (relationship.object_id IS :: STRING NOT NULL)
    OR relationship.object_id <> object.id
    OR relationship.subject_id = relationship.object_id
    OR NOT (relationship.project_id IS :: STRING NOT NULL)
    OR NOT relationship.project_id =~ $uuid7_pattern
    OR NOT (relationship.repository_id IS :: STRING NOT NULL)
    OR NOT relationship.repository_id =~ $uuid7_pattern
    OR NOT (relationship.schema_version IS :: INTEGER NOT NULL)
    OR relationship.schema_version < 1
    OR NOT (relationship.created_at IS :: ZONED DATETIME NOT NULL)
    OR NOT (relationship.recorded_from IS :: ZONED DATETIME NOT NULL)
    OR relationship.created_at > relationship.recorded_from
    OR NOT (relationship.recorded_to IS NULL
            OR relationship.recorded_to IS :: ZONED DATETIME NOT NULL)
    OR (relationship.recorded_to IS NOT NULL
        AND relationship.recorded_to <= relationship.recorded_from)
    OR NOT (relationship.classification IS :: STRING NOT NULL)
    OR NOT relationship.classification IN $classifications
    OR NOT (relationship.content_fingerprint IS :: STRING NOT NULL)
    OR NOT relationship.content_fingerprint =~ $digest_pattern
    OR relationship.content_fingerprint = $zero_digest
    OR NOT (relationship.revision_id IS :: STRING NOT NULL)
    OR NOT relationship.revision_id =~ $digest_pattern)
RETURN count(relationship) AS invalid
"""

_SEARCH_QUERY = f"""CYPHER 25
MATCH (record:VectorRecord)
SEARCH record IN (
  VECTOR INDEX {VECTOR_INDEX_NAME}
  FOR $query_vector
  WHERE record.brain_id = $brain_id
    AND record.generation_id = $generation_id
    AND record.classification = 'internal'
    AND record.status = 'active'
  LIMIT 5
) SCORE AS score
RETURN record.id AS id, score
ORDER BY score DESC, id ASC
"""


class Neo4jGraphAdapter:
    """Use parameterized Cypher 25 against one explicit application database."""

    def __init__(self, driver: AsyncDriver, database: str, brains: ActiveBrainPort) -> None:
        """Bind the driver to a validated database and exact local Brain."""
        if (
            not database
            or len(database) > _MAX_DATABASE_NAME_LENGTH
            or not database.replace("_", "").isalnum()
        ):
            msg = "Neo4j database identity is invalid"
            raise ValueError(msg)
        self._driver = driver
        self._database = database
        self._brains = brains

    async def verify(self, binding: ReadinessBinding) -> str:
        """Verify driver/server/schema/vector-index compatibility and generation binding."""
        del binding
        if neo4j.__version__ != EXPECTED_DRIVER_VERSION:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "Neo4j driver version is not certified"
            )
        try:
            # The official Neo4j 6.2 stub leaves this method's **config untyped.
            await self._driver.verify_connectivity()  # pyright: ignore[reportUnknownMemberType]
            component_records, _, _ = await self._driver.execute_query(
                "CYPHER 25 CALL dbms.components() YIELD name, versions "
                "WHERE name = 'Neo4j Kernel' RETURN versions[0] AS version",
                database_=self._database,
                routing_=RoutingControl.READ,
            )
            schema_records, _, _ = await self._driver.execute_query(
                "CYPHER 25 MATCH (schema:AgentMemorySchema "
                "{brain_id: 'installation', id: 'singleton'}) RETURN schema.version AS version",
                database_=self._database,
                routing_=RoutingControl.READ,
            )
            index_records, _, _ = await self._driver.execute_query(
                "CYPHER 25 SHOW VECTOR INDEXES YIELD name, state, indexProvider, properties "
                "WHERE name = $name RETURN state, indexProvider, properties",
                name=VECTOR_INDEX_NAME,
                database_=self._database,
                routing_=RoutingControl.READ,
            )
            constraint_records, _, _ = await self._driver.execute_query(
                "CYPHER 25 SHOW CONSTRAINTS YIELD name WHERE name IN $names "
                "RETURN collect(name) AS names",
                names=list(GRA001_CONSTRAINT_NAMES),
                database_=self._database,
                routing_=RoutingControl.READ,
            )
            entity_integrity_records, _, _ = await self._driver.execute_query(
                _GRAPH_ENTITY_INTEGRITY_QUERY,
                entity_types=list(_GRAPH_ENTITY_TYPES),
                global_entity_types=list(_GLOBAL_GRAPH_ENTITY_TYPES),
                classifications=list(_CLASSIFICATIONS),
                uuid7_pattern=_UUID7_PATTERN,
                digest_pattern=_DIGEST_PATTERN,
                zero_digest="0" * 64,
                database_=self._database,
                routing_=RoutingControl.READ,
            )
            relationship_integrity_records, _, _ = await self._driver.execute_query(
                _GRAPH_RELATIONSHIP_INTEGRITY_QUERY,
                relationship_types=list(_GRAPH_RELATIONSHIP_TYPES),
                classifications=list(_CLASSIFICATIONS),
                uuid7_pattern=_UUID7_PATTERN,
                digest_pattern=_DIGEST_PATTERN,
                zero_digest="0" * 64,
                database_=self._database,
                routing_=RoutingControl.READ,
            )
        except (DriverError, Neo4jError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "Neo4j schema compatibility could not be verified",
                retryable=True,
            ) from error
        if len(component_records) != 1 or len(schema_records) != 1 or len(index_records) != 1:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "Neo4j readiness metadata is incomplete"
            )
        if len(constraint_records) != 1 or set(constraint_records[0].get("names", ())) != set(
            GRA001_CONSTRAINT_NAMES
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "Neo4j graph constraints are incomplete"
            )
        if not _integrity_count_is_zero(entity_integrity_records) or not _integrity_count_is_zero(
            relationship_integrity_records
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "Neo4j graph records failed schema integrity"
            )
        server_version = str(component_records[0]["version"])
        if _version_tuple(server_version) < MINIMUM_NEO4J_VERSION:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE, "Neo4j server version is not certified"
            )
        if schema_records[0]["version"] != NEO4J_SCHEMA_HEAD:
            raise OperationError(ErrorCode.CONFLICT, "Neo4j schema migration head is not active")
        index = index_records[0]
        properties: object = index["properties"]
        expected_properties = [
            "embedding",
            "brain_id",
            "generation_id",
            "classification",
            "status",
        ]
        if (
            index["state"] != "ONLINE"
            or index["indexProvider"] != "vector-2026.06"
            or not isinstance(properties, Sequence)
            or list(cast("Sequence[object]", properties)) != expected_properties
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "Neo4j vector index is not certified"
            )
        return f"neo4j:{server_version}:driver:{neo4j.__version__}:schema:{NEO4J_SCHEMA_HEAD}"

    async def index(
        self,
        binding: ReadinessBinding,
        canary_id: str,
        source_digest: str,
        vector: EmbeddingVector,
    ) -> None:
        """Write one immutable-generation canary with exact source lineage."""
        if len(vector.values) != _EMBEDDING_DIMENSION:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "semantic canary vector dimension is invalid"
            )
        brain_id = await self._brains.get()
        try:
            await self._driver.execute_query(
                "CYPHER 25 MERGE (record:VectorRecord {brain_id: $brain_id, id: $id}) "
                "ON CREATE SET record.entity_type = 'readiness_canary', record.schema_version = 1, "
                "record.created_at = datetime(), record.recorded_from = datetime() "
                "SET record.generation_id = $generation_id, record.source_digest = $source_digest, "
                "record.classification = 'internal', record.status = 'active', "
                "record.embedding = $embedding, record.recorded_to = null",
                brain_id=brain_id.value,
                id=canary_id,
                generation_id=binding.generation_id.value,
                source_digest=source_digest,
                embedding=list(vector.values),
                database_=self._database,
            )
        except (DriverError, Neo4jError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "semantic canary could not be indexed",
                retryable=True,
            ) from error

    async def recall(
        self,
        binding: ReadinessBinding,
        query_vector: EmbeddingVector,
        expected_canary_id: str,
    ) -> tuple[str, ...]:
        """Use pre-filtered Cypher 25 SEARCH inside the exact Brain/generation."""
        del expected_canary_id
        brain_id = await self._brains.get()
        try:
            records, _, _ = await self._driver.execute_query(
                _SEARCH_QUERY,
                query_vector=list(query_vector.values),
                brain_id=brain_id.value,
                generation_id=binding.generation_id.value,
                database_=self._database,
                routing_=RoutingControl.READ,
            )
        except (DriverError, Neo4jError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "semantic canary recall is unavailable",
                retryable=True,
            ) from error
        identifiers = tuple(record["id"] for record in records)
        if any(not isinstance(identifier, str) for identifier in identifiers):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "semantic recall returned invalid IDs"
            )
        return identifiers

    async def delete(self, binding: ReadinessBinding, canary_id: str) -> None:
        """Delete only this Brain/generation's synthetic readiness projection."""
        brain_id = await self._brains.get()
        try:
            await self._driver.execute_query(
                "CYPHER 25 MATCH (record:VectorRecord {brain_id: $brain_id, id: $id, "
                "generation_id: $generation_id}) DELETE record",
                brain_id=brain_id.value,
                id=canary_id,
                generation_id=binding.generation_id.value,
                database_=self._database,
            )
        except (DriverError, Neo4jError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "semantic canary cleanup is unavailable",
                retryable=True,
            ) from error


def _version_tuple(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) < _MINIMUM_VERSION_PARTS:
        return (0, 0, 0)
    try:
        return int(parts[0]), int(parts[1]), int(parts[2].split("-")[0])
    except ValueError:
        return (0, 0, 0)


def _integrity_count_is_zero(records: Sequence[object]) -> bool:
    if len(records) != 1 or not isinstance(records[0], Mapping):
        return False
    invalid = cast("Mapping[str, object]", records[0]).get("invalid")
    return isinstance(invalid, int) and not isinstance(invalid, bool) and invalid == 0
