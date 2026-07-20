"""Official-driver Neo4j schema probe and filtered semantic canary index."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

import neo4j
from neo4j import AsyncDriver, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.domain.dependency_ports import ActiveBrainPort, EmbeddingVector
    from agentmemory.operations.domain.readiness import ReadinessBinding

NEO4J_SCHEMA_HEAD = "0002_pf002_projection_schema"
VECTOR_INDEX_NAME = "am_pf001_vectors"
MINIMUM_NEO4J_VERSION = (2026, 6, 0)
EXPECTED_DRIVER_VERSION = "6.2.0"
_MAX_DATABASE_NAME_LENGTH = 63
_EMBEDDING_DIMENSION = 1024
_MINIMUM_VERSION_PARTS = 3

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
                "CYPHER 25 CALL dbms.components() YIELD versions RETURN versions[0] AS version",
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
