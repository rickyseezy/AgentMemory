"""PRO-004 Neo4j provisioner and atomic vector-write repository."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, LiteralString, cast

from neo4j import Query
from neo4j.exceptions import DriverError, Neo4jError

from agentmemory.providers.domain.embedding_space_ports import VectorWriteReceipt
from agentmemory.providers.domain.embedding_spaces import VectorWriteBatch
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
)

if TYPE_CHECKING:
    from neo4j import AsyncDriver, AsyncManagedTransaction

    from agentmemory.providers.domain.embedding_spaces import EmbeddingSpace, IndexGeneration
    from agentmemory.shared.clock import Clock

_MAX_DATABASE_NAME_LENGTH = 63
_ERR_DATABASE = "Neo4j database identity is invalid"
_ERR_PHYSICAL = "embedding physical index contract conflicts with existing graph state"
_ERR_GRAPH = "embedding graph storage is unavailable"
_ERR_BINDING = "vector generation binding is invalid"
_ERR_SOURCE = "vector source content is stale or unavailable"
_ERR_EXISTING = "existing vector conflicts with immutable content"
_ERR_CARDINALITY = "vector write cardinality is invalid"
_INDEX_QUANTIZATION = "none"

_ENSURE_METADATA = """CYPHER 25
MERGE (space:GraphEntity:EmbeddingSpace {brain_id: $brain_id, id: $space_id})
ON CREATE SET space.entity_type='EmbeddingSpace',
              space.schema_version=1,
              space.created_at=$created_at,
              space.recorded_from=$created_at,
              space.recorded_to=NULL,
              space.classification='internal',
              space.content_fingerprint=$fingerprint,
              space.revision_id=$fingerprint,
              space.immutable_fingerprint=$fingerprint,
              space.dimension=$dimension,
              space.similarity=$similarity
MERGE (generation:GraphEntity:IndexGeneration {brain_id: $brain_id, id: $generation_id})
ON CREATE SET generation.entity_type='IndexGeneration',
              generation.schema_version=1,
              generation.created_at=$created_at,
              generation.recorded_from=$created_at,
              generation.recorded_to=NULL,
              generation.classification='internal',
              generation.content_fingerprint=$generation_fingerprint,
              generation.revision_id=$generation_fingerprint,
              generation.space_id=$space_id,
              generation.space_fingerprint=$fingerprint,
              generation.generated_label=$generated_label,
              generation.vector_index_name=$vector_index_name,
              generation.vector_property='embedding',
              generation.dimension=$dimension,
              generation.similarity=$similarity,
              generation.state='creating'
RETURN space.immutable_fingerprint AS immutable_fingerprint,
       space.id AS space_id,
       generation.id AS generation_id,
       generation.generated_label AS generated_label,
       generation.vector_index_name AS vector_index_name,
       generation.dimension AS dimension,
       generation.similarity AS similarity
"""

_SHOW_INDEX = """CYPHER 25
SHOW VECTOR INDEXES
YIELD name, state, labelsOrTypes, properties, options
WHERE name=$index_name
RETURN name, state, labelsOrTypes, properties, options
"""

_MARK_POPULATING = """CYPHER 25
MATCH (generation:IndexGeneration {brain_id: $brain_id, id: $generation_id})
WHERE generation.space_id=$space_id
  AND generation.space_fingerprint=$fingerprint
  AND generation.generated_label=$generated_label
  AND generation.vector_index_name=$vector_index_name
  AND generation.dimension=$dimension
  AND generation.similarity=$similarity
  AND generation.state IN ['creating','populating']
SET generation.state='populating'
RETURN generation.state AS state
"""

_BINDING_PREFLIGHT = """CYPHER 25
MATCH (space:EmbeddingSpace {brain_id: $brain_id, id: $space_id})
MATCH (generation:IndexGeneration {brain_id: $brain_id, id: $generation_id})
WHERE space.immutable_fingerprint=$space_fingerprint
  AND generation.space_id=$space_id
  AND generation.space_fingerprint=$space_fingerprint
  AND generation.generated_label=$generated_label
  AND generation.vector_index_name=$vector_index_name
  AND generation.dimension=$dimension
  AND generation.similarity=$similarity
  AND generation.state IN ['populating','shadow_ready','active']
RETURN count(generation) AS binding_count
"""

_SOURCE_PREFLIGHT = """CYPHER 25
UNWIND $records AS record
MATCH (source:GraphEntity {brain_id: $brain_id, id: record.source_entity_id})
WHERE source.content_fingerprint=record.source_content_hash
  AND source.project_id=record.project_id
  AND source.repository_id=record.repository_id
  AND (source.checkout_id IS NULL OR source.checkout_id=record.checkout_id)
  AND source.classification=record.classification
RETURN count(source) AS source_count
"""

_EXISTING_PREFLIGHT = """CYPHER 25
UNWIND $records AS record
OPTIONAL MATCH (vector:VectorRecord {brain_id: $brain_id, id: record.record_id})
WITH record, vector
WHERE vector IS NULL
   OR (vector.source_entity_id=record.source_entity_id
       AND vector.source_content_hash=record.source_content_hash
       AND vector.project_id=record.project_id
       AND vector.repository_id=record.repository_id
       AND ((vector.checkout_id IS NULL AND record.checkout_id IS NULL)
            OR vector.checkout_id=record.checkout_id)
       AND vector.classification=record.classification
       AND vector.space_id=$space_id
       AND vector.space_fingerprint=$space_fingerprint
       AND vector.generation_id=$generation_id
       AND vector.provider_profile_id=record.provider_profile_id
       AND vector.idempotency_key=record.idempotency_key
       AND vector.dimension=$dimension
       AND vector.dtype=$dtype
       AND vector.normalization=$normalization
       AND vector.similarity=$similarity
       AND vector.purpose=$purpose
       AND vector.status='active'
       AND vector.embedding=record.vector)
RETURN count(record) AS compatible_count
"""


class Neo4jIndexGenerationProvisioner:
    """Create and prove one UUID-derived vector index without user identifiers."""

    def __init__(self, driver: AsyncDriver, database: str) -> None:
        """Bind the official driver to one closed local database."""
        _validate_database(database)
        self._driver = driver
        self._database = database

    async def ensure(self, space: EmbeddingSpace, generation: IndexGeneration) -> None:
        """Idempotently provision exact metadata, DDL, online state, and writability."""
        parameters = _generation_parameters(space, generation)
        try:
            rows, _, _ = await self._driver.execute_query(
                _ENSURE_METADATA,
                **parameters,
                database_=self._database,
            )
            if len(rows) != 1 or not _metadata_exact(rows[0], parameters):
                _physical_conflict()
            await self._driver.execute_query(
                # UUID-derived identifiers and closed numeric enums are validated by domain.
                Query(_create_vector_index(generation)),  # pyright: ignore[reportArgumentType]
                database_=self._database,
            )
            await self._driver.execute_query(
                "CYPHER 25 CALL db.awaitIndex($index_name, 300)",
                index_name=generation.names.vector_index,
                database_=self._database,
            )
            rows, _, _ = await self._driver.execute_query(
                _SHOW_INDEX,
                index_name=generation.names.vector_index,
                generated_label=generation.names.label,
                dimension=generation.dimension,
                similarity=generation.similarity,
                database_=self._database,
            )
            if len(rows) != 1 or not _index_exact(rows[0], generation):
                _physical_conflict()
            rows, _, _ = await self._driver.execute_query(
                _MARK_POPULATING,
                **parameters,
                database_=self._database,
            )
            if len(rows) != 1 or rows[0].get("state") != "populating":
                _physical_conflict()
        except EmbeddingSpaceConflictError:
            raise
        except (DriverError, Neo4jError) as error:
            raise EmbeddingSpaceDependencyError(_ERR_GRAPH) from error
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingSpaceConflictError(_ERR_PHYSICAL) from error


class Neo4jVectorWriteRepository:
    """Revalidate and commit one vector batch in one managed transaction."""

    def __init__(self, driver: AsyncDriver, database: str, clock: Clock) -> None:
        """Bind driver, database, and explicit receipt clock."""
        _validate_database(database)
        self._driver = driver
        self._database = database
        self._clock = clock

    async def write(self, batch: VectorWriteBatch) -> VectorWriteReceipt:
        """Roll back the entire batch on any binding, source, or content mismatch."""
        validated = VectorWriteBatch.create(batch.space, batch.generation, batch.records)
        parameters = _write_parameters(validated)
        query = _write_query(validated.generation.names.label)
        try:
            session_context = self._driver.session(  # pyright: ignore[reportUnknownMemberType]
                database=self._database
            )
            async with session_context as session:
                await session.execute_write(
                    _write_transaction,
                    validated,
                    parameters,
                    query,
                )
        except EmbeddingSpaceConflictError:
            raise
        except (DriverError, Neo4jError) as error:
            raise EmbeddingSpaceDependencyError(_ERR_GRAPH) from error
        return VectorWriteReceipt(
            generation_id=validated.generation.generation_id,
            space_fingerprint=validated.space.immutable_fingerprint,
            record_count=len(validated.records),
            batch_digest=validated.batch_digest,
            committed_at=self._clock.now(),
        )


async def _write_transaction(
    transaction: AsyncManagedTransaction,
    batch: VectorWriteBatch,
    parameters: dict[str, Any],
    write_query: str,
) -> None:
    await _require_count(
        transaction,
        _BINDING_PREFLIGHT,
        parameters,
        "binding_count",
        1,
        _ERR_BINDING,
    )
    expected = len(batch.records)
    await _require_count(
        transaction,
        _SOURCE_PREFLIGHT,
        parameters,
        "source_count",
        expected,
        _ERR_SOURCE,
    )
    await _require_count(
        transaction,
        _EXISTING_PREFLIGHT,
        parameters,
        "compatible_count",
        expected,
        _ERR_EXISTING,
    )
    await _require_count(
        transaction,
        write_query,
        parameters,
        "written_count",
        expected,
        _ERR_CARDINALITY,
    )


async def _require_count(  # noqa: PLR0913 -- Query cardinality assertion coordinates.
    transaction: AsyncManagedTransaction,
    query: str,
    parameters: dict[str, Any],
    key: str,
    expected: int,
    message: str,
) -> None:
    # Dynamic text contains only a UUID-derived label already validated by domain.
    trusted_query: LiteralString = query  # pyright: ignore[reportAssignmentType]
    result = await transaction.run(trusted_query, **parameters)
    row = await result.single(strict=True)
    if row.get(key) != expected:
        raise EmbeddingSpaceConflictError(message)


def _generation_parameters(
    space: EmbeddingSpace,
    generation: IndexGeneration,
) -> dict[str, Any]:
    generation_authority = (
        f"{generation.brain_id}|{generation.generation_id}|"
        f"{space.immutable_fingerprint}|{generation.dimension}|{generation.similarity}"
    )
    return {
        "brain_id": generation.brain_id,
        "created_at": generation.created_at,
        "dimension": generation.dimension,
        "fingerprint": space.immutable_fingerprint,
        "generated_label": generation.names.label,
        "generation_fingerprint": hashlib.sha256(generation_authority.encode()).hexdigest(),
        "generation_id": generation.generation_id,
        "similarity": generation.similarity,
        "space_id": space.space_id,
        "vector_index_name": generation.names.vector_index,
    }


def _metadata_exact(
    row: Mapping[str, object],
    parameters: Mapping[str, object],
) -> bool:
    expected = {
        "immutable_fingerprint": parameters["fingerprint"],
        "space_id": parameters["space_id"],
        "generation_id": parameters["generation_id"],
        "generated_label": parameters["generated_label"],
        "vector_index_name": parameters["vector_index_name"],
        "dimension": parameters["dimension"],
        "similarity": parameters["similarity"],
    }
    return all(row.get(key) == value for key, value in expected.items())


def _index_exact(
    row: Mapping[str, object],
    generation: IndexGeneration,
) -> bool:
    options = row.get("options")
    if not isinstance(options, Mapping):
        return False
    typed_options = cast("Mapping[str, object]", options)
    config = typed_options.get("indexConfig")
    if not isinstance(config, Mapping):
        return False
    typed_config = cast("Mapping[str, object]", config)
    return (
        row.get("name") == generation.names.vector_index
        and row.get("state") == "ONLINE"
        and row.get("labelsOrTypes") == [generation.names.label]
        and row.get("properties") == [generation.names.vector_property]
        and typed_config.get("vector.dimensions") == generation.dimension
        and _normalized_config(typed_config, "vector.similarity_function") == generation.similarity
        and _normalized_config(typed_config, "vector.quantization.type") == _INDEX_QUANTIZATION
    )


def _create_vector_index(generation: IndexGeneration) -> str:
    return f"""CYPHER 25
CREATE VECTOR INDEX {generation.names.vector_index} IF NOT EXISTS
FOR (record:{generation.names.label})
ON record.{generation.names.vector_property}
OPTIONS {{indexConfig: {{
  `vector.dimensions`: {generation.dimension},
  `vector.similarity_function`: '{generation.similarity}',
  `vector.quantization.type`: '{_INDEX_QUANTIZATION}'
}}}}
"""


def _normalized_config(config: Mapping[str, object], key: str) -> str | None:
    value = config.get(key)
    return value.lower() if isinstance(value, str) else None


def _write_parameters(batch: VectorWriteBatch) -> dict[str, Any]:
    descriptor = batch.space.descriptor
    return {
        "brain_id": batch.generation.brain_id,
        "dimension": descriptor.dimension,
        "dtype": descriptor.dtype.value,
        "generated_label": batch.generation.names.label,
        "generation_id": batch.generation.generation_id,
        "normalization": descriptor.normalization.value,
        "purpose": descriptor.purpose.value,
        "records": [
            {
                "checkout_id": record.checkout_id,
                "classification": record.classification,
                "embedded_at": record.embedded_at,
                "idempotency_key": record.idempotency_key,
                "project_id": record.project_id,
                "provider_profile_id": record.provider_profile_id,
                "record_id": record.record_id,
                "repository_id": record.repository_id,
                "source_content_hash": record.source_content_hash,
                "source_entity_id": record.source_entity_id,
                "vector": list(record.vector),
            }
            for record in batch.records
        ],
        "similarity": descriptor.similarity,
        "space_fingerprint": batch.space.immutable_fingerprint,
        "space_id": batch.space.space_id,
        "vector_index_name": batch.generation.names.vector_index,
    }


def _write_query(label: str) -> str:
    return f"""CYPHER 25
UNWIND $records AS record
MATCH (source:GraphEntity {{brain_id: $brain_id, id: record.source_entity_id}})
WHERE source.content_fingerprint=record.source_content_hash
  AND source.project_id=record.project_id
  AND source.repository_id=record.repository_id
  AND (source.checkout_id IS NULL OR source.checkout_id=record.checkout_id)
  AND source.classification=record.classification
MERGE (vector:GraphEntity:VectorRecord:{label} {{
  brain_id: $brain_id,
  id: record.record_id
}})
ON CREATE SET vector.entity_type='VectorRecord',
              vector.project_id=record.project_id,
              vector.repository_id=record.repository_id,
              vector.checkout_id=record.checkout_id,
              vector.schema_version=1,
              vector.created_at=record.embedded_at,
              vector.recorded_from=record.embedded_at,
              vector.recorded_to=NULL,
              vector.classification=record.classification,
              vector.content_fingerprint=record.idempotency_key,
              vector.revision_id=record.idempotency_key,
              vector.source_entity_id=record.source_entity_id,
              vector.source_content_hash=record.source_content_hash,
              vector.space_id=$space_id,
              vector.space_fingerprint=$space_fingerprint,
              vector.generation_id=$generation_id,
              vector.provider_profile_id=record.provider_profile_id,
              vector.idempotency_key=record.idempotency_key,
              vector.dimension=$dimension,
              vector.dtype=$dtype,
              vector.normalization=$normalization,
              vector.similarity=$similarity,
              vector.purpose=$purpose,
              vector.status='active',
              vector.embedding=record.vector
WITH record, vector
WHERE vector.source_entity_id=record.source_entity_id
  AND vector.source_content_hash=record.source_content_hash
  AND vector.project_id=record.project_id
  AND vector.repository_id=record.repository_id
  AND ((vector.checkout_id IS NULL AND record.checkout_id IS NULL)
       OR vector.checkout_id=record.checkout_id)
  AND vector.classification=record.classification
  AND vector.space_id=$space_id
  AND vector.space_fingerprint=$space_fingerprint
  AND vector.generation_id=$generation_id
  AND vector.provider_profile_id=record.provider_profile_id
  AND vector.idempotency_key=record.idempotency_key
  AND vector.dimension=$dimension
  AND vector.dtype=$dtype
  AND vector.normalization=$normalization
  AND vector.similarity=$similarity
  AND vector.purpose=$purpose
  AND vector.status='active'
  AND vector.embedding=record.vector
RETURN count(vector) AS written_count
"""


def _validate_database(database: str) -> None:
    if (
        not database
        or len(database) > _MAX_DATABASE_NAME_LENGTH
        or not database.replace("_", "").isalnum()
    ):
        raise ValueError(_ERR_DATABASE)


def _physical_conflict() -> None:
    raise EmbeddingSpaceConflictError(_ERR_PHYSICAL)
