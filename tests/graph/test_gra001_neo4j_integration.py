"""GRA-001 live pinned-Neo4j constraint, concurrency, and isolation proof."""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from anyio import Path as AsyncPath
from neo4j import AsyncGraphDatabase
from neo4j.exceptions import ConstraintError

from agentmemory.graph.adapters.outbound.neo4j_repository import Neo4jGraphRepository
from agentmemory.graph.domain.models import (
    GraphClassification,
    GraphEntity,
    GraphEntityQuery,
    GraphEntityType,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.operations.adapters.outbound.neo4j_graph import Neo4jGraphAdapter
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Uuid7Id
from agentmemory.operations.infrastructure.neo4j_migrations import migrate_neo4j
from agentmemory.providers.adapters.neo4j_embedding_spaces import (
    Neo4jIndexGenerationProvisioner,
    Neo4jVectorWriteRepository,
)
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpace,
    IndexGeneration,
    IndexGenerationState,
    VectorRecord,
    VectorWriteBatch,
)
from agentmemory.providers.domain.errors import EmbeddingSpaceConflictError
from tests.core.support import FixedClock, digest
from tests.providers.test_pro004_embedding_spaces_domain import descriptor

if TYPE_CHECKING:
    from agentmemory.operations.domain.readiness import ReadinessBinding

URI = os.getenv("AGENTMEMORY_TEST_NEO4J_URI")
PASSWORD_FILE = os.getenv("AGENTMEMORY_TEST_NEO4J_PASSWORD_FILE")
BRAIN_ID = "018f0000-0000-7000-8000-000000000074"
OTHER_BRAIN_ID = "018f0000-0000-7000-8000-000000000075"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000072"
PROJECT_ID = "018f0000-0000-7000-8000-000000000076"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000077"
ENTITY_ID = "018f0000-0000-7000-8000-000000000078"
DUPLICATE_ID = "018f0000-0000-7000-8000-000000000079"
SPACE_ID = "018f0000-0000-7000-8000-000000000081"
PROFILE_ID = "018f0000-0000-7000-8000-000000000082"
GENERATION_ID = "018f0000-0000-7000-8000-000000000083"
VECTOR_ID = "018f0000-0000-7000-8000-000000000084"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        URI is None or PASSWORD_FILE is None,
        reason="live pinned Neo4j integration credentials are not configured",
    ),
]


@pytest.mark.asyncio
async def test_live_constraints_concurrent_merge_and_cross_brain_canary() -> None:
    assert URI is not None
    assert PASSWORD_FILE is not None
    password = (await AsyncPath(PASSWORD_FILE).read_bytes()).hex()
    driver = AsyncGraphDatabase.driver(  # pyright: ignore[reportUnknownMemberType]
        URI, auth=("neo4j", password), max_connection_pool_size=50
    )
    try:
        await migrate_neo4j(driver, "neo4j", Path(__file__).parents[2] / "migrations" / "neo4j")
        await driver.execute_query(
            "CYPHER 25 MATCH (entity:GraphEntity) "
            "WHERE entity.brain_id IN [$brain_id, $other_brain_id] DETACH DELETE entity",
            brain_id=BRAIN_ID,
            other_brain_id=OTHER_BRAIN_ID,
            database_="neo4j",
        )
        writer = Neo4jGraphRepository(driver, "neo4j", _scope("graph.project", BRAIN_ID))
        outcomes = await asyncio.gather(*(writer.merge_entity(_entity()) for _ in range(32)))
        assert sum(outcome.created for outcome in outcomes) == 1
        assert len({outcome.revision_id for outcome in outcomes}) == 1

        records, _, _ = await driver.execute_query(
            "CYPHER 25 MATCH (entity:GraphEntity {brain_id: $brain_id, id: $id}) "
            "RETURN count(entity) AS count",
            brain_id=BRAIN_ID,
            id=ENTITY_ID,
            database_="neo4j",
        )
        assert records[0]["count"] == 1

        embedding_space = EmbeddingSpace.create(
            space_id=SPACE_ID,
            profile_id=PROFILE_ID,
            capability_attestation_id=digest("live-pro004-attestation").value,
            descriptor=descriptor(),
            created_at=datetime(2026, 7, 21, 12, tzinfo=UTC),
        )
        index_generation = IndexGeneration.create(
            generation_id=GENERATION_ID,
            brain_id=BRAIN_ID,
            space=embedding_space,
            state=IndexGenerationState.CREATING,
            created_at=datetime(2026, 7, 21, 12, tzinfo=UTC),
        )
        await Neo4jIndexGenerationProvisioner(driver, "neo4j").ensure(
            embedding_space,
            index_generation,
        )
        writable_generation = replace(
            index_generation,
            state=IndexGenerationState.POPULATING,
        )
        vector = VectorRecord(
            record_id=VECTOR_ID,
            brain_id=BRAIN_ID,
            project_id=PROJECT_ID,
            repository_id=REPOSITORY_ID,
            checkout_id=None,
            source_entity_id=ENTITY_ID,
            source_content_hash="a" * 64,
            space_id=SPACE_ID,
            space_fingerprint=embedding_space.immutable_fingerprint,
            generation_id=GENERATION_ID,
            provider_profile_id=PROFILE_ID,
            purpose=embedding_space.descriptor.purpose,
            classification="internal",
            vector=(0.6, 0.8),
            embedded_at=datetime(2026, 7, 21, 12, tzinfo=UTC),
        )
        batch = VectorWriteBatch.create(
            embedding_space,
            writable_generation,
            (vector,),
        )
        receipt = await Neo4jVectorWriteRepository(driver, "neo4j", FixedClock()).write(batch)
        assert receipt.record_count == 1
        with pytest.raises(EmbeddingSpaceConflictError, match="source content"):
            await Neo4jVectorWriteRepository(driver, "neo4j", FixedClock()).write(
                VectorWriteBatch.create(
                    embedding_space,
                    writable_generation,
                    (replace(vector, source_content_hash="b" * 64),),
                )
            )
        records, _, _ = await driver.execute_query(
            "CYPHER 25 MATCH (vector:VectorRecord {brain_id: $brain_id, id: $id}) "
            "RETURN count(vector) AS count",
            brain_id=BRAIN_ID,
            id=VECTOR_ID,
            database_="neo4j",
        )
        assert records[0]["count"] == 1

        readiness_binding = cast("ReadinessBinding", object())
        proof = await Neo4jGraphAdapter(driver, "neo4j", _Brain()).verify(readiness_binding)
        assert "schema:0005_pro004_embedding_space_constraints" in proof

        malformed_id = "018f0000-0000-7000-8000-000000000080"
        await driver.execute_query(
            "CYPHER 25 CREATE (:GraphEntity:File {brain_id: $brain_id, id: $id})",
            brain_id=BRAIN_ID,
            id=malformed_id,
            database_="neo4j",
        )
        with pytest.raises(OperationError) as integrity_error:
            await Neo4jGraphAdapter(driver, "neo4j", _Brain()).verify(readiness_binding)
        assert integrity_error.value.code is ErrorCode.INTEGRITY_VIOLATION
        await driver.execute_query(
            "CYPHER 25 MATCH (entity:GraphEntity {brain_id: $brain_id, id: $id}) DELETE entity",
            brain_id=BRAIN_ID,
            id=malformed_id,
            database_="neo4j",
        )

        with pytest.raises(ConstraintError):
            await driver.execute_query(
                "CYPHER 25 CREATE (:File {brain_id: $brain_id, id: $id}), "
                "(:File {brain_id: $brain_id, id: $id})",
                brain_id=BRAIN_ID,
                id=DUPLICATE_ID,
                database_="neo4j",
            )

        other_reader = Neo4jGraphRepository(driver, "neo4j", _scope("graph.read", OTHER_BRAIN_ID))
        assert (
            await other_reader.get_entity(GraphEntityQuery(GraphEntityType.FILE, ENTITY_ID)) is None
        )
    finally:
        await driver.close()


class _Brain:
    async def get(self) -> Uuid7Id:
        return Uuid7Id(BRAIN_ID)


def _entity() -> GraphEntity:
    now = datetime(2026, 7, 21, 12, tzinfo=UTC)
    return GraphEntity.create(
        entity_id=ENTITY_ID,
        brain_id=BRAIN_ID,
        entity_type=GraphEntityType.FILE,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        checkout_id=None,
        schema_version=1,
        created_at=now,
        recorded_from=now,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint="a" * 64,
    )


def _scope(action: str, brain_id: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(brain_id),
        principal_id=StableId(PRINCIPAL_ID),
        role=RetrievalRole.WORKER if action == "graph.project" else RetrievalRole.READER,
        mode=RetrievalScopeMode.SELECTED,
        members=(ScopeMember(StableId(PROJECT_ID), (StableId(REPOSITORY_ID),), ()),),
        classification_ceiling=Classification.INTERNAL,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="graph_integration",
    )
