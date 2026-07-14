"""Neo4j compatibility, migration, and semantic-index adapter tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query
from neo4j.exceptions import ServiceUnavailable

from agentmemory.operations.adapters.outbound.neo4j_graph import (
    NEO4J_SCHEMA_HEAD,
    VECTOR_INDEX_NAME,
    Neo4jGraphAdapter,
)
from agentmemory.operations.domain.dependency_ports import EmbeddingVector
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Uuid7Id
from agentmemory.operations.infrastructure.neo4j_migrations import migrate_neo4j
from tests.core.support import BRAIN_ID, binding

if TYPE_CHECKING:
    from neo4j import AsyncDriver


@dataclass(slots=True)
class _Brain:
    async def get(self) -> Uuid7Id:
        return Uuid7Id(BRAIN_ID)


@dataclass(slots=True)
class _Driver:
    server_version: str = "2026.06.0"
    schema_version: str = NEO4J_SCHEMA_HEAD
    index_state: str = "ONLINE"
    index_provider: str = "vector-2026.06"
    fail: bool = False
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )

    async def verify_connectivity(self, **config: object) -> None:
        del config
        if self.fail:
            msg = "unavailable"
            raise ServiceUnavailable(msg)

    async def execute_query(
        self,
        query: str | Query,
        **parameters: object,
    ) -> tuple[list[dict[str, object]], None, None]:
        query_text = query.text if isinstance(query, Query) else query
        self.calls.append((query_text, parameters))
        if self.fail:
            msg = "unavailable"
            raise ServiceUnavailable(msg)
        if "dbms.components" in query_text:
            return ([{"version": self.server_version}], None, None)
        if "AgentMemorySchema" in query_text and "RETURN schema.version" in query_text:
            return ([{"version": self.schema_version}], None, None)
        if "SHOW VECTOR INDEXES" in query_text:
            return (
                [
                    {
                        "state": self.index_state,
                        "indexProvider": self.index_provider,
                        "properties": [
                            "embedding",
                            "brain_id",
                            "generation_id",
                            "classification",
                            "status",
                        ],
                    }
                ],
                None,
                None,
            )
        if "SEARCH record IN" in query_text:
            return ([{"id": parameters.get("expected_canary", "canary")}], None, None)
        return ([], None, None)


def _adapter(driver: _Driver) -> Neo4jGraphAdapter:
    return Neo4jGraphAdapter(cast("AsyncDriver", driver), "agentmemory", _Brain())


def _vector(content_id: str = "canary", dimension: int = 1024) -> EmbeddingVector:
    return EmbeddingVector(
        content_id=content_id,
        values=(0.25,) * dimension,
        model_id="Qwen/Qwen3-Embedding-0.6B",
        model_revision="0123456789abcdef",
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_graph_compatibility_checks_live_version_schema_and_filtered_index() -> None:
    driver = _Driver()
    proof = await _adapter(driver).verify(binding())
    assert proof == ("neo4j:2026.06.0:driver:6.2.0:schema:0001_pf001_core_schema")
    assert any("SHOW VECTOR INDEXES" in query for query, _ in driver.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("driver", "code"),
    [
        (_Driver(server_version="2025.12.0"), ErrorCode.DEPENDENCY_UNAVAILABLE),
        (_Driver(schema_version="old"), ErrorCode.CONFLICT),
        (_Driver(index_state="POPULATING"), ErrorCode.INTEGRITY_VIOLATION),
        (_Driver(fail=True), ErrorCode.DEPENDENCY_UNAVAILABLE),
    ],
)
async def test_graph_compatibility_fails_closed_on_dependency_or_schema_drift(
    driver: _Driver,
    code: ErrorCode,
) -> None:
    with pytest.raises(OperationError) as raised:
        await _adapter(driver).verify(binding())
    assert raised.value.code is code


@pytest.mark.asyncio
async def test_semantic_index_uses_prefiltered_cypher25_and_exact_generation() -> None:
    driver = _Driver()
    adapter = _adapter(driver)
    readiness_binding = binding()
    await adapter.index(readiness_binding, "canary", "a" * 64, _vector())
    recalled = await adapter.recall(readiness_binding, _vector("query"), "canary")
    await adapter.delete(readiness_binding, "canary")
    assert recalled == ("canary",)
    search_query, search_parameters = next(
        (query, parameters) for query, parameters in driver.calls if "SEARCH record IN" in query
    )
    assert "CYPHER 25" in search_query
    assert f"VECTOR INDEX {VECTOR_INDEX_NAME}" in search_query
    assert "WHERE record.brain_id = $brain_id" in search_query
    assert "record.generation_id = $generation_id" in search_query
    assert search_parameters["brain_id"] == BRAIN_ID
    assert search_parameters["generation_id"] == readiness_binding.generation_id.value


@pytest.mark.asyncio
async def test_semantic_index_rejects_wrong_vector_dimension_before_write() -> None:
    driver = _Driver()
    with pytest.raises(OperationError) as raised:
        await _adapter(driver).index(binding(), "canary", "a" * 64, _vector(dimension=3))
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
    assert driver.calls == []


@pytest.mark.asyncio
@pytest.mark.migration
async def test_graph_migration_runs_closed_ordered_schema_and_awaits_index() -> None:
    driver = _Driver()
    migration_directory = Path(__file__).parents[2] / "migrations" / "neo4j"
    await migrate_neo4j(cast("AsyncDriver", driver), "agentmemory", migration_directory)
    assert len(driver.calls) == 5
    assert "CREATE CONSTRAINT" in driver.calls[0][0]
    assert "CREATE VECTOR INDEX" in driver.calls[2][0]
    assert NEO4J_SCHEMA_HEAD in driver.calls[3][0]
    assert "db.awaitIndex" in driver.calls[4][0]
    assert driver.calls[4][1]["index_name"] == VECTOR_INDEX_NAME


@pytest.mark.asyncio
@pytest.mark.security
async def test_graph_migration_rejects_any_tampered_bundle(tmp_path: Path) -> None:
    source = Path(__file__).parents[2] / "migrations" / "neo4j" / ("0001_pf001_core_schema.cypher")
    target = tmp_path / source.name
    target.write_bytes(source.read_bytes() + b"\n// tampered")
    with pytest.raises(RuntimeError, match="digest integrity"):
        await migrate_neo4j(cast("AsyncDriver", _Driver()), "agentmemory", tmp_path)


def test_graph_adapter_rejects_invalid_database_identity() -> None:
    with pytest.raises(ValueError, match="database identity"):
        Neo4jGraphAdapter(cast("AsyncDriver", _Driver()), "bad-name", _Brain())
