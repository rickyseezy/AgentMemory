"""PRO-008 exact idempotent physical generation cleanup tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

import pytest
from neo4j.exceptions import ServiceUnavailable

from agentmemory.providers.adapters.neo4j_embedding_spaces import (
    Neo4jEmbeddingGenerationCleaner,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
)

if TYPE_CHECKING:
    from neo4j import AsyncDriver, Query

GENERATION_ID = "018f0000-0000-7000-8000-000000000112"


@dataclass
class _Driver:
    queries: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )
    fail: bool = False

    async def execute_query(
        self,
        query: str | Query,
        **parameters: Any,
    ) -> tuple[list[dict[str, object]], None, None]:
        if self.fail:
            raise ServiceUnavailable
        query_text = str(query)
        self.queries.append((query_text, dict(parameters)))
        return [], None, None


@pytest.mark.asyncio
async def test_cleanup_drops_only_uuid_derived_index_records_and_metadata() -> None:
    driver = _Driver()
    cleaner = Neo4jEmbeddingGenerationCleaner(
        cast("AsyncDriver", driver),
        "agentmemory",
    )
    await cleaner.delete(GENERATION_ID)
    await cleaner.delete(GENERATION_ID)

    assert len(driver.queries) == 4
    assert "DROP INDEX am_vec_018f0000000070008000000000000112 IF EXISTS" in driver.queries[0][0]
    assert "VectorRecord:AMVector_018f0000000070008000000000000112" in driver.queries[1][0]
    assert driver.queries[1][1]["generation_id"] == GENERATION_ID
    assert "DETACH DELETE generation" in driver.queries[1][0]


@pytest.mark.asyncio
async def test_cleanup_rejects_hostile_identity_before_graph_access() -> None:
    driver = _Driver()
    cleaner = Neo4jEmbeddingGenerationCleaner(
        cast("AsyncDriver", driver),
        "agentmemory",
    )
    with pytest.raises(EmbeddingSpaceValidationError, match="input is invalid"):
        await cleaner.delete("generation`) DETACH DELETE n //")
    assert driver.queries == []


@pytest.mark.asyncio
async def test_cleanup_translates_graph_outage_without_leaking_driver_details() -> None:
    cleaner = Neo4jEmbeddingGenerationCleaner(
        cast("AsyncDriver", _Driver(fail=True)),
        "agentmemory",
    )
    with pytest.raises(
        EmbeddingSpaceDependencyError,
        match=r"^embedding graph storage is unavailable$",
    ):
        await cleaner.delete(GENERATION_ID)
