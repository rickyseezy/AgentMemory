"""GRA-001 signed Neo4j schema migration acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query

from agentmemory.graph.domain.models import GraphEntityType, GraphRelationshipType
from agentmemory.operations.adapters.outbound.neo4j_graph import NEO4J_SCHEMA_HEAD
from agentmemory.operations.infrastructure.neo4j_migrations import migrate_neo4j

if TYPE_CHECKING:
    from neo4j import AsyncDriver


@pytest.mark.asyncio
@pytest.mark.migration
async def test_gra001_migration_installs_every_stable_label_and_relationship_constraint() -> None:
    driver = _Driver()
    await migrate_neo4j(
        cast("AsyncDriver", driver),
        "agentmemory",
        Path(__file__).parents[2] / "migrations" / "neo4j",
    )
    source = "\n".join(query for query, _ in driver.calls)
    assert NEO4J_SCHEMA_HEAD == "0004_gra003_materialized_edge_indexes"
    assert "FOR (entity:GraphEntity)" in source
    for entity_type in GraphEntityType:
        assert f"FOR (entity:{entity_type.value})" in source
    for relationship_type in GraphRelationshipType:
        assert f"[relationship:{relationship_type.value}]" in source
    assert "(entity.brain_id, entity.id) IS UNIQUE" in source
    assert "schema.community_property_guard = 'repository+startup_integrity'" in source
    assert "db.awaitIndex" in driver.calls[-1][0]


@pytest.mark.asyncio
@pytest.mark.migration
async def test_gra001_migration_is_ordered_repeatable_and_digest_pinned() -> None:
    directory = Path(__file__).parents[2] / "migrations" / "neo4j"
    first = _Driver()
    second = _Driver()
    await migrate_neo4j(cast("AsyncDriver", first), "agentmemory", directory)
    await migrate_neo4j(cast("AsyncDriver", second), "agentmemory", directory)
    assert first.calls == second.calls
    heads = [query for query, _ in first.calls if "schema.version" in query]
    assert NEO4J_SCHEMA_HEAD in heads[-1]


@dataclass(slots=True)
class _Driver:
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )

    async def execute_query(
        self,
        query: str | Query,
        **parameters: object,
    ) -> tuple[list[dict[str, object]], None, None]:
        text = query.text if isinstance(query, Query) else query
        self.calls.append((text, parameters))
        return ([], None, None)
