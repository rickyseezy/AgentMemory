"""GRA-003 signed Neo4j projection-index migration tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query

from agentmemory.graph.domain.assertions import AssertionPredicate
from agentmemory.graph.domain.materialized_edges import PredicateRegistry
from agentmemory.operations.adapters.outbound.neo4j_graph import NEO4J_SCHEMA_HEAD
from agentmemory.operations.infrastructure.neo4j_migrations import migrate_neo4j

if TYPE_CHECKING:
    from neo4j import AsyncDriver


@pytest.mark.asyncio
@pytest.mark.migration
async def test_gra003_migration_indexes_every_materialized_predicate_and_advances_head() -> None:
    driver = _Driver()
    await migrate_neo4j(
        cast("AsyncDriver", driver),
        "agentmemory",
        Path(__file__).parents[2] / "migrations" / "neo4j",
    )
    source = "\n".join(item for item, _ in driver.calls)
    assert NEO4J_SCHEMA_HEAD == "0005_pro004_embedding_space_constraints"
    for predicate in AssertionPredicate:
        relationship_type = PredicateRegistry.relationship_type(predicate).value
        assert f"[edge:{relationship_type}]" in source
    for property_name in (
        "edge.brain_id",
        "edge.assertion_id",
        "edge.generation_id",
        "edge.projection_status",
        "edge.quarantined",
    ):
        assert property_name in source
    assert "canonical_assertion+integrity_quarantine" in source
    assert "db.awaitIndex" in driver.calls[-1][0]


@dataclass(slots=True)
class _Driver:
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )

    async def execute_query(
        self, query: str | Query, **parameters: object
    ) -> tuple[list[dict[str, object]], None, None]:
        text = query.text if isinstance(query, Query) else query
        self.calls.append((text, parameters))
        return ([], None, None)
