"""GRA-006 fixed-Cypher Neo4j migration, scan, and repair adapter tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, cast

import pytest
from neo4j.exceptions import ServiceUnavailable

from agentmemory.graph.adapters.outbound.neo4j_graph_integrity import (
    GRAPH_INTEGRITY_QUERIES,
    REGISTERED_GRAPH_MIGRATION_CHECKSUM,
    Neo4jGraphIntegrityAdapter,
)
from agentmemory.graph.domain.errors import GraphIntegrityError, GraphUnavailableError
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityObservation,
    GraphIntegrityPolicy,
    GraphMigrationRun,
    GraphProjectionKind,
    GraphRepairPolicy,
)
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra006_graph_integrity_domain import (
    CANONICAL,
    CURRENT_GENERATION,
    NOW,
    PROJECTION,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from neo4j import AsyncDriver

from tests.identity.test_checkout_observation_sqlite import PROJECT_ID, REPOSITORY_ID


@pytest.mark.parametrize("database", ["", "x" * 64, "neo4j-prod"])
def test_neo4j_adapter_rejects_every_invalid_database_identity(database: str) -> None:
    """A database name cannot bypass the fixed identifier boundary."""
    with pytest.raises(ValueError, match="database identity"):
        Neo4jGraphIntegrityAdapter(cast("AsyncDriver", _Driver()), database)


@pytest.mark.asyncio
async def test_neo4j_migration_is_checksum_bound_batched_and_validated() -> None:
    driver = _Driver(
        responses=[
            [{"count": 3}],
            [{"scanned": 2, "changed": 2}],
            [{"count": 3, "exact": 3}],
        ]
    )
    adapter = Neo4jGraphIntegrityAdapter(cast("AsyncDriver", driver), "neo4j")
    scope = _scope("graph.integrity.migrate")
    assert (
        await adapter.source_watermark(
            scope, "gra006-integrity-v1", REGISTERED_GRAPH_MIGRATION_CHECKSUM
        )
        == 3
    )
    run = GraphMigrationRun.start(
        operation_id="graph-migration-neo4j-1",
        brain_id=scope.brain_id.value,
        migration_id="gra006-integrity-v1",
        migration_checksum=REGISTERED_GRAPH_MIGRATION_CHECKSUM,
        source_watermark=3,
        batch_size=2,
        started_at=NOW,
    )
    batch = await adapter.apply_batch(scope, run)
    assert batch.next_cursor == 2
    assert batch.changed == 2
    assert await adapter.validate(scope, run.checkpoint(3, 3, 3, 0, NOW))
    assert all(query.startswith("CYPHER 25\n") for query in GRAPH_INTEGRITY_QUERIES)
    assert all("$" in query for query in GRAPH_INTEGRITY_QUERIES)

    with pytest.raises(GraphIntegrityError, match="registered"):
        await adapter.source_watermark(scope, "free-form", REGISTERED_GRAPH_MIGRATION_CHECKSUM)
    with pytest.raises(GraphIntegrityError, match="registered"):
        await adapter.source_watermark(scope, "gra006-integrity-v1", "f" * 64)
    with pytest.raises(GraphIntegrityError, match="registered"):
        await adapter.apply_batch(scope, replace(run, migration_checksum="f" * 64))
    with pytest.raises(GraphIntegrityError, match="registered"):
        await adapter.validate(scope, replace(run, migration_checksum="f" * 64))

    wrong_scope = replace(run, brain_id=CANONICAL)
    with pytest.raises(GraphIntegrityError, match="malformed evidence"):
        await adapter.apply_batch(scope, wrong_scope)
    with pytest.raises(GraphIntegrityError, match="malformed evidence"):
        await adapter.validate(scope, wrong_scope)

    empty_batch = Neo4jGraphIntegrityAdapter(
        cast("AsyncDriver", _Driver(responses=[[{"scanned": 0, "changed": 0}]])), "neo4j"
    )
    with pytest.raises(GraphIntegrityError, match="malformed evidence"):
        await empty_batch.apply_batch(scope, run)


@pytest.mark.asyncio
async def test_neo4j_scan_decodes_bounded_content_free_projection_metadata() -> None:
    driver = _Driver(
        responses=[
            [
                {
                    "projection_id": "c" * 64,
                    "projection_kind": "assertion",
                    "brain_id": _scope("graph.integrity.validate").brain_id.value,
                    "project_id": PROJECT_ID.value,
                    "repository_id": REPOSITORY_ID.value,
                    "canonical_id": CANONICAL,
                    "canonical_supported": False,
                    "temporal_valid": True,
                    "scope_matches": True,
                    "generation_id": CURRENT_GENERATION,
                    "projection_digest": "d" * 64,
                },
                {
                    "projection_id": "d" * 64,
                    "projection_kind": "edge",
                    "brain_id": _scope("graph.integrity.validate").brain_id.value,
                    "project_id": PROJECT_ID.value,
                    "repository_id": REPOSITORY_ID.value,
                    "canonical_id": CANONICAL,
                    "canonical_supported": True,
                    "temporal_valid": True,
                    "scope_matches": True,
                    "generation_id": CURRENT_GENERATION,
                    "projection_digest": "e" * 64,
                },
            ]
        ]
    )
    adapter = Neo4jGraphIntegrityAdapter(cast("AsyncDriver", driver), "neo4j")
    observations = await adapter.scan(_scope("graph.integrity.validate"))
    assert [item.projection_kind for item in observations] == [
        GraphProjectionKind.ASSERTION,
        GraphProjectionKind.EDGE,
    ]
    assert not observations[0].canonical_supported
    assert observations[1].canonical_supported
    findings = GraphIntegrityPolicy.evaluate(observations, CURRENT_GENERATION, NOW)
    assert [item.kind.value for item in findings] == ["unsupported_assertion"]
    assert "source_text" not in driver.calls[0][1]
    assert "CALL {" in driver.calls[0][0]
    assert "LIMIT $limit" in driver.calls[0][0]


@pytest.mark.asyncio
async def test_neo4j_scan_fails_closed_for_malformed_over_limit_and_cross_scope_rows() -> None:
    """A partial or unauthorized scan must never be reported as a clean graph."""
    malformed = Neo4jGraphIntegrityAdapter(
        cast("AsyncDriver", _Driver(responses=[[{"projection_id": PROJECTION}]])), "neo4j"
    )
    with pytest.raises(GraphIntegrityError, match="malformed evidence"):
        await malformed.scan(_scope("graph.integrity.validate"))

    over_limit = Neo4jGraphIntegrityAdapter(
        cast("AsyncDriver", _Driver(responses=[[{}] * 10_001])), "neo4j"
    )
    with pytest.raises(GraphIntegrityError, match="malformed evidence"):
        await over_limit.scan(_scope("graph.integrity.validate"))

    scope = _scope("graph.integrity.validate")
    cross_scope_row: dict[str, object] = {
        "projection_id": PROJECTION,
        "projection_kind": "vector",
        "brain_id": scope.brain_id.value,
        "project_id": CANONICAL,
        "repository_id": REPOSITORY_ID.value,
        "canonical_id": None,
        "canonical_supported": False,
        "temporal_valid": True,
        "scope_matches": False,
        "generation_id": CURRENT_GENERATION,
        "projection_digest": "d" * 64,
    }
    cross_scope = Neo4jGraphIntegrityAdapter(
        cast("AsyncDriver", _Driver(responses=[[cross_scope_row]])), "neo4j"
    )
    with pytest.raises(GraphIntegrityError, match="malformed evidence"):
        await cross_scope.scan(scope)


@pytest.mark.asyncio
async def test_neo4j_repair_only_shadows_or_quarantines_and_maps_dependency_failure() -> None:
    scope = _scope("graph.integrity.repair")
    observation = GraphIntegrityObservation(
        projection_id=PROJECTION,
        projection_kind=GraphProjectionKind.EDGE,
        brain_id=scope.brain_id.value,
        project_id=PROJECT_ID.value,
        repository_id=REPOSITORY_ID.value,
        canonical_id=None,
        canonical_supported=True,
        temporal_valid=True,
        scope_matches=True,
        generation_id=CURRENT_GENERATION,
        projection_digest="d" * 64,
    )
    finding = GraphIntegrityPolicy.evaluate((observation,), CURRENT_GENERATION, NOW)[0]
    driver = _Driver(responses=[[{"count": 1}], [{"count": 1}], [{"count": 1}]])
    adapter = Neo4jGraphIntegrityAdapter(cast("AsyncDriver", driver), "neo4j")
    await adapter.execute(scope, finding, GraphRepairPolicy.plan(finding), NOW)
    assert "DELETE" not in driver.calls[0][0]
    assert "quarantined = true" in driver.calls[0][0]

    unsupported = replace(
        observation,
        projection_id="a" * 64,
        projection_kind=GraphProjectionKind.ASSERTION,
        canonical_id=CANONICAL,
        canonical_supported=False,
    )
    unsupported_finding = GraphIntegrityPolicy.evaluate((unsupported,), CURRENT_GENERATION, NOW)[0]
    await adapter.execute(
        scope, unsupported_finding, GraphRepairPolicy.plan(unsupported_finding), NOW
    )
    assert "GraphRepairShadow" in driver.calls[1][0]

    orphan_vector = replace(
        observation,
        projection_id="b" * 64,
        projection_kind=GraphProjectionKind.VECTOR,
    )
    vector_finding = GraphIntegrityPolicy.evaluate((orphan_vector,), CURRENT_GENERATION, NOW)[0]
    await adapter.execute(scope, vector_finding, GraphRepairPolicy.plan(vector_finding), NOW)
    assert "MATCH (projection)" in driver.calls[2][0]
    assert "quarantined = true" in driver.calls[2][0]

    destructive = GraphRepairPolicy.plan(
        finding,
        destructive=True,
        approval_id=CANONICAL,
        canonical_rebuild_verified=True,
    )
    with pytest.raises(GraphIntegrityError):
        await adapter.execute(scope, finding, destructive, NOW)

    unavailable = Neo4jGraphIntegrityAdapter(
        cast("AsyncDriver", _Driver(failure=ServiceUnavailable("offline"))), "neo4j"
    )
    with pytest.raises(GraphUnavailableError):
        await unavailable.scan(_scope("graph.integrity.validate"))


@dataclass
class _Driver:
    responses: list[list[dict[str, object]]] = field(default_factory=list[list[dict[str, object]]])
    failure: Exception | None = None
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )

    async def execute_query(self, query: object, **kwargs: object) -> tuple[object, object, object]:
        parameters = cast("Mapping[str, object]", kwargs["parameters_"])
        self.calls.append((str(query), dict(parameters)))
        if self.failure is not None:
            raise self.failure
        return (self.responses.pop(0), object(), object())
