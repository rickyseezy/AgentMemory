"""PF-002 Neo4j shadow-generation adapter tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query
from neo4j.exceptions import ServiceUnavailable

from agentmemory.operations.adapters.outbound.neo4j_projection_rebuild import (
    Neo4jProjectionGenerationAdapter,
    ProjectionGenerationRouter,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRecord,
    ProjectionType,
    ProjectionValidation,
    RebuildManifest,
    SourceRecord,
    canonical_json,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from tests.core.support import BRAIN_ID, digest

if TYPE_CHECKING:
    from neo4j import AsyncDriver


def _manifest() -> RebuildManifest:
    return RebuildManifest(
        "build@1",
        "relational@2",
        "graph@2",
        "parser@1",
        "extractor@1",
        ("provider@1",),
        "embedding@1",
        digest("implementation"),
    )


def _source() -> SourceRecord:
    payload = canonical_json({"assertion": "frontend consumes user API"})
    return SourceRecord(
        ProjectionRecord(
            "assertion-1",
            "event-1",
            1,
            digest("source"),
            Sha256Digest.from_bytes(payload.encode()),
            payload,
        ),
        "assertion",
        digest("target"),
    )


@dataclass(slots=True)
class _Driver:
    fail: bool = False
    divergent_prepare: bool = False
    values: dict[str, dict[str, object]] = field(default_factory=dict[str, dict[str, object]])
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )

    async def execute_query(
        self,
        query: str | Query,
        **parameters: object,
    ) -> tuple[list[dict[str, object]], None, None]:
        query_text = query.text if isinstance(query, Query) else query
        supplied = parameters.pop("parameters_", {})
        assert isinstance(supplied, dict)
        parameters.update(cast("dict[str, object]", supplied))
        self.calls.append((query_text, parameters))
        if self.fail:
            msg = "offline"
            raise ServiceUnavailable(msg)
        if "ProjectionGeneration" in query_text:
            if self.divergent_prepare:
                return ([{"manifest_digest": "wrong", "state": "active"}], None, None)
            return (
                [
                    {
                        "manifest_digest": parameters["manifest_digest"],
                        "state": "shadow",
                    }
                ],
                None,
                None,
            )
        if "MERGE (record:ProjectionRecord" in query_text:
            stable_id = cast("str", parameters["stable_id"])
            current = self.values.setdefault(
                stable_id,
                {
                    key: value
                    for key, value in parameters.items()
                    if key
                    in {
                        "source_event_id",
                        "source_sequence",
                        "source_digest",
                        "content_digest",
                        "target_type",
                        "target_id_hash",
                        "payload_json",
                        "manifest_digest",
                    }
                },
            )
            return ([current], None, None)
        return (
            [
                {
                    "stable_id": stable_id,
                    **value,
                }
                for stable_id, value in sorted(self.values.items())
            ],
            None,
            None,
        )


def _adapter(driver: _Driver) -> Neo4jProjectionGenerationAdapter:
    return Neo4jProjectionGenerationAdapter(cast("AsyncDriver", driver), "agentmemory")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_neo4j_generation_is_brain_scoped_idempotent_and_digest_validated() -> None:
    driver = _Driver()
    adapter = _adapter(driver)
    brain = Uuid7Id(BRAIN_ID)
    generation = digest("generation")
    manifest = _manifest()
    source = _source()
    await adapter.prepare(brain, ProjectionType.GRAPH, generation, manifest)
    await adapter.put(brain, ProjectionType.GRAPH, generation, source, manifest)
    await adapter.put(brain, ProjectionType.GRAPH, generation, source, manifest)
    validation = await adapter.validate(brain, ProjectionType.GRAPH, generation, manifest)
    assert validation.passed
    assert validation.record_count == 1
    assert all(parameters["brain_id"] == BRAIN_ID for _, parameters in driver.calls)
    assert all(parameters["generation_id"] == generation.value for _, parameters in driver.calls)


@pytest.mark.asyncio
@pytest.mark.resilience
async def test_neo4j_provider_outage_is_typed_retryable_and_content_free() -> None:
    adapter = _adapter(_Driver(fail=True))
    with pytest.raises(OperationError) as raised:
        await adapter.prepare(
            Uuid7Id(BRAIN_ID),
            ProjectionType.VECTOR,
            digest("generation"),
            _manifest(),
        )
    assert raised.value.code is ErrorCode.DEPENDENCY_UNAVAILABLE
    assert raised.value.retryable
    assert str(raised.value) == "Neo4j projection generation is unavailable"


@pytest.mark.parametrize("database", ["", "x" * 64, "agent-memory"])
def test_neo4j_adapter_rejects_invalid_database_identity(database: str) -> None:
    with pytest.raises(ValueError, match="database identity"):
        Neo4jProjectionGenerationAdapter(cast("AsyncDriver", _Driver()), database)


@pytest.mark.asyncio
async def test_neo4j_adapter_fails_closed_on_divergent_generation_or_record() -> None:
    driver = _Driver()
    adapter = _adapter(driver)
    brain = Uuid7Id(BRAIN_ID)
    generation = digest("generation")
    manifest = _manifest()

    driver.divergent_prepare = True
    with pytest.raises(OperationError) as prepare_error:
        await adapter.prepare(brain, ProjectionType.GRAPH, generation, manifest)
    assert prepare_error.value.code is ErrorCode.INTEGRITY_VIOLATION

    driver.divergent_prepare = False
    driver.values["assertion-1"] = {"source_event_id": "different"}
    with pytest.raises(OperationError) as put_error:
        await adapter.put(brain, ProjectionType.GRAPH, generation, _source(), manifest)
    assert put_error.value.code is ErrorCode.INTEGRITY_VIOLATION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [("manifest_digest", "wrong"), ("source_sequence", "one"), ("source_digest", 1)],
)
async def test_neo4j_validation_marks_malformed_or_divergent_rows_invalid(
    field: str,
    value: object,
) -> None:
    driver = _Driver()
    adapter = _adapter(driver)
    brain = Uuid7Id(BRAIN_ID)
    generation = digest("generation")
    manifest = _manifest()
    await adapter.put(brain, ProjectionType.GRAPH, generation, _source(), manifest)
    driver.values["assertion-1"][field] = value
    validation = await adapter.validate(brain, ProjectionType.GRAPH, generation, manifest)
    assert not validation.passed


@dataclass(slots=True)
class _GenerationSpy:
    validation: ProjectionValidation
    prepared: int = 0
    written: int = 0
    validated: int = 0

    async def prepare(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> None:
        del brain_id, projection_type, generation_id, manifest
        self.prepared += 1

    async def put(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        record: SourceRecord,
        manifest: RebuildManifest,
    ) -> bool:
        del brain_id, projection_type, generation_id, record, manifest
        self.written += 1
        return True

    async def validate(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> ProjectionValidation:
        del brain_id, projection_type, generation_id, manifest
        self.validated += 1
        return self.validation


@pytest.mark.asyncio
@pytest.mark.parametrize("projection_type", [ProjectionType.MEMORY, ProjectionType.GRAPH])
async def test_generation_router_uses_graph_store_only_for_graph_families(
    projection_type: ProjectionType,
) -> None:
    validation = ProjectionValidation(
        record_count=1,
        generation_digest=digest("generation-digest"),
        lineage_complete=True,
        integrity_valid=True,
        authorization_valid=True,
        tombstones_current=True,
        golden_queries_passed=True,
    )
    local = _GenerationSpy(validation)
    graph = _GenerationSpy(validation)
    router = ProjectionGenerationRouter(local, graph)
    brain = Uuid7Id(BRAIN_ID)
    generation = digest("generation")
    manifest = _manifest()
    await router.prepare(brain, projection_type, generation, manifest)
    assert await router.put(brain, projection_type, generation, _source(), manifest)
    result = await router.validate(brain, projection_type, generation, manifest)
    assert result.passed
    expected_graph_calls = int(projection_type is ProjectionType.GRAPH)
    assert graph.prepared == expected_graph_calls
    assert graph.written == expected_graph_calls
    assert graph.validated == expected_graph_calls
