"""GRA-001 official-driver repository and scoped-query contract tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query
from neo4j.exceptions import ServiceUnavailable

from agentmemory.graph.adapters.outbound.neo4j_repository import (
    GRAPH_QUERY_TEMPLATES,
    Neo4jGraphRepository,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
    GraphValidationError,
)
from agentmemory.graph.domain.models import (
    GraphClassification,
    GraphEntity,
    GraphEntityQuery,
    GraphEntityType,
    GraphRelationship,
    GraphRelationshipType,
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

if TYPE_CHECKING:
    from neo4j import AsyncDriver

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
OTHER_BRAIN_ID = "018f0000-0000-7000-8000-000000000005"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
ENTITY_ID = "018f0000-0000-7000-8000-000000000030"
OBJECT_ID = "018f0000-0000-7000-8000-000000000031"
RELATIONSHIP_ID = "018f0000-0000-7000-8000-000000000040"


@pytest.mark.asyncio
async def test_merge_is_parameterized_scope_bound_and_idempotent_under_concurrency() -> None:
    driver = _Driver()
    repository = _repository(driver, "graph.project")
    results = await asyncio.gather(*(repository.merge_entity(_entity()) for _ in range(20)))
    assert len({result.revision_id for result in results}) == 1
    assert sum(result.created for result in results) == 1
    assert driver.nodes == {(BRAIN_ID, ENTITY_ID): _row()}
    query, parameters = driver.calls[0]
    assert "$brain_id" in query
    assert "$entity_label" in query
    assert parameters["brain_id"] == BRAIN_ID
    assert parameters["entity_label"] == "File"
    assert BRAIN_ID not in query
    assert ENTITY_ID not in query


@pytest.mark.asyncio
async def test_divergent_same_stable_entity_is_rejected_without_overwrite() -> None:
    driver = _Driver()
    repository = _repository(driver, "graph.project")
    await repository.merge_entity(_entity())
    with pytest.raises(GraphConflictError):
        await repository.merge_entity(_entity_with_fingerprint("b" * 64))
    assert driver.nodes[(BRAIN_ID, ENTITY_ID)]["content_fingerprint"] == "a" * 64


@pytest.mark.asyncio
async def test_relationship_merge_requires_scoped_existing_endpoints_and_is_idempotent() -> None:
    driver = _Driver(
        nodes={
            (BRAIN_ID, ENTITY_ID): _entity().document(),
            (BRAIN_ID, OBJECT_ID): _entity_with_id(OBJECT_ID).document(),
        }
    )
    repository = _repository(driver, "graph.project")
    first = await repository.merge_relationship(_relationship())
    second = await repository.merge_relationship(_relationship())
    assert first.created
    assert not second.created
    assert len(driver.relationships) == 1
    query, parameters = next(
        (query, parameters) for query, parameters in driver.calls if "MERGE (subject)-" in query
    )
    assert "$relationship_type" in query
    assert parameters["relationship_type"] == "IMPORTS"
    assert parameters["brain_id"] == BRAIN_ID

    del driver.nodes[(BRAIN_ID, OBJECT_ID)]
    driver.relationships.clear()
    with pytest.raises(GraphAuthorizationError):
        await repository.merge_relationship(_relationship())


@pytest.mark.asyncio
async def test_query_rechecks_brain_project_repository_classification_and_shape() -> None:
    driver = _Driver(nodes={(BRAIN_ID, ENTITY_ID): _row()})
    repository = _repository(driver, "graph.read")
    result = await repository.get_entity(GraphEntityQuery(GraphEntityType.FILE, ENTITY_ID))
    assert result == _entity()
    query, parameters = driver.calls[-1]
    for predicate in (
        "entity.brain_id = $brain_id",
        "entity.project_id IN $project_ids",
        "entity.repository_id IN $repository_ids",
        "entity.classification IN $classifications",
    ):
        assert predicate in query
    assert parameters["project_ids"] == [PROJECT_ID]
    assert parameters["repository_ids"] == [REPOSITORY_ID]

    driver.nodes[(BRAIN_ID, ENTITY_ID)] = {**_row(), "brain_id": OTHER_BRAIN_ID}
    with pytest.raises(GraphIntegrityError):
        await repository.get_entity(GraphEntityQuery(GraphEntityType.FILE, ENTITY_ID))


@pytest.mark.asyncio
async def test_cross_brain_and_malicious_dynamic_identifiers_fail_closed() -> None:
    driver = _Driver()
    repository = _repository(driver, "graph.project")
    with pytest.raises(GraphAuthorizationError):
        await repository.merge_entity(replace(_entity(), brain_id=OTHER_BRAIN_ID))
    with pytest.raises(GraphValidationError):
        GraphEntityQuery(
            cast("GraphEntityType", "File) MATCH (secret) RETURN secret //"), ENTITY_ID
        )
    assert driver.calls == []
    for template in GRAPH_QUERY_TEMPLATES:
        assert "$brain_id" in template
        assert "%" not in template
        assert ".format(" not in template


@pytest.mark.asyncio
async def test_driver_failure_and_malformed_duplicate_rows_are_typed_content_free() -> None:
    with pytest.raises(GraphUnavailableError, match="graph storage is unavailable") as raised:
        await _repository(_Driver(fail=True), "graph.read").get_entity(
            GraphEntityQuery(GraphEntityType.FILE, ENTITY_ID)
        )
    assert "bolt" not in str(raised.value).lower()

    driver = _Driver(nodes={(BRAIN_ID, ENTITY_ID): _row()}, duplicate_read=True)
    with pytest.raises(GraphIntegrityError, match="graph query returned invalid cardinality"):
        await _repository(driver, "graph.read").get_entity(
            GraphEntityQuery(GraphEntityType.FILE, ENTITY_ID)
        )


def test_repository_rejects_invalid_database_and_scope_action() -> None:
    driver = cast("AsyncDriver", _Driver())
    with pytest.raises(ValueError, match="database identity"):
        Neo4jGraphRepository(driver, "bad-name", _scope("graph.read"))
    with pytest.raises(GraphAuthorizationError, match="scope action"):
        Neo4jGraphRepository(driver, "agentmemory", _scope("memory.recall"))


def _entity() -> GraphEntity:
    return _entity_with_fingerprint("a" * 64)


def _entity_with_fingerprint(fingerprint: str) -> GraphEntity:
    return _entity_with_id(ENTITY_ID, fingerprint)


def _entity_with_id(entity_id: str, fingerprint: str = "a" * 64) -> GraphEntity:
    return GraphEntity.create(
        entity_id=entity_id,
        brain_id=BRAIN_ID,
        entity_type=GraphEntityType.FILE,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        checkout_id=None,
        schema_version=1,
        created_at=NOW,
        recorded_from=NOW,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint=fingerprint,
    )


def _relationship() -> GraphRelationship:
    return GraphRelationship.create(
        relationship_id=RELATIONSHIP_ID,
        brain_id=BRAIN_ID,
        relationship_type=GraphRelationshipType.IMPORTS,
        subject_id=ENTITY_ID,
        object_id=OBJECT_ID,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        schema_version=1,
        created_at=NOW,
        recorded_from=NOW,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint="c" * 64,
    )


def _row() -> dict[str, object]:
    entity = _entity()
    return {key: value for key, value in entity.document().items() if value is not None}


def _scope(action: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
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
        purpose="graph_test",
    )


def _repository(driver: _Driver, action: str) -> Neo4jGraphRepository:
    return Neo4jGraphRepository(cast("AsyncDriver", driver), "agentmemory", _scope(action))


@dataclass(slots=True)
class _Driver:
    nodes: dict[tuple[str, str], dict[str, object]] = field(
        default_factory=dict[tuple[str, str], dict[str, object]]
    )
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )
    relationships: dict[tuple[str, str], dict[str, object]] = field(
        default_factory=dict[tuple[str, str], dict[str, object]]
    )
    fail: bool = False
    duplicate_read: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def execute_query(
        self,
        query: str | Query,
        **config: object,
    ) -> tuple[list[dict[str, object]], None, None]:
        text = query.text if isinstance(query, Query) else query
        parameters = cast("dict[str, object]", config["parameters_"])
        self.calls.append((text, parameters))
        if self.fail:
            msg = "bolt://secret-host"
            raise ServiceUnavailable(msg)
        key = (cast("str", parameters["brain_id"]), cast("str", parameters["id"]))
        async with self._lock:
            if "MERGE (subject)-" in text:
                subject_key = (key[0], cast("str", parameters["subject_id"]))
                object_key = (key[0], cast("str", parameters["object_id"]))
                if subject_key not in self.nodes or object_key not in self.nodes:
                    return ([], None, None)
                raw_relationship = parameters["relationship"]
                assert isinstance(raw_relationship, dict)
                candidate_relationship = cast("dict[str, object]", raw_relationship)
                created = key not in self.relationships
                self.relationships.setdefault(key, dict(candidate_relationship))
                relationship = self.relationships[key]
                exact = relationship == candidate_relationship
                return (
                    [{"relationship": relationship, "exact": exact, "created": created}],
                    None,
                    None,
                )
            if "MERGE (entity" in text:
                created = key not in self.nodes
                raw_entity = parameters["entity"]
                assert isinstance(raw_entity, dict)
                candidate = cast("dict[str, object]", raw_entity)
                self.nodes.setdefault(key, dict(candidate))
                row = self.nodes[key]
                exact = row == candidate
                return ([{"entity": row, "exact": exact, "created": created}], None, None)
            existing = self.nodes.get(key)
            if existing is None:
                return ([], None, None)
            rows: list[dict[str, object]] = [{"entity": existing}]
            if self.duplicate_read:
                rows.append({"entity": existing})
            return (rows, None, None)
