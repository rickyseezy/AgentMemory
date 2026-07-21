"""GRA-003 Neo4j materialized-edge projection acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest
from neo4j import Query
from neo4j.exceptions import ServiceUnavailable

from agentmemory.graph.adapters.outbound.neo4j_materialized_edges import (
    EDGE_QUERY_TEMPLATES,
    Neo4jMaterializedEdgeProjection,
)
from agentmemory.graph.domain.assertions import (
    Assertion,
    AssertionCandidate,
    AssertionConfidence,
    AssertionExtractor,
    AssertionPredicate,
    AssertionScope,
    AssertionTemporal,
    EvidenceKind,
    ResolvedAssertionEvidence,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphUnavailableError,
)
from agentmemory.graph.domain.materialized_edges import MaterializedAssertionEdge
from agentmemory.graph.domain.models import GraphRelationshipType
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
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000021"
SUBJECT_ID = "018f0000-0000-7000-8000-000000000030"
OBJECT_ID = "018f0000-0000-7000-8000-000000000031"
ASSERTION_ID = "018f0000-0000-7000-8000-000000000040"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000050"
SOURCE_ID = "018f0000-0000-7000-8000-000000000060"
ACTIVATED_EVENT_ID = "018f0000-0000-7000-8000-000000000070"
DISPUTED_EVENT_ID = "018f0000-0000-7000-8000-000000000071"
GENERATION_ID = "a" * 64


@pytest.mark.asyncio
async def test_active_projection_is_parameterized_scope_bound_and_exactly_idempotent() -> None:
    driver = _Driver(nodes={(BRAIN_ID, SUBJECT_ID), (BRAIN_ID, OBJECT_ID)})
    repository = _repository(driver, "graph.assertion.materialize")
    edge = _edge(_active(), ACTIVATED_EVENT_ID, NOW)
    first = await repository.project(edge)
    second = await repository.project(edge)
    assert first.created
    assert first.applied
    assert not second.created
    assert second.applied
    assert driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)]["assertion_id"] == ASSERTION_ID
    query, parameters = driver.calls[0]
    assert "gra003:project-active" in query
    assert "$relationship_type" in query
    assert parameters["relationship_type"] == "CONSUMES"
    assert ASSERTION_ID not in query
    assert BRAIN_ID not in query


@pytest.mark.asyncio
async def test_invalidation_race_is_monotonic_and_old_activation_cannot_resurrect_edge() -> None:
    driver = _Driver(nodes={(BRAIN_ID, SUBJECT_ID), (BRAIN_ID, OBJECT_ID)})
    repository = _repository(driver, "graph.assertion.materialize")
    active = _edge(_active(), ACTIVATED_EVENT_ID, NOW)
    disputed = _active().reconcile_evidence((), NOW + timedelta(seconds=1))
    retired = _edge(disputed, DISPUTED_EVENT_ID, NOW + timedelta(seconds=1))
    await repository.project(active)
    await repository.project(retired)
    assert driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)]["projection_status"] == "retired"
    with pytest.raises(GraphConflictError, match="conflicts"):
        await repository.project(active)
    assert driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)]["aggregate_version"] == 2


@pytest.mark.asyncio
async def test_projection_keeps_old_and_new_generations_isolated() -> None:
    driver = _Driver(nodes={(BRAIN_ID, SUBJECT_ID), (BRAIN_ID, OBJECT_ID)})
    repository = _repository(driver, "graph.assertion.materialize")
    old_edge = _edge(_active(), ACTIVATED_EVENT_ID, NOW)
    new_generation = "b" * 64
    new_edge = MaterializedAssertionEdge.from_assertion(
        _active(),
        source_event_id=ACTIVATED_EVENT_ID,
        generation_id=new_generation,
        projected_at=NOW,
    )
    await repository.project(old_edge)
    await repository.project(new_edge)
    assert set(driver.edges) == {
        (BRAIN_ID, GENERATION_ID, ASSERTION_ID),
        (BRAIN_ID, new_generation, ASSERTION_ID),
    }
    await _repository(driver, "graph.assertion.edge.integrity").quarantine(
        ASSERTION_ID, new_generation, "orphan_assertion", NOW
    )
    assert driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)]["quarantined"] is False
    assert driver.edges[(BRAIN_ID, new_generation, ASSERTION_ID)]["quarantined"] is True


@pytest.mark.asyncio
async def test_retirement_before_activation_is_safe_noop_and_missing_endpoints_are_retryable() -> (
    None
):
    disputed = _active().reconcile_evidence((), NOW + timedelta(seconds=1))
    retired = _edge(disputed, DISPUTED_EVENT_ID, NOW + timedelta(seconds=1))
    empty = _repository(_Driver(), "graph.assertion.materialize")
    result = await empty.project(retired)
    assert not result.applied
    assert not result.created

    with pytest.raises(GraphUnavailableError, match="storage is unavailable"):
        await empty.project(_edge(_active(), ACTIVATED_EVENT_ID, NOW))


@pytest.mark.asyncio
async def test_integrity_listing_orphan_quarantine_and_repair_touch_only_named_edge() -> None:
    first = _edge(_active(), ACTIVATED_EVENT_ID, NOW)
    other_assertion = "018f0000-0000-7000-8000-000000000041"
    second = _edge(_active_with_id(other_assertion), ACTIVATED_EVENT_ID, NOW)
    driver = _Driver(
        nodes={(BRAIN_ID, SUBJECT_ID), (BRAIN_ID, OBJECT_ID)},
        edges={
            (BRAIN_ID, GENERATION_ID, first.assertion_id): _document(first),
            (BRAIN_ID, GENERATION_ID, second.assertion_id): _document(second),
        },
    )
    repository = _repository(driver, "graph.assertion.edge.integrity")
    listed = await repository.list_edges(GENERATION_ID)
    assert {item.assertion_id for item in listed} == {first.assertion_id, second.assertion_id}
    await repository.quarantine(first.assertion_id, GENERATION_ID, "orphan_assertion", NOW)
    assert driver.edges[(BRAIN_ID, GENERATION_ID, first.assertion_id)]["quarantined"] is True
    assert driver.edges[(BRAIN_ID, GENERATION_ID, second.assertion_id)]["quarantined"] is False
    repaired = await repository.project(first)
    assert repaired.applied
    assert driver.edges[(BRAIN_ID, GENERATION_ID, first.assertion_id)]["quarantined"] is False


@pytest.mark.asyncio
async def test_traversal_excludes_quarantined_retired_other_generation_and_cross_brain_edges() -> (
    None
):
    active = _edge(_active(), ACTIVATED_EVENT_ID, NOW)
    quarantined = _document(active.quarantine("orphan_assertion"))
    driver = _Driver(
        nodes={(BRAIN_ID, SUBJECT_ID), (BRAIN_ID, OBJECT_ID)},
        edges={(BRAIN_ID, GENERATION_ID, ASSERTION_ID): quarantined},
    )
    traversal = _repository(driver, "graph.assertion.traverse")
    assert (
        await traversal.traverse(SUBJECT_ID, (GraphRelationshipType.CONSUMES,), GENERATION_ID, 10)
        == ()
    )
    driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)] = _document(active)
    result = await traversal.traverse(
        SUBJECT_ID, (GraphRelationshipType.CONSUMES,), GENERATION_ID, 10
    )
    assert result[0].assertion_id == ASSERTION_ID
    assert result[0].source_event_id == ACTIVATED_EVENT_ID

    driver.edges[(BRAIN_ID, GENERATION_ID, ASSERTION_ID)]["generation_id"] = "b" * 64
    assert (
        await traversal.traverse(SUBJECT_ID, (GraphRelationshipType.CONSUMES,), GENERATION_ID, 10)
        == ()
    )
    driver.edges[(OTHER_BRAIN_ID, GENERATION_ID, ASSERTION_ID)] = _document(active)
    assert all(key[0] == BRAIN_ID for key in driver.nodes)


def test_closed_query_templates_and_scope_actions_reject_injection() -> None:
    for query in EDGE_QUERY_TEMPLATES:
        assert "$brain_id" in query
        assert "%" not in query
        assert ".format(" not in query
    with pytest.raises(GraphAuthorizationError, match="action"):
        Neo4jMaterializedEdgeProjection(
            cast("AsyncDriver", _Driver()), "agentmemory", _scope("graph.read")
        )
    with pytest.raises(ValueError, match="database"):
        Neo4jMaterializedEdgeProjection(
            cast("AsyncDriver", _Driver()),
            "bad-name",
            _scope("graph.assertion.traverse"),
        )


@pytest.mark.asyncio
async def test_driver_failure_is_typed_and_content_free() -> None:
    with pytest.raises(GraphUnavailableError, match="storage is unavailable") as raised:
        await _repository(_Driver(fail=True), "graph.assertion.edge.integrity").list_edges(
            GENERATION_ID
        )
    assert "bolt" not in str(raised.value).lower()


@dataclass(slots=True)
class _Driver:
    nodes: set[tuple[str, str]] = field(default_factory=set[tuple[str, str]])
    edges: dict[tuple[str, str, str], dict[str, object]] = field(
        default_factory=dict[tuple[str, str, str], dict[str, object]]
    )
    calls: list[tuple[str, dict[str, object]]] = field(
        default_factory=list[tuple[str, dict[str, object]]]
    )
    fail: bool = False

    async def execute_query(
        self, query: str | Query, **config: object
    ) -> tuple[list[dict[str, object]], None, None]:
        text = query.text if isinstance(query, Query) else query
        parameters = cast("dict[str, object]", config["parameters_"])
        self.calls.append((text, parameters))
        if self.fail:
            message = "bolt://secret-host"
            raise ServiceUnavailable(message)
        brain_id = cast("str", parameters["brain_id"])
        if "gra003:project-active" in text:
            return self._project_active(brain_id, parameters)
        if "gra003:project-retired" in text:
            return self._project_retired(brain_id, parameters)
        if "gra003:list" in text:
            return (
                [
                    {"edge": row, "actual_relationship_type": row["relationship_type"]}
                    for row in self._visible_rows(parameters, traversal=False)
                ],
                None,
                None,
            )
        if "gra003:quarantine" in text:
            key = (
                brain_id,
                cast("str", parameters["generation_id"]),
                cast("str", parameters["assertion_id"]),
            )
            row = self.edges.get(key)
            if row is None:
                return ([{"changed": 0}], None, None)
            row.update(
                {
                    "quarantined": True,
                    "quarantine_reason": parameters["reason"],
                    "quarantined_at": parameters["quarantined_at"],
                }
            )
            return ([{"changed": 1}], None, None)
        rows = self._visible_rows(parameters, traversal=True)
        return (
            [
                {"edge": row, "actual_relationship_type": row["relationship_type"]}
                for row in rows[: cast("int", parameters["limit"])]
            ],
            None,
            None,
        )

    def _project_active(
        self, brain_id: str, parameters: dict[str, object]
    ) -> tuple[list[dict[str, object]], None, None]:
        if (brain_id, cast("str", parameters["subject_id"])) not in self.nodes or (
            brain_id,
            cast("str", parameters["object_id"]),
        ) not in self.nodes:
            return ([], None, None)
        return self._apply(brain_id, parameters, allow_create=True)

    def _project_retired(
        self, brain_id: str, parameters: dict[str, object]
    ) -> tuple[list[dict[str, object]], None, None]:
        candidate = cast("dict[str, object]", parameters["edge"])
        key = (
            brain_id,
            cast("str", candidate["generation_id"]),
            cast("str", parameters["assertion_id"]),
        )
        if key not in self.edges:
            return ([{"edge": None, "applied": False, "created": False}], None, None)
        return self._apply(brain_id, parameters, allow_create=False)

    def _apply(
        self, brain_id: str, parameters: dict[str, object], *, allow_create: bool
    ) -> tuple[list[dict[str, object]], None, None]:
        candidate = cast("dict[str, object]", parameters["edge"])
        key = (
            brain_id,
            cast("str", candidate["generation_id"]),
            cast("str", parameters["assertion_id"]),
        )
        current = self.edges.get(key)
        created = current is None and allow_create
        if current is None and not allow_create:
            return ([{"edge": None, "applied": False, "created": False}], None, None)
        applied = current is None or int(cast("int", current["aggregate_version"])) < int(
            cast("int", candidate["aggregate_version"])
        )
        if current is not None and current["aggregate_version"] == candidate["aggregate_version"]:
            applied = (
                current["projection_digest"] == candidate["projection_digest"]
                or parameters["allow_repair"] is True
            )
        if applied:
            self.edges[key] = dict(candidate)
        return (
            [{"edge": self.edges[key], "applied": applied, "created": created}],
            None,
            None,
        )

    def _visible_rows(
        self, parameters: dict[str, object], *, traversal: bool
    ) -> list[dict[str, object]]:
        brain_id = cast("str", parameters["brain_id"])
        generation_id = cast("str", parameters["generation_id"])
        project_ids = cast("list[str]", parameters["project_ids"])
        repository_ids = cast("list[str]", parameters["repository_ids"])
        classifications = cast("list[str]", parameters["classifications"])
        rows = [
            row
            for (brain, _, _), row in sorted(self.edges.items())
            if brain == brain_id
            and row["generation_id"] == generation_id
            and row["project_id"] in project_ids
            and row["repository_id"] in repository_ids
            and row["classification"] in classifications
        ]
        if traversal:
            relationship_types = cast("list[str]", parameters["relationship_types"])
            rows = [
                row
                for row in rows
                if row["subject_id"] == parameters["subject_id"]
                and row["relationship_type"] in relationship_types
                and row["projection_status"] == "active"
                and row["quarantined"] is False
                and row.get("recorded_to") is None
            ]
        return rows


def _repository(driver: _Driver, action: str) -> Neo4jMaterializedEdgeProjection:
    return Neo4jMaterializedEdgeProjection(
        cast("AsyncDriver", driver), "agentmemory", _scope(action)
    )


def _scope(action: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(PRINCIPAL_ID),
        role=RetrievalRole.WORKER if action != "graph.assertion.traverse" else RetrievalRole.READER,
        mode=RetrievalScopeMode.SELECTED,
        members=(
            ScopeMember(
                StableId(PROJECT_ID),
                (StableId(REPOSITORY_ID),),
                (StableId(CHECKOUT_ID),),
            ),
        ),
        classification_ceiling=Classification.INTERNAL,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="graph_projection_test",
    )


def _edge(assertion: Assertion, event_id: str, projected_at: datetime) -> MaterializedAssertionEdge:
    return MaterializedAssertionEdge.from_assertion(
        assertion,
        source_event_id=event_id,
        generation_id=GENERATION_ID,
        projected_at=projected_at,
    )


def _active(checkout_id: str | None = CHECKOUT_ID) -> Assertion:
    return _active_with_id(ASSERTION_ID, checkout_id)


def _active_with_id(assertion_id: str, checkout_id: str | None = CHECKOUT_ID) -> Assertion:
    scope = AssertionScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, checkout_id, "internal")
    evidence = ResolvedAssertionEvidence(
        evidence_id=EVIDENCE_ID,
        source_id=SOURCE_ID,
        kind=EvidenceKind.USER_STATEMENT,
        scope=scope,
        source_digest="c" * 64,
        occurred_at=NOW,
        accessible=True,
        deleted=False,
        immutable=True,
    )
    return AssertionCandidate.create(
        candidate_id=assertion_id,
        subject_id=SUBJECT_ID,
        predicate=AssertionPredicate.CONSUMES,
        object_id=OBJECT_ID,
        scope=scope,
        temporal=AssertionTemporal(NOW - timedelta(days=1), None, NOW, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor("graph.extractor", "1.0.0", "qwen3", "revision-1"),
        evidence_ids=(EVIDENCE_ID,),
    ).activate((evidence,), NOW)


def _document(edge: MaterializedAssertionEdge) -> dict[str, object]:
    return {key: value for key, value in edge.document().items() if value is not None}
