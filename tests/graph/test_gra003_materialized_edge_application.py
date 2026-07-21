"""GRA-003 materialization, integrity repair, and traversal application tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

import pytest

from agentmemory.graph.application.materialized_edges import (
    MaterializeAssertionEdgeCommand,
    MaterializeAssertionEdgeHandler,
    TraverseAssertionEdgesHandler,
    TraverseAssertionEdgesQuery,
    ValidateAssertionEdgesCommand,
    ValidateAssertionEdgesHandler,
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
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphIntegrityError
from agentmemory.graph.domain.materialized_edges import (
    EdgeIntegrityFinding,
    EdgeIntegrityFindingKind,
    MaterializedAssertionEdge,
    MaterializedEdgeWriteResult,
    ProjectionEdgeStatus,
    TraversalEdgeExplanation,
)
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

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000021"
OTHER_CHECKOUT_ID = "018f0000-0000-7000-8000-000000000022"
SUBJECT_ID = "018f0000-0000-7000-8000-000000000030"
OBJECT_ID = "018f0000-0000-7000-8000-000000000031"
ASSERTION_ID = "018f0000-0000-7000-8000-000000000040"
ORPHAN_ID = "018f0000-0000-7000-8000-000000000041"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000050"
SOURCE_ID = "018f0000-0000-7000-8000-000000000060"
ACTIVATED_EVENT_ID = "018f0000-0000-7000-8000-000000000070"
DISPUTED_EVENT_ID = "018f0000-0000-7000-8000-000000000071"
GENERATION_ID = "a" * 64


@pytest.mark.asyncio
async def test_activation_event_materializes_complete_current_edge() -> None:
    source = _Source(_active(), ACTIVATED_EVENT_ID, NOW)
    projection = _Projection()
    edge = await MaterializeAssertionEdgeHandler(source, projection).execute(
        MaterializeAssertionEdgeCommand(
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
            GENERATION_ID,
            _scope("graph.assertion.materialize"),
        )
    )
    assert edge.projection_status is ProjectionEdgeStatus.ACTIVE
    assert projection.values[ASSERTION_ID] == edge
    assert source.trigger_ids == [ACTIVATED_EVENT_ID]


@pytest.mark.asyncio
async def test_delayed_activation_after_invalidation_projects_latest_retirement() -> None:
    disputed = _active().reconcile_evidence((), NOW + timedelta(seconds=1))
    source = _Source(disputed, DISPUTED_EVENT_ID, NOW + timedelta(seconds=1))
    projection = _Projection()
    edge = await MaterializeAssertionEdgeHandler(source, projection).execute(
        MaterializeAssertionEdgeCommand(
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
            GENERATION_ID,
            _scope("graph.assertion.materialize"),
        )
    )
    assert edge.source_event_id == DISPUTED_EVENT_ID
    assert edge.projection_status is ProjectionEdgeStatus.RETIRED
    assert edge.aggregate_version == 2


@pytest.mark.asyncio
async def test_integrity_worker_quarantines_orphan_and_repairs_missing_edge() -> None:
    expected = _edge(_active(), ACTIVATED_EVENT_ID)
    orphan = _edge(replace(_active(), id=ORPHAN_ID), ACTIVATED_EVENT_ID)
    source = _Source(_active(), ACTIVATED_EVENT_ID, NOW, expected=(expected,))
    projection = _Projection(values={ORPHAN_ID: orphan})
    journal = _Journal()
    kinds = await ValidateAssertionEdgesHandler(source, projection, journal).execute(
        ValidateAssertionEdgesCommand(
            GENERATION_ID,
            NOW + timedelta(seconds=2),
            _scope("graph.assertion.edge.integrity"),
        )
    )
    assert kinds == (EdgeIntegrityFindingKind.MISSING, EdgeIntegrityFindingKind.ORPHAN)
    assert projection.values[ASSERTION_ID] == expected
    assert projection.values[ORPHAN_ID].quarantined
    assert len(journal.findings) == len(journal.repairs) == 2


@pytest.mark.asyncio
async def test_branch_scope_mismatch_is_repaired_from_canonical_expectation() -> None:
    expected = _edge(_active(CHECKOUT_ID), ACTIVATED_EVENT_ID)
    mismatch = _edge(_active(OTHER_CHECKOUT_ID), ACTIVATED_EVENT_ID)
    source = _Source(_active(CHECKOUT_ID), ACTIVATED_EVENT_ID, NOW, expected=(expected,))
    projection = _Projection(values={ASSERTION_ID: mismatch})
    journal = _Journal()
    kinds = await ValidateAssertionEdgesHandler(source, projection, journal).execute(
        ValidateAssertionEdgesCommand(
            GENERATION_ID,
            NOW + timedelta(seconds=2),
            _scope("graph.assertion.edge.integrity", (CHECKOUT_ID, OTHER_CHECKOUT_ID)),
        )
    )
    assert kinds == (EdgeIntegrityFindingKind.MISMATCH,)
    assert projection.values[ASSERTION_ID].checkout_id == CHECKOUT_ID


@pytest.mark.asyncio
async def test_traversal_returns_assertion_explanation_and_rejects_malformed_results() -> None:
    edge = _edge(_active(), ACTIVATED_EVENT_ID)
    projection = _Projection(values={ASSERTION_ID: edge})
    query = TraverseAssertionEdgesQuery(
        SUBJECT_ID,
        (GraphRelationshipType.CONSUMES,),
        GENERATION_ID,
        10,
        _scope("graph.assertion.traverse"),
    )
    result = await TraverseAssertionEdgesHandler(projection).execute(query)
    assert result == (TraversalEdgeExplanation.from_edge(edge),)
    assert result[0].assertion_id == ASSERTION_ID

    projection.traversal_override = (
        replace(result[0], relationship_type=GraphRelationshipType.IMPORTS),
    )
    with pytest.raises(GraphIntegrityError, match="does not match"):
        await TraverseAssertionEdgesHandler(projection).execute(query)


@pytest.mark.asyncio
async def test_commands_fail_closed_on_action_generation_and_projection_receipt() -> None:
    handler = MaterializeAssertionEdgeHandler(
        _Source(_active(), ACTIVATED_EVENT_ID, NOW), _Projection()
    )
    with pytest.raises(GraphAuthorizationError, match="action"):
        await handler.execute(
            MaterializeAssertionEdgeCommand(
                ACTIVATED_EVENT_ID,
                ASSERTION_ID,
                GENERATION_ID,
                _scope("graph.read"),
            )
        )
    for invalid_generation in (None, "a" * 63, "g" * 64, "0" * 64):
        with pytest.raises(GraphIntegrityError, match="generation"):
            MaterializeAssertionEdgeCommand(
                ACTIVATED_EVENT_ID,
                ASSERTION_ID,
                invalid_generation,  # type: ignore[arg-type]
                _scope("graph.assertion.materialize"),
            )
    corrupt = _Projection(corrupt_receipt=True)
    with pytest.raises(GraphIntegrityError, match="does not match"):
        await MaterializeAssertionEdgeHandler(
            _Source(_active(), ACTIVATED_EVENT_ID, NOW), corrupt
        ).execute(
            MaterializeAssertionEdgeCommand(
                ACTIVATED_EVENT_ID,
                ASSERTION_ID,
                GENERATION_ID,
                _scope("graph.assertion.materialize"),
            )
        )


@dataclass(slots=True)
class _Source:
    assertion: Assertion
    event_id: str
    occurred_at: datetime
    expected: tuple[MaterializedAssertionEdge, ...] = ()
    trigger_ids: list[str] = field(default_factory=list[str])

    async def current_for_event(
        self, scope: AuthorizedScope, source_event_id: str, assertion_id: str
    ) -> tuple[Assertion, str, datetime]:
        del scope
        assert assertion_id == self.assertion.id
        self.trigger_ids.append(source_event_id)
        return self.assertion, self.event_id, self.occurred_at

    async def expected_edges(
        self, scope: AuthorizedScope, generation_id: str, projected_at: datetime
    ) -> tuple[MaterializedAssertionEdge, ...]:
        del scope, projected_at
        assert generation_id == GENERATION_ID
        return self.expected


@dataclass(slots=True)
class _Projection:
    values: dict[str, MaterializedAssertionEdge] = field(
        default_factory=dict[str, MaterializedAssertionEdge]
    )
    corrupt_receipt: bool = False
    traversal_override: tuple[TraversalEdgeExplanation, ...] | None = None

    def projection(self, scope: AuthorizedScope) -> _Projection:
        del scope
        return self

    async def project(self, edge: MaterializedAssertionEdge) -> MaterializedEdgeWriteResult:
        current = self.values.get(edge.assertion_id)
        applied = current is None or current.aggregate_version <= edge.aggregate_version
        if applied:
            self.values[edge.assertion_id] = edge
        digest = "b" * 64 if self.corrupt_receipt else edge.projection_digest
        return MaterializedEdgeWriteResult(edge.assertion_id, digest, applied, current is None)

    async def list_edges(self, generation_id: str) -> tuple[MaterializedAssertionEdge, ...]:
        assert generation_id == GENERATION_ID
        return tuple(self.values[key] for key in sorted(self.values))

    async def quarantine(
        self,
        assertion_id: str,
        generation_id: str,
        reason: str,
        at: datetime,
    ) -> None:
        del at
        assert generation_id == GENERATION_ID
        self.values[assertion_id] = self.values[assertion_id].quarantine(reason)

    async def traverse(
        self,
        subject_id: str,
        relationship_types: tuple[GraphRelationshipType, ...],
        generation_id: str,
        limit: int,
    ) -> tuple[TraversalEdgeExplanation, ...]:
        if self.traversal_override is not None:
            return self.traversal_override
        return tuple(
            TraversalEdgeExplanation.from_edge(edge)
            for edge in self.values.values()
            if edge.subject_id == subject_id
            and edge.relationship_type in relationship_types
            and edge.generation_id == generation_id
            and edge.retrieval_visible
        )[:limit]


@dataclass(slots=True)
class _Journal:
    findings: list[EdgeIntegrityFinding] = field(default_factory=list[EdgeIntegrityFinding])
    repairs: list[EdgeIntegrityFinding] = field(default_factory=list[EdgeIntegrityFinding])

    async def record(
        self, scope: AuthorizedScope, findings: tuple[EdgeIntegrityFinding, ...]
    ) -> None:
        del scope
        self.findings.extend(findings)

    async def repaired(
        self, scope: AuthorizedScope, finding: EdgeIntegrityFinding, repaired_at: datetime
    ) -> None:
        del scope, repaired_at
        self.repairs.append(finding)


def _edge(assertion: Assertion, event_id: str) -> MaterializedAssertionEdge:
    return MaterializedAssertionEdge.from_assertion(
        assertion,
        source_event_id=event_id,
        generation_id=GENERATION_ID,
        projected_at=NOW,
    )


def _active(checkout_id: str | None = None) -> Assertion:
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
        candidate_id=ASSERTION_ID,
        subject_id=SUBJECT_ID,
        predicate=AssertionPredicate.CONSUMES,
        object_id=OBJECT_ID,
        scope=scope,
        temporal=AssertionTemporal(NOW - timedelta(days=1), None, NOW, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor("graph.extractor", "1.0.0", "qwen3", "revision-1"),
        evidence_ids=(EVIDENCE_ID,),
    ).activate((evidence,), NOW)


def _scope(action: str, checkout_ids: tuple[str, ...] = ()) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(PRINCIPAL_ID),
        role=RetrievalRole.WORKER if action != "graph.assertion.traverse" else RetrievalRole.READER,
        mode=RetrievalScopeMode.SELECTED,
        members=(
            ScopeMember(
                StableId(PROJECT_ID),
                (StableId(REPOSITORY_ID),),
                tuple(StableId(value) for value in checkout_ids),
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
