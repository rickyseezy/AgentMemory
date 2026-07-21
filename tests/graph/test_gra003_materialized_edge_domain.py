"""GRA-003 materialized-edge domain acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

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
from agentmemory.graph.domain.errors import GraphValidationError
from agentmemory.graph.domain.materialized_edges import (
    EdgeIntegrityFindingKind,
    EdgeIntegrityPolicy,
    MaterializedAssertionEdge,
    PredicateRegistry,
    ProjectionEdgeStatus,
)
from agentmemory.graph.domain.models import GraphRelationshipType

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000021"
SUBJECT_ID = "018f0000-0000-7000-8000-000000000030"
OBJECT_ID = "018f0000-0000-7000-8000-000000000031"
ASSERTION_ID = "018f0000-0000-7000-8000-000000000040"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000050"
SOURCE_ID = "018f0000-0000-7000-8000-000000000060"
EVENT_ID = "018f0000-0000-7000-8000-000000000070"
GENERATION_ID = "a" * 64


def test_every_supported_predicate_has_one_closed_relationship_mapping() -> None:
    expected = {
        AssertionPredicate.CALLS: GraphRelationshipType.CALLS,
        AssertionPredicate.IMPORTS: GraphRelationshipType.IMPORTS,
        AssertionPredicate.CONSUMES: GraphRelationshipType.CONSUMES,
        AssertionPredicate.IMPLEMENTS: GraphRelationshipType.IMPLEMENTS,
        AssertionPredicate.DEPENDS_ON: GraphRelationshipType.DEPENDS_ON,
        AssertionPredicate.PRODUCES: GraphRelationshipType.PRODUCES,
        AssertionPredicate.DEPLOYED_AS: GraphRelationshipType.DEPLOYED_AS,
    }
    assert {
        item: PredicateRegistry.relationship_type(item) for item in AssertionPredicate
    } == expected
    with pytest.raises(GraphValidationError, match="predicate"):
        PredicateRegistry.relationship_type(cast("AssertionPredicate", "MATCH (n) RETURN n"))


def test_active_assertion_materializes_complete_authority_and_branch_metadata() -> None:
    edge = _edge(checkout_id=CHECKOUT_ID)
    assert edge.assertion_id == ASSERTION_ID
    assert edge.id != edge.assertion_id
    assert edge.relationship_type is GraphRelationshipType.CONSUMES
    assert edge.checkout_id == CHECKOUT_ID
    assert edge.aggregate_version == 1
    assert edge.projection_status is ProjectionEdgeStatus.ACTIVE
    assert edge.retrieval_visible
    assert edge.document()["assertion_id"] == ASSERTION_ID
    assert edge.document()["created_at"] == edge.recorded_from
    assert edge.document()["revision_id"] == edge.assertion_revision_id
    assert edge == MaterializedAssertionEdge.from_document(edge.document())


def test_materialized_edge_identity_and_projection_digest_match_golden_vector() -> None:
    edge = _edge(checkout_id=CHECKOUT_ID)
    assert edge.id == "11eb649e-cb77-7690-9a31-0cd26b877006"
    assert edge.projection_digest == (
        "dd2d410c559a2a5b18f024ffb7442ff78c79f7db9b8b407ff63e2f4eddc170ff"
    )


def test_disputed_assertion_retires_only_its_edge_and_closes_recorded_time() -> None:
    active = _active()
    disputed = active.reconcile_evidence((), NOW + timedelta(seconds=1))
    edge = MaterializedAssertionEdge.from_assertion(
        disputed,
        source_event_id=EVENT_ID,
        generation_id=GENERATION_ID,
        projected_at=NOW + timedelta(seconds=1),
    )
    assert edge.aggregate_version == 2
    assert edge.projection_status is ProjectionEdgeStatus.RETIRED
    assert edge.recorded_to == NOW + timedelta(seconds=1)
    assert not edge.retrieval_visible


def test_quarantine_excludes_edge_without_changing_authoritative_projection_digest() -> None:
    edge = _edge()
    quarantined = edge.quarantine("orphan_assertion")
    assert quarantined.quarantined
    assert quarantined.quarantine_reason == "orphan_assertion"
    assert quarantined.projection_digest == edge.projection_digest
    assert not quarantined.retrieval_visible
    with pytest.raises(GraphValidationError, match="quarantine"):
        replace(edge, quarantined=True, quarantine_reason="free form reason")


def test_reverse_integrity_checks_find_missing_orphan_and_mismatch_deterministically() -> None:
    expected = _edge()
    orphan_id = "018f0000-0000-7000-8000-000000000041"
    orphan = MaterializedAssertionEdge.from_assertion(
        replace(_active(), id=orphan_id),
        source_event_id=EVENT_ID,
        generation_id=GENERATION_ID,
        projected_at=NOW,
    )
    missing = EdgeIntegrityPolicy.evaluate((expected,), (), NOW)
    assert [item.kind for item in missing] == [EdgeIntegrityFindingKind.MISSING]

    orphaned = EdgeIntegrityPolicy.evaluate((), (orphan,), NOW)
    assert [item.kind for item in orphaned] == [EdgeIntegrityFindingKind.ORPHAN]

    divergent = _edge(CHECKOUT_ID)
    mismatch = EdgeIntegrityPolicy.evaluate((expected,), (divergent,), NOW)
    assert [item.kind for item in mismatch] == [EdgeIntegrityFindingKind.MISMATCH]
    assert (
        mismatch[0].id
        == EdgeIntegrityPolicy.evaluate((expected,), (divergent,), NOW + timedelta(seconds=1))[0].id
    )
    assert EdgeIntegrityPolicy.evaluate((), (orphan.quarantine("orphan_assertion"),), NOW) == ()


def test_edge_schema_rejects_forged_scope_time_generation_and_digest() -> None:
    edge = _edge()
    invalid = (
        ({"generation_id": "0" * 64}, "generation"),
        ({"generation_id": "a" * 63}, "generation"),
        ({"assertion_revision_id": "g" * 64}, "generation"),
        ({"projection_digest": "b" * 64}, "integrity"),
        ({"aggregate_version": 2}, "version"),
        ({"schema_version": 2}, "version"),
        ({"projected_at": NOW.replace(tzinfo=None)}, "time"),
        ({"subject_id": OBJECT_ID}, "scope"),
    )
    for changes, message in invalid:
        with pytest.raises(GraphValidationError, match=message):
            replace(edge, **changes)
    with pytest.raises(GraphValidationError, match="document"):
        MaterializedAssertionEdge.from_document({**edge.document(), "quarantined": 1})


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", 1),
        ("aggregate_version", True),
        ("quarantined", 1),
        ("checkout_id", 1),
        ("valid_to", 1),
    ],
)
def test_untrusted_document_decoder_reports_the_exact_invalid_field(
    key: str,
    value: object,
) -> None:
    document = {**_edge().document(), key: value}
    with pytest.raises(GraphValidationError, match="document") as error:
        MaterializedAssertionEdge.from_document(document)
    assert isinstance(error.value.__cause__, TypeError)
    assert error.value.__cause__.args == (key,)


def test_duplicate_projected_facts_produce_one_deterministic_repair_finding() -> None:
    expected = _edge()
    duplicate = _edge(CHECKOUT_ID)
    findings = EdgeIntegrityPolicy.evaluate((expected,), (expected, duplicate), NOW)
    assert len(findings) == 1
    assert findings[0].kind is EdgeIntegrityFindingKind.MISMATCH
    assert findings[0].actual_digest not in {
        expected.projection_digest,
        duplicate.projection_digest,
    }

    with pytest.raises(GraphValidationError, match="integrity"):
        EdgeIntegrityPolicy.evaluate((expected, expected), (), NOW)


def _edge(checkout_id: str | None = None) -> MaterializedAssertionEdge:
    return MaterializedAssertionEdge.from_assertion(
        _active(checkout_id),
        source_event_id=EVENT_ID,
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
    candidate = AssertionCandidate.create(
        candidate_id=ASSERTION_ID,
        subject_id=SUBJECT_ID,
        predicate=AssertionPredicate.CONSUMES,
        object_id=OBJECT_ID,
        scope=scope,
        temporal=AssertionTemporal(NOW - timedelta(days=1), None, NOW, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor("graph.extractor", "1.0.0", "qwen3", "revision-1"),
        evidence_ids=(EVIDENCE_ID,),
    )
    return candidate.activate((evidence,), NOW)
