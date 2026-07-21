"""GRA-002 assertion aggregate TDD acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionEventType,
    AssertionEvidenceError,
    AssertionEvidenceReference,
    AssertionEvidenceRevocation,
    AssertionExtractor,
    AssertionLifecycleEvent,
    AssertionPredicate,
    AssertionScope,
    AssertionStatus,
    AssertionTemporal,
    AssertionTransitionError,
    AssertionValidationError,
    EvidenceKind,
    EvidenceRevocationReason,
    ResolvedAssertionEvidence,
)

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
SUBJECT_ID = "018f0000-0000-7000-8000-000000000030"
OBJECT_ID = "018f0000-0000-7000-8000-000000000031"
CANDIDATE_ID = "018f0000-0000-7000-8000-000000000040"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000050"
SECOND_EVIDENCE_ID = "018f0000-0000-7000-8000-000000000051"
SOURCE_ID = "018f0000-0000-7000-8000-000000000060"
SECOND_SOURCE_ID = "018f0000-0000-7000-8000-000000000061"


def test_proposal_is_deterministic_but_never_authoritative() -> None:
    candidate = _candidate(())
    assert candidate.status is AssertionStatus.CANDIDATE
    assert len(candidate.content_fingerprint) == 64
    assert candidate == _candidate(())
    with pytest.raises(AssertionEvidenceError, match="unavailable"):
        candidate.activate((), NOW + timedelta(seconds=1))
    with pytest.raises(AssertionEvidenceError, match="unresolved"):
        _candidate((EVIDENCE_ID,)).activate((), NOW + timedelta(seconds=1))


def test_explicit_user_evidence_activates_with_complete_lineage() -> None:
    evidence = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.USER_STATEMENT)
    assertion = _candidate((EVIDENCE_ID,), confidence=0).activate((evidence,), NOW)
    assert assertion.status is AssertionStatus.ACTIVE
    assert assertion.evidence == (evidence,)
    assert assertion.temporal.recorded_from == NOW
    assert assertion.subject_id == SUBJECT_ID
    assert assertion.predicate is AssertionPredicate.CONSUMES
    assert assertion.object_id == OBJECT_ID


def test_automated_activation_requires_threshold_and_two_independent_sources() -> None:
    first = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.EVENT)
    second = _evidence(SECOND_EVIDENCE_ID, SECOND_SOURCE_ID, EvidenceKind.SOURCE_SPAN)
    ids = (EVIDENCE_ID, SECOND_EVIDENCE_ID)
    assert _candidate(ids).activate((second, first), NOW).status is AssertionStatus.ACTIVE
    with pytest.raises(AssertionEvidenceError, match="policy"):
        _candidate(ids, confidence=6_999).activate((first, second), NOW)
    with pytest.raises(AssertionEvidenceError, match="policy"):
        _candidate((EVIDENCE_ID,)).activate((first,), NOW)


def test_inaccessible_deleted_mutable_or_out_of_scope_evidence_cannot_activate() -> None:
    valid = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.USER_STATEMENT)
    invalid = (
        replace(valid, accessible=False),
        replace(valid, deleted=True),
        replace(valid, immutable=False),
        replace(
            valid,
            scope=AssertionScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None, "restricted"),
        ),
    )
    for evidence in invalid:
        with pytest.raises(AssertionEvidenceError, match="unavailable"):
            _candidate((EVIDENCE_ID,)).activate((evidence,), NOW)


def test_removing_all_evidence_disputes_but_one_usable_source_keeps_active() -> None:
    evidence = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.USER_STATEMENT)
    active = _candidate((EVIDENCE_ID,)).activate((evidence,), NOW)
    assert active.reconcile_evidence((evidence,), NOW + timedelta(seconds=1)) is active
    disputed = active.reconcile_evidence(
        (replace(evidence, deleted=True),), NOW + timedelta(seconds=1)
    )
    assert disputed.status is AssertionStatus.DISPUTED
    assert disputed.temporal.recorded_to == NOW + timedelta(seconds=1)


def test_closed_predicate_confidence_temporal_and_evidence_schema_fail_closed() -> None:
    with pytest.raises(AssertionValidationError, match="predicate"):
        replace(_candidate(()), predicate=cast("AssertionPredicate", "reads"))
    for confidence in (-1, 10_001, True):
        with pytest.raises(AssertionValidationError, match="confidence"):
            AssertionConfidence(confidence, 9_000, 9_000)
    with pytest.raises(AssertionValidationError, match="interval"):
        AssertionTemporal(NOW, NOW, NOW, None)
    with pytest.raises(AssertionValidationError, match="endpoints"):
        replace(_candidate(()), object_id=SUBJECT_ID)
    with pytest.raises(AssertionValidationError, match="identities"):
        replace(_candidate((EVIDENCE_ID,)), evidence_ids=(EVIDENCE_ID, EVIDENCE_ID))


def test_temporal_policy_rejects_time_travel_and_future_evidence() -> None:
    evidence = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.USER_STATEMENT)
    with pytest.raises(AssertionEvidenceError, match="temporal policy"):
        _candidate((EVIDENCE_ID,)).activate((evidence,), NOW - timedelta(microseconds=1))
    with pytest.raises(AssertionEvidenceError, match="temporal policy"):
        _candidate((EVIDENCE_ID,)).activate(
            (replace(evidence, occurred_at=NOW + timedelta(seconds=1)),),
            NOW,
        )
    with pytest.raises(AssertionValidationError, match="interval"):
        replace(
            _candidate((EVIDENCE_ID,)),
            temporal=AssertionTemporal(NOW, None, NOW, NOW + timedelta(seconds=1)),
        )


def test_typed_evidence_reference_and_revocation_reject_free_form_sources() -> None:
    artifact_id = "018f0000-0000-7000-8000-000000000070"
    assert (
        AssertionEvidenceReference(
            EVIDENCE_ID,
            SOURCE_ID,
            EvidenceKind.SOURCE_SPAN,
            artifact_id,
            0,
            10,
        ).span_end
        == 10
    )
    for invalid in (
        (EvidenceKind.EVENT, artifact_id, None, None),
        (EvidenceKind.SOURCE_SPAN, artifact_id, 10, 10),
        (EvidenceKind.ARTIFACT, None, None, None),
    ):
        with pytest.raises(AssertionValidationError, match="reference"):
            AssertionEvidenceReference(EVIDENCE_ID, SOURCE_ID, *invalid)
    assert (
        AssertionEvidenceRevocation(
            "assertion-revoke-1",
            EVIDENCE_ID,
            EvidenceRevocationReason.USER_RETRACTED,
            NOW,
        ).reason
        is EvidenceRevocationReason.USER_RETRACTED
    )


def test_authoritative_and_event_invariants_reject_forged_runtime_values() -> None:
    evidence = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.USER_STATEMENT)
    candidate = _candidate((EVIDENCE_ID,))
    active = candidate.activate((evidence,), NOW)
    with pytest.raises(AssertionValidationError, match="candidate status"):
        replace(candidate, status=AssertionStatus.ACTIVE)
    with pytest.raises(AssertionValidationError, match="fingerprint"):
        replace(candidate, content_fingerprint="b" * 64)
    with pytest.raises(AssertionValidationError, match="status"):
        replace(active, status=AssertionStatus.CANDIDATE)
    with pytest.raises(AssertionValidationError, match="evidence is required"):
        replace(active, evidence=())
    disputed = active.reconcile_evidence((), NOW + timedelta(seconds=1))
    with pytest.raises(AssertionTransitionError, match="only active"):
        disputed.reconcile_evidence((), NOW + timedelta(seconds=2))

    event = AssertionLifecycleEvent.create(
        event_id="018f0000-0000-7000-8000-000000000071",
        operation_id="assertion-event-1",
        assertion=active,
        event_type=AssertionEventType.ACTIVATED,
        occurred_at=NOW,
    )
    with pytest.raises(AssertionValidationError, match="event is invalid"):
        replace(event, evidence_ids=(EVIDENCE_ID, EVIDENCE_ID))
    with pytest.raises(AssertionValidationError, match="event is invalid"):
        replace(event, status=AssertionStatus.DISPUTED)
    with pytest.raises(AssertionValidationError, match="event is invalid"):
        replace(event, operation_id="UPPERCASE INVALID")


def test_assertion_and_lifecycle_digests_match_the_versioned_golden_vector() -> None:
    """Freeze canonical hashing so every adapter and future release agrees exactly."""
    candidate = _candidate((EVIDENCE_ID,))
    evidence = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.USER_STATEMENT)
    active = candidate.activate((evidence,), NOW)
    event = AssertionLifecycleEvent.create(
        event_id="018f0000-0000-7000-8000-000000000071",
        operation_id="assertion-event-1",
        assertion=active,
        event_type=AssertionEventType.ACTIVATED,
        occurred_at=NOW,
    )

    assert candidate.content_fingerprint == (
        "2823de7a29ac703fa53c651966aff3c8298250fa3465cff996c3344f12bec3e0"
    )
    assert candidate.revision_id == (
        "0bcbb1eb061377a27e7f9fdb4ba4afb51af17478fd1134a1d0d6ca73cdb5e276"
    )
    assert event.digest == ("526b0d4b5c45a75b2acff09abd727d0df378de0737734e87571bdbabc68d8d28")


def test_scope_evidence_and_extractor_runtime_types_fail_closed() -> None:
    checkout_id = "018f0000-0000-7000-8000-000000000080"
    assert (
        AssertionScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, checkout_id, "internal").checkout_id
        == checkout_id
    )
    with pytest.raises(AssertionValidationError, match="classification"):
        AssertionScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None, "secret")
    with pytest.raises(AssertionValidationError, match="extractor"):
        AssertionExtractor("UPPER", "1.0.0", "qwen3", "revision-1")
    evidence = _evidence(EVIDENCE_ID, SOURCE_ID, EvidenceKind.EVENT)
    with pytest.raises(AssertionValidationError, match="kind"):
        replace(evidence, kind=cast("EvidenceKind", "url"))
    with pytest.raises(AssertionValidationError, match="state"):
        replace(evidence, accessible=cast("bool", 1))
    with pytest.raises(AssertionValidationError, match="digest"):
        replace(evidence, source_digest="0" * 64)
    with pytest.raises(AssertionValidationError, match="revocation"):
        AssertionEvidenceRevocation(
            "assertion-revoke-invalid",
            EVIDENCE_ID,
            cast("EvidenceRevocationReason", "free_form"),
            NOW,
        )
    with pytest.raises(AssertionValidationError, match="not UTC"):
        replace(evidence, occurred_at=NOW.replace(tzinfo=None))


def _candidate(evidence_ids: tuple[str, ...], confidence: int = 9_000) -> AssertionCandidate:
    return AssertionCandidate.create(
        candidate_id=CANDIDATE_ID,
        subject_id=SUBJECT_ID,
        predicate=AssertionPredicate.CONSUMES,
        object_id=OBJECT_ID,
        scope=AssertionScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None, "internal"),
        temporal=AssertionTemporal(NOW, None, NOW, None),
        confidence=AssertionConfidence(confidence, confidence, confidence),
        extractor=AssertionExtractor("graph.extractor", "1.0.0", "qwen3", "revision-1"),
        evidence_ids=evidence_ids,
    )


def _evidence(
    evidence_id: str,
    source_id: str,
    kind: EvidenceKind,
) -> ResolvedAssertionEvidence:
    return ResolvedAssertionEvidence(
        evidence_id=evidence_id,
        source_id=source_id,
        kind=kind,
        scope=AssertionScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None, "internal"),
        source_digest="a" * 64,
        occurred_at=NOW,
        accessible=True,
        deleted=False,
        immutable=True,
    )
