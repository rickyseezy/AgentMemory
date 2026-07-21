"""GRA-005 contradiction detection, resolution, and retrieval-policy tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from agentmemory.graph.domain.assertions import AssertionPolarity, AssertionPredicate
from agentmemory.graph.domain.contradictions import (
    AssertionAuthority,
    ContradictionCandidate,
    ContradictionDecision,
    ContradictionDetector,
    ContradictionPolicy,
    ContradictionResolution,
    ContradictionResolutionOutcome,
    ContradictionState,
    ContradictionValidationError,
    RetrievalAssertionCandidate,
)

NOW = datetime(2026, 7, 21, 9, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)
LEFT = "019f54aa-1111-7111-8111-111111111111"
RIGHT = "019f54aa-2222-7222-8222-222222222222"
THIRD = "019f54aa-3333-7333-8333-333333333333"
SUBJECT = "019f54aa-4444-7444-8444-444444444444"
OBJECT_A = "019f54aa-5555-7555-8555-555555555555"
OBJECT_B = "019f54aa-6666-7666-8666-666666666666"
EVIDENCE_A = "019f54aa-7777-7777-8777-777777777777"
EVIDENCE_B = "019f54aa-8888-7888-8888-888888888888"
ACTOR = "019f54aa-9999-7999-8999-999999999999"
GRANT = "019f54aa-aaaa-7aaa-8aaa-aaaaaaaaaaaa"


def _claim(  # noqa: PLR0913 -- Test factory exposes every conflict dimension.
    assertion_id: str,
    *,
    predicate: AssertionPredicate = AssertionPredicate.CALLS,
    object_id: str = OBJECT_A,
    polarity: AssertionPolarity = AssertionPolarity.POSITIVE,
    authority: AssertionAuthority = AssertionAuthority.EVIDENCE_BACKED,
    valid_from: datetime = NOW,
    valid_to: datetime | None = None,
    evidence_id: str = EVIDENCE_A,
) -> ContradictionCandidate:
    return ContradictionCandidate(
        assertion_id=assertion_id,
        subject_id=SUBJECT,
        predicate=predicate,
        object_id=object_id,
        polarity=polarity,
        authority=authority,
        valid_from=valid_from,
        valid_to=valid_to,
        evidence_ids=(evidence_id,),
        confidence_basis_points=9_000,
    )


def test_predicate_conflict_table_and_polarity_are_deterministic() -> None:
    positive = _claim(LEFT)
    negative = _claim(
        RIGHT,
        polarity=AssertionPolarity.NEGATIVE,
        evidence_id=EVIDENCE_B,
    )
    conflicts = ContradictionDetector.detect((negative, positive), NOW)
    assert len(conflicts) == 1
    assert conflicts[0].left_assertion_id == LEFT
    assert conflicts[0].right_assertion_id == RIGHT
    assert conflicts[0].dimension.value == "polarity"
    assert conflicts[0].evidence_ids == (EVIDENCE_A, EVIDENCE_B)

    exclusive = ContradictionDetector.detect(
        (
            _claim(LEFT, predicate=AssertionPredicate.DEPLOYED_AS),
            _claim(
                RIGHT,
                predicate=AssertionPredicate.DEPLOYED_AS,
                object_id=OBJECT_B,
                evidence_id=EVIDENCE_B,
            ),
        ),
        NOW,
    )
    assert [item.dimension.value for item in exclusive] == ["exclusive_object"]

    assert (
        ContradictionDetector.detect(
            (
                _claim(LEFT, predicate=AssertionPredicate.CALLS),
                _claim(RIGHT, predicate=AssertionPredicate.CALLS, object_id=OBJECT_B),
            ),
            NOW,
        )
        == ()
    )


def test_non_overlapping_time_and_model_only_candidates_do_not_create_false_conflicts() -> None:
    assert (
        ContradictionDetector.detect(
            (
                _claim(LEFT, valid_to=LATER),
                _claim(
                    RIGHT,
                    polarity=AssertionPolarity.NEGATIVE,
                    valid_from=LATER,
                    evidence_id=EVIDENCE_B,
                ),
            ),
            NOW,
        )
        == ()
    )
    assert (
        ContradictionDetector.detect(
            (
                _claim(LEFT),
                _claim(
                    RIGHT,
                    polarity=AssertionPolarity.NEGATIVE,
                    authority=AssertionAuthority.MODEL_ONLY,
                    evidence_id=EVIDENCE_B,
                ),
            ),
            NOW,
        )
        == ()
    )


def test_user_resolution_preserves_the_original_dispute() -> None:
    dispute = ContradictionDetector.detect(
        (
            _claim(LEFT),
            _claim(
                RIGHT,
                polarity=AssertionPolarity.NEGATIVE,
                evidence_id=EVIDENCE_B,
            ),
        ),
        NOW,
    )[0]
    resolution = ContradictionResolution.create(
        contradiction_id=dispute.id,
        outcome=ContradictionResolutionOutcome.LEFT_ASSERTION,
        actor_id=ACTOR,
        grant_id=GRANT,
        reason_code="user_confirmed",
        evidence_ids=(EVIDENCE_A,),
        resolved_at=LATER,
    )
    resolved = dispute.resolve(resolution)
    assert resolved.state is ContradictionState.RESOLVED
    assert resolved.resolution == resolution
    assert resolved.left_assertion_id == dispute.left_assertion_id
    assert resolved.right_assertion_id == dispute.right_assertion_id
    assert resolved.detected_at == dispute.detected_at
    with pytest.raises(ContradictionValidationError, match="resolution"):
        resolved.resolve(resolution)


def test_retrieval_abstains_on_unresolved_conflict_regardless_of_rank() -> None:
    dispute = ContradictionDetector.detect(
        (
            _claim(LEFT),
            _claim(
                RIGHT,
                polarity=AssertionPolarity.NEGATIVE,
                evidence_id=EVIDENCE_B,
            ),
        ),
        NOW,
    )[0]
    result = ContradictionPolicy.apply(
        (
            RetrievalAssertionCandidate(LEFT, 10_000, authoritative=True),
            RetrievalAssertionCandidate(RIGHT, 1, authoritative=True),
        ),
        (dispute,),
    )
    assert result.decision is ContradictionDecision.UNKNOWN
    assert result.selected_assertion_ids == ()
    assert result.disputed_assertion_ids == (LEFT, RIGHT)

    qualified = ContradictionPolicy.apply(
        (RetrievalAssertionCandidate(LEFT, 10_000, authoritative=True),),
        (dispute,),
    )
    assert qualified.decision is ContradictionDecision.QUALIFIED
    assert qualified.selected_assertion_ids == (LEFT,)

    resolved = dispute.resolve(
        ContradictionResolution.create(
            contradiction_id=dispute.id,
            outcome=ContradictionResolutionOutcome.LEFT_ASSERTION,
            actor_id=ACTOR,
            grant_id=GRANT,
            reason_code="user_confirmed",
            evidence_ids=(EVIDENCE_A,),
            resolved_at=LATER,
        )
    )
    certain = ContradictionPolicy.apply(
        (
            RetrievalAssertionCandidate(LEFT, 10_000, authoritative=True),
            RetrievalAssertionCandidate(RIGHT, 9_000, authoritative=True),
        ),
        (resolved,),
    )
    assert certain.decision is ContradictionDecision.CERTAIN
    assert certain.selected_assertion_ids == (LEFT,)


def test_contradiction_values_reject_forgery_and_noncanonical_inputs() -> None:
    with pytest.raises(ContradictionValidationError):
        _claim(LEFT, evidence_id="bad")
    with pytest.raises(ContradictionValidationError):
        ContradictionDetector.detect((_claim(LEFT), _claim(LEFT)), NOW)
    dispute = ContradictionDetector.detect(
        (
            _claim(LEFT),
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        ),
        NOW,
    )[0]
    with pytest.raises(ContradictionValidationError):
        replace(dispute, evidence_ids=(EVIDENCE_B, EVIDENCE_A))
    with pytest.raises(ContradictionValidationError):
        replace(dispute, detection_digest="0" * 64)


def test_candidate_validation_is_applied_during_construction() -> None:
    invalid_changes = (
        {"object_id": SUBJECT},
        {"evidence_ids": ()},
        {"evidence_ids": (EVIDENCE_A, EVIDENCE_A)},
        {"confidence_basis_points": True},
        {"confidence_basis_points": 10_001},
        {"valid_from": NOW.replace(tzinfo=None)},
        {"valid_to": NOW},
        {"assertion_id": cast("str", 1)},
        {"predicate": cast("AssertionPredicate", "calls")},
    )
    for changes in invalid_changes:
        with pytest.raises(ContradictionValidationError, match="candidate"):
            replace(_claim(LEFT), **changes)


def test_detection_rejects_oversized_and_forged_aggregates() -> None:
    claim = _claim(LEFT)
    with pytest.raises(ContradictionValidationError, match="detection"):
        ContradictionDetector.detect((claim,) * 2_001, NOW)

    dispute = ContradictionDetector.detect(
        (
            claim,
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        ),
        NOW,
    )[0]
    for changes in (
        {"left_assertion_id": dispute.right_assertion_id},
        {"policy_version": "forged"},
        {"state": ContradictionState.RESOLVED},
        {"id": "0" * 64},
    ):
        with pytest.raises(ContradictionValidationError):
            replace(dispute, **changes)


def test_resolution_rejects_invalid_authority_and_temporal_coordinates() -> None:
    dispute = ContradictionDetector.detect(
        (
            _claim(LEFT),
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        ),
        NOW,
    )[0]
    valid = ContradictionResolution.create(
        contradiction_id=dispute.id,
        outcome=ContradictionResolutionOutcome.LEFT_ASSERTION,
        actor_id=ACTOR,
        grant_id=GRANT,
        reason_code="user_confirmed",
        evidence_ids=(EVIDENCE_A,),
        resolved_at=LATER,
    )
    for changes in (
        {"reason_code": "INVALID REASON"},
        {"evidence_ids": ()},
        {"policy_version": "forged"},
        {"resolution_digest": "f" * 64},
    ):
        with pytest.raises(ContradictionValidationError, match="resolution"):
            replace(valid, **changes)

    too_early = ContradictionResolution.create(
        contradiction_id=dispute.id,
        outcome=ContradictionResolutionOutcome.LEFT_ASSERTION,
        actor_id=ACTOR,
        grant_id=GRANT,
        reason_code="user_confirmed",
        evidence_ids=(EVIDENCE_A,),
        resolved_at=NOW - timedelta(microseconds=1),
    )
    with pytest.raises(ContradictionValidationError, match="resolution"):
        dispute.resolve(too_early)
    with pytest.raises(ContradictionValidationError, match="resolution"):
        ContradictionResolution.create(
            contradiction_id=dispute.id,
            outcome=cast("ContradictionResolutionOutcome", "left_assertion"),
            actor_id=ACTOR,
            grant_id=GRANT,
            reason_code="user_confirmed",
            evidence_ids=(EVIDENCE_A,),
            resolved_at=LATER,
        )


def test_policy_covers_all_resolution_outcomes_and_irrelevant_disputes() -> None:
    dispute = ContradictionDetector.detect(
        (
            _claim(LEFT),
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        ),
        NOW,
    )[0]
    candidates = (
        RetrievalAssertionCandidate(LEFT, 9_000, authoritative=True),
        RetrievalAssertionCandidate(RIGHT, 8_000, authoritative=True),
    )
    expected = {
        ContradictionResolutionOutcome.RIGHT_ASSERTION: (RIGHT,),
        ContradictionResolutionOutcome.BOTH_VALID: (LEFT, RIGHT),
        ContradictionResolutionOutcome.NEITHER_VALID: (),
    }
    for outcome, selected in expected.items():
        resolved = dispute.resolve(
            ContradictionResolution.create(
                contradiction_id=dispute.id,
                outcome=outcome,
                actor_id=ACTOR,
                grant_id=GRANT,
                reason_code="user_confirmed",
                evidence_ids=(EVIDENCE_A,),
                resolved_at=LATER,
            )
        )
        assert ContradictionPolicy.apply(candidates, (resolved,)).selected_assertion_ids == selected

    irrelevant = ContradictionPolicy.apply(
        (RetrievalAssertionCandidate(THIRD, 1, authoritative=False),),
        (dispute,),
    )
    assert irrelevant.decision is ContradictionDecision.UNKNOWN
    assert irrelevant.contradiction_ids == ()

    with pytest.raises(ContradictionValidationError, match="policy"):
        RetrievalAssertionCandidate(LEFT, 1, authoritative=cast("bool", 1))
    duplicate = RetrievalAssertionCandidate(LEFT, 1, authoritative=True)
    with pytest.raises(ContradictionValidationError, match="policy"):
        ContradictionPolicy.apply((duplicate, duplicate), ())
