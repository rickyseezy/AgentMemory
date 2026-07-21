"""GRA-004 bitemporal scope, revision graph, and evidence policy tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from agentmemory.graph.domain.assertions import AssertionPredicate
from agentmemory.graph.domain.errors import GraphValidationError
from agentmemory.graph.domain.temporal_truth import (
    EvidenceRevisionAnchor,
    EvidenceRevisionImpact,
    ResolvedVcsRevision,
    RevisionApplicability,
    RevisionEvidencePolicy,
    RevisionEvidenceProof,
    TemporalAssertionCandidate,
    TemporalAssertionCriteria,
    TemporalAssertionExplanation,
    TemporalAssertionResult,
    TemporalTruthMode,
    TruthCurrency,
    TruthTemporalScope,
    VcsRefObservation,
    VcsRevisionBatch,
    VcsRevisionNode,
    VcsRevisionSelector,
)
from tests.graph.test_gra003_materialized_edge_application import (
    ACTIVATED_EVENT_ID,
    _active,  # pyright: ignore[reportPrivateUsage]
)

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
OTHER_REPOSITORY_ID = "018f0000-0000-7000-8000-000000000021"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000030"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000040"
ROOT = "1" * 40
MAIN = "2" * 40
FEATURE = "3" * 40
MERGE = "4" * 40


def test_temporal_scope_requires_explicit_current_or_at_least_one_historical_axis() -> None:
    assert TruthTemporalScope.current().evaluation_times(NOW) == (NOW, NOW)
    historical = TruthTemporalScope.historical(
        as_of_valid=NOW - timedelta(days=1),
        revision=VcsRevisionSelector(REPOSITORY_ID, branch_name="feature/api"),
    )
    assert historical.mode is TemporalTruthMode.HISTORICAL
    assert historical.evaluation_times(NOW) == (NOW - timedelta(days=1), NOW)

    with pytest.raises(GraphValidationError, match="scope"):
        TruthTemporalScope(TemporalTruthMode.HISTORICAL)
    with pytest.raises(GraphValidationError, match="scope"):
        TruthTemporalScope(TemporalTruthMode.CURRENT, as_of_recorded=NOW)
    with pytest.raises(GraphValidationError, match="scope"):
        TruthTemporalScope.historical(as_of_valid=NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    ("branch", "commit"),
    [
        (None, None),
        ("main", MAIN),
        ("bad\nbranch", None),
        (None, "not-a-commit"),
    ],
)
def test_revision_selector_requires_exactly_one_safe_branch_or_commit(
    branch: str | None,
    commit: str | None,
) -> None:
    with pytest.raises(GraphValidationError, match="revision"):
        VcsRevisionSelector(REPOSITORY_ID, branch, commit)
    assert VcsRevisionSelector(REPOSITORY_ID, branch_name="main").branch_name == "main"
    assert VcsRevisionSelector(REPOSITORY_ID, commit_sha=MAIN).commit_sha == MAIN


def test_revision_batch_binds_complete_dag_refs_and_impacts_to_stable_digest() -> None:
    batch = _batch()
    assert batch.digest == "165d369950a8272891fc26bbcffa793be4164bd90aa947dfaa99566a3767b123"
    assert batch.refs[0].id == "d346d75615a50b81fe2c478c497be39e1c640d14eac615ae29cffbea27e12973"
    assert batch.impacts[0].id == (
        "674196b51db57227a431a0b9ef03c289d1c8dd1b47349036be85f3424256cc1e"
    )

    with pytest.raises(GraphValidationError, match="batch"):
        replace(batch, nodes=tuple(reversed(batch.nodes)))
    incremental = replace(
        batch,
        nodes=(VcsRevisionNode(MAIN, ("5" * 40,)),),
        refs=(),
        impacts=(),
    )
    assert incremental.nodes[0].parent_shas == ("5" * 40,)
    ref_only = replace(batch, nodes=(), impacts=())
    assert ref_only.refs == batch.refs
    with pytest.raises(GraphValidationError, match="batch"):
        replace(batch, nodes=(), refs=(), impacts=())


def test_revision_policy_distinguishes_global_reachable_unreachable_and_stale_evidence() -> None:
    selector = VcsRevisionSelector(REPOSITORY_ID, branch_name="main")
    resolved = ResolvedVcsRevision(
        selector,
        MERGE,
        "a" * 64,
        NOW,
        "b" * 64,
        force_pushed=False,
    )
    anchor = EvidenceRevisionAnchor(
        EVIDENCE_ID,
        REPOSITORY_ID,
        CHECKOUT_ID,
        MAIN,
        "main",
        NOW - timedelta(days=1),
    )
    global_proof = RevisionEvidencePolicy.proof(
        EVIDENCE_ID,
        None,
        resolved,
        anchor_reachable=False,
        reachable_invalidations=(),
    )
    assert global_proof.applicability is RevisionApplicability.UNVERSIONED
    assert global_proof.supports_revision

    reachable = RevisionEvidencePolicy.proof(
        EVIDENCE_ID,
        anchor,
        resolved,
        anchor_reachable=True,
        reachable_invalidations=(),
    )
    assert reachable.applicability is RevisionApplicability.REACHABLE

    unreachable = RevisionEvidencePolicy.proof(
        EVIDENCE_ID,
        replace(anchor, repository_id=OTHER_REPOSITORY_ID),
        resolved,
        anchor_reachable=True,
        reachable_invalidations=(),
    )
    assert unreachable.applicability is RevisionApplicability.UNREACHABLE
    assert not unreachable.supports_revision

    stale = RevisionEvidencePolicy.proof(
        EVIDENCE_ID,
        anchor,
        resolved,
        anchor_reachable=True,
        reachable_invalidations=(FEATURE,),
    )
    assert stale.applicability is RevisionApplicability.STALE
    assert not stale.supports_revision
    assert RevisionEvidencePolicy.assertion_supported((stale, global_proof))
    assert not RevisionEvidencePolicy.assertion_supported((stale, unreachable))


def test_revision_batch_rejects_duplicate_future_and_malformed_observations() -> None:
    batch = _batch()
    with pytest.raises(GraphValidationError, match="batch"):
        replace(batch, refs=(batch.refs[0], batch.refs[0]))
    with pytest.raises(GraphValidationError, match="batch"):
        replace(batch, impacts=(batch.impacts[0], batch.impacts[0]))
    with pytest.raises(GraphValidationError, match="batch"):
        replace(
            batch,
            refs=(replace(batch.refs[0], observed_at=NOW + timedelta(seconds=1)),),
        )
    with pytest.raises(GraphValidationError, match="batch"):
        replace(batch, operation_id="bad operation")
    with pytest.raises(GraphValidationError, match="batch"):
        replace(batch, source_digest="0" * 64)
    with pytest.raises(GraphValidationError, match="batch"):
        VcsRevisionNode(MAIN, (MAIN,))


def test_revision_proof_and_resolution_reject_contradictory_coordinates() -> None:
    branch = VcsRevisionSelector(REPOSITORY_ID, branch_name="main")
    commit = VcsRevisionSelector(REPOSITORY_ID, commit_sha=MAIN)
    with pytest.raises(GraphValidationError, match="proof"):
        ResolvedVcsRevision(branch, MAIN, "a" * 64, NOW, None, force_pushed=False)
    with pytest.raises(GraphValidationError, match="proof"):
        ResolvedVcsRevision(commit, MAIN, "a" * 64, NOW, "b" * 64, force_pushed=False)
    with pytest.raises(GraphValidationError, match="proof"):
        ResolvedVcsRevision(
            branch,
            MAIN,
            "a" * 64,
            NOW,
            "b" * 64,
            cast("bool", "false"),
        )
    with pytest.raises(GraphValidationError, match="proof"):
        RevisionEvidenceProof(
            EVIDENCE_ID,
            RevisionApplicability.STALE,
            MAIN,
            MERGE,
            (),
            "a" * 64,
        )
    with pytest.raises(GraphValidationError, match="proof"):
        RevisionEvidenceProof(
            EVIDENCE_ID,
            RevisionApplicability.UNVERSIONED,
            MAIN,
            MERGE,
            (),
            "a" * 64,
        )
    with pytest.raises(GraphValidationError, match="proof"):
        RevisionEvidenceProof(
            EVIDENCE_ID,
            RevisionApplicability.STALE,
            MAIN,
            MERGE,
            (FEATURE, ROOT),
            "a" * 64,
        )


def test_temporal_criteria_candidate_and_explanation_are_internally_consistent() -> None:
    TemporalAssertionCriteria(
        None,
        None,
        (AssertionPredicate.CALLS,),
        NOW,
        NOW,
        1,
    )
    with pytest.raises(GraphValidationError, match="scope"):
        TemporalAssertionCriteria(
            None,
            None,
            (cast("AssertionPredicate", "CALLS"),),
            NOW,
            NOW,
            1,
        )
    with pytest.raises(GraphValidationError, match="scope"):
        TemporalAssertionCriteria(
            None,
            None,
            (AssertionPredicate.CALLS, AssertionPredicate.CALLS),
            NOW,
            NOW,
            1,
        )
    with pytest.raises(GraphValidationError, match="scope"):
        TemporalAssertionCriteria(None, None, (), NOW, NOW, 0)
    active = _active()
    with pytest.raises(GraphValidationError, match="explanation"):
        TemporalAssertionCandidate(
            active,
            ACTIVATED_EVENT_ID,
            currently_authoritative=True,
            evidence_anchors=(),
        )
    with pytest.raises(GraphValidationError, match="explanation"):
        TemporalAssertionCandidate(
            active,
            ACTIVATED_EVENT_ID,
            cast("bool", 1),
            (None,),
        )
    explanation = TemporalAssertionExplanation(
        active.id,
        active.revision_id,
        ACTIVATED_EVENT_ID,
        TruthCurrency.HISTORICAL,
        NOW,
        NOW,
        currently_authoritative=True,
        resolved_revision=None,
        evidence_proofs=(),
    )
    assert TemporalAssertionResult(active, explanation).assertion == active
    with pytest.raises(GraphValidationError, match="explanation"):
        replace(explanation, currency=TruthCurrency.CURRENT, currently_authoritative=False)
    with pytest.raises(GraphValidationError, match="explanation"):
        TemporalAssertionResult(replace(active, id=CHECKOUT_ID), explanation)


def _batch() -> VcsRevisionBatch:
    return VcsRevisionBatch(
        "vcs-import-1",
        BRAIN_ID,
        REPOSITORY_ID,
        (
            VcsRevisionNode(ROOT, ()),
            VcsRevisionNode(MAIN, (ROOT,)),
            VcsRevisionNode(FEATURE, (ROOT,)),
            VcsRevisionNode(MERGE, (MAIN, FEATURE)),
        ),
        (VcsRefObservation("main", MERGE, NOW),),
        (EvidenceRevisionImpact(EVIDENCE_ID, FEATURE, NOW),),
        NOW,
        "c" * 64,
    )
