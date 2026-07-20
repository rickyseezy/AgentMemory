"""ID-003 repository-topology aggregate and policy acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError
from agentmemory.identity.domain.topology import (
    LinkConfirmation,
    ProjectRepositoryLink,
    RepositoryLinkHistoryEntry,
    RepositoryRelationType,
    RepositoryTopologyCandidate,
    TopologyConfirmationSource,
    TopologyEndpointType,
    TopologyEvidence,
    TopologyEvidenceKind,
    TopologyEvidenceStrength,
    TopologyLinkEventType,
)
from agentmemory.identity.domain.value_objects import Fingerprint, StableId

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
ACTOR_ID = StableId("018f0000-0000-7000-8000-000000000002")
GRANT_ID = StableId("018f0000-0000-7000-8000-000000000003")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHILD_REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000021")
LINK_ID = StableId("018f0000-0000-7000-8000-000000000040")


def _evidence(
    seed: bytes = b"nested",
    *,
    kind: TopologyEvidenceKind = TopologyEvidenceKind.NESTED_GIT_MARKER,
    strength: TopologyEvidenceStrength = TopologyEvidenceStrength.DETERMINISTIC_VCS,
) -> TopologyEvidence:
    return TopologyEvidence(Fingerprint.from_bytes(seed), kind, strength)


def _nested_candidate() -> RepositoryTopologyCandidate:
    return RepositoryTopologyCandidate(
        brain_id=BRAIN_ID,
        subject_type=TopologyEndpointType.REPOSITORY,
        subject_id=REPOSITORY_ID,
        relation_type=RepositoryRelationType.CONTAINS_REPOSITORY,
        target_type=TopologyEndpointType.REPOSITORY,
        target_id=CHILD_REPOSITORY_ID,
        component_root_fingerprint=None,
        evidence=(_evidence(),),
    )


def test_nested_and_submodule_candidates_require_distinct_repository_entities() -> None:
    candidate = _nested_candidate()
    assert candidate.subject_id != candidate.target_id
    assert candidate.can_confirm(TopologyConfirmationSource.DETERMINISTIC_VCS)

    with pytest.raises(IdentityValidationError, match="distinct Repository"):
        RepositoryTopologyCandidate(
            brain_id=BRAIN_ID,
            subject_type=TopologyEndpointType.REPOSITORY,
            subject_id=REPOSITORY_ID,
            relation_type=RepositoryRelationType.SUBMODULE_OF,
            target_type=TopologyEndpointType.REPOSITORY,
            target_id=REPOSITORY_ID,
            component_root_fingerprint=None,
            evidence=(_evidence(),),
        )


def test_project_use_candidate_carries_a_separate_monorepo_scope_boundary() -> None:
    component_root = Fingerprint.from_bytes(b"packages/frontend")
    candidate = RepositoryTopologyCandidate(
        brain_id=BRAIN_ID,
        subject_type=TopologyEndpointType.PROJECT,
        subject_id=PROJECT_ID,
        relation_type=RepositoryRelationType.PROJECT_USES_REPOSITORY,
        target_type=TopologyEndpointType.REPOSITORY,
        target_id=REPOSITORY_ID,
        component_root_fingerprint=component_root,
        evidence=(
            _evidence(
                b"manifest",
                kind=TopologyEvidenceKind.PROJECT_MANIFEST,
                strength=TopologyEvidenceStrength.DETERMINISTIC_MANIFEST,
            ),
        ),
    )
    assert candidate.component_root_fingerprint == component_root

    with pytest.raises(IdentityValidationError, match="endpoint shape"):
        RepositoryTopologyCandidate(
            brain_id=BRAIN_ID,
            subject_type=TopologyEndpointType.PROJECT,
            subject_id=PROJECT_ID,
            relation_type=RepositoryRelationType.FORK_OF,
            target_type=TopologyEndpointType.REPOSITORY,
            target_id=REPOSITORY_ID,
            component_root_fingerprint=None,
            evidence=(_evidence(),),
        )


def test_resemblance_only_fork_remains_candidate_until_user_confirmation() -> None:
    candidate = RepositoryTopologyCandidate(
        brain_id=BRAIN_ID,
        subject_type=TopologyEndpointType.REPOSITORY,
        subject_id=CHILD_REPOSITORY_ID,
        relation_type=RepositoryRelationType.FORK_OF,
        target_type=TopologyEndpointType.REPOSITORY,
        target_id=REPOSITORY_ID,
        component_root_fingerprint=None,
        evidence=(
            _evidence(
                b"shared-content",
                kind=TopologyEvidenceKind.SHARED_CONTENT,
                strength=TopologyEvidenceStrength.CANDIDATE,
            ),
            _evidence(
                b"similar-remote",
                kind=TopologyEvidenceKind.SIMILAR_REMOTE,
                strength=TopologyEvidenceStrength.CANDIDATE,
            ),
        ),
    )
    assert not candidate.can_confirm(TopologyConfirmationSource.DETERMINISTIC_VCS)
    assert candidate.can_confirm(TopologyConfirmationSource.USER)
    with pytest.raises(IdentityValidationError, match="deterministic evidence"):
        ProjectRepositoryLink.confirm(
            LINK_ID,
            candidate,
            LinkConfirmation(
                "confirm-fork-1",
                ACTOR_ID,
                GRANT_ID,
                TopologyConfirmationSource.DETERMINISTIC_VCS,
                10,
            ),
        )


def test_confirmation_and_correction_append_complete_version_history() -> None:
    aggregate, event = ProjectRepositoryLink.confirm(
        LINK_ID,
        _nested_candidate(),
        LinkConfirmation(
            "confirm-link-1",
            ACTOR_ID,
            GRANT_ID,
            TopologyConfirmationSource.DETERMINISTIC_VCS,
            10,
        ),
    )
    assert aggregate.version == 1
    assert event.event_type is TopologyLinkEventType.CONFIRMED
    assert aggregate.history == (event.history_entry,)

    corrected_candidate = RepositoryTopologyCandidate(
        brain_id=BRAIN_ID,
        subject_type=TopologyEndpointType.REPOSITORY,
        subject_id=REPOSITORY_ID,
        relation_type=RepositoryRelationType.SUBMODULE_OF,
        target_type=TopologyEndpointType.REPOSITORY,
        target_id=CHILD_REPOSITORY_ID,
        component_root_fingerprint=None,
        evidence=(
            _evidence(
                b"gitlink",
                kind=TopologyEvidenceKind.GITLINK,
                strength=TopologyEvidenceStrength.DETERMINISTIC_VCS,
            ),
        ),
    )
    corrected, correction_event = aggregate.correct(
        corrected_candidate,
        LinkConfirmation(
            "correct-link-1",
            ACTOR_ID,
            GRANT_ID,
            TopologyConfirmationSource.USER,
            20,
            "user_verified_submodule",
        ),
        expected_version=1,
    )
    assert corrected.version == 2
    assert corrected.relation_type is RepositoryRelationType.SUBMODULE_OF
    assert correction_event.event_type is TopologyLinkEventType.CORRECTED
    assert correction_event.history_entry.previous_version == 1
    assert len(corrected.history) == 2
    assert corrected.history[0].relation_type is RepositoryRelationType.CONTAINS_REPOSITORY
    assert corrected.history[1].correction_reason == "user_verified_submodule"


def test_correction_rejects_stale_version_endpoint_rebinding_and_time_reversal() -> None:
    aggregate, _ = ProjectRepositoryLink.confirm(
        LINK_ID,
        _nested_candidate(),
        LinkConfirmation(
            "confirm-link-1",
            ACTOR_ID,
            GRANT_ID,
            TopologyConfirmationSource.USER,
            10,
        ),
    )
    with pytest.raises(IdentityConflictError):
        aggregate.correct(
            _nested_candidate(),
            LinkConfirmation(
                "correct-link-1",
                ACTOR_ID,
                GRANT_ID,
                TopologyConfirmationSource.USER,
                20,
                "stale",
            ),
            expected_version=2,
        )
    rebound = RepositoryTopologyCandidate(
        brain_id=BRAIN_ID,
        subject_type=TopologyEndpointType.REPOSITORY,
        subject_id=CHILD_REPOSITORY_ID,
        relation_type=RepositoryRelationType.CONTAINS_REPOSITORY,
        target_type=TopologyEndpointType.REPOSITORY,
        target_id=REPOSITORY_ID,
        component_root_fingerprint=None,
        evidence=(_evidence(b"rebound"),),
    )
    with pytest.raises(IdentityConflictError):
        aggregate.correct(
            rebound,
            LinkConfirmation(
                "correct-link-2",
                ACTOR_ID,
                GRANT_ID,
                TopologyConfirmationSource.USER,
                20,
                "rebind",
            ),
            expected_version=1,
        )
    with pytest.raises(IdentityValidationError, match="after"):
        aggregate.correct(
            _nested_candidate(),
            LinkConfirmation(
                "correct-link-3",
                ACTOR_ID,
                GRANT_ID,
                TopologyConfirmationSource.USER,
                9,
                "time_reversal",
            ),
            expected_version=1,
        )


def test_candidate_evidence_is_bounded_unique_and_canonical() -> None:
    first = _evidence(b"one")
    second = _evidence(b"two")
    canonical = tuple(sorted((first, second), key=lambda item: item.digest.value))
    with pytest.raises(IdentityValidationError, match="canonical"):
        RepositoryTopologyCandidate(
            brain_id=BRAIN_ID,
            subject_type=TopologyEndpointType.REPOSITORY,
            subject_id=REPOSITORY_ID,
            relation_type=RepositoryRelationType.CONTAINS_REPOSITORY,
            target_type=TopologyEndpointType.REPOSITORY,
            target_id=CHILD_REPOSITORY_ID,
            component_root_fingerprint=None,
            evidence=tuple(reversed(canonical)),
        )
    with pytest.raises(IdentityValidationError, match="canonical"):
        RepositoryTopologyCandidate(
            brain_id=BRAIN_ID,
            subject_type=TopologyEndpointType.REPOSITORY,
            subject_id=REPOSITORY_ID,
            relation_type=RepositoryRelationType.CONTAINS_REPOSITORY,
            target_type=TopologyEndpointType.REPOSITORY,
            target_id=CHILD_REPOSITORY_ID,
            component_root_fingerprint=None,
            evidence=(first, first),
        )


def test_empty_or_excessive_evidence_and_strength_classification_fail_closed() -> None:
    assert _evidence().deterministic
    assert not _evidence(
        strength=TopologyEvidenceStrength.CANDIDATE,
    ).deterministic
    with pytest.raises(IdentityValidationError, match="empty or exceeds"):
        RepositoryTopologyCandidate(
            BRAIN_ID,
            TopologyEndpointType.REPOSITORY,
            REPOSITORY_ID,
            RepositoryRelationType.CONTAINS_REPOSITORY,
            TopologyEndpointType.REPOSITORY,
            CHILD_REPOSITORY_ID,
            None,
            (),
        )
    excessive = tuple(
        sorted(
            (_evidence(str(index).encode()) for index in range(33)),
            key=lambda item: item.digest.value,
        )
    )
    with pytest.raises(IdentityValidationError, match="empty or exceeds"):
        RepositoryTopologyCandidate(
            BRAIN_ID,
            TopologyEndpointType.REPOSITORY,
            REPOSITORY_ID,
            RepositoryRelationType.CONTAINS_REPOSITORY,
            TopologyEndpointType.REPOSITORY,
            CHILD_REPOSITORY_ID,
            None,
            excessive,
        )


def _history_zero_version(value: RepositoryLinkHistoryEntry) -> RepositoryLinkHistoryEntry:
    return replace(value, version=0)


def _history_zero_time(value: RepositoryLinkHistoryEntry) -> RepositoryLinkHistoryEntry:
    return replace(value, effective_at=0)


def _history_bad_operation(value: RepositoryLinkHistoryEntry) -> RepositoryLinkHistoryEntry:
    return replace(value, operation_id="bad operation")


def _history_bad_reason(value: RepositoryLinkHistoryEntry) -> RepositoryLinkHistoryEntry:
    return replace(value, correction_reason="BAD REASON")


@pytest.mark.parametrize(
    ("invalidate", "match"),
    [
        (_history_zero_version, "version and effective"),
        (_history_zero_time, "version and effective"),
        (_history_bad_operation, "operation ID"),
        (_history_bad_reason, "correction reason"),
    ],
)
def test_history_entry_rejects_invalid_canonical_metadata(
    invalidate: Callable[[RepositoryLinkHistoryEntry], RepositoryLinkHistoryEntry],
    match: str,
) -> None:
    entry = RepositoryLinkHistoryEntry(
        1,
        None,
        "confirm-1",
        ACTOR_ID,
        GRANT_ID,
        TopologyConfirmationSource.USER,
        RepositoryRelationType.CONTAINS_REPOSITORY,
        None,
        (_evidence(),),
        None,
        1,
    )
    with pytest.raises(IdentityValidationError, match=match):
        invalidate(entry)


def _confirmation_bad_operation(value: LinkConfirmation) -> LinkConfirmation:
    return replace(value, operation_id="bad operation")


def _confirmation_zero_time(value: LinkConfirmation) -> LinkConfirmation:
    return replace(value, effective_at=0)


def _confirmation_bad_reason(value: LinkConfirmation) -> LinkConfirmation:
    return replace(value, correction_reason="BAD REASON")


@pytest.mark.parametrize(
    ("invalidate", "match"),
    [
        (_confirmation_bad_operation, "operation ID"),
        (_confirmation_zero_time, "effective time"),
        (_confirmation_bad_reason, "correction reason"),
    ],
)
def test_confirmation_metadata_rejects_invalid_values(
    invalidate: Callable[[LinkConfirmation], LinkConfirmation],
    match: str,
) -> None:
    confirmation = LinkConfirmation(
        "confirm-1",
        ACTOR_ID,
        GRANT_ID,
        TopologyConfirmationSource.USER,
        1,
    )
    with pytest.raises(IdentityValidationError, match=match):
        invalidate(confirmation)


def test_aggregate_rejects_inconsistent_snapshot_and_transition_shapes() -> None:
    aggregate, _ = ProjectRepositoryLink.confirm(
        LINK_ID,
        _nested_candidate(),
        LinkConfirmation(
            "confirm-1",
            ACTOR_ID,
            GRANT_ID,
            TopologyConfirmationSource.USER,
            10,
        ),
    )
    for changes in (
        {"version": 0},
        {"valid_from": 0},
        {"valid_to": 10},
        {"history": ()},
        {"relation_type": RepositoryRelationType.FORK_OF},
    ):
        with pytest.raises(IdentityValidationError, match="snapshot and history"):
            replace(aggregate, **changes)
    with pytest.raises(IdentityValidationError, match="cannot carry"):
        ProjectRepositoryLink.confirm(
            LINK_ID,
            _nested_candidate(),
            LinkConfirmation(
                "confirm-2",
                ACTOR_ID,
                GRANT_ID,
                TopologyConfirmationSource.USER,
                11,
                "not_a_correction",
            ),
        )
    with pytest.raises(IdentityValidationError, match="requires a reason"):
        aggregate.correct(
            _nested_candidate(),
            LinkConfirmation(
                "correct-1",
                ACTOR_ID,
                GRANT_ID,
                TopologyConfirmationSource.USER,
                11,
            ),
            expected_version=1,
        )
