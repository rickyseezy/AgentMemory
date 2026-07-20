"""ID-001 stable workspace identity domain tests."""

from __future__ import annotations

import pytest

from agentmemory.identity.domain.errors import IdentityValidationError
from agentmemory.identity.domain.services import IdentityResolutionPolicy
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    IdentityCandidate,
    IdentityEvidence,
    IdentitySource,
    ObservedWorkspaceQuery,
    ProjectManifest,
    ResolutionStatus,
    StableId,
    VcsIdentity,
    VcsType,
    WorkspaceObservation,
    WorkspaceResolution,
)

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
PROJECT_A = StableId("018f0000-0000-7000-8000-000000000010")
PROJECT_B = StableId("018f0000-0000-7000-8000-000000000011")
REPOSITORY_A = StableId("018f0000-0000-7000-8000-000000000020")
REPOSITORY_B = StableId("018f0000-0000-7000-8000-000000000021")
CHECKOUT_A = StableId("018f0000-0000-7000-8000-000000000030")
CHECKOUT_B = StableId("018f0000-0000-7000-8000-000000000031")


def _candidate(
    project_id: StableId = PROJECT_A,
    repository_id: StableId = REPOSITORY_A,
    checkout_id: StableId | None = CHECKOUT_A,
) -> IdentityCandidate:
    return IdentityCandidate(project_id, repository_id, checkout_id)


@pytest.mark.parametrize(
    ("manifest", "checkout", "repository", "heuristic", "expected_source"),
    [
        (
            (_candidate(),),
            (_candidate(),),
            (_candidate(),),
            (_candidate(),),
            IdentitySource.MANIFEST,
        ),
        ((), (_candidate(),), (_candidate(),), (_candidate(),), IdentitySource.CHECKOUT_REGISTRY),
        ((), (), (_candidate(),), (_candidate(),), IdentitySource.REPOSITORY_FINGERPRINT),
        ((), (), (), (_candidate(),), IdentitySource.APPROVED_HEURISTIC),
    ],
)
def test_precedence_selects_first_authoritative_evidence(
    manifest: tuple[IdentityCandidate, ...],
    checkout: tuple[IdentityCandidate, ...],
    repository: tuple[IdentityCandidate, ...],
    heuristic: tuple[IdentityCandidate, ...],
    expected_source: IdentitySource,
) -> None:
    resolution = IdentityResolutionPolicy().resolve(
        BRAIN_ID,
        IdentityEvidence(manifest, checkout, repository, heuristic),
    )
    assert resolution.status is ResolutionStatus.RESOLVED
    assert resolution.brain_id == BRAIN_ID
    assert resolution.source is expected_source
    assert resolution.selected == _candidate()
    assert resolution.explanation == (f"selected:{expected_source.value}",)


def test_ambiguous_candidates_fail_separate_without_silent_merge() -> None:
    candidates = (
        _candidate(),
        _candidate(PROJECT_B, REPOSITORY_B, CHECKOUT_B),
    )
    resolution = IdentityResolutionPolicy().resolve(
        BRAIN_ID,
        IdentityEvidence((), (), candidates, ()),
    )
    assert resolution.status is ResolutionStatus.AMBIGUOUS
    assert resolution.brain_id == BRAIN_ID
    assert resolution.selected is None
    assert resolution.source is IdentitySource.REPOSITORY_FINGERPRINT
    assert resolution.candidates == candidates
    assert resolution.explanation == ("ambiguous:repository_fingerprint",)


def test_no_evidence_returns_not_found_without_manufacturing_path_identity() -> None:
    resolution = IdentityResolutionPolicy().resolve(BRAIN_ID, IdentityEvidence((), (), (), ()))
    assert resolution == WorkspaceResolution.not_found(BRAIN_ID)
    assert resolution.candidates == ()
    assert resolution.selected is None


def test_resolution_value_rejects_incoherent_status_and_candidate_shapes() -> None:
    with pytest.raises(IdentityValidationError, match="resolved identity"):
        WorkspaceResolution(
            BRAIN_ID,
            ResolutionStatus.RESOLVED,
            IdentitySource.MANIFEST,
            None,
            (),
            ("invalid",),
        )


@pytest.mark.parametrize(
    "value",
    [
        "not-a-uuid",
        "550e8400-e29b-41d4-a716-446655440000",
        "018F0000-0000-7000-8000-000000000004",
    ],
)
def test_stable_id_rejects_malformed_non_v7_or_noncanonical_values(value: str) -> None:
    with pytest.raises(IdentityValidationError, match="UUIDv7"):
        StableId(value)


@pytest.mark.parametrize("value", ["A" * 64, "0" * 64, "short"])
def test_fingerprint_rejects_noncanonical_or_sentinel_values(value: str) -> None:
    with pytest.raises(IdentityValidationError, match="fingerprint"):
        Fingerprint(value)


def test_workspace_queries_bound_operation_and_path_inputs() -> None:
    with pytest.raises(IdentityValidationError, match="operation ID"):
        WorkspaceObservation("unsafe/op", BRAIN_ID, BRAIN_ID, BRAIN_ID, "/work")
    with pytest.raises(IdentityValidationError, match="path"):
        WorkspaceObservation("resolve-1", BRAIN_ID, BRAIN_ID, BRAIN_ID, "")
    with pytest.raises(IdentityValidationError, match="operation ID"):
        ObservedWorkspaceQuery("unsafe/op", BRAIN_ID, BRAIN_ID, BRAIN_ID)


def test_manifest_and_vcs_values_reject_incoherent_identity_claims() -> None:
    with pytest.raises(IdentityValidationError, match="schema version"):
        ProjectManifest(2, PROJECT_A, REPOSITORY_A)
    fingerprint = Fingerprint.from_bytes(b"repository")
    with pytest.raises(IdentityValidationError, match="Git identity"):
        VcsIdentity(VcsType.GIT, None, None, None)
    with pytest.raises(IdentityValidationError, match="non-Git"):
        VcsIdentity(VcsType.NONE, fingerprint, None, None)
    with pytest.raises(IdentityValidationError, match="lookup authority"):
        VcsIdentity(VcsType.NONE, None, None, None, repository_lookup_approved=True)


def test_not_found_resolution_rejects_candidates_or_selected_identity() -> None:
    with pytest.raises(IdentityValidationError, match="not-found"):
        WorkspaceResolution(
            BRAIN_ID,
            ResolutionStatus.NOT_FOUND,
            IdentitySource.MANIFEST,
            _candidate(),
            (_candidate(),),
            ("invalid",),
        )


def test_device_identity_is_an_immutable_path_free_value() -> None:
    value = DeviceIdentity(
        BRAIN_ID,
        Fingerprint.from_bytes(b"device"),
        Fingerprint.from_bytes(b"volume"),
        Fingerprint.from_bytes(b"path"),
        verified=True,
    )
    assert "/" not in repr(value)
    with pytest.raises(IdentityValidationError, match="ambiguous identity"):
        WorkspaceResolution(
            BRAIN_ID,
            ResolutionStatus.AMBIGUOUS,
            IdentitySource.MANIFEST,
            None,
            (_candidate(),),
            ("invalid",),
        )
