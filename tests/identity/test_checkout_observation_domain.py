"""ID-002 Checkout aggregate and continuity policy tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agentmemory.identity.domain.checkout import (
    CheckoutAggregate,
    CheckoutContinuityPolicy,
    CheckoutEventType,
    CheckoutObservation,
)
from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError
from agentmemory.identity.domain.value_objects import Fingerprint, StableId

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHECKOUT_ID = StableId("018f0000-0000-7000-8000-000000000030")


def _fingerprint(value: str) -> Fingerprint:
    return Fingerprint.from_bytes(value.encode())


def _observation(  # noqa: PLR0913 -- Complete observation fixture controls each continuity axis.
    *,
    path: str = "path-a",
    file_id: str = "file-a",
    checkout: str = "checkout-a",
    worktree: str = "worktree-a",
    common: str = "common-a",
    branch: str | None = "main",
    head: str | None = "a" * 40,
    dirty: str = "clean",
) -> CheckoutObservation:
    return CheckoutObservation(
        repository_id=REPOSITORY_ID,
        device_id=DEVICE_ID,
        volume_fingerprint=_fingerprint("volume"),
        path_fingerprint=_fingerprint(path),
        logical_path_fingerprint=_fingerprint(f"logical-{path}"),
        file_fingerprint=_fingerprint(file_id),
        checkout_fingerprint=_fingerprint(checkout),
        worktree_fingerprint=_fingerprint(worktree),
        common_directory_fingerprint=_fingerprint(common),
        branch=branch,
        head_commit=head,
        dirty_digest=_fingerprint(dirty),
        remote_fingerprints=(_fingerprint("origin"),),
    )


def test_moved_checkout_retains_id_and_emits_moved_event() -> None:
    initial, created = CheckoutAggregate.create(CHECKOUT_ID, BRAIN_ID, _observation())
    moved, event = initial.observe(_observation(path="path-b"), expected_version=1)
    assert created.event_type is CheckoutEventType.OBSERVED
    assert event.event_type is CheckoutEventType.MOVED
    assert moved.checkout_id == CHECKOUT_ID
    assert moved.version == 2
    assert moved.current.path_fingerprint == _fingerprint("path-b")
    assert event.previous_path_fingerprint == _fingerprint("path-a")
    assert created.checkout_id == CHECKOUT_ID
    assert created.brain_id == BRAIN_ID
    assert created.aggregate_version == 1
    assert created.observation == initial.current
    assert event.checkout_id == CHECKOUT_ID
    assert event.brain_id == BRAIN_ID
    assert event.aggregate_version == 2
    assert event.observation == moved.current


def test_revision_only_change_emits_observed_and_preserves_checkout() -> None:
    initial, _ = CheckoutAggregate.create(CHECKOUT_ID, BRAIN_ID, _observation())
    changed, event = initial.observe(
        _observation(branch="feature", head="b" * 40, dirty="dirty"),
        expected_version=1,
    )
    assert event.event_type is CheckoutEventType.OBSERVED
    assert changed.current.branch == "feature"
    assert changed.current.head_commit == "b" * 40
    assert changed.current.dirty_digest == _fingerprint("dirty")


def test_stale_aggregate_version_fails_without_event() -> None:
    initial, _ = CheckoutAggregate.create(CHECKOUT_ID, BRAIN_ID, _observation())
    with pytest.raises(IdentityConflictError):
        initial.observe(_observation(path="path-b"), expected_version=0)


def test_continuity_distinguishes_move_clone_and_worktree() -> None:
    policy = CheckoutContinuityPolicy()
    existing = _observation()
    assert policy.matches(existing, _observation(path="moved"))
    assert not policy.matches(
        existing,
        _observation(
            path="clone",
            file_id="clone-file",
            checkout="clone-checkout",
            common="clone-common",
        ),
    )
    assert not policy.matches(
        existing,
        _observation(
            path="worktree",
            file_id="worktree-file",
            checkout="worktree-checkout",
            worktree="worktree-b",
        ),
    )


def test_symlink_alias_with_same_real_path_is_observed_not_moved() -> None:
    initial, _ = CheckoutAggregate.create(CHECKOUT_ID, BRAIN_ID, _observation())
    alias = _observation()
    changed, event = initial.observe(alias, expected_version=1)
    assert event.event_type is CheckoutEventType.OBSERVED
    assert changed.current.logical_path_fingerprint == alias.logical_path_fingerprint


@pytest.mark.parametrize("branch", ["", "x" * 1025, "feature\ninvalid"])
def test_observation_rejects_invalid_branch_boundaries(branch: str) -> None:
    with pytest.raises(IdentityValidationError, match="branch"):
        _observation(branch=branch)
    assert _observation(branch="x" * 1024).branch == "x" * 1024
    assert _observation(branch=None).branch is None


def test_observation_rejects_invalid_head_and_accepts_absence() -> None:
    with pytest.raises(IdentityValidationError, match="HEAD"):
        _observation(head="abc")
    assert _observation(head=None).head_commit is None


def test_observation_requires_bounded_unique_sorted_remotes() -> None:
    first = _fingerprint("first")
    second = _fingerprint("second")
    ordered = tuple(sorted((first, second), key=lambda value: value.value))
    base = _observation()
    assert replace(base, remote_fingerprints=ordered).remote_fingerprints == ordered
    for invalid in (
        (first, first),
        tuple(reversed(ordered)),
        tuple(
            sorted(
                (_fingerprint(f"remote-{index}") for index in range(65)),
                key=lambda value: value.value,
            )
        ),
    ):
        with pytest.raises(IdentityValidationError, match="remote"):
            replace(base, remote_fingerprints=invalid)
    maximum = tuple(
        sorted(
            (_fingerprint(f"bounded-{index}") for index in range(64)),
            key=lambda value: value.value,
        )
    )
    assert len(replace(base, remote_fingerprints=maximum).remote_fingerprints) == 64


def test_continuity_requires_each_non_null_evidence_component() -> None:
    policy = CheckoutContinuityPolicy()
    existing = _observation()
    other_repository = StableId("018f0000-0000-7000-8000-000000000021")
    other_device = StableId("018f0000-0000-7000-8000-000000000007")
    assert not policy.matches(existing, replace(existing, repository_id=other_repository))
    assert not policy.matches(existing, replace(existing, device_id=other_device))
    without_checkout = replace(existing, checkout_fingerprint=None)
    assert not policy.matches(
        without_checkout,
        replace(
            without_checkout,
            file_fingerprint=None,
            worktree_fingerprint=None,
            common_directory_fingerprint=None,
        ),
    )
