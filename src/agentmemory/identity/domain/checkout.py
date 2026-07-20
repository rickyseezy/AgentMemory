"""ID-002 Checkout aggregate, observations, events, and continuity policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError

if TYPE_CHECKING:
    from agentmemory.identity.domain.value_objects import Fingerprint, StableId

_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_BRANCH_MAX = 1024
_MAX_REMOTES = 64


@dataclass(frozen=True, slots=True)
class CheckoutObservation:
    """One privacy-safe host and revision observation of a Checkout."""

    repository_id: StableId
    device_id: StableId
    volume_fingerprint: Fingerprint
    path_fingerprint: Fingerprint
    logical_path_fingerprint: Fingerprint
    file_fingerprint: Fingerprint | None
    checkout_fingerprint: Fingerprint | None
    worktree_fingerprint: Fingerprint | None
    common_directory_fingerprint: Fingerprint | None
    branch: str | None
    head_commit: str | None
    dirty_digest: Fingerprint | None
    remote_fingerprints: tuple[Fingerprint, ...]

    def __post_init__(self) -> None:
        """Require canonical bounded revision evidence without raw host values."""
        _validate_revision_evidence(self.branch, self.head_commit, self.remote_fingerprints)


class CheckoutEventType(StrEnum):
    """Canonical ID-002 Checkout lifecycle event types."""

    OBSERVED = "CheckoutObserved"
    MOVED = "CheckoutMoved"


@dataclass(frozen=True, slots=True)
class CheckoutEvent:
    """One pending canonical event produced by the Checkout aggregate."""

    checkout_id: StableId
    brain_id: StableId
    aggregate_version: int
    event_type: CheckoutEventType
    observation: CheckoutObservation
    previous_path_fingerprint: Fingerprint | None


@dataclass(frozen=True, slots=True)
class CheckoutAggregate:
    """Optimistically versioned Checkout snapshot."""

    checkout_id: StableId
    brain_id: StableId
    current: CheckoutObservation
    version: int

    def __post_init__(self) -> None:
        """Reject impossible persisted aggregate versions."""
        _require_positive_version(self.version)

    @classmethod
    def create(
        cls,
        checkout_id: StableId,
        brain_id: StableId,
        observation: CheckoutObservation,
    ) -> tuple[CheckoutAggregate, CheckoutEvent]:
        """Create a new clone/worktree identity and its first observation event."""
        return _create_checkout(cls, checkout_id, brain_id, observation)

    def observe(
        self,
        observation: CheckoutObservation,
        *,
        expected_version: int,
    ) -> tuple[CheckoutAggregate, CheckoutEvent]:
        """Apply one exact expected-version observation without rewriting history."""
        return _observe_checkout(self, observation, expected_version)


@dataclass(frozen=True, slots=True)
class CheckoutContinuityPolicy:
    """Recognize only deterministic same-Checkout evidence and favor separation."""

    def matches(self, existing: CheckoutObservation, observed: CheckoutObservation) -> bool:
        """Return true for exact aliases, stable file identity, or exact Git worktree identity."""
        return _matches_continuity(existing, observed)


def _validate_revision_evidence(
    branch: str | None,
    head_commit: str | None,
    remote_fingerprints: tuple[Fingerprint, ...],
) -> None:
    if branch is not None and (
        not branch
        or len(branch) > _BRANCH_MAX
        or any(character in branch for character in "\x00\r\n")
    ):
        msg = "Checkout branch evidence is invalid"
        raise IdentityValidationError(msg)
    if head_commit is not None and _GIT_OBJECT_ID.fullmatch(head_commit) is None:
        msg = "Checkout HEAD evidence is invalid"
        raise IdentityValidationError(msg)
    if (
        len(remote_fingerprints) > _MAX_REMOTES
        or len(set(remote_fingerprints)) != len(remote_fingerprints)
        or remote_fingerprints != tuple(sorted(remote_fingerprints, key=lambda value: value.value))
    ):
        msg = "Checkout remote evidence must be unique and canonical"
        raise IdentityValidationError(msg)


def _require_positive_version(version: int) -> None:
    if version < 1:
        msg = "Checkout aggregate version must be positive"
        raise IdentityValidationError(msg)


def _create_checkout(
    aggregate_type: type[CheckoutAggregate],
    checkout_id: StableId,
    brain_id: StableId,
    observation: CheckoutObservation,
) -> tuple[CheckoutAggregate, CheckoutEvent]:
    aggregate = aggregate_type(checkout_id, brain_id, observation, 1)
    event = CheckoutEvent(
        checkout_id,
        brain_id,
        1,
        CheckoutEventType.OBSERVED,
        observation,
        None,
    )
    return aggregate, event


def _observe_checkout(
    aggregate: CheckoutAggregate,
    observation: CheckoutObservation,
    expected_version: int,
) -> tuple[CheckoutAggregate, CheckoutEvent]:
    if expected_version != aggregate.version:
        raise IdentityConflictError
    if observation.repository_id != aggregate.current.repository_id:
        raise IdentityConflictError
    next_version = aggregate.version + 1
    moved = observation.path_fingerprint != aggregate.current.path_fingerprint
    event = CheckoutEvent(
        aggregate.checkout_id,
        aggregate.brain_id,
        next_version,
        CheckoutEventType.MOVED if moved else CheckoutEventType.OBSERVED,
        observation,
        aggregate.current.path_fingerprint if moved else None,
    )
    return (
        CheckoutAggregate(
            aggregate.checkout_id,
            aggregate.brain_id,
            observation,
            next_version,
        ),
        event,
    )


def _matches_continuity(
    existing: CheckoutObservation,
    observed: CheckoutObservation,
) -> bool:
    if existing.repository_id != observed.repository_id or existing.device_id != observed.device_id:
        return False
    if (
        existing.checkout_fingerprint is not None
        and existing.checkout_fingerprint == observed.checkout_fingerprint
    ):
        return True
    if (
        existing.file_fingerprint is not None
        and existing.file_fingerprint == observed.file_fingerprint
        and existing.volume_fingerprint == observed.volume_fingerprint
    ):
        return True
    return (
        existing.worktree_fingerprint is not None
        and existing.worktree_fingerprint == observed.worktree_fingerprint
        and existing.common_directory_fingerprint is not None
        and existing.common_directory_fingerprint == observed.common_directory_fingerprint
    )
