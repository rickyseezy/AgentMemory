"""ID-002 authorized, idempotent Checkout observation command."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agentmemory.identity.domain.checkout import (
    CheckoutAggregate,
    CheckoutContinuityPolicy,
    CheckoutObservation,
)
from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError
from agentmemory.identity.domain.value_objects import DeviceIdentity, StableId, VcsIdentity, VcsType

if TYPE_CHECKING:
    from agentmemory.identity.domain.ports import (
        CheckoutObservationUnitOfWorkFactory,
        StableIdentityGenerator,
    )

_OPERATION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


@dataclass(frozen=True, slots=True)
class ObserveCheckoutCommand:
    """Authenticated privacy-safe evidence for one local Checkout observation."""

    operation_id: str
    brain_id: StableId
    actor_id: StableId
    grant_id: StableId
    repository_id: StableId
    device: DeviceIdentity
    vcs: VcsIdentity
    expected_version: int | None = None

    def __post_init__(self) -> None:
        """Reject malformed commands before entering the write transaction."""
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "Checkout observation operation ID is invalid"
            raise IdentityValidationError(msg)
        if not self.device.verified:
            msg = "Checkout observation requires a verified device"
            raise IdentityValidationError(msg)
        if self.vcs.vcs_type is not VcsType.GIT:
            msg = "Checkout observation requires Git evidence"
            raise IdentityValidationError(msg)
        if self.expected_version is not None and self.expected_version < 1:
            msg = "Checkout expected version must be positive"
            raise IdentityValidationError(msg)

    def observation(self) -> CheckoutObservation:
        """Translate adapter evidence into the canonical aggregate value."""
        vcs = self.vcs
        device = self.device
        if (
            device.logical_path_fingerprint is None
            or vcs.repository_fingerprint is None
            or vcs.head_commit is None
            or vcs.dirty_digest is None
        ):
            msg = "Checkout observation evidence is incomplete"
            raise IdentityValidationError(msg)
        return CheckoutObservation(
            repository_id=self.repository_id,
            device_id=device.device_id,
            volume_fingerprint=device.volume_fingerprint,
            path_fingerprint=device.path_fingerprint,
            logical_path_fingerprint=device.logical_path_fingerprint,
            file_fingerprint=device.file_fingerprint,
            checkout_fingerprint=vcs.checkout_fingerprint,
            worktree_fingerprint=vcs.worktree_fingerprint,
            common_directory_fingerprint=vcs.common_directory_fingerprint,
            branch=vcs.branch,
            head_commit=vcs.head_commit,
            dirty_digest=vcs.dirty_digest,
            remote_fingerprints=vcs.remote_fingerprints,
        )


@dataclass(frozen=True, slots=True)
class ObserveCheckoutHandler:
    """Recognize Checkout continuity and commit all canonical facts atomically."""

    unit_of_work: CheckoutObservationUnitOfWorkFactory
    identities: StableIdentityGenerator
    continuity: CheckoutContinuityPolicy = field(default_factory=CheckoutContinuityPolicy)

    async def execute(self, command: ObserveCheckoutCommand) -> CheckoutAggregate:
        """Create or update exactly one Checkout under optimistic concurrency."""
        observation = command.observation()
        async with self.unit_of_work() as unit_of_work:
            await unit_of_work.authorization.authorize(
                command.brain_id,
                command.actor_id,
                command.grant_id,
            )
            await unit_of_work.checkouts.require_repository(
                command.brain_id,
                command.repository_id,
            )
            prior_result = await unit_of_work.checkouts.find_operation(
                command.brain_id,
                command.operation_id,
            )
            if prior_result is not None:
                if prior_result.current != observation:
                    raise IdentityConflictError
                return prior_result
            candidates = await unit_of_work.checkouts.find_continuity(
                command.brain_id,
                command.repository_id,
                command.device,
                command.vcs,
            )
            matching = tuple(
                candidate
                for candidate in candidates
                if self.continuity.matches(candidate.current, observation)
            )
            if len(matching) > 1:
                raise IdentityConflictError
            if matching:
                current = matching[0]
                expected = (
                    current.version
                    if command.expected_version is None
                    else command.expected_version
                )
                aggregate, event = current.observe(observation, expected_version=expected)
                previous_version: int | None = current.version
            else:
                if command.expected_version is not None:
                    raise IdentityConflictError
                aggregate, event = CheckoutAggregate.create(
                    self.identities.new(),
                    command.brain_id,
                    observation,
                )
                previous_version = None
            await unit_of_work.checkouts.append(
                command.operation_id,
                self.identities.new(),
                aggregate,
                event,
                expected_previous_version=previous_version,
            )
            await unit_of_work.commit()
            return aggregate
