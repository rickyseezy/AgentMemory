"""ID-003 authorized, idempotent repository-link confirmation command."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError
from agentmemory.identity.domain.topology import (
    LinkConfirmation,
    ProjectRepositoryLink,
    RepositoryTopologyCandidate,
    TopologyConfirmationSource,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.ports import (
        RepositoryLinkUnitOfWorkFactory,
        StableIdentityGenerator,
    )
    from agentmemory.identity.domain.value_objects import StableId
    from agentmemory.shared.clock import Clock

_OPERATION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


@dataclass(frozen=True, slots=True)
class ConfirmRepositoryLinkCommand:
    """Confirm a candidate or append an explicit correction to an existing link."""

    operation_id: str
    brain_id: StableId
    actor_id: StableId
    grant_id: StableId
    candidate: RepositoryTopologyCandidate
    confirmation_source: TopologyConfirmationSource
    link_id: StableId | None = None
    expected_version: int | None = None
    correction_reason: str | None = None

    def __post_init__(self) -> None:
        """Reject malformed create/correction shapes before opening a transaction."""
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "repository link operation ID is invalid"
            raise IdentityValidationError(msg)
        if self.candidate.brain_id != self.brain_id:
            raise IdentityConflictError
        is_correction = self.link_id is not None
        if is_correction != (
            self.expected_version is not None and self.correction_reason is not None
        ):
            raise IdentityConflictError
        if self.expected_version is not None and self.expected_version < 1:
            msg = "repository link expected version must be positive"
            raise IdentityValidationError(msg)

    def confirmation(self, effective_at: int) -> LinkConfirmation:
        """Create the transition metadata from command authority and injected time."""
        return LinkConfirmation(
            self.operation_id,
            self.actor_id,
            self.grant_id,
            self.confirmation_source,
            effective_at,
            self.correction_reason,
        )

    def request_digest(self) -> str:
        """Bind idempotency to every semantic command field with canonical JSON."""
        candidate = self.candidate
        payload = {
            "actor_id": self.actor_id.value,
            "brain_id": self.brain_id.value,
            "candidate": {
                "component_root_fingerprint": (
                    None
                    if candidate.component_root_fingerprint is None
                    else candidate.component_root_fingerprint.value
                ),
                "evidence": [
                    {
                        "digest": evidence.digest.value,
                        "kind": evidence.kind.value,
                        "strength": evidence.strength.value,
                    }
                    for evidence in candidate.evidence
                ],
                "relation_type": candidate.relation_type.value,
                "subject_id": candidate.subject_id.value,
                "subject_type": candidate.subject_type.value,
                "target_id": candidate.target_id.value,
                "target_type": candidate.target_type.value,
            },
            "confirmation_source": self.confirmation_source.value,
            "correction_reason": self.correction_reason,
            "expected_version": self.expected_version,
            "grant_id": self.grant_id.value,
            "link_id": None if self.link_id is None else self.link_id.value,
            "operation_id": self.operation_id,
        }
        encoded = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ConfirmRepositoryLinkHandler:
    """Commit one canonical topology aggregate version in a serialized Unit of Work."""

    unit_of_work: RepositoryLinkUnitOfWorkFactory
    identities: StableIdentityGenerator
    clock: Clock

    async def execute(self, command: ConfirmRepositoryLinkCommand) -> ProjectRepositoryLink:
        """Confirm or correct with current authorization, CAS, and idempotency checks."""
        request_digest = command.request_digest()
        async with self.unit_of_work() as unit_of_work:
            await unit_of_work.authorization.authorize(
                command.brain_id,
                command.actor_id,
                command.grant_id,
            )
            await unit_of_work.links.require_candidate(command.candidate)
            prior = await unit_of_work.links.find_operation(
                command.brain_id,
                command.operation_id,
            )
            if prior is not None:
                prior_digest, aggregate = prior
                if prior_digest != request_digest:
                    raise IdentityConflictError
                return aggregate
            effective_at = _unix_microseconds(self.clock.now())
            if command.link_id is None:
                if await unit_of_work.links.find_active(command.candidate) is not None:
                    raise IdentityConflictError
                aggregate, _ = ProjectRepositoryLink.confirm(
                    self.identities.new(),
                    command.candidate,
                    command.confirmation(effective_at),
                )
                previous_version: int | None = None
            else:
                current = await unit_of_work.links.find_link(
                    command.brain_id,
                    command.link_id,
                )
                if current is None or command.expected_version is None:
                    raise IdentityConflictError
                aggregate, _ = current.correct(
                    command.candidate,
                    command.confirmation(effective_at),
                    expected_version=command.expected_version,
                )
                previous_version = current.version
            await unit_of_work.links.append(
                request_digest,
                self.identities.new(),
                aggregate,
                expected_previous_version=previous_version,
            )
            await unit_of_work.commit()
            return aggregate


def _unix_microseconds(value: datetime) -> int:
    return int(value.timestamp() * 1_000_000)
