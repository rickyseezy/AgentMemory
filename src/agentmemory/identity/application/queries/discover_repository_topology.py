"""ID-003 authorized repository-topology candidate discovery query."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError
from agentmemory.identity.domain.topology import RepositoryTopologyCandidate

if TYPE_CHECKING:
    from agentmemory.identity.domain.ports import (
        IdentityAuthorizationPolicy,
        RepositoryTopologyReadRepository,
    )
    from agentmemory.identity.domain.value_objects import StableId

_OPERATION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_OBSERVATIONS = 512


@dataclass(frozen=True, slots=True)
class DiscoverRepositoryTopologyQuery:
    """Authenticated, path-free batch of host parser candidate observations."""

    operation_id: str
    brain_id: StableId
    actor_id: StableId
    grant_id: StableId
    observations: tuple[RepositoryTopologyCandidate, ...]

    def __post_init__(self) -> None:
        """Bound transport work and reject cross-Brain observations before I/O."""
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "repository topology discovery operation ID is invalid"
            raise IdentityValidationError(msg)
        if len(self.observations) > _MAX_OBSERVATIONS:
            msg = "repository topology discovery exceeds its observation bound"
            raise IdentityValidationError(msg)
        if any(candidate.brain_id != self.brain_id for candidate in self.observations):
            raise IdentityConflictError


@dataclass(frozen=True, slots=True)
class RepositoryTopologyDiscovery:
    """Content-free canonical candidate set and closed explanations."""

    brain_id: StableId
    candidates: tuple[RepositoryTopologyCandidate, ...]
    explanation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiscoverRepositoryTopologyHandler:
    """Authorize, validate endpoint ownership, and coalesce parser evidence."""

    authorization: IdentityAuthorizationPolicy
    repository: RepositoryTopologyReadRepository

    async def execute(
        self,
        query: DiscoverRepositoryTopologyQuery,
    ) -> RepositoryTopologyDiscovery:
        """Return candidate links without creating, merging, or correcting identities."""
        await self.authorization.authorize_resolution(
            query.brain_id,
            query.actor_id,
            query.grant_id,
        )
        for candidate in query.observations:
            await self.repository.require_candidate(candidate)
        candidates = _coalesce(query.observations)
        return RepositoryTopologyDiscovery(
            query.brain_id,
            candidates,
            tuple(f"candidate:{candidate.relation_type.value}" for candidate in candidates),
        )


def _coalesce(
    candidates: tuple[RepositoryTopologyCandidate, ...],
) -> tuple[RepositoryTopologyCandidate, ...]:
    grouped: dict[tuple[str, ...], list[RepositoryTopologyCandidate]] = {}
    for candidate in candidates:
        candidate_key = (
            candidate.subject_type.value,
            candidate.subject_id.value,
            candidate.relation_type.value,
            candidate.target_type.value,
            candidate.target_id.value,
            (
                ""
                if candidate.component_root_fingerprint is None
                else candidate.component_root_fingerprint.value
            ),
        )
        grouped.setdefault(candidate_key, []).append(candidate)
    results: list[RepositoryTopologyCandidate] = []
    for group_key in sorted(grouped):
        group = grouped[group_key]
        template = group[0]
        evidence = tuple(
            sorted(
                {item for candidate in group for item in candidate.evidence},
                key=lambda item: item.digest.value,
            )
        )
        results.append(
            RepositoryTopologyCandidate(
                template.brain_id,
                template.subject_type,
                template.subject_id,
                template.relation_type,
                template.target_type,
                template.target_id,
                template.component_root_fingerprint,
                evidence,
            )
        )
    return tuple(results)
