"""GRA-005 detect, resolve, and retrieval-qualification use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.graph.domain.contradictions import (
    ContradictionDetector,
    ContradictionPolicy,
    ContradictionResolution,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphConflictError
from agentmemory.graph.domain.models import stable_graph_id

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.contradiction_ports import ContradictionRepository
    from agentmemory.graph.domain.contradictions import (
        Contradiction,
        ContradictionPolicyResult,
        ContradictionResolutionOutcome,
        RetrievalAssertionCandidate,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_MAX_FUSED_CANDIDATES = 1_000
_ERR_ACTION = "contradiction action is not authorized"
_ERR_SCOPE = "contradiction scope is not authorized"
_ERR_NOT_FOUND = "contradiction was not found"
_ERR_QUERY = "contradiction query is invalid"


@dataclass(frozen=True, slots=True)
class DetectContradictionsCommand:
    """Detect all deterministic conflicts for one authorized Repository."""

    operation_id: str
    scope: AuthorizedScope
    repository_id: str
    detected_at: datetime

    def __post_init__(self) -> None:
        """Reject a Repository outside the immutable authorization scope."""
        if self.repository_id not in {item.value for item in self.scope.repository_ids}:
            raise GraphAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class DetectContradictionsHandler:
    """Run closed incompatibility rules and append the resulting disputes."""

    repository: ContradictionRepository

    async def execute(self, command: DetectContradictionsCommand) -> tuple[Contradiction, ...]:
        """Authorize before loading assertion metadata or counts."""
        _require_action(command.scope, "graph.contradiction.detect")
        candidates = await self.repository.detection_candidates(
            command.scope, command.repository_id
        )
        contradictions = ContradictionDetector.detect(candidates, command.detected_at)
        return await self.repository.record_detection(
            command.scope,
            command.operation_id,
            command.repository_id,
            contradictions,
        )


@dataclass(frozen=True, slots=True)
class ResolveContradictionCommand:
    """Resolve one dispute with explicit current user/grant authority and evidence."""

    operation_id: str
    scope: AuthorizedScope
    contradiction_id: str
    grant_id: str
    outcome: ContradictionResolutionOutcome
    reason_code: str
    evidence_ids: tuple[str, ...]
    resolved_at: datetime


@dataclass(frozen=True, slots=True)
class ResolveContradictionHandler:
    """Append a resolution while preserving the immutable dispute record."""

    repository: ContradictionRepository

    async def execute(self, command: ResolveContradictionCommand) -> Contradiction:
        """Authorize, load the dispute, bind the current actor, and resolve once."""
        _require_action(command.scope, "graph.contradiction.resolve")
        contradiction = await self.repository.get(command.scope, command.contradiction_id)
        if contradiction is None:
            raise GraphConflictError(_ERR_NOT_FOUND)
        resolution = ContradictionResolution.create(
            contradiction_id=contradiction.id,
            outcome=command.outcome,
            actor_id=command.scope.principal_id.value,
            grant_id=command.grant_id,
            reason_code=command.reason_code,
            evidence_ids=command.evidence_ids,
            resolved_at=command.resolved_at,
        )
        return await self.repository.resolve(
            command.scope,
            command.operation_id,
            contradiction,
            resolution,
        )


@dataclass(frozen=True, slots=True)
class EvaluateContradictionsQuery:
    """Apply contradiction policy to candidates after retrieval fusion."""

    scope: AuthorizedScope
    candidates: tuple[RetrievalAssertionCandidate, ...]

    def __post_init__(self) -> None:
        """Require a bounded, duplicate-free fused candidate list."""
        if (
            not self.candidates
            or len(self.candidates) > _MAX_FUSED_CANDIDATES
            or len({item.assertion_id for item in self.candidates}) != len(self.candidates)
        ):
            raise GraphConflictError(_ERR_QUERY)


@dataclass(frozen=True, slots=True)
class EvaluateContradictionsHandler:
    """Qualify or abstain after fusion and before response synthesis."""

    repository: ContradictionRepository

    async def execute(self, query: EvaluateContradictionsQuery) -> ContradictionPolicyResult:
        """Load current dispute state and apply rank-independent truth policy."""
        _require_action(query.scope, "graph.contradiction.query")
        assertion_ids = tuple(sorted(item.assertion_id for item in query.candidates))
        for assertion_id in assertion_ids:
            stable_graph_id(assertion_id)
        contradictions = await self.repository.for_assertions(query.scope, assertion_ids)
        return ContradictionPolicy.apply(query.candidates, contradictions)


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)
