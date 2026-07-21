"""GRA-002 propose, activate, and evidence-reconciliation use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.graph.domain.assertions import (
    AssertionEventType,
    AssertionLifecycleEvent,
    AssertionStatus,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphConflictError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertion_ports import ScopedAssertionRepositoryFactory
    from agentmemory.graph.domain.assertions import Assertion, AssertionCandidate
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_ERR_ACTION = "assertion action is not authorized"
_ERR_SCOPE = "assertion is outside authorized scope"
_ERR_NOT_FOUND = "assertion candidate was not found"
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")


@dataclass(frozen=True, slots=True)
class ProposeAssertionCommand:
    """Persist one non-authoritative candidate under explicit scope."""

    operation_id: str
    scope: AuthorizedScope
    candidate: AssertionCandidate


@dataclass(frozen=True, slots=True)
class ActivateAssertionCommand:
    """Activate one candidate after current evidence resolution."""

    operation_id: str
    event_id: str
    candidate_id: str
    scope: AuthorizedScope
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class ReconcileAssertionEvidenceCommand:
    """Re-evaluate active evidence after deletion or authorization changes."""

    operation_id: str
    event_id: str
    assertion_id: str
    scope: AuthorizedScope
    occurred_at: datetime


class AuthorizationPolicy:
    """Apply action, Brain, project, repository, checkout, and classification authority."""

    @staticmethod
    def authorize(
        scope: AuthorizedScope,
        assertion: AssertionCandidate | Assertion,
        action: str,
    ) -> None:
        """Fail closed unless the complete assertion coordinates fit the immutable scope."""
        _authorize(scope, assertion, action)


@dataclass(frozen=True, slots=True)
class ProposeAssertionHandler:
    """Create candidates without conflating model output with authority."""

    repositories: ScopedAssertionRepositoryFactory

    async def execute(self, command: ProposeAssertionCommand) -> AssertionCandidate:
        """Authorize the exact scope before candidate persistence."""
        AuthorizationPolicy.authorize(command.scope, command.candidate, "graph.assertion.propose")
        return await self.repositories.assertions(command.scope).propose(
            command.operation_id, command.candidate
        )


@dataclass(frozen=True, slots=True)
class ActivateAssertionHandler:
    """Resolve evidence and atomically activate one candidate revision."""

    repositories: ScopedAssertionRepositoryFactory

    async def execute(self, command: ActivateAssertionCommand) -> Assertion:
        """Apply authorization, evidence, temporal, aggregate, and idempotency policies."""
        _require_action(command.scope, "graph.assertion.activate")
        repository = self.repositories.assertions(command.scope)
        candidate = await repository.get_candidate(command.candidate_id)
        if candidate is None:
            raise GraphConflictError(_ERR_NOT_FOUND)
        AuthorizationPolicy.authorize(command.scope, candidate, "graph.assertion.activate")
        evidence = await self.repositories.evidence(command.scope).resolve(
            candidate.evidence_ids, command.occurred_at
        )
        assertion = candidate.activate(evidence, command.occurred_at)
        event = AssertionLifecycleEvent.create(
            event_id=command.event_id,
            operation_id=command.operation_id,
            assertion=assertion,
            event_type=AssertionEventType.ACTIVATED,
            occurred_at=command.occurred_at,
        )
        return await repository.activate(command.operation_id, assertion, event)


@dataclass(frozen=True, slots=True)
class ReconcileAssertionEvidenceHandler:
    """Dispute active assertions whose complete evidence set lost authority."""

    repositories: ScopedAssertionRepositoryFactory

    async def execute(self, command: ReconcileAssertionEvidenceCommand) -> Assertion:
        """Keep supported assertions active and atomically record disputes."""
        _require_action(command.scope, "graph.assertion.reconcile")
        repository = self.repositories.assertions(command.scope)
        assertion = await repository.get_assertion(command.assertion_id)
        if assertion is None:
            raise GraphConflictError(_ERR_NOT_FOUND)
        AuthorizationPolicy.authorize(command.scope, assertion, "graph.assertion.reconcile")
        if assertion.status is AssertionStatus.ACTIVE:
            evidence = await self.repositories.evidence(command.scope).resolve(
                tuple(item.evidence_id for item in assertion.evidence),
                command.occurred_at,
            )
            reconciled = assertion.reconcile_evidence(evidence, command.occurred_at)
            if reconciled.status is AssertionStatus.ACTIVE:
                return reconciled
        elif assertion.status is AssertionStatus.DISPUTED:
            reconciled = assertion
        else:
            raise GraphConflictError(_ERR_NOT_FOUND)
        event = AssertionLifecycleEvent.create(
            event_id=command.event_id,
            operation_id=command.operation_id,
            assertion=reconciled,
            event_type=AssertionEventType.DISPUTED,
            occurred_at=command.occurred_at,
        )
        return await repository.dispute(command.operation_id, reconciled, event)


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)


def _authorize(
    scope: AuthorizedScope,
    assertion: AssertionCandidate | Assertion,
    action: str,
) -> None:
    _require_action(scope, action)
    coordinates = assertion.scope
    if coordinates.brain_id != scope.brain_id.value:
        raise GraphAuthorizationError(_ERR_SCOPE)
    member = next(
        (item for item in scope.members if item.project_id.value == coordinates.project_id),
        None,
    )
    if member is None or coordinates.repository_id not in {
        item.value for item in member.repository_ids
    }:
        raise GraphAuthorizationError(_ERR_SCOPE)
    if (
        coordinates.checkout_id is not None
        and member.checkout_ids
        and coordinates.checkout_id not in {item.value for item in member.checkout_ids}
    ):
        raise GraphAuthorizationError(_ERR_SCOPE)
    ceiling = _CLASSIFICATIONS.index(scope.classification_ceiling.value)
    if _CLASSIFICATIONS.index(coordinates.classification) > ceiling:
        raise GraphAuthorizationError(_ERR_SCOPE)
