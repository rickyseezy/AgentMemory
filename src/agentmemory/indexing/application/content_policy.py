"""IDX-006 policy activation, repository gate, and reconciliation worker."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyLayer,
    PolicyRuleSource,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.content_policy import PolicyDecision
    from agentmemory.indexing.domain.content_policy_ports import (
        IndexContentPolicyRepository,
        PolicyChangeResult,
        PolicyProjectionPort,
        PolicyReconciliationRepository,
        PolicySourceDocuments,
    )
    from agentmemory.shared.clock import Clock

_OPERATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERR_ACTION = "content policy action is not authorized"
_ERR_SCOPE = "content policy requires one exact project and repository"
_ERR_REQUEST = "content policy request is invalid"
_ERR_NOT_FOUND = "content policy change was not found"


@dataclass(frozen=True, slots=True)
class ActivateIndexPolicyCommand:
    """Activate one immutable administrator-defined Brain policy revision."""

    operation_id: str
    scope: AuthorizedScope
    revision: IndexPolicyRevision
    activated_at: datetime

    def __post_init__(self) -> None:
        """Reject ambiguous replay coordinates before persistence."""
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise IndexingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class GetIndexPolicyChangeQuery:
    """Read one content-free activation/reconciliation summary."""

    scope: AuthorizedScope
    change_id: str

    def __post_init__(self) -> None:
        """Require the stable change identity."""
        if _DIGEST.fullmatch(self.change_id) is None:
            raise IndexingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class ActivateIndexPolicyHandler:
    """Authorize and atomically activate/schedule one policy revision."""

    repository: IndexContentPolicyRepository

    async def execute(self, command: ActivateIndexPolicyCommand) -> PolicyChangeResult:
        """Validate exact scope ownership before any canonical write."""
        _require_action(command.scope, "indexing.policy.activate")
        _, repository_id = _exact_scope(command.scope)
        if (
            command.revision.brain_id != command.scope.brain_id.value
            or command.revision.repository_id != repository_id
            or command.revision.activated_at != command.activated_at
        ):
            raise IndexingValidationError(_ERR_REQUEST)
        return await self.repository.activate(
            command.scope,
            command.operation_id,
            command.revision,
            command.activated_at,
        )


@dataclass(frozen=True, slots=True)
class GetIndexPolicyChangeHandler:
    """Read a policy change only through current authorization."""

    repository: IndexContentPolicyRepository

    async def execute(self, query: GetIndexPolicyChangeQuery) -> PolicyChangeResult:
        """Return one summary without revealing paths or rule contents."""
        _require_action(query.scope, "indexing.policy.read")
        result = await self.repository.get_change(query.scope, query.change_id)
        if result is None:
            raise IndexingValidationError(_ERR_NOT_FOUND)
        return result


@dataclass(frozen=True, slots=True)
class IndexContentPolicyGate:
    """Resolve repository policy sources and durably record every decision."""

    repository: IndexContentPolicyRepository

    async def prepare(
        self,
        repository_id: str,
        documents: PolicySourceDocuments,
        observed_at: datetime,
    ) -> IndexContentPolicy:
        """Bind current Brain authority and exact repository-source hashes."""
        revision = await self.repository.resolve_revision(repository_id, observed_at)
        agentmemoryignore = await self._source(
            repository_id,
            PolicyLayer.AGENTMEMORY_IGNORE,
            documents.agentmemoryignore,
            observed_at,
        )
        gitignore = await self._source(
            repository_id,
            PolicyLayer.GITIGNORE,
            documents.gitignore,
            observed_at,
        )
        return IndexContentPolicy(revision, agentmemoryignore, gitignore)

    async def _source(
        self,
        repository_id: str,
        layer: PolicyLayer,
        content: bytes | None,
        observed_at: datetime,
    ) -> PolicyRuleSource:
        if content is None:
            return PolicyRuleSource.empty(layer)
        return await self.repository.observe_source(repository_id, layer, content, observed_at)

    async def record(self, decision: PolicyDecision) -> None:
        """Persist the exact content-free result before downstream release."""
        await self.repository.record_decision(decision)


@dataclass(frozen=True, slots=True)
class PolicyReconciliationWorker:
    """Drain bounded policy deletion/reindex work through one projection port."""

    repository: PolicyReconciliationRepository
    projection: PolicyProjectionPort
    clock: Clock

    async def run_once(self) -> bool:
        """Apply and acknowledge one item; failed work remains retryable."""
        work = await self.repository.claim_next(self.clock.now())
        if work is None:
            return False
        await self.projection.apply(work)
        await self.repository.complete(work.item_id, self.clock.now())
        return True

    async def run(self, stop: asyncio.Event, *, idle_seconds: float = 0.1) -> None:
        """Drain until graceful shutdown without swallowing cancellation."""
        while not stop.is_set():
            if not await self.run_once():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=idle_seconds)
                except TimeoutError:
                    continue


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _exact_scope(scope: AuthorizedScope) -> tuple[str, str]:
    if len(scope.project_ids) != 1 or len(scope.repository_ids) != 1:
        raise IndexingAuthorizationError(_ERR_SCOPE)
    return scope.project_ids[0].value, scope.repository_ids[0].value
