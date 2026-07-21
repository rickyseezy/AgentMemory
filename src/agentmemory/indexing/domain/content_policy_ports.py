"""IDX-006 ports for policy resolution, evidence, reconciliation, and projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.content_policy import (
        IndexContentPolicy,
        IndexPolicyRevision,
        PolicyDecision,
        PolicyLayer,
        PolicyRuleSource,
        ReconciliationAction,
    )


@dataclass(frozen=True, slots=True)
class PolicySourceDocuments:
    """Bounded repository-owned ignore sources read only as policy metadata."""

    agentmemoryignore: bytes | None
    gitignore: bytes | None


@dataclass(frozen=True, slots=True)
class PolicyChangeResult:
    """Content-free activation and bounded reconciliation summary."""

    change_id: str
    operation_id: str
    brain_id: str
    repository_id: str
    previous_policy_digest: str | None
    current_policy_digest: str
    delete_count: int
    reindex_count: int
    activated_at: datetime


@dataclass(frozen=True, slots=True)
class PolicyReconciliationWork:
    """One idempotent derivative deletion or rebuild request."""

    item_id: str
    change_id: str
    repository_id: str
    relative_path: str
    action: ReconciliationAction
    policy_digest: str
    claimed_at: datetime


class IndexContentPolicyRepository(Protocol):
    """Persist immutable policy revisions, sources, decisions, and change work."""

    async def resolve_revision(
        self,
        repository_id: str,
        resolved_at: datetime,
    ) -> IndexPolicyRevision:
        """Resolve repository, then Brain, then secure-default policy authority."""
        ...

    async def observe_source(
        self,
        repository_id: str,
        layer: PolicyLayer,
        content: bytes,
        observed_at: datetime,
    ) -> PolicyRuleSource:
        """Store content-free parsed source evidence and return its stable version."""
        ...

    async def record_decision(self, decision: PolicyDecision) -> None:
        """Append or exactly replay one decision without retaining source bytes."""
        ...

    async def activate(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        revision: IndexPolicyRevision,
        activated_at: datetime,
    ) -> PolicyChangeResult:
        """Activate the next revision and atomically schedule affected derivatives."""
        ...

    async def get_change(
        self,
        scope: AuthorizedScope,
        change_id: str,
    ) -> PolicyChangeResult | None:
        """Return one currently authorized content-free policy change."""
        ...


class RepositoryContentPolicyGate(Protocol):
    """Sole policy boundary used by a repository source before downstream work."""

    async def prepare(
        self,
        repository_id: str,
        documents: PolicySourceDocuments,
        observed_at: datetime,
    ) -> IndexContentPolicy:
        """Resolve a complete hash-bound policy session for one inspection."""
        ...

    async def record(self, decision: PolicyDecision) -> None:
        """Persist a path/content decision before its result is consumed."""
        ...


class PolicyReconciliationRepository(Protocol):
    """Lease and complete bounded policy-change work."""

    async def claim_next(self, claimed_at: datetime) -> PolicyReconciliationWork | None:
        """Claim the oldest currently authorized item with an expiring lease."""
        ...

    async def complete(self, item_id: str, completed_at: datetime) -> None:
        """Append the exact idempotent completion receipt."""
        ...


class PolicyProjectionPort(Protocol):
    """Delete excluded derivatives or enqueue a clean reindex through one boundary."""

    async def apply(self, work: PolicyReconciliationWork) -> None:
        """Apply one idempotent deletion/invalidation or rebuild request."""
        ...
