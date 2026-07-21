"""IDX-003 narrow ports for revision processing, graph proofs, and history reads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.revision_history import (
        CommitGraphAnswer,
        CommitGraphSnapshot,
        SourceRevisionHistoryCandidate,
        SourceRevisionOutcome,
        SourceRevisionTransition,
    )


@dataclass(frozen=True, slots=True)
class SourceRevisionWork:
    """One trusted committed projection event ready for branch-aware processing."""

    operation_id: str
    transition: SourceRevisionTransition


class CommitGraphPort(Protocol):
    """Answer commit reachability against one persisted immutable graph watermark."""

    async def pin_commit(
        self,
        brain_id: str,
        repository_id: str,
        commit_sha: str,
        recorded_at: datetime,
        answered_at: datetime,
    ) -> CommitGraphSnapshot:
        """Pin a known commit and canonical graph digest at recorded time."""
        ...

    async def pin_branch(
        self,
        brain_id: str,
        repository_id: str,
        branch_name: str,
        recorded_at: datetime,
        answered_at: datetime,
    ) -> CommitGraphSnapshot:
        """Resolve a mutable ref once, then pin its commit and graph digest."""
        ...

    async def ancestry(
        self,
        snapshot: CommitGraphSnapshot,
        ancestor_sha: str,
        descendant_sha: str,
        answered_at: datetime,
    ) -> CommitGraphAnswer:
        """Return and persist whether ancestor reaches descendant at the pinned watermark."""
        ...

    async def merge_bases(
        self,
        snapshot: CommitGraphSnapshot,
        left_sha: str,
        right_sha: str,
        answered_at: datetime,
    ) -> CommitGraphAnswer:
        """Return and persist every best common ancestor at the pinned watermark."""
        ...


class SourceRevisionRepository(Protocol):
    """Maintain append-only source context, evidence lineage, and processing receipts."""

    async def claim_next(self, claimed_at: datetime) -> SourceRevisionWork | None:
        """Claim the oldest committed source projection after grant revalidation."""
        ...

    async def find_outcome(self, operation_id: str, event_id: str) -> SourceRevisionOutcome | None:
        """Resolve an exact idempotent processing replay."""
        ...

    async def complete(
        self,
        work: SourceRevisionWork,
        snapshot: CommitGraphSnapshot,
        answers: tuple[CommitGraphAnswer, ...],
        processed_at: datetime,
    ) -> SourceRevisionOutcome:
        """Atomically append contexts, impacts, lineage, job, and receipt."""
        ...

    async def candidates(
        self,
        scope: AuthorizedScope,
        repository_id: str,
        relative_path: str,
        recorded_at: datetime,
        limit: int,
    ) -> tuple[SourceRevisionHistoryCandidate, ...]:
        """Return authorized retained history rows as known at recorded time."""
        ...

    async def register_lineage(  # noqa: PLR0913 -- Port binds complete lineage mutation.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        context_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        """Append or replay one source revision → evidence → assertion reverse edge."""
        ...
