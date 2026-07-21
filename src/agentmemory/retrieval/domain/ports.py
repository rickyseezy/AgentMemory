"""Repository ports for ADP-006 continuity reads and procedures."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.retrieval.domain.continuity import (
        CodeRevision,
        ContextInjectedEvent,
        ContinuityItem,
        ProcedureCandidate,
        SessionBriefing,
        StartSessionBriefingQuery,
    )


class ContinuityReadRepository(Protocol):
    """Read only candidates already narrowed by an immutable authorized scope."""

    async def list_items(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ContinuityItem, ...]:
        """Return bounded candidates without filtering by consumer host."""
        ...


class TaskReadRepository(Protocol):
    """Read authorized task/checkpoint continuity candidates."""

    async def list_items(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ContinuityItem, ...]:
        """Return bounded task-derived semantic atoms."""
        ...


class MemoryQueryRepository(Protocol):
    """Read authorized current long-term memory candidates."""

    async def list_items(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ContinuityItem, ...]:
        """Return bounded current memory atoms with complete evidence."""
        ...


class CodeRevisionQuery(Protocol):
    """Read latest authorized revisions for current Checkout members."""

    async def current_revisions(
        self, authorized_scope: AuthorizedScope
    ) -> tuple[CodeRevision, ...]:
        """Return one current revision per explicitly scoped Checkout."""
        ...


class RetrievalPipeline(Protocol):
    """Apply deterministic policy to already authorized bounded source results."""

    def select(
        self,
        query: StartSessionBriefingQuery,
        task_items: tuple[ContinuityItem, ...],
        memory_items: tuple[ContinuityItem, ...],
        revisions: tuple[CodeRevision, ...],
        procedures: tuple[ProcedureCandidate, ...],
    ) -> SessionBriefing:
        """Return a complete bounded briefing without performing I/O."""
        ...


class ContextInjectionRepository(Protocol):
    """Persist one content-free ContextInjected event after selection."""

    async def record(
        self,
        authorized_scope: AuthorizedScope,
        event: ContextInjectedEvent,
    ) -> str:
        """Append once and return the canonical event ID, including on exact retry."""
        ...


class ProcedureReadRepository(Protocol):
    """Read authorized active procedure candidates before applicability filtering."""

    async def list_candidates(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ProcedureCandidate, ...]:
        """Return bounded authorized candidates independent of delivery format."""
        ...
