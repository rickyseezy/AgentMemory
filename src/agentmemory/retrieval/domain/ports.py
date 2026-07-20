"""Repository ports for ADP-006 continuity reads and procedures."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.retrieval.domain.continuity import ContinuityItem, ProcedureCandidate


class ContinuityReadRepository(Protocol):
    """Read only candidates already narrowed by an immutable authorized scope."""

    async def list_items(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ContinuityItem, ...]:
        """Return bounded candidates without filtering by consumer host."""
        ...


class ProcedureReadRepository(Protocol):
    """Read authorized active procedure candidates before applicability filtering."""

    async def list_candidates(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ProcedureCandidate, ...]:
        """Return bounded authorized candidates independent of delivery format."""
        ...
