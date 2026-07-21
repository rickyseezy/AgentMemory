"""GRA-005 contradiction persistence boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.graph.domain.contradictions import (
        Contradiction,
        ContradictionCandidate,
        ContradictionResolution,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


class ContradictionRepository(Protocol):
    """Authorize and persist contradiction state independently of ranking."""

    async def detection_candidates(
        self, scope: AuthorizedScope, repository_id: str
    ) -> tuple[ContradictionCandidate, ...]:
        """Load content-free canonical assertion candidates for one Repository."""
        ...

    async def record_detection(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        repository_id: str,
        contradictions: tuple[Contradiction, ...],
    ) -> tuple[Contradiction, ...]:
        """Append a deterministic detection result idempotently."""
        ...

    async def get(self, scope: AuthorizedScope, contradiction_id: str) -> Contradiction | None:
        """Load one currently authorized dispute including any resolution."""
        ...

    async def resolve(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        contradiction: Contradiction,
        resolution: ContradictionResolution,
    ) -> Contradiction:
        """Append one user-authoritative resolution idempotently."""
        ...

    async def for_assertions(
        self, scope: AuthorizedScope, assertion_ids: tuple[str, ...]
    ) -> tuple[Contradiction, ...]:
        """Load disputes relevant to already-fused assertion candidates."""
        ...
