"""IDX-007 ports for evidence lookup, exact bytes, and host path resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.source_navigation import CheckoutCandidate, SourceEvidence


class SourceEvidenceRepository(Protocol):
    """Load one currently authorized immutable semantic evidence record."""

    async def get(self, scope: AuthorizedScope, evidence_id: str) -> SourceEvidence | None:
        """Return exact evidence, hiding revoked or policy-invalidated rows."""
        ...


class SourceContentPort(Protocol):
    """Read bounded revision/current bytes without exposing repository roots."""

    async def historical(self, evidence: SourceEvidence) -> bytes | None:
        """Return exact historical/CAS bytes when locally available."""
        ...

    async def checkout_candidates(self, evidence: SourceEvidence) -> tuple[CheckoutCandidate, ...]:
        """Return bounded rename/diff candidates from one active checkout."""
        ...


class LocalPathResolverPort(Protocol):
    """Resolve a verified relative source target only at the trusted host boundary."""

    async def resolve(
        self,
        repository_id: str,
        relative_path: str,
        expected_digest: str,
    ) -> str | None:
        """Return an absolute path only if it remains inside the configured repository."""
        ...
