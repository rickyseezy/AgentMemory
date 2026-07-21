"""GRA-002 segregated evidence and assertion repository ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertions import (
        Assertion,
        AssertionCandidate,
        AssertionEvidenceReference,
        AssertionEvidenceRevocation,
        AssertionLifecycleEvent,
        ResolvedAssertionEvidence,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


class AssertionRepository(Protocol):
    """Persist canonical candidate and authoritative assertion transitions atomically."""

    async def propose(self, operation_id: str, candidate: AssertionCandidate) -> AssertionCandidate:
        """Persist or return an exact idempotent candidate proposal."""
        ...

    async def get_candidate(self, candidate_id: str) -> AssertionCandidate | None:
        """Load one scoped candidate by stable identity."""
        ...

    async def get_assertion(self, assertion_id: str) -> Assertion | None:
        """Load one scoped authoritative assertion."""
        ...

    async def activate(
        self,
        operation_id: str,
        assertion: Assertion,
        event: AssertionLifecycleEvent,
    ) -> Assertion:
        """Atomically activate a candidate and append its lifecycle event."""
        ...

    async def dispute(
        self,
        operation_id: str,
        assertion: Assertion,
        event: AssertionLifecycleEvent,
    ) -> Assertion:
        """Atomically dispute an assertion and append its lifecycle event."""
        ...


class AssertionEvidenceRepository(Protocol):
    """Resolve immutable evidence metadata without accepting arbitrary source text."""

    async def resolve(
        self,
        evidence_ids: tuple[str, ...],
        resolved_at: datetime,
    ) -> tuple[ResolvedAssertionEvidence, ...]:
        """Resolve only currently authorized evidence identities."""
        ...


class AssertionEvidenceCatalog(Protocol):
    """Register typed canonical sources and append evidence revocations."""

    async def register(
        self,
        reference: AssertionEvidenceReference,
        registered_at: datetime,
    ) -> ResolvedAssertionEvidence:
        """Resolve and register a canonical source without caller-supplied content or digest."""
        ...

    async def revoke(self, revocation: AssertionEvidenceRevocation) -> tuple[Assertion, ...]:
        """Atomically revoke evidence and dispute every newly unsupported assertion."""
        ...


class ScopedAssertionRepositoryFactory(Protocol):
    """Create operation-scoped canonical and evidence capabilities."""

    def assertions(self, scope: AuthorizedScope) -> AssertionRepository:
        """Bind canonical assertion access to one immutable scope."""
        ...

    def evidence(self, scope: AuthorizedScope) -> AssertionEvidenceRepository:
        """Bind evidence resolution to one immutable scope."""
        ...


class ScopedAssertionEvidenceCatalogFactory(Protocol):
    """Create trusted evidence-catalog capabilities independently of assertion use cases."""

    def evidence_catalog(self, scope: AuthorizedScope) -> AssertionEvidenceCatalog:
        """Bind trusted evidence registration and revocation to one immutable scope."""
        ...
