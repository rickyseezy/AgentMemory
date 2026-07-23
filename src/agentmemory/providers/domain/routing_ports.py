"""PRO-005 ports for immutable policy storage, profile reads, identities, and cache."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.routing import (
        ProviderRoutingPolicy,
        RepositoryRoutingRestriction,
        RoutableProviderProfile,
        RouteDecision,
    )


class ProviderRoutingRepository(Protocol):
    """Persist immutable policies, restrictions, and decision evidence."""

    async def current_policy(
        self,
        scope: AuthorizedScope,
        requested_at: datetime,
    ) -> ProviderRoutingPolicy | None:
        """Load the latest Brain policy under current authorization."""
        ...

    async def profiles(
        self,
        scope: AuthorizedScope,
        profile_ids: tuple[str, ...],
        requested_at: datetime,
    ) -> tuple[RoutableProviderProfile, ...]:
        """Load exact current capability projections for referenced profiles."""
        ...

    async def publish_policy(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        expected_current_version: int,
        policy: ProviderRoutingPolicy,
    ) -> ProviderRoutingPolicy:
        """Atomically publish or replay one next immutable policy version."""
        ...

    async def current_restriction(
        self,
        scope: AuthorizedScope,
        repository_id: str,
        requested_at: datetime,
    ) -> RepositoryRoutingRestriction | None:
        """Load the latest repository filter, if configured."""
        ...

    async def publish_restriction(  # noqa: PLR0913 -- Port binds authority and revision.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        expected_current_version: int,
        restriction: RepositoryRoutingRestriction,
        created_at: datetime,
    ) -> RepositoryRoutingRestriction:
        """Atomically publish or replay one next immutable repository filter."""
        ...

    async def record_decision(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        cache_key: str,
        decision: RouteDecision,
        decided_at: datetime,
    ) -> RouteDecision:
        """Append or exactly replay content-free decision evidence."""
        ...


class ProviderRoutingIdentityGenerator(Protocol):
    """Generate unpredictable RFC 9562 UUIDv7 routing identities."""

    def new(self) -> str:
        """Return one fresh routing identity."""
        ...


class ProviderRouteCache(Protocol):
    """Bounded cache of deterministic semantic route decisions."""

    async def get(self, key: str) -> RouteDecision | None:
        """Return a cached decision or ``None``."""
        ...

    async def put(self, key: str, decision: RouteDecision) -> None:
        """Store one immutable decision under its complete version key."""
        ...
