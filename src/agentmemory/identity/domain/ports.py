"""Capability-specific identity context ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.identity.domain.checkout import CheckoutAggregate, CheckoutEvent
    from agentmemory.identity.domain.topology import (
        ProjectRepositoryLink,
        RepositoryTopologyCandidate,
    )
    from agentmemory.identity.domain.value_objects import (
        DeviceIdentity,
        Fingerprint,
        IdentityCandidate,
        ProjectManifest,
        StableId,
        VcsIdentity,
    )


class IdentityAuthorizationPolicy(Protocol):
    """Authorize a workspace resolution before observing sensitive host evidence."""

    async def authorize_resolution(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        """Raise a typed denial unless the actor/grant may inspect this Brain."""
        ...


class ManifestReader(Protocol):
    """Read one ownership-validated explicit workspace manifest."""

    async def read(self, path: str) -> ProjectManifest | None:
        """Return a strict manifest or absence for the observed directory."""
        ...


class DeviceIdentityPort(Protocol):
    """Return installation-keyed device, volume, and path evidence."""

    async def observe(self, path: str) -> DeviceIdentity:
        """Observe a path without returning a raw machine identifier."""
        ...


class VcsIdentityPort(Protocol):
    """Return privacy-safe VCS repository and checkout evidence."""

    async def observe(self, path: str, device: DeviceIdentity) -> VcsIdentity | None:
        """Return VCS evidence or absence without persisting repository content."""
        ...


class ProjectRepository(Protocol):
    """Resolve projects through manifests and explicit repository mappings."""

    async def resolve_manifest(
        self,
        brain_id: StableId,
        manifest: ProjectManifest,
        repository_fingerprint: Fingerprint | None,
    ) -> tuple[IdentityCandidate, ...]:
        """Resolve an explicit project declaration with compatibility checks."""
        ...

    async def find_by_repository(
        self,
        brain_id: StableId,
        repository_ids: tuple[StableId, ...],
    ) -> tuple[IdentityCandidate, ...]:
        """Return authorized Project mappings for exact Repository IDs."""
        ...


class CheckoutRepository(Protocol):
    """Resolve known aliases and separately approved local heuristics."""

    async def find_by_observation(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        checkout_fingerprint: Fingerprint | None,
    ) -> tuple[IdentityCandidate, ...]:
        """Resolve an exact path or checkout fingerprint alias."""
        ...

    async def find_approved_heuristic(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
    ) -> tuple[IdentityCandidate, ...]:
        """Return only previously approved local continuity mappings."""
        ...


class RepositoryIdentityRepository(Protocol):
    """Map a versioned repository fingerprint to existing Repository identities."""

    async def find_by_fingerprint(
        self,
        brain_id: StableId,
        fingerprint: Fingerprint,
    ) -> tuple[StableId, ...]:
        """Resolve the exact versioned keyed fingerprint inside one Brain."""
        ...


class StableIdentityGenerator(Protocol):
    """Generate unpredictable canonical UUIDv7 identity values."""

    def new(self) -> StableId:
        """Return one fresh stable identity."""
        ...


class CheckoutObservationRepository(Protocol):
    """Persist Checkout snapshots, events, and append-only observations."""

    async def require_repository(
        self,
        brain_id: StableId,
        repository_id: StableId,
    ) -> None:
        """Reject a missing, inactive, or cross-Brain Repository."""
        ...

    async def find_operation(
        self,
        brain_id: StableId,
        operation_id: str,
    ) -> CheckoutAggregate | None:
        """Return the original idempotent operation result when it exists."""
        ...

    async def find_continuity(
        self,
        brain_id: StableId,
        repository_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity,
    ) -> tuple[CheckoutAggregate, ...]:
        """Return every deterministic same-Checkout candidate in one Brain."""
        ...

    async def append(
        self,
        operation_id: str,
        event_id: StableId,
        aggregate: CheckoutAggregate,
        event: CheckoutEvent,
        *,
        expected_previous_version: int | None,
    ) -> None:
        """Atomically append provenance and compare-and-swap the snapshot."""
        ...


class CheckoutObservationAuthorizationPolicy(Protocol):
    """Authorize Checkout mutation from inside its write transaction."""

    async def authorize(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        """Raise a typed denial unless the current grant may mutate the Brain."""
        ...


class CheckoutObservationUnitOfWork(Protocol):
    """Own one serialized Checkout observation transaction."""

    @property
    def authorization(self) -> CheckoutObservationAuthorizationPolicy:
        """Return transaction-scoped authorization."""
        ...

    @property
    def checkouts(self) -> CheckoutObservationRepository:
        """Return transaction-scoped Checkout persistence."""
        ...

    async def __aenter__(self) -> Self:
        """Open the write transaction."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless explicitly committed."""
        ...

    async def commit(self) -> None:
        """Commit snapshot, event, and observation together."""
        ...


class CheckoutObservationUnitOfWorkFactory(Protocol):
    """Construct a fresh Checkout write transaction."""

    def __call__(self) -> CheckoutObservationUnitOfWork:
        """Return one unopened transaction."""
        ...


class RepositoryTopologyReadRepository(Protocol):
    """Validate candidate endpoint ownership without exposing repository content."""

    async def require_candidate(self, candidate: RepositoryTopologyCandidate) -> None:
        """Reject inactive, missing, cross-Brain, or mismatched endpoint entities."""
        ...


class ProjectRepositoryLinkRepository(Protocol):
    """Persist the governed topology aggregate and its append-only history."""

    async def require_candidate(self, candidate: RepositoryTopologyCandidate) -> None:
        """Require all candidate endpoints to be active in the candidate Brain."""
        ...

    async def find_operation(
        self,
        brain_id: StableId,
        operation_id: str,
    ) -> tuple[str, ProjectRepositoryLink] | None:
        """Return the immutable request digest and exact prior command result."""
        ...

    async def find_link(
        self,
        brain_id: StableId,
        link_id: StableId,
    ) -> ProjectRepositoryLink | None:
        """Load one aggregate and its complete correction history."""
        ...

    async def find_active(
        self,
        candidate: RepositoryTopologyCandidate,
    ) -> ProjectRepositoryLink | None:
        """Find duplicate effective state with the same immutable endpoints."""
        ...

    async def append(
        self,
        request_digest: str,
        event_id: StableId,
        aggregate: ProjectRepositoryLink,
        *,
        expected_previous_version: int | None,
    ) -> None:
        """Compare-and-swap the snapshot and append event/history atomically."""
        ...


class RepositoryLinkUnitOfWork(Protocol):
    """Own one serialized repository-link confirmation transaction."""

    @property
    def authorization(self) -> CheckoutObservationAuthorizationPolicy:
        """Return transaction-scoped owner authorization."""
        ...

    @property
    def links(self) -> ProjectRepositoryLinkRepository:
        """Return transaction-scoped topology persistence."""
        ...

    async def __aenter__(self) -> Self:
        """Open the write transaction."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless explicitly committed."""
        ...

    async def commit(self) -> None:
        """Commit snapshot, history, event, and current projection together."""
        ...


class RepositoryLinkUnitOfWorkFactory(Protocol):
    """Construct a fresh repository-link write transaction."""

    def __call__(self) -> RepositoryLinkUnitOfWork:
        """Return one unopened transaction."""
        ...
