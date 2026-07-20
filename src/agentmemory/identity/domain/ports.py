"""Capability-specific identity context ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
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
