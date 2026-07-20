"""ID-001 stable workspace resolution query."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityDependencyError
from agentmemory.identity.domain.services import IdentityResolutionPolicy
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    IdentityCandidate,
    IdentityEvidence,
    ObservedWorkspaceQuery,
    ProjectManifest,
    StableId,
    VcsIdentity,
    WorkspaceObservation,
    WorkspaceResolution,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.ports import (
        CheckoutRepository,
        DeviceIdentityPort,
        IdentityAuthorizationPolicy,
        ManifestReader,
        ProjectRepository,
        RepositoryIdentityRepository,
        VcsIdentityPort,
    )


@dataclass(frozen=True, slots=True)
class IdentityResolutionDependencies:
    """Authorization and persistence ports required by every resolution query."""

    authorization: IdentityAuthorizationPolicy
    projects: ProjectRepository
    checkouts: CheckoutRepository
    repositories: RepositoryIdentityRepository


@dataclass(frozen=True, slots=True)
class WorkspaceObservationDependencies:
    """Host observation ports used by an in-process MCP session bridge."""

    manifests: ManifestReader
    devices: DeviceIdentityPort
    vcs: VcsIdentityPort


@dataclass(frozen=True, slots=True)
class ResolveWorkspaceHandler:
    """Resolve only existing authorized identity mappings without mutation."""

    dependencies: IdentityResolutionDependencies
    observations: WorkspaceObservationDependencies | None = None
    policy: IdentityResolutionPolicy = field(default_factory=IdentityResolutionPolicy)

    async def execute(self, query: WorkspaceObservation) -> WorkspaceResolution:
        """Observe evidence once and stop at the first authoritative non-empty tier."""
        ports = self.dependencies
        await ports.authorization.authorize_resolution(
            query.brain_id,
            query.actor_id,
            query.grant_id,
        )
        observations = self.observations
        if observations is None:
            raise IdentityDependencyError
        device = await observations.devices.observe(query.path)
        vcs = await observations.vcs.observe(query.path, device)
        manifest = await observations.manifests.read(query.path)
        return await self._resolve_authorized(query.brain_id, device, vcs, manifest)

    async def execute_observed(
        self,
        query: ObservedWorkspaceQuery,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
        manifest: ProjectManifest | None,
    ) -> WorkspaceResolution:
        """Resolve bridge-observed keyed evidence after authorization and without raw paths."""
        ports = self.dependencies
        await ports.authorization.authorize_resolution(
            query.brain_id,
            query.actor_id,
            query.grant_id,
        )
        return await self._resolve_authorized(query.brain_id, device, vcs, manifest)

    async def _resolve_authorized(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
        manifest: ProjectManifest | None,
    ) -> WorkspaceResolution:
        """Apply persistence precedence to already-authorized privacy-safe evidence."""
        ports = self.dependencies
        repository_fingerprint = None if vcs is None else vcs.repository_fingerprint
        if manifest is not None:
            candidates = await ports.projects.resolve_manifest(
                brain_id,
                manifest,
                repository_fingerprint,
            )
            if candidates:
                return self._resolve(brain_id, manifest=candidates)

        checkout_fingerprint = None if vcs is None else vcs.checkout_fingerprint
        if device.verified:
            candidates = await ports.checkouts.find_by_observation(
                brain_id,
                device,
                checkout_fingerprint,
            )
            if candidates:
                return self._resolve(brain_id, checkout=candidates)

        if (
            repository_fingerprint is not None
            and vcs is not None
            and vcs.repository_lookup_approved
        ):
            repository_ids = await ports.repositories.find_by_fingerprint(
                brain_id,
                repository_fingerprint,
            )
            if repository_ids:
                candidates = await ports.projects.find_by_repository(brain_id, repository_ids)
                if candidates:
                    return self._resolve(brain_id, repository=candidates)

        candidates = (
            await ports.checkouts.find_approved_heuristic(brain_id, device, vcs)
            if device.verified
            else ()
        )
        return self._resolve(brain_id, heuristic=candidates)

    def _resolve(
        self,
        brain_id: StableId,
        *,
        manifest: tuple[IdentityCandidate, ...] = (),
        checkout: tuple[IdentityCandidate, ...] = (),
        repository: tuple[IdentityCandidate, ...] = (),
        heuristic: tuple[IdentityCandidate, ...] = (),
    ) -> WorkspaceResolution:
        """Translate one evidence tier into the pure resolution policy."""
        return self.policy.resolve(
            brain_id,
            IdentityEvidence(manifest, checkout, repository, heuristic),
        )
