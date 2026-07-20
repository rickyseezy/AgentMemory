"""ID-001 ResolveWorkspaceQuery application acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from agentmemory.identity.application.queries.resolve_workspace import (
    IdentityResolutionDependencies,
    ResolveWorkspaceHandler,
    WorkspaceObservationDependencies,
)
from agentmemory.identity.domain.errors import IdentityAuthorizationError
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    IdentityCandidate,
    IdentitySource,
    ObservedWorkspaceQuery,
    ProjectManifest,
    ResolutionStatus,
    StableId,
    VcsIdentity,
    VcsType,
    WorkspaceObservation,
)

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
ACTOR_ID = StableId("018f0000-0000-7000-8000-000000000002")
GRANT_ID = StableId("018f0000-0000-7000-8000-000000000003")
DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHECKOUT_ID = StableId("018f0000-0000-7000-8000-000000000030")


def _fingerprint(seed: str) -> Fingerprint:
    return Fingerprint.from_bytes(seed.encode())


def _candidate() -> IdentityCandidate:
    return IdentityCandidate(PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID)


def _observation(path: str = "/Users/owner/work/project") -> WorkspaceObservation:
    return WorkspaceObservation("resolve-1", BRAIN_ID, ACTOR_ID, GRANT_ID, path)


@dataclass(slots=True)
class _Authorization:
    allowed: bool = True
    calls: int = 0

    async def authorize_resolution(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        assert (brain_id, actor_id, grant_id) == (BRAIN_ID, ACTOR_ID, GRANT_ID)
        self.calls += 1
        if not self.allowed:
            raise IdentityAuthorizationError


@dataclass(slots=True)
class _ManifestReader:
    value: ProjectManifest | None = None
    calls: int = 0

    async def read(self, path: str) -> ProjectManifest | None:
        assert path == "/Users/owner/work/project"
        self.calls += 1
        return self.value


@dataclass(slots=True)
class _DevicePort:
    value: DeviceIdentity = field(
        default_factory=lambda: DeviceIdentity(
            DEVICE_ID,
            _fingerprint("device"),
            _fingerprint("volume"),
            _fingerprint("path"),
            verified=True,
        )
    )

    async def observe(self, path: str) -> DeviceIdentity:
        assert path == "/Users/owner/work/project"
        return self.value


@dataclass(slots=True)
class _VcsPort:
    value: VcsIdentity | None = field(
        default_factory=lambda: VcsIdentity(
            VcsType.GIT,
            _fingerprint("repository"),
            _fingerprint("checkout"),
            _fingerprint("worktree"),
            repository_lookup_approved=True,
        )
    )
    calls: int = 0

    async def observe(self, path: str, device: DeviceIdentity) -> VcsIdentity | None:
        assert path == "/Users/owner/work/project"
        assert device.device_id == DEVICE_ID
        self.calls += 1
        return self.value


@dataclass(slots=True)
class _Projects:
    manifest: tuple[IdentityCandidate, ...] = ()
    repository: tuple[IdentityCandidate, ...] = ()
    manifest_calls: int = 0
    repository_calls: int = 0

    async def resolve_manifest(
        self,
        brain_id: StableId,
        manifest: ProjectManifest,
        repository_fingerprint: Fingerprint | None,
    ) -> tuple[IdentityCandidate, ...]:
        assert brain_id == BRAIN_ID
        assert manifest.project_id == PROJECT_ID
        del repository_fingerprint
        self.manifest_calls += 1
        return self.manifest

    async def find_by_repository(
        self,
        brain_id: StableId,
        repository_ids: tuple[StableId, ...],
    ) -> tuple[IdentityCandidate, ...]:
        assert brain_id == BRAIN_ID
        assert repository_ids
        self.repository_calls += 1
        return self.repository


@dataclass(slots=True)
class _Checkouts:
    alias: tuple[IdentityCandidate, ...] = ()
    heuristic: tuple[IdentityCandidate, ...] = ()
    alias_calls: int = 0
    heuristic_calls: int = 0

    async def find_by_observation(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        checkout_fingerprint: Fingerprint | None,
    ) -> tuple[IdentityCandidate, ...]:
        assert brain_id == BRAIN_ID
        assert device.device_id == DEVICE_ID
        del checkout_fingerprint
        self.alias_calls += 1
        return self.alias

    async def find_approved_heuristic(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
    ) -> tuple[IdentityCandidate, ...]:
        assert brain_id == BRAIN_ID
        assert device.device_id == DEVICE_ID
        del vcs
        self.heuristic_calls += 1
        return self.heuristic


@dataclass(slots=True)
class _Repositories:
    values: tuple[StableId, ...] = ()
    calls: int = 0

    async def find_by_fingerprint(
        self,
        brain_id: StableId,
        fingerprint: Fingerprint,
    ) -> tuple[StableId, ...]:
        assert brain_id == BRAIN_ID
        assert fingerprint == _fingerprint("repository")
        self.calls += 1
        return self.values


def _handler(  # noqa: PLR0913 -- Explicit fake selection keeps precedence tests readable.
    *,
    authorization: _Authorization | None = None,
    manifest: _ManifestReader | None = None,
    projects: _Projects | None = None,
    checkouts: _Checkouts | None = None,
    repositories: _Repositories | None = None,
    vcs: _VcsPort | None = None,
    device: _DevicePort | None = None,
) -> ResolveWorkspaceHandler:
    return ResolveWorkspaceHandler(
        IdentityResolutionDependencies(
            authorization or _Authorization(),
            projects or _Projects(),
            checkouts or _Checkouts(),
            repositories or _Repositories(),
        ),
        WorkspaceObservationDependencies(
            manifest or _ManifestReader(),
            device or _DevicePort(),
            vcs or _VcsPort(),
        ),
    )


@pytest.mark.asyncio
async def test_manifest_wins_and_returns_explanation_without_raw_path() -> None:
    projects = _Projects(manifest=(_candidate(),))
    checkouts = _Checkouts(alias=(_candidate(),), heuristic=(_candidate(),))
    repositories = _Repositories((REPOSITORY_ID,))
    result = await _handler(
        manifest=_ManifestReader(ProjectManifest(1, PROJECT_ID, REPOSITORY_ID)),
        projects=projects,
        checkouts=checkouts,
        repositories=repositories,
    ).execute(_observation())
    assert result.status is ResolutionStatus.RESOLVED
    assert result.source is IdentitySource.MANIFEST
    assert result.selected == _candidate()
    assert "/Users" not in repr(result)
    assert checkouts.alias_calls == 0
    assert repositories.calls == 0
    assert checkouts.heuristic_calls == 0


@pytest.mark.asyncio
async def test_checkout_registry_precedes_repository_fingerprint() -> None:
    checkouts = _Checkouts(alias=(_candidate(),))
    repositories = _Repositories((REPOSITORY_ID,))
    result = await _handler(checkouts=checkouts, repositories=repositories).execute(_observation())
    assert result.source is IdentitySource.CHECKOUT_REGISTRY
    assert repositories.calls == 0


@pytest.mark.asyncio
async def test_repository_fingerprint_resolves_git_clone_without_using_path_as_identity() -> None:
    repositories = _Repositories((REPOSITORY_ID,))
    projects = _Projects(repository=(_candidate(),))
    result = await _handler(projects=projects, repositories=repositories).execute(_observation())
    assert result.source is IdentitySource.REPOSITORY_FINGERPRINT
    assert result.selected == _candidate()


@pytest.mark.asyncio
async def test_non_git_directory_uses_only_approved_registered_heuristic() -> None:
    checkouts = _Checkouts(heuristic=(_candidate(),))
    result = await _handler(checkouts=checkouts, vcs=_VcsPort(value=None)).execute(_observation())
    assert result.source is IdentitySource.APPROVED_HEURISTIC
    assert result.selected == _candidate()


@pytest.mark.asyncio
async def test_ambiguous_fork_returns_candidates_and_never_merges() -> None:
    other = IdentityCandidate(
        StableId("018f0000-0000-7000-8000-000000000011"),
        StableId("018f0000-0000-7000-8000-000000000021"),
        StableId("018f0000-0000-7000-8000-000000000031"),
    )
    repositories = _Repositories((REPOSITORY_ID, other.repository_id))
    projects = _Projects(repository=(_candidate(), other))
    result = await _handler(projects=projects, repositories=repositories).execute(_observation())
    assert result.status is ResolutionStatus.AMBIGUOUS
    assert result.candidates == (_candidate(), other)
    assert result.selected is None


@pytest.mark.asyncio
async def test_authorization_denial_stops_all_identity_observation() -> None:
    authorization = _Authorization(allowed=False)
    manifest = _ManifestReader()
    vcs = _VcsPort()
    with pytest.raises(IdentityAuthorizationError):
        await _handler(authorization=authorization, manifest=manifest, vcs=vcs).execute(
            _observation()
        )
    assert authorization.calls == 1
    assert manifest.calls == 0
    assert vcs.calls == 0


@pytest.mark.asyncio
async def test_path_free_bridge_observation_uses_the_same_authorized_precedence() -> None:
    authorization = _Authorization()
    checkouts = _Checkouts(alias=(_candidate(),))
    handler = _handler(authorization=authorization, checkouts=checkouts)
    result = await handler.execute_observed(
        ObservedWorkspaceQuery("resolve-bridge-1", BRAIN_ID, ACTOR_ID, GRANT_ID),
        _DevicePort().value,
        _VcsPort().value,
        None,
    )
    assert result.source is IdentitySource.CHECKOUT_REGISTRY
    assert result.selected == _candidate()
    assert authorization.calls == 1


@pytest.mark.asyncio
async def test_root_only_git_evidence_never_auto_merges_a_repository() -> None:
    repositories = _Repositories((REPOSITORY_ID,))
    projects = _Projects(repository=(_candidate(),))
    vcs = _VcsPort(
        VcsIdentity(
            VcsType.GIT,
            _fingerprint("repository"),
            _fingerprint("checkout"),
            _fingerprint("worktree"),
            repository_lookup_approved=False,
        )
    )
    result = await _handler(projects=projects, repositories=repositories, vcs=vcs).execute(
        _observation()
    )
    assert result.status is ResolutionStatus.NOT_FOUND
    assert repositories.calls == 0
    assert projects.repository_calls == 0


@pytest.mark.asyncio
async def test_unverified_changed_device_stops_checkout_and_heuristic_merge() -> None:
    unverified = _DevicePort(
        DeviceIdentity(
            DEVICE_ID,
            _fingerprint("changed-device"),
            _fingerprint("volume"),
            _fingerprint("path"),
            verified=False,
        )
    )
    checkouts = _Checkouts(alias=(_candidate(),), heuristic=(_candidate(),))
    result = await _handler(checkouts=checkouts, device=unverified).execute(_observation())
    assert result.status is ResolutionStatus.NOT_FOUND
    assert checkouts.alias_calls == 0
    assert checkouts.heuristic_calls == 0
