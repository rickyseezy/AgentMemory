"""Bounded argv-only Git and manifest topology discovery for ID-003."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, cast

from agentmemory.identity.domain.errors import IdentityDependencyError, IdentityValidationError
from agentmemory.identity.domain.topology import (
    RepositoryRelationType,
    RepositoryTopologyCandidate,
    TopologyEndpointType,
    TopologyEvidence,
    TopologyEvidenceKind,
    TopologyEvidenceStrength,
)
from agentmemory.identity.domain.value_objects import StableId, VcsType

if TYPE_CHECKING:
    from agentmemory.identity.adapters.outbound.fingerprints import IdentityFingerprinter
    from agentmemory.identity.domain.value_objects import Fingerprint

_MAX_DIRECTORIES = 50_000
_MAX_DEPTH = 16
_MAX_REPOSITORIES = 256
_MAX_MANIFESTS = 512
_MAX_GIT_OUTPUT = 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_REPOSITORY_ID_BYTES = 128
_ALLOWED_MANIFEST_FIELDS = frozenset(
    {"schema_version", "project_id", "repository_id", "display_name", "component_roots"}
)


@dataclass(frozen=True, slots=True)
class DiscoveredRepository:
    """One path-free repository node observed by the local host adapter."""

    repository_id: StableId | None
    repository_fingerprint: Fingerprint
    relative_root_fingerprint: Fingerprint
    ancestry_fingerprint: Fingerprint | None
    remote_fingerprints: tuple[Fingerprint, ...]
    vcs_type: VcsType
    bare: bool


@dataclass(frozen=True, slots=True)
class HostRepositoryTopologyDiscovery:
    """Privacy-safe candidate graph plus unresolved repository count."""

    repositories: tuple[DiscoveredRepository, ...]
    candidates: tuple[RepositoryTopologyCandidate, ...]
    unresolved_repositories: int


@dataclass(frozen=True, slots=True)
class _RepositoryRecord:
    """Ephemeral adapter record; raw paths never cross the adapter boundary."""

    path: Path
    public: DiscoveredRepository
    upstream_fingerprints: tuple[Fingerprint, ...]


@dataclass(frozen=True, slots=True)
class _ProjectManifest:
    project_id: StableId
    repository_id: StableId
    component_roots: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GitCliRepositoryTopologyAdapter:
    """Discover bounded Git/non-Git topology without merging any identity."""

    executable: Path
    fingerprinter: IdentityFingerprinter

    def __post_init__(self) -> None:
        """Reject mutable PATH lookup for the Git executable."""
        if not self.executable.is_absolute():
            msg = "Git executable must be an absolute path"
            raise IdentityValidationError(msg)

    async def discover(
        self,
        path: str,
        brain_id: StableId,
    ) -> HostRepositoryTopologyDiscovery:
        """Parse one bounded workspace tree and emit candidates only."""
        try:
            root = await asyncio.to_thread(_resolve_directory, path)
            repository_paths, manifest_paths = await asyncio.to_thread(_scan_workspace, root)
        except IdentityValidationError:
            raise
        except OSError as error:
            raise IdentityDependencyError from error
        records = [await self._git_record(root, repository) for repository in repository_paths]
        records.extend(await self._non_git_records(root, manifest_paths, records))
        records.sort(key=lambda record: record.public.relative_root_fingerprint.value)
        candidates = [*self._nested_candidates(brain_id, records)]
        candidates.extend(await self._submodule_candidates(brain_id, records))
        candidates.extend(self._fork_candidates(brain_id, records))
        candidates.extend(await self._project_candidates(brain_id, root, manifest_paths, records))
        candidates.sort(key=_candidate_sort_key)
        public = tuple(record.public for record in records)
        return HostRepositoryTopologyDiscovery(
            public,
            tuple(candidates),
            sum(repository.repository_id is None for repository in public),
        )

    async def _git_record(self, root: Path, path: Path) -> _RepositoryRecord:
        bare_output = await self._git(path, "rev-parse", "--is-bare-repository")
        object_format = await self._git(path, "rev-parse", "--show-object-format")
        roots_output = await self._git(path, "rev-list", "--max-parents=0", "--all")
        if bare_output not in {"true", "false"} or object_format is None or roots_output is None:
            raise IdentityDependencyError
        repository_id = await asyncio.to_thread(_read_repository_id, path)
        roots = tuple(sorted(line for line in roots_output.splitlines() if line))
        remotes = await self._remote_fingerprints(path)
        origin = await self._git(path, "config", "--get", "remote.origin.url", required=False)
        if origin is not None and self._safe_remote_fingerprint(origin) is None:
            origin = None
        if roots:
            repository_fingerprint = self.fingerprinter.repository(
                VcsType.GIT,
                object_format,
                roots,
                repository_id,
                origin,
            )
            ancestry = self.fingerprinter.opaque(
                "GitRootSetFingerprintV1",
                json.dumps([object_format, *roots], separators=(",", ":")),
            )
        elif repository_id is not None:
            repository_fingerprint = self.fingerprinter.opaque(
                "EmptyGitRepositoryFingerprintV1",
                repository_id.value,
            )
            ancestry = None
        else:
            repository_fingerprint = self.fingerprinter.opaque(
                "LocalEmptyGitRepositoryFingerprintV1",
                _local_directory_identity(path),
            )
            ancestry = None
        relative = _relative_posix(root, path)
        upstream = await self._named_remote_fingerprints(path, "upstream")
        return _RepositoryRecord(
            path,
            DiscoveredRepository(
                repository_id,
                repository_fingerprint,
                self.fingerprinter.opaque("RepositoryRelativeRootFingerprintV1", relative),
                ancestry,
                remotes,
                VcsType.GIT,
                bare_output == "true",
            ),
            upstream,
        )

    async def _non_git_records(
        self,
        root: Path,
        manifests: tuple[Path, ...],
        git_records: list[_RepositoryRecord],
    ) -> list[_RepositoryRecord]:
        records: list[_RepositoryRecord] = []
        known_ids = {
            record.public.repository_id
            for record in git_records
            if record.public.repository_id is not None
        }
        for manifest_path in manifests:
            workspace = manifest_path.parent.parent
            if _closest_repository(workspace, git_records) is not None:
                continue
            manifest = await asyncio.to_thread(_read_project_manifest, manifest_path)
            if manifest.repository_id in known_ids:
                continue
            known_ids.add(manifest.repository_id)
            relative = _relative_posix(root, workspace)
            records.append(
                _RepositoryRecord(
                    workspace,
                    DiscoveredRepository(
                        manifest.repository_id,
                        self.fingerprinter.opaque(
                            "NonGitRepositoryManifestFingerprintV1",
                            manifest.repository_id.value,
                        ),
                        self.fingerprinter.opaque(
                            "RepositoryRelativeRootFingerprintV1",
                            relative,
                        ),
                        None,
                        (),
                        VcsType.NONE,
                        bare=False,
                    ),
                    (),
                )
            )
        return records

    def _nested_candidates(
        self,
        brain_id: StableId,
        records: list[_RepositoryRecord],
    ) -> tuple[RepositoryTopologyCandidate, ...]:
        candidates: list[RepositoryTopologyCandidate] = []
        for child in records:
            if child.public.vcs_type is not VcsType.GIT:
                continue
            parents = [
                candidate
                for candidate in records
                if candidate is not child
                and candidate.public.vcs_type is VcsType.GIT
                and _is_strict_descendant(child.path, candidate.path)
            ]
            if not parents:
                continue
            parent = max(parents, key=lambda item: len(item.path.parts))
            if parent.public.repository_id is None or child.public.repository_id is None:
                continue
            evidence = self._evidence(
                TopologyEvidenceKind.NESTED_GIT_MARKER,
                TopologyEvidenceStrength.DETERMINISTIC_VCS,
                parent.public.relative_root_fingerprint,
                child.public.relative_root_fingerprint,
            )
            candidates.append(
                _repository_candidate(
                    brain_id,
                    parent.public.repository_id,
                    RepositoryRelationType.CONTAINS_REPOSITORY,
                    child.public.repository_id,
                    (evidence,),
                )
            )
        return tuple(candidates)

    async def _submodule_candidates(
        self,
        brain_id: StableId,
        records: list[_RepositoryRecord],
    ) -> tuple[RepositoryTopologyCandidate, ...]:
        candidates: list[RepositoryTopologyCandidate] = []
        by_path = {record.path.resolve(): record for record in records}
        for parent in records:
            gitmodules = parent.path / ".gitmodules"
            if parent.public.vcs_type is not VcsType.GIT or not gitmodules.is_file():
                continue
            names_output = await self._git(
                parent.path,
                "config",
                "--file",
                ".gitmodules",
                "--name-only",
                "--get-regexp",
                r"^submodule\..*\.path$",
                required=False,
            )
            if not names_output:
                continue
            for name in names_output.splitlines():
                child_relative = await self._git(
                    parent.path,
                    "config",
                    "--file",
                    ".gitmodules",
                    "--get",
                    name,
                )
                if child_relative is None:
                    raise IdentityDependencyError
                _validate_relative_path(child_relative)
                child_path = (parent.path / child_relative).resolve()
                if not child_path.is_relative_to(parent.path.resolve()):
                    msg = "submodule path escapes its parent repository"
                    raise IdentityValidationError(msg)
                child = by_path.get(child_path)
                if (
                    child is None
                    or child.public.repository_id is None
                    or parent.public.repository_id is None
                ):
                    continue
                stage = await self._git(
                    parent.path,
                    "ls-files",
                    "--stage",
                    "--",
                    child_relative,
                    required=False,
                )
                if stage is None or not stage.startswith("160000 "):
                    continue
                evidence = (
                    self._evidence(
                        TopologyEvidenceKind.GITLINK,
                        TopologyEvidenceStrength.DETERMINISTIC_VCS,
                        parent.public.repository_fingerprint,
                        child.public.repository_fingerprint,
                    ),
                    self._evidence(
                        TopologyEvidenceKind.GITMODULE_DECLARATION,
                        TopologyEvidenceStrength.DETERMINISTIC_VCS,
                        parent.public.relative_root_fingerprint,
                        child.public.relative_root_fingerprint,
                    ),
                )
                candidates.append(
                    _repository_candidate(
                        brain_id,
                        child.public.repository_id,
                        RepositoryRelationType.SUBMODULE_OF,
                        parent.public.repository_id,
                        tuple(sorted(evidence, key=lambda item: item.digest.value)),
                    )
                )
        return tuple(candidates)

    def _fork_candidates(
        self,
        brain_id: StableId,
        records: list[_RepositoryRecord],
    ) -> tuple[RepositoryTopologyCandidate, ...]:
        candidates: list[RepositoryTopologyCandidate] = []
        git_records = [
            record
            for record in records
            if record.public.vcs_type is VcsType.GIT
            and record.public.repository_id is not None
            and record.public.ancestry_fingerprint is not None
        ]
        for index, first in enumerate(git_records):
            for second in git_records[index + 1 :]:
                if (
                    first.public.ancestry_fingerprint != second.public.ancestry_fingerprint
                    or first.public.repository_fingerprint == second.public.repository_fingerprint
                ):
                    continue
                source, target, deterministic = _fork_direction(first, second)
                source_id = source.public.repository_id
                target_id = target.public.repository_id
                if source_id is None or target_id is None:
                    continue
                evidence = self._evidence(
                    (
                        TopologyEvidenceKind.UPSTREAM_REMOTE
                        if deterministic
                        else TopologyEvidenceKind.SHARED_GIT_ROOTS
                    ),
                    (
                        TopologyEvidenceStrength.DETERMINISTIC_VCS
                        if deterministic
                        else TopologyEvidenceStrength.CANDIDATE
                    ),
                    source.public.repository_fingerprint,
                    target.public.repository_fingerprint,
                )
                candidates.append(
                    _repository_candidate(
                        brain_id,
                        source_id,
                        RepositoryRelationType.FORK_OF,
                        target_id,
                        (evidence,),
                    )
                )
        return tuple(candidates)

    async def _project_candidates(
        self,
        brain_id: StableId,
        root: Path,
        manifests: tuple[Path, ...],
        records: list[_RepositoryRecord],
    ) -> tuple[RepositoryTopologyCandidate, ...]:
        candidates: list[RepositoryTopologyCandidate] = []
        for manifest_path in manifests:
            manifest = await asyncio.to_thread(_read_project_manifest, manifest_path)
            workspace = manifest_path.parent.parent
            repository = _closest_repository(workspace, records)
            if repository is None or repository.public.repository_id is None:
                continue
            if repository.public.repository_id != manifest.repository_id:
                msg = "project manifest repository does not match observed repository"
                raise IdentityValidationError(msg)
            component_root = _component_scope(
                self.fingerprinter,
                root,
                repository.path,
                workspace,
                manifest.component_roots,
            )
            evidence_kind = (
                TopologyEvidenceKind.NON_GIT_MANIFEST
                if repository.public.vcs_type is VcsType.NONE
                else TopologyEvidenceKind.PROJECT_MANIFEST
            )
            evidence = self._evidence(
                evidence_kind,
                TopologyEvidenceStrength.DETERMINISTIC_MANIFEST,
                repository.public.repository_fingerprint,
                self.fingerprinter.opaque("ProjectManifestIdentityV1", manifest.project_id.value),
            )
            candidates.append(
                RepositoryTopologyCandidate(
                    brain_id,
                    TopologyEndpointType.PROJECT,
                    manifest.project_id,
                    RepositoryRelationType.PROJECT_USES_REPOSITORY,
                    TopologyEndpointType.REPOSITORY,
                    manifest.repository_id,
                    component_root,
                    (evidence,),
                )
            )
        return tuple(candidates)

    def _evidence(
        self,
        kind: TopologyEvidenceKind,
        strength: TopologyEvidenceStrength,
        first: Fingerprint,
        second: Fingerprint,
    ) -> TopologyEvidence:
        digest = self.fingerprinter.opaque(
            "RepositoryTopologyEvidenceV1",
            json.dumps(
                [kind.value, first.value, second.value],
                separators=(",", ":"),
            ),
        )
        return TopologyEvidence(digest, kind, strength)

    async def _remote_fingerprints(self, path: Path) -> tuple[Fingerprint, ...]:
        names_output = await self._git(path, "remote", required=False)
        if not names_output:
            return ()
        values: set[Fingerprint] = set()
        for name in names_output.splitlines():
            remote = await self._git(path, "config", "--get", f"remote.{name}.url")
            if remote is None:
                raise IdentityDependencyError
            fingerprint = self._safe_remote_fingerprint(remote)
            if fingerprint is not None:
                values.add(fingerprint)
        return tuple(sorted(values, key=lambda item: item.value))

    async def _named_remote_fingerprints(
        self,
        path: Path,
        name: str,
    ) -> tuple[Fingerprint, ...]:
        remote = await self._git(path, "config", "--get", f"remote.{name}.url", required=False)
        fingerprint = None if remote is None else self._safe_remote_fingerprint(remote)
        return () if fingerprint is None else (fingerprint,)

    def _safe_remote_fingerprint(self, remote: str) -> Fingerprint | None:
        """Ignore local-path remotes so their raw host location never becomes identity."""
        try:
            return self.fingerprinter.remote(remote)
        except IdentityValidationError:
            return None

    async def _git(
        self,
        path: Path,
        *arguments: str,
        required: bool = True,
    ) -> str | None:
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self.executable),
                "-C",
                os.fspath(path),
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await process.communicate()
        except OSError as error:
            raise IdentityDependencyError from error
        if len(stdout) > _MAX_GIT_OUTPUT:
            msg = "Git topology output exceeded the supported bound"
            raise IdentityValidationError(msg)
        if process.returncode != 0:
            if required:
                raise IdentityDependencyError
            return None
        try:
            return stdout.decode("utf-8", errors="strict").strip()
        except UnicodeError as error:
            msg = "Git topology output was not UTF-8"
            raise IdentityValidationError(msg) from error


def _resolve_directory(path: str) -> Path:
    if not path or "\x00" in path:
        msg = "repository topology root is invalid"
        raise IdentityValidationError(msg)
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_dir():
        msg = "repository topology root must be a directory"
        raise IdentityValidationError(msg)
    return resolved


def _scan_workspace(  # noqa: C901 -- One bounded walker enforces a single traversal budget.
    root: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    repositories: list[Path] = []
    manifests: list[Path] = []
    pending: list[tuple[Path, int]] = [(root, 0)]
    visited = 0
    while pending:
        directory, depth = pending.pop()
        visited += 1
        if visited > _MAX_DIRECTORIES:
            msg = "repository topology directory bound exceeded"
            raise IdentityValidationError(msg)
        manifest = directory / ".agentmemory" / "project.json"
        if manifest.exists():
            manifests.append(manifest)
            if len(manifests) > _MAX_MANIFESTS:
                msg = "repository topology manifest bound exceeded"
                raise IdentityValidationError(msg)
        marker = directory / ".git"
        is_worktree = marker.is_dir() or marker.is_file()
        is_bare = _looks_bare(directory)
        if is_worktree or is_bare:
            repositories.append(directory)
            if len(repositories) > _MAX_REPOSITORIES:
                msg = "repository topology repository bound exceeded"
                raise IdentityValidationError(msg)
        if is_bare or depth >= _MAX_DEPTH:
            continue
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name in {".git", ".agentmemory"} or entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append((Path(entry.path), depth + 1))
    return tuple(sorted(set(repositories))), tuple(sorted(set(manifests)))


def _looks_bare(path: Path) -> bool:
    return (path / "HEAD").is_file() and (path / "objects").is_dir() and (path / "refs").is_dir()


def _read_repository_id(path: Path) -> StableId | None:
    target = path / ".agentmemory" / "repository-id"
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return None
    if not target.is_file() or target.is_symlink() or metadata.st_size > _MAX_REPOSITORY_ID_BYTES:
        msg = "repository identity file must be a bounded regular file"
        raise IdentityValidationError(msg)
    try:
        return StableId(target.read_text(encoding="utf-8").strip())
    except OSError as error:
        raise IdentityDependencyError from error


def _read_project_manifest(  # noqa: C901 -- One closed schema is validated field by field.
    path: Path,
) -> _ProjectManifest:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise IdentityDependencyError from error
    if not path.is_file() or path.is_symlink() or metadata.st_size > _MAX_MANIFEST_BYTES:
        msg = "project topology manifest must be a bounded regular file"
        raise IdentityValidationError(msg)
    try:
        raw_payload: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        msg = "project topology manifest is unreadable or invalid JSON"
        raise IdentityValidationError(msg) from error
    if not isinstance(raw_payload, dict):
        msg = "project topology manifest root must be an object"
        raise IdentityValidationError(msg)
    payload = cast("dict[str, object]", raw_payload)
    if set(payload) - _ALLOWED_MANIFEST_FIELDS:
        msg = "project topology manifest has unsupported fields"
        raise IdentityValidationError(msg)
    if payload.get("schema_version") != 1 or isinstance(payload.get("schema_version"), bool):
        msg = "project topology manifest schema is unsupported"
        raise IdentityValidationError(msg)
    project_value = payload.get("project_id")
    repository_value = payload.get("repository_id")
    if not isinstance(project_value, str) or not isinstance(repository_value, str):
        msg = "project topology manifest requires Project and Repository identities"
        raise IdentityValidationError(msg)
    component_payload = payload.get("component_roots", [])
    if not isinstance(component_payload, list):
        msg = "project topology component roots are invalid"
        raise IdentityValidationError(msg)
    component_values = cast("list[object]", component_payload)
    if any(not isinstance(value, str) for value in component_values):
        msg = "project topology component roots are invalid"
        raise IdentityValidationError(msg)
    components = tuple(cast("list[str]", component_values))
    if len(set(components)) != len(components):
        msg = "project topology component roots must be unique"
        raise IdentityValidationError(msg)
    for component in components:
        _validate_relative_path(component)
    return _ProjectManifest(StableId(project_value), StableId(repository_value), components)


def _validate_relative_path(value: str) -> None:
    candidate = PurePosixPath(value)
    if (
        not value
        or "\x00" in value
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        msg = "repository topology path must be a normalized relative path"
        raise IdentityValidationError(msg)


def _component_scope(
    fingerprinter: IdentityFingerprinter,
    discovery_root: Path,
    repository_root: Path,
    workspace: Path,
    component_roots: tuple[str, ...],
) -> Fingerprint | None:
    repository = repository_root.resolve()
    if component_roots:
        targets = tuple((workspace / PurePosixPath(value)).resolve() for value in component_roots)
    elif workspace.resolve() != repository:
        targets = (workspace.resolve(),)
    else:
        return None
    if any(not target.is_relative_to(repository) for target in targets):
        msg = "project component scope escapes its Repository"
        raise IdentityValidationError(msg)
    relative = tuple(sorted(_relative_posix(repository, target) for target in targets))
    del discovery_root
    return fingerprinter.opaque(
        "ProjectComponentRootSetFingerprintV1",
        json.dumps(relative, separators=(",", ":")),
    )


def _closest_repository(
    workspace: Path,
    records: list[_RepositoryRecord],
) -> _RepositoryRecord | None:
    candidates = [
        record
        for record in records
        if workspace.resolve() == record.path.resolve()
        or workspace.resolve().is_relative_to(record.path.resolve())
    ]
    return None if not candidates else max(candidates, key=lambda item: len(item.path.parts))


def _fork_direction(
    first: _RepositoryRecord,
    second: _RepositoryRecord,
) -> tuple[_RepositoryRecord, _RepositoryRecord, bool]:
    if set(first.upstream_fingerprints) & set(second.public.remote_fingerprints):
        return first, second, True
    if set(second.upstream_fingerprints) & set(first.public.remote_fingerprints):
        return second, first, True
    ordered = sorted(
        (first, second),
        key=lambda item: item.public.repository_fingerprint.value,
    )
    return ordered[1], ordered[0], False


def _repository_candidate(
    brain_id: StableId,
    subject_id: StableId,
    relation: RepositoryRelationType,
    target_id: StableId,
    evidence: tuple[TopologyEvidence, ...],
) -> RepositoryTopologyCandidate:
    return RepositoryTopologyCandidate(
        brain_id,
        TopologyEndpointType.REPOSITORY,
        subject_id,
        relation,
        TopologyEndpointType.REPOSITORY,
        target_id,
        None,
        evidence,
    )


def _candidate_sort_key(candidate: RepositoryTopologyCandidate) -> tuple[str, ...]:
    return (
        candidate.subject_type.value,
        candidate.subject_id.value,
        candidate.relation_type.value,
        candidate.target_type.value,
        candidate.target_id.value,
        (
            ""
            if candidate.component_root_fingerprint is None
            else candidate.component_root_fingerprint.value
        ),
    )


def _relative_posix(root: Path, value: Path) -> str:
    relative = value.resolve().relative_to(root.resolve()).as_posix()
    return "." if relative == "." else relative


def _is_strict_descendant(child: Path, parent: Path) -> bool:
    resolved_child = child.resolve()
    resolved_parent = parent.resolve()
    return resolved_child != resolved_parent and resolved_child.is_relative_to(resolved_parent)


def _local_directory_identity(path: Path) -> str:
    metadata = path.stat()
    return f"{metadata.st_dev}:{metadata.st_ino}"
