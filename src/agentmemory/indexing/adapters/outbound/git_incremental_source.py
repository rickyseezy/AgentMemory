"""IDX-002 safe Git diff, dirty-worktree manifest, and changed-artifact adapter."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.incremental import IndexFingerprint, VcsDelta, VcsDeltaKind
from agentmemory.indexing.domain.incremental_ports import (
    RepositoryInspection,
    RepositoryManifestEntry,
)
from agentmemory.indexing.domain.ports import SourceArtifact

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from agentmemory.indexing.domain.incremental import PriorIndexedUnit
    from agentmemory.indexing.domain.ports import LanguagePluginPort

_ERR_CONFIG = "incremental Git source configuration is invalid"
_ERR_GIT = "incremental Git inspection is unavailable"
_ERR_SOURCE = "incremental Git source changed during indexing"
_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")
_MAX_FILES = 1_000_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_GIT_OUTPUT = 256 * 1024 * 1024
_MIN_GIT_TIMEOUT = 0.1
_MAX_GIT_TIMEOUT = 300.0
_GENERATED_PARTS = frozenset({".generated", "dist", "generated", "gen", "vendor", "node_modules"})


@dataclass(frozen=True, slots=True)
class GitSourcePolicy:
    """Bound all local Git and file operations."""

    max_files: int = 250_000
    max_file_bytes: int = _MAX_FILE_BYTES
    git_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Reject ineffective or unbounded local limits."""
        if (
            not 1 <= self.max_files <= _MAX_FILES
            or not 1 <= self.max_file_bytes <= _MAX_FILE_BYTES
            or not _MIN_GIT_TIMEOUT <= self.git_timeout_seconds <= _MAX_GIT_TIMEOUT
        ):
            raise IndexingValidationError(_ERR_CONFIG)


class GitIncrementalRepositorySource:
    """Inspect configured repository mounts without persisting their absolute paths."""

    def __init__(
        self,
        roots: Mapping[str, Path],
        policy: GitSourcePolicy | None = None,
        *,
        git_executable: Path | None = None,
    ) -> None:
        """Resolve trusted mounts and a fixed Git executable at composition time."""
        if not roots:
            raise IndexingValidationError(_ERR_CONFIG)
        resolved: dict[str, Path] = {}
        for repository_id, root in roots.items():
            if not repository_id or not root.is_absolute() or root.is_symlink():
                raise IndexingValidationError(_ERR_CONFIG)
            try:
                canonical = root.resolve(strict=True)
            except OSError as error:
                raise IndexingUnavailableError(_ERR_GIT) from error
            if not canonical.is_dir() or not (canonical / ".git").exists():
                raise IndexingValidationError(_ERR_CONFIG)
            resolved[repository_id] = canonical
        selected = git_executable
        if selected is None:
            discovered = shutil.which("git")
            if discovered is None:
                raise IndexingUnavailableError(_ERR_GIT)
            selected = Path(discovered)
        try:
            executable = selected.resolve(strict=True)
        except OSError as error:
            raise IndexingUnavailableError(_ERR_GIT) from error
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise IndexingValidationError(_ERR_CONFIG)
        self._roots = resolved
        self._policy = policy or GitSourcePolicy()
        self._git_executable = executable

    async def inspect(
        self,
        repository_id: str,
        base_commit_id: str | None,
        target_commit_id: str | None,
        previous: tuple[PriorIndexedUnit, ...],
    ) -> RepositoryInspection:
        """Hash only changed files after the first scan and preserve dirty worktree state."""
        root = self._root(repository_id)
        target = await self._resolve_commit(root, target_commit_id or "HEAD")
        explicit_target = target_commit_id is not None
        if target_commit_id is not None and (
            _COMMIT.fullmatch(target_commit_id) is None or not target.startswith(target_commit_id)
        ):
            raise IndexingValidationError(_ERR_GIT)
        if base_commit_id is not None and _COMMIT.fullmatch(base_commit_id) is None:
            raise IndexingValidationError(_ERR_GIT)
        deltas = await self._deltas(root, base_commit_id, target, explicit_target=explicit_target)
        if previous and base_commit_id is not None:
            entries = await self._incremental_manifest(
                root,
                target,
                previous,
                deltas,
                explicit_target=explicit_target,
            )
        else:
            entries = await self._full_manifest(root, target, explicit_target=explicit_target)
        working_digest = _manifest_digest(entries)
        return RepositoryInspection(target, working_digest, entries, deltas)

    async def read(
        self,
        repository_id: str,
        target_commit_id: str | None,
        relative_path: str,
        expected_digest: str,
    ) -> SourceArtifact:
        """Read worktree first, then immutable Git blob, accepting only the planned hash."""
        root = self._root(repository_id)
        _relative_path(relative_path)
        worktree = root / relative_path
        try:
            content = await asyncio.to_thread(self._read_regular, root, worktree)
        except IndexingUnavailableError:
            content = None
        if content is not None and hashlib.sha256(content).hexdigest() == expected_digest:
            return SourceArtifact(relative_path, content)
        if target_commit_id is not None:
            content = await self._git_blob(root, target_commit_id, relative_path)
            if hashlib.sha256(content).hexdigest() == expected_digest:
                return SourceArtifact(relative_path, content)
        raise IndexingUnavailableError(_ERR_SOURCE)

    async def _incremental_manifest(
        self,
        root: Path,
        target: str,
        previous: tuple[PriorIndexedUnit, ...],
        deltas: tuple[VcsDelta, ...],
        *,
        explicit_target: bool,
    ) -> tuple[RepositoryManifestEntry, ...]:
        current = {
            item.relative_path: RepositoryManifestEntry(
                item.relative_path,
                item.content_digest,
                0,
                _generated(item.relative_path),
            )
            for item in previous
        }
        for delta in deltas:
            if delta.kind is VcsDeltaKind.DELETE:
                current.pop(delta.relative_path, None)
                continue
            if delta.kind is VcsDeltaKind.RENAME:
                current.pop(str(delta.previous_path), None)
            content = await self._read_selected(
                root,
                target,
                delta.relative_path,
                explicit_target=explicit_target,
            )
            current[delta.relative_path] = _manifest_entry(delta.relative_path, content)
        return _bounded_entries(current.values(), self._policy.max_files)

    async def _full_manifest(
        self, root: Path, target: str, *, explicit_target: bool
    ) -> tuple[RepositoryManifestEntry, ...]:
        paths = await self._current_paths(root, target, explicit_target=explicit_target)
        if len(paths) > self._policy.max_files:
            raise IndexingUnavailableError(_ERR_SOURCE)
        entries: list[RepositoryManifestEntry] = []
        for path in paths:
            content = await self._read_selected(root, target, path, explicit_target=explicit_target)
            entries.append(_manifest_entry(path, content))
        return tuple(entries)

    async def _deltas(
        self,
        root: Path,
        base: str | None,
        target: str,
        *,
        explicit_target: bool,
    ) -> tuple[VcsDelta, ...]:
        if base is None:
            return ()
        arguments = ["diff", "--name-status", "-z", "-M", "-C", "--find-copies-harder", base]
        if explicit_target:
            arguments.append(target)
        arguments.append("--")
        raw = await self._git(root, *arguments)
        deltas = list(_parse_name_status(raw))
        if not explicit_target:
            untracked = await self._git(root, "ls-files", "--others", "--exclude-standard", "-z")
            existing = {item.relative_path for item in deltas}
            for token in _nul_tokens(untracked):
                path = token.decode("utf-8", "strict")
                _relative_path(path)
                if path not in existing:
                    deltas.append(VcsDelta(VcsDeltaKind.ADD, path))
        return tuple(
            sorted(
                deltas,
                key=lambda item: (item.kind.value, item.previous_path or "", item.relative_path),
            )
        )

    async def _current_paths(
        self, root: Path, target: str, *, explicit_target: bool
    ) -> tuple[str, ...]:
        if explicit_target:
            output = await self._git(root, "ls-tree", "-r", "--name-only", "-z", target)
        else:
            output = await self._git(
                root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"
            )
        paths: list[str] = []
        for token in _nul_tokens(output):
            path = token.decode("utf-8", "strict")
            _relative_path(path)
            if explicit_target or (root / path).is_file():
                paths.append(path)
        return tuple(sorted(set(paths)))

    async def _read_selected(
        self, root: Path, target: str, relative_path: str, *, explicit_target: bool
    ) -> bytes:
        if explicit_target:
            return await self._git_blob(root, target, relative_path)
        return await asyncio.to_thread(self._read_regular, root, root / relative_path)

    async def _git_blob(self, root: Path, commit: str, relative_path: str) -> bytes:
        _relative_path(relative_path)
        content = await self._git(root, "cat-file", "blob", f"{commit}:{relative_path}")
        if len(content) > self._policy.max_file_bytes:
            raise IndexingUnavailableError(_ERR_SOURCE)
        return content

    async def _resolve_commit(self, root: Path, value: str) -> str:
        output = await self._git(root, "rev-parse", "--verify", f"{value}^{{commit}}")
        resolved = output.decode("ascii", "strict").strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", resolved):
            raise IndexingUnavailableError(_ERR_GIT)
        return resolved

    async def _git(self, root: Path, *arguments: str) -> bytes:
        try:
            process = await asyncio.create_subprocess_exec(
                str(self._git_executable),
                "-C",
                str(root),
                "-c",
                "core.quotepath=false",
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": os.environ.get("PATH", "")},
            )
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=self._policy.git_timeout_seconds
            )
        except (OSError, TimeoutError, UnicodeError) as error:
            raise IndexingUnavailableError(_ERR_GIT) from error
        if process.returncode != 0 or len(stdout) > _MAX_GIT_OUTPUT:
            raise IndexingUnavailableError(_ERR_GIT)
        return stdout

    def _read_regular(self, root: Path, path: Path) -> bytes:
        descriptor: int | None = None
        content = b""
        try:
            relative = path.relative_to(root).as_posix()
            _relative_path(relative)
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > self._policy.max_file_bytes:
                raise IndexingUnavailableError(_ERR_SOURCE)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise IndexingUnavailableError(_ERR_SOURCE)
            chunks: list[bytes] = []
            remaining = self._policy.max_file_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(content) > self._policy.max_file_bytes or (
                opened.st_size,
                opened.st_mtime_ns,
            ) != (after.st_size, after.st_mtime_ns):
                raise IndexingUnavailableError(_ERR_SOURCE)
        except (OSError, ValueError) as error:
            raise IndexingUnavailableError(_ERR_SOURCE) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return content

    def _root(self, repository_id: str) -> Path:
        try:
            return self._roots[repository_id]
        except KeyError as error:
            raise IndexingAuthorizationError(_ERR_CONFIG) from error


class LanguagePluginFingerprintProvider:
    """Derive per-path cache keys from the exact reviewed language and policy lock."""

    def __init__(
        self,
        plugin: LanguagePluginPort,
        *,
        language_lock_digest: str,
        extraction_config_digest: str,
        privacy_policy_version: str,
    ) -> None:
        """Bind every global implementation coordinate once at composition."""
        for value in (language_lock_digest, extraction_config_digest):
            if re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise IndexingValidationError(_ERR_CONFIG)
        self._plugin = plugin
        self._language_lock_digest = language_lock_digest
        self._extraction_config_digest = extraction_config_digest
        self._privacy_policy_version = privacy_policy_version
        document = {
            "extraction_config_digest": extraction_config_digest,
            "language_lock_digest": language_lock_digest,
            "privacy_policy_version": privacy_policy_version,
        }
        self._implementation_digest = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @property
    def implementation_digest(self) -> str:
        """Return the exact reviewed global implementation identity."""
        return self._implementation_digest

    def for_path(self, relative_path: str) -> IndexFingerprint:
        """Resolve parser and grammar/query evidence without reading source bytes."""
        _relative_path(relative_path)
        try:
            language = self._plugin.detect(relative_path, b"")
            if language is None:
                return IndexFingerprint(
                    "binary-detector-v1",
                    "binary-v1",
                    hashlib.sha256(b"").hexdigest(),
                    self._extraction_config_digest,
                    self._privacy_policy_version,
                )
            descriptor = self._plugin.describe(language)
            return IndexFingerprint(
                descriptor.parser_version,
                descriptor.grammar_revision,
                descriptor.query_pack_digest,
                self._extraction_config_digest,
                self._privacy_policy_version,
            )
        except (AttributeError, TypeError) as error:
            raise IndexingUnavailableError(_ERR_GIT) from error


def _parse_name_status(value: bytes) -> tuple[VcsDelta, ...]:
    tokens = list(_nul_tokens(value))
    result: list[VcsDelta] = []
    cursor = 0
    while cursor < len(tokens):
        status_token = tokens[cursor].decode("ascii", "strict")
        cursor += 1
        if "\t" in status_token:
            status, first = status_token.split("\t", 1)
        else:
            status = status_token
            if cursor >= len(tokens):
                raise IndexingUnavailableError(_ERR_GIT)
            first = tokens[cursor].decode("utf-8", "strict")
            cursor += 1
        code = status[0]
        if code in {"R", "C"}:
            if cursor >= len(tokens):
                raise IndexingUnavailableError(_ERR_GIT)
            second = tokens[cursor].decode("utf-8", "strict")
            cursor += 1
            _relative_path(first)
            _relative_path(second)
            kind = VcsDeltaKind.RENAME if code == "R" else VcsDeltaKind.COPY
            result.append(VcsDelta(kind, second, first))
        else:
            _relative_path(first)
            simple_kind = {
                "A": VcsDeltaKind.ADD,
                "M": VcsDeltaKind.MODIFY,
                "T": VcsDeltaKind.MODIFY,
                "D": VcsDeltaKind.DELETE,
            }.get(code)
            if simple_kind is None:
                raise IndexingUnavailableError(_ERR_GIT)
            result.append(VcsDelta(simple_kind, first))
    return tuple(result)


def _nul_tokens(value: bytes) -> tuple[bytes, ...]:
    if not value:
        return ()
    if not value.endswith(b"\0"):
        raise IndexingUnavailableError(_ERR_GIT)
    return tuple(item for item in value[:-1].split(b"\0") if item)


def _manifest_entry(path: str, content: bytes) -> RepositoryManifestEntry:
    return RepositoryManifestEntry(
        path, hashlib.sha256(content).hexdigest(), len(content), _generated(path)
    )


def _bounded_entries(
    values: Iterable[RepositoryManifestEntry], max_files: int
) -> tuple[RepositoryManifestEntry, ...]:
    entries = tuple(sorted(values, key=lambda item: item.relative_path))
    if len(entries) > max_files:
        raise IndexingUnavailableError(_ERR_SOURCE)
    return entries


def _manifest_digest(entries: tuple[RepositoryManifestEntry, ...]) -> str:
    document = [
        {
            "content_digest": item.content_digest,
            "generated": item.generated,
            "path": item.relative_path,
        }
        for item in entries
    ]
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _generated(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    name = path.name.lower()
    return (
        any(part.lower() in _GENERATED_PARTS for part in path.parts[:-1])
        or ".generated." in name
        or name.endswith((".min.js", ".min.css", "_pb2.py", ".designer.cs"))
    )


def _relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_SOURCE)
