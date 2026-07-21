"""IDX-007 bounded Git/history, worktree mapping, and local-open adapters."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.content_policy_ports import PolicySourceDocuments
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.source_navigation import CheckoutCandidate, SourceEvidence

if TYPE_CHECKING:
    from collections.abc import Mapping

    from agentmemory.indexing.domain.content_policy import IndexContentPolicy
    from agentmemory.indexing.domain.content_policy_ports import RepositoryContentPolicyGate
    from agentmemory.shared.clock import Clock

_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ERR_CONFIG = "source navigation Git configuration is invalid"
_ERR_GIT = "source navigation Git operation is unavailable"
_ERR_SOURCE = "source navigation source is unavailable"
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_GIT_OUTPUT = 256 * 1024 * 1024
_MAX_POLICY_BYTES = 256 * 1024
_MAX_CANDIDATES = 16
_MAX_PATH_BYTES = 4_096
_MIN_TIMEOUT = 0.1
_MAX_TIMEOUT = 300.0


@dataclass(frozen=True, slots=True)
class GitSourceNavigationPolicy:
    """Bound source reads, Git execution, and the fixed executable."""

    max_file_bytes: int = _MAX_FILE_BYTES
    timeout_seconds: float = 30.0
    git_executable: Path | None = None

    def __post_init__(self) -> None:
        """Reject ineffective or unbounded navigation limits."""
        if (
            not 1 <= self.max_file_bytes <= _MAX_FILE_BYTES
            or not _MIN_TIMEOUT <= self.timeout_seconds <= _MAX_TIMEOUT
        ):
            raise IndexingValidationError(_ERR_CONFIG)


class GitSourceContentAdapter:
    """Read exact Git blobs and bounded current rename candidates from configured roots."""

    def __init__(
        self,
        roots: Mapping[str, Path],
        *,
        content_policy: RepositoryContentPolicyGate,
        clock: Clock,
        policy: GitSourceNavigationPolicy | None = None,
    ) -> None:
        """Resolve every trusted root/executable once, outside all request data."""
        if not roots:
            raise IndexingValidationError(_ERR_CONFIG)
        selected_policy = policy or GitSourceNavigationPolicy()
        resolved: dict[str, Path] = {}
        for repository_id, root in roots.items():
            if not repository_id or not root.is_absolute() or root.is_symlink():
                raise IndexingValidationError(_ERR_CONFIG)
            try:
                canonical = root.resolve(strict=True)
            except OSError as error:
                raise IndexingUnavailableError(_ERR_CONFIG) from error
            if not canonical.is_dir() or not (canonical / ".git").exists():
                raise IndexingValidationError(_ERR_CONFIG)
            resolved[repository_id] = canonical
        selected = selected_policy.git_executable or (
            Path(value) if (value := shutil.which("git")) else None
        )
        if selected is None:
            raise IndexingUnavailableError(_ERR_CONFIG)
        try:
            executable = selected.resolve(strict=True)
        except OSError as error:
            raise IndexingUnavailableError(_ERR_CONFIG) from error
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise IndexingValidationError(_ERR_CONFIG)
        self._roots = resolved
        self._content_policy = content_policy
        self._clock = clock
        self._git = executable
        self._max_file_bytes = selected_policy.max_file_bytes
        self._timeout = selected_policy.timeout_seconds

    async def historical(self, evidence: SourceEvidence) -> bytes | None:
        """Return a policy-authorized Git blob only when it matches the exact commit/path."""
        if evidence.commit_id is None:
            return None
        root = self._root(evidence.repository_id)
        policy = await self._policy(evidence.repository_id, root)
        try:
            symlink, size = await self._git_metadata(
                root, evidence.commit_id, evidence.relative_path
            )
        except IndexingUnavailableError:
            return None
        await self._allow_path(
            policy,
            evidence.relative_path,
            symlink=symlink,
            byte_length=size,
        )
        content = await self._git_blob(root, evidence.commit_id, evidence.relative_path, size)
        return await self._allow_content(policy, evidence.relative_path, content)

    async def checkout_candidates(self, evidence: SourceEvidence) -> tuple[CheckoutCandidate, ...]:
        """Return same-path and Git rename candidates without scanning unrelated files."""
        root = self._root(evidence.repository_id)
        head = await self._resolve_commit(root, "HEAD")
        dirty = bool(
            await self._run_git(
                root,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=normal",
            )
        )
        paths = {evidence.relative_path}
        if evidence.commit_id is not None:
            paths.update(
                await self._renamed_paths(root, evidence.commit_id, evidence.relative_path)
            )
        if len(paths) > _MAX_CANDIDATES:
            raise IndexingUnavailableError(_ERR_SOURCE)
        policy = await self._policy(evidence.repository_id, root)
        candidates: list[CheckoutCandidate] = []
        for relative_path in sorted(paths):
            try:
                content = await self._worktree_file(policy, root, relative_path)
            except IndexingAuthorizationError, IndexingUnavailableError:
                continue
            candidates.append(CheckoutCandidate(head, relative_path, content, dirty))
        return tuple(candidates)

    async def _worktree_file(
        self, policy: IndexContentPolicy, root: Path, relative_path: str
    ) -> bytes:
        _path(relative_path)
        path = root / relative_path
        try:
            observation = path.lstat()
        except OSError as error:
            raise IndexingUnavailableError(_ERR_SOURCE) from error
        await self._allow_path(
            policy,
            relative_path,
            symlink=stat.S_ISLNK(observation.st_mode),
            byte_length=observation.st_size,
        )
        content = await asyncio.to_thread(self._read_regular, root, path)
        return await self._allow_content(policy, relative_path, content)

    async def _policy(self, repository_id: str, root: Path) -> IndexContentPolicy:
        return await self._content_policy.prepare(
            repository_id,
            PolicySourceDocuments(
                await asyncio.to_thread(self._optional_policy_file, root, ".agentmemoryignore"),
                await asyncio.to_thread(self._optional_policy_file, root, ".gitignore"),
            ),
            self._clock.now(),
        )

    async def _allow_path(
        self,
        policy: IndexContentPolicy,
        relative_path: str,
        *,
        symlink: bool,
        byte_length: int,
    ) -> None:
        decision = policy.evaluate_path(
            relative_path,
            symlink=symlink,
            byte_length=byte_length,
            decided_at=self._clock.now(),
        )
        await self._content_policy.record(decision)
        if decision.excluded:
            raise IndexingAuthorizationError(_ERR_SOURCE)

    async def _allow_content(
        self, policy: IndexContentPolicy, relative_path: str, content: bytes
    ) -> bytes:
        decision = policy.evaluate_content(relative_path, content, self._clock.now())
        await self._content_policy.record(decision)
        if decision.excluded:
            raise IndexingAuthorizationError(_ERR_SOURCE)
        return content

    async def _renamed_paths(self, root: Path, commit: str, path: str) -> tuple[str, ...]:
        output = await self._run_git(
            root,
            "diff",
            "--name-status",
            "-z",
            "-M",
            "--find-renames",
            commit,
            "--",
        )
        tokens = output.split(b"\x00")
        if tokens and not tokens[-1]:
            tokens.pop()
        renamed: list[str] = []
        index = 0
        try:
            while index < len(tokens):
                status = tokens[index].decode("ascii", "strict")
                index += 1
                old = tokens[index].decode("utf-8", "strict")
                index += 1
                _path(old)
                if status.startswith(("R", "C")):
                    new = tokens[index].decode("utf-8", "strict")
                    index += 1
                    _path(new)
                    if old == path:
                        renamed.append(new)
        except (IndexError, UnicodeError) as error:
            raise IndexingUnavailableError(_ERR_GIT) from error
        return tuple(sorted(set(renamed)))

    async def _git_metadata(self, root: Path, commit: str, path: str) -> tuple[bool, int]:
        _path(path)
        output = await self._run_git(root, "ls-tree", "-l", commit, "--", path)
        try:
            header, encoded_path = output.rstrip(b"\n").split(b"\t", 1)
            mode, kind, _object_id, raw_size = header.split(b" ", 3)
            decoded_path = encoded_path.decode("utf-8", "strict")
            size = int(raw_size)
        except (UnicodeError, ValueError) as error:
            raise IndexingUnavailableError(_ERR_SOURCE) from error
        if kind != b"blob" or decoded_path != path or size < 0 or size > self._max_file_bytes:
            raise IndexingUnavailableError(_ERR_SOURCE)
        return mode == b"120000", size

    async def _git_blob(self, root: Path, commit: str, path: str, expected_size: int) -> bytes:
        content = await self._run_git(root, "cat-file", "blob", f"{commit}:{path}")
        if len(content) != expected_size or len(content) > self._max_file_bytes:
            raise IndexingUnavailableError(_ERR_SOURCE)
        return content

    async def _resolve_commit(self, root: Path, value: str) -> str:
        output = await self._run_git(root, "rev-parse", "--verify", f"{value}^{{commit}}")
        commit = output.decode("ascii", "strict").strip()
        if _COMMIT.fullmatch(commit) is None:
            raise IndexingUnavailableError(_ERR_GIT)
        return commit

    async def _run_git(self, root: Path, *arguments: str) -> bytes:
        try:
            process = await asyncio.create_subprocess_exec(
                str(self._git),
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
            stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=self._timeout)
        except (OSError, TimeoutError, UnicodeError) as error:
            raise IndexingUnavailableError(_ERR_GIT) from error
        if process.returncode != 0 or len(stdout) > _MAX_GIT_OUTPUT:
            raise IndexingUnavailableError(_ERR_GIT)
        return stdout

    def _read_regular(self, root: Path, path: Path) -> bytes:
        descriptor: int | None = None
        try:
            relative = path.relative_to(root).as_posix()
            _path(relative)
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > self._max_file_bytes:
                raise IndexingUnavailableError(_ERR_SOURCE)
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise IndexingUnavailableError(_ERR_SOURCE)
            chunks: list[bytes] = []
            remaining = self._max_file_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(content) > self._max_file_bytes or (
                opened.st_size,
                opened.st_mtime_ns,
            ) != (after.st_size, after.st_mtime_ns):
                raise IndexingUnavailableError(_ERR_SOURCE)
        except (OSError, ValueError) as error:
            raise IndexingUnavailableError(_ERR_SOURCE) from error
        else:
            return content
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _optional_policy_file(self, root: Path, name: str) -> bytes | None:
        try:
            content = self._read_regular(root, root / name)
        except IndexingUnavailableError:
            return None
        if len(content) > _MAX_POLICY_BYTES:
            raise IndexingUnavailableError(_ERR_SOURCE)
        return content

    def _root(self, repository_id: str) -> Path:
        try:
            return self._roots[repository_id]
        except KeyError as error:
            raise IndexingAuthorizationError(_ERR_CONFIG) from error


class BoundedLocalPathResolver:
    """Resolve and rehash a current source path beneath a configured repository root."""

    def __init__(self, roots: Mapping[str, Path], *, max_file_bytes: int = _MAX_FILE_BYTES) -> None:
        """Pin canonical non-symlink roots outside request control."""
        if not roots or not 1 <= max_file_bytes <= _MAX_FILE_BYTES:
            raise IndexingValidationError(_ERR_CONFIG)
        resolved: dict[str, Path] = {}
        for repository_id, root in roots.items():
            if not repository_id or not root.is_absolute() or root.is_symlink():
                raise IndexingValidationError(_ERR_CONFIG)
            try:
                canonical = root.resolve(strict=True)
            except OSError as error:
                raise IndexingUnavailableError(_ERR_CONFIG) from error
            if not canonical.is_dir():
                raise IndexingValidationError(_ERR_CONFIG)
            resolved[repository_id] = canonical
        self._roots = resolved
        self._max_file_bytes = max_file_bytes

    async def resolve(
        self, repository_id: str, relative_path: str, expected_digest: str
    ) -> str | None:
        """Return a path only after containment, symlink, regular-file, and hash checks."""
        _path(relative_path)
        if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
            raise IndexingValidationError(_ERR_SOURCE)
        try:
            root = self._roots[repository_id]
        except KeyError as error:
            raise IndexingAuthorizationError(_ERR_CONFIG) from error
        candidate = root.joinpath(*PurePosixPath(relative_path).parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise IndexingAuthorizationError(_ERR_SOURCE) from error
        if candidate.absolute() != resolved:
            raise IndexingAuthorizationError(_ERR_SOURCE)
        content = await asyncio.to_thread(_bounded_read, resolved, self._max_file_bytes)
        if hashlib.sha256(content).hexdigest() != expected_digest:
            return None
        return str(resolved)


def _bounded_read(path: Path, maximum: int) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise IndexingUnavailableError(_ERR_SOURCE)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise IndexingUnavailableError(_ERR_SOURCE)
        content = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if len(content) > maximum or (opened.st_size, opened.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            raise IndexingUnavailableError(_ERR_SOURCE)
    except OSError as error:
        raise IndexingUnavailableError(_ERR_SOURCE) from error
    else:
        return content
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _path(value: str) -> None:
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise IndexingValidationError(_ERR_SOURCE) from error
    path = PurePosixPath(value)
    if (
        not value
        or len(encoded) > _MAX_PATH_BYTES
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_SOURCE)
