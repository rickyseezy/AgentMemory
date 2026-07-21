"""Bounded local workspace capture without durable absolute host paths."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.content_policy_ports import PolicySourceDocuments
from agentmemory.indexing.domain.errors import (
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.ports import SourceArtifact

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.content_policy_ports import RepositoryContentPolicyGate
    from agentmemory.shared.clock import Clock

_ERR_POLICY = "workspace source policy is invalid"
_ERR_READ = "workspace source could not be captured safely"
_ERR_LIMIT = "workspace source exceeds configured local limits"
_MAX_FILES = 1_000_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
_DEFAULT_EXCLUDED = frozenset(
    {
        ".agentmemory",
        ".git",
        ".hg",
        ".svn",
    }
)


@dataclass(frozen=True, slots=True)
class WorkspaceReadPolicy:
    """Fail-closed local traversal and memory bounds."""

    max_files: int = 250_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    excluded_names: frozenset[str] = field(default_factory=lambda: _DEFAULT_EXCLUDED)

    def __post_init__(self) -> None:
        """Reject ineffective limits and unsafe path-like exclusion entries."""
        if (
            not 1 <= self.max_files <= _MAX_FILES
            or not 1 <= self.max_file_bytes <= _MAX_FILE_BYTES
            or not self.max_file_bytes <= self.max_total_bytes <= _MAX_TOTAL_BYTES
            or any(
                not value or value in {".", ".."} or "/" in value or "\\" in value
                for value in self.excluded_names
            )
        ):
            raise IndexingValidationError(_ERR_POLICY)


class LocalWorkspaceSnapshotSource:
    """Read a configured workspace mount with symlink and race protection."""

    def __init__(
        self,
        root: Path,
        policy: WorkspaceReadPolicy | None = None,
        *,
        content_policy: RepositoryContentPolicyGate,
        clock: Clock,
    ) -> None:
        """Capture the trusted mount root ephemerally; it is never returned or persisted."""
        if not root.is_absolute():
            raise IndexingValidationError(_ERR_POLICY)
        if root.is_symlink():
            raise IndexingValidationError(_ERR_POLICY)
        try:
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise IndexingUnavailableError(_ERR_READ) from error
        if not resolved.is_dir():
            raise IndexingValidationError(_ERR_POLICY)
        self._root = resolved
        self._policy = policy or WorkspaceReadPolicy()
        self._content_policy = content_policy
        self._clock = clock

    async def read(self, scope: AuthorizedScope) -> tuple[SourceArtifact, ...]:
        """Return a deterministic, repository-relative snapshot of regular files."""
        if len(scope.repository_ids) != 1:
            raise IndexingValidationError(_ERR_POLICY)
        repository_id = scope.repository_ids[0].value
        policy = await self._content_policy.prepare(
            repository_id,
            PolicySourceDocuments(
                self._policy_document(".agentmemoryignore"),
                self._policy_document(".gitignore"),
            ),
            self._clock.now(),
        )
        paths = self._discover()
        artifacts: list[SourceArtifact] = []
        total = 0
        for relative, absolute, symlink, byte_length in paths:
            path_decision = policy.evaluate_path(
                relative,
                symlink=symlink,
                byte_length=byte_length,
                decided_at=self._clock.now(),
            )
            await self._content_policy.record(path_decision)
            if path_decision.excluded:
                continue
            content = self._read_regular(absolute)
            content_decision = policy.evaluate_content(relative, content, self._clock.now())
            await self._content_policy.record(content_decision)
            if content_decision.excluded:
                continue
            total += len(content)
            if total > self._policy.max_total_bytes:
                raise IndexingUnavailableError(_ERR_LIMIT)
            artifacts.append(SourceArtifact(relative, content))
        return tuple(artifacts)

    def _discover(self) -> tuple[tuple[str, Path, bool, int], ...]:
        pending = [self._root]
        discovered: list[tuple[str, Path, bool, int]] = []
        try:
            while pending:
                directory = pending.pop()
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if entry.name in self._policy.excluded_names:
                            continue
                        path = Path(entry.path)
                        relative = path.relative_to(self._root).as_posix()
                        if entry.is_symlink():
                            observed = entry.stat(follow_symlinks=False)
                            discovered.append((relative, path, True, observed.st_size))
                            _limit_if(condition=len(discovered) > self._policy.max_files)
                        elif entry.is_dir(follow_symlinks=False):
                            pending.append(path)
                        elif entry.is_file(follow_symlinks=False):
                            observed = entry.stat(follow_symlinks=False)
                            discovered.append((relative, path, False, observed.st_size))
                            _limit_if(condition=len(discovered) > self._policy.max_files)
        except OSError as error:
            raise IndexingUnavailableError(_ERR_READ) from error
        return tuple(sorted(discovered, key=lambda item: item[0]))

    def _policy_document(self, name: str) -> bytes | None:
        try:
            return self._read_regular(self._root / name)
        except IndexingUnavailableError:
            return None

    def _read_regular(self, path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            before = path.lstat()
            _limit_if(
                condition=not stat.S_ISREG(before.st_mode)
                or before.st_size > self._policy.max_file_bytes
            )
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            _read_error_if(
                condition=(before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            )
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
            _limit_if(
                condition=len(content) > self._policy.max_file_bytes
                or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            )
        except OSError as error:
            raise IndexingUnavailableError(_ERR_READ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return content


def _limit_if(*, condition: bool) -> None:
    if condition:
        raise IndexingUnavailableError(_ERR_LIMIT)


def _read_error_if(*, condition: bool) -> None:
    if condition:
        raise IndexingUnavailableError(_ERR_READ)
