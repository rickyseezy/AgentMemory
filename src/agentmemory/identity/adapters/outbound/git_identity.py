"""Argv-only Git identity observation adapter."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityDependencyError, IdentityValidationError
from agentmemory.identity.domain.value_objects import DeviceIdentity, StableId, VcsIdentity, VcsType

if TYPE_CHECKING:
    from agentmemory.identity.adapters.outbound.fingerprints import IdentityFingerprinter
    from agentmemory.identity.domain.value_objects import Fingerprint

_MAX_GIT_OUTPUT = 1024 * 1024
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REMOTE_NAME = re.compile(r"^[^\x00\r\n]{1,1024}$")


@dataclass(frozen=True, slots=True)
class GitCliIdentityAdapter:
    """Observe Git through a fixed executable and return only keyed evidence."""

    executable: Path
    fingerprinter: IdentityFingerprinter

    def __post_init__(self) -> None:
        """Reject PATH lookup and mutable executable identities."""
        if not self.executable.is_absolute():
            msg = "Git executable must be an absolute path"
            raise IdentityValidationError(msg)

    async def observe(self, path: str, device: DeviceIdentity) -> VcsIdentity | None:
        """Return stable repository/checkout evidence or absence for non-Git directories."""
        inside = await self._git(path, "rev-parse", "--is-inside-work-tree", required=False)
        if inside is None or inside != "true":
            return None
        object_format = await self._git(path, "rev-parse", "--show-object-format")
        roots_output = await self._git(path, "rev-list", "--max-parents=0", "--all")
        if object_format is None or roots_output is None:
            raise IdentityDependencyError
        roots = tuple(line for line in roots_output.splitlines() if line)
        if not roots or any(_OBJECT_ID.fullmatch(root) is None for root in roots):
            msg = "Git root evidence is incomplete"
            raise IdentityValidationError(msg)
        remote = await self._git(path, "config", "--get", "remote.origin.url", required=False)
        common_directory = await self._git(
            path, "rev-parse", "--path-format=absolute", "--git-common-dir"
        )
        worktree_directory = await self._git(
            path, "rev-parse", "--path-format=absolute", "--git-dir"
        )
        if common_directory is None or worktree_directory is None:
            raise IdentityDependencyError
        stable_repository_id = await asyncio.to_thread(_read_repository_id, path)
        repository = self.fingerprinter.repository(
            VcsType.GIT,
            object_format,
            roots,
            stable_repository_id,
            remote,
        )
        try:
            common_identity, worktree_identity = await asyncio.to_thread(
                _git_directory_identities,
                common_directory,
                worktree_directory,
            )
        except OSError as error:
            raise IdentityDependencyError from error
        common = self.fingerprinter.opaque("GitCommonDirectoryFingerprintV1", common_identity)
        worktree = self.fingerprinter.opaque("GitWorktreeFingerprintV1", worktree_identity)
        branch = await self._git(path, "symbolic-ref", "--quiet", "--short", "HEAD", required=False)
        head_commit = await self._git(path, "rev-parse", "--verify", "HEAD")
        dirty = await self._git(
            path,
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
        )
        if head_commit is None or dirty is None:
            raise IdentityDependencyError
        remote_fingerprints = await self._remote_fingerprints(path)
        checkout = self.fingerprinter.checkout(
            repository,
            device.device_id,
            device.volume_fingerprint,
            device.path_fingerprint,
            worktree.value,
        )
        return VcsIdentity(
            VcsType.GIT,
            repository,
            checkout,
            worktree,
            repository_lookup_approved=remote is not None or stable_repository_id is not None,
            common_directory_fingerprint=common,
            branch=branch,
            head_commit=head_commit,
            remote_fingerprints=remote_fingerprints,
            dirty_digest=self.fingerprinter.opaque(
                "GitDirtyDigestV1",
                dirty or "clean",
            ),
        )

    async def _remote_fingerprints(self, path: str) -> tuple[Fingerprint, ...]:
        """Return a canonical unique set of keyed remote URLs."""
        names_output = await self._git(path, "remote", required=False)
        names = () if not names_output else tuple(names_output.splitlines())
        fingerprints: set[Fingerprint] = set()
        for name in names:
            if _REMOTE_NAME.fullmatch(name) is None:
                msg = "Git remote name evidence is invalid"
                raise IdentityValidationError(msg)
            remote = await self._git(path, "config", "--get", f"remote.{name}.url")
            if remote is None:
                raise IdentityDependencyError
            fingerprints.add(self.fingerprinter.remote(remote))
        return tuple(sorted(fingerprints, key=lambda value: value.value))

    async def _git(self, path: str, *arguments: str, required: bool = True) -> str | None:
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self.executable),
                "-C",
                path,
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await process.communicate()
        except OSError as error:
            raise IdentityDependencyError from error
        if len(stdout) > _MAX_GIT_OUTPUT:
            msg = "Git identity output exceeded the supported bound"
            raise IdentityValidationError(msg)
        if process.returncode != 0:
            if required:
                raise IdentityDependencyError
            return None
        try:
            return stdout.decode("utf-8", errors="strict").strip()
        except UnicodeError as error:
            msg = "Git identity output was not UTF-8"
            raise IdentityValidationError(msg) from error


def _read_repository_id(path: str) -> StableId | None:
    repository_id_path = Path(path) / ".agentmemory" / "repository-id"
    try:
        value = repository_id_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise IdentityDependencyError from error
    return StableId(value)


def _git_directory_identities(common_directory: str, worktree_directory: str) -> tuple[str, str]:
    common = Path(common_directory).stat()
    worktree = Path(worktree_directory).stat()
    return f"{common.st_dev}:{common.st_ino}", f"{worktree.st_dev}:{worktree.st_ino}"
