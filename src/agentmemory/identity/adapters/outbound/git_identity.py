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

_MAX_GIT_OUTPUT = 1024 * 1024
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


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
        common_directory = await self._git(path, "rev-parse", "--git-common-dir")
        worktree_directory = await self._git(path, "rev-parse", "--git-dir")
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
        worktree = self.fingerprinter.opaque(
            "GitWorktreeFingerprintV1",
            f"{common_directory}\x00{worktree_directory}",
        )
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
        )

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
