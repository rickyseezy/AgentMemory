"""Strict, no-follow AgentMemory project manifest reader."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import cast

from agentmemory.identity.domain.errors import IdentityDependencyError, IdentityValidationError
from agentmemory.identity.domain.value_objects import ProjectManifest, StableId

_MAX_MANIFEST_BYTES = 64 * 1024
_ALLOWED_KEYS = frozenset(
    {"schema_version", "project_id", "repository_id", "display_name", "component_roots"}
)


class SecureJsonManifestReader:
    """Read a bounded strict manifest without following a manifest symlink."""

    async def read(self, path: str) -> ProjectManifest | None:
        """Return a validated manifest or absence; malformed declarations fail closed."""
        return await asyncio.to_thread(self._read_sync, path)

    @staticmethod
    def _read_sync(path: str) -> ProjectManifest | None:
        workspace = Path(path)
        manifest_path = workspace / ".agentmemory" / "project.json"
        try:
            metadata = manifest_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise IdentityDependencyError from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_MANIFEST_BYTES:
            msg = "project manifest must be a bounded regular file"
            raise IdentityValidationError(msg)
        return _parse_manifest(_read_bounded(manifest_path))


def _read_bounded(manifest_path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(manifest_path, flags)
        with os.fdopen(descriptor, "rb") as manifest_file:
            payload = manifest_file.read(_MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        raise IdentityDependencyError from error
    if len(payload) > _MAX_MANIFEST_BYTES:
        msg = "project manifest exceeds the supported size"
        raise IdentityValidationError(msg)
    return payload


def _parse_manifest(payload: bytes) -> ProjectManifest:
    try:
        parsed = cast("object", json.loads(payload))
    except (json.JSONDecodeError, UnicodeError) as error:
        msg = "project manifest is invalid JSON"
        raise IdentityValidationError(msg) from error
    if not isinstance(parsed, dict):
        msg = "project manifest root must be an object"
        raise IdentityValidationError(msg)
    values = cast("dict[object, object]", parsed)
    if any(not isinstance(key, str) for key in values) or set(values) - _ALLOWED_KEYS:
        msg = "project manifest contains unsupported fields"
        raise IdentityValidationError(msg)
    schema_version = values.get("schema_version")
    project_id = values.get("project_id")
    repository_id = values.get("repository_id")
    display_name = values.get("display_name")
    component_roots = values.get("component_roots", [])
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or not isinstance(project_id, str)
        or (repository_id is not None and not isinstance(repository_id, str))
        or (display_name is not None and not isinstance(display_name, str))
        or not isinstance(component_roots, list)
    ):
        msg = "project manifest field types are invalid"
        raise IdentityValidationError(msg)
    _validate_component_roots(cast("list[object]", component_roots))
    return ProjectManifest(
        schema_version,
        StableId(project_id),
        None if repository_id is None else StableId(repository_id),
    )


def _validate_component_roots(values: list[object]) -> None:
    roots: list[str] = []
    for value in values:
        if not isinstance(value, str):
            msg = "project manifest component roots must be relative paths"
            raise IdentityValidationError(msg)
        path = PurePosixPath(value)
        if path.is_absolute() or not value or ".." in path.parts or "\\" in value:
            msg = "project manifest component roots must be relative paths"
            raise IdentityValidationError(msg)
        roots.append(value)
    if len(set(roots)) != len(roots):
        msg = "project manifest component roots must be unique"
        raise IdentityValidationError(msg)
