"""Descriptor-bound reads for provider capability files."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_CAPABILITY_BYTES = 32
_MAX_CREDENTIAL_BYTES = 4096
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024


def read_capability(path: Path) -> bytearray:
    """Read exactly 32 owner-only bytes without following a link."""
    return _read_protected(path, minimum_bytes=_CAPABILITY_BYTES, maximum_bytes=_CAPABILITY_BYTES)


def read_provider_credential(path: Path, maximum_bytes: int = _MAX_CREDENTIAL_BYTES) -> bytearray:
    """Read one bounded owner-only credential without following a link."""
    if not 1 <= maximum_bytes <= _MAX_CREDENTIAL_BYTES:
        msg = "provider credential length policy is invalid"
        raise ValueError(msg)
    return _read_protected(path, minimum_bytes=1, maximum_bytes=maximum_bytes)


def read_provider_document(path: Path, maximum_bytes: int) -> bytearray:
    """Read one bounded owner-only control document into a mutable buffer."""
    if not 1 <= maximum_bytes <= _MAX_DOCUMENT_BYTES:
        msg = "provider document length policy is invalid"
        raise ValueError(msg)
    return _read_protected(path, minimum_bytes=2, maximum_bytes=maximum_bytes)


def _read_protected(
    path: Path,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
) -> bytearray:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        observation = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observation.st_mode)
            or observation.st_uid != os.geteuid()
            or observation.st_gid != os.getegid()
            or stat.S_IMODE(observation.st_mode) & 0o077
            or observation.st_nlink != 1
            or not minimum_bytes <= observation.st_size <= maximum_bytes
        ):
            msg = "provider capability file is unsafe"
            raise PermissionError(msg)
        content = bytearray()
        while len(content) <= maximum_bytes:
            chunk = os.read(descriptor, maximum_bytes + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        if not minimum_bytes <= len(content) <= maximum_bytes:
            zero(content)
            msg = "provider capability length is invalid"
            raise PermissionError(msg)
        after = os.fstat(descriptor)
        if (observation.st_dev, observation.st_ino, observation.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            zero(content)
            msg = "provider capability changed while reading"
            raise PermissionError(msg)
        return content
    finally:
        os.close(descriptor)


def zero(value: bytearray) -> None:
    """Best-effort overwrite of a mutable secret buffer."""
    value[:] = b"\x00" * len(value)
