"""Descriptor-bound reads for provider capability files."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_CAPABILITY_BYTES = 32


def read_capability(path: Path) -> bytearray:
    """Read exactly 32 owner-only bytes without following a link."""
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
            or observation.st_size != _CAPABILITY_BYTES
        ):
            msg = "provider capability file is unsafe"
            raise PermissionError(msg)
        content = bytearray()
        while len(content) <= _CAPABILITY_BYTES:
            chunk = os.read(descriptor, _CAPABILITY_BYTES + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != _CAPABILITY_BYTES:
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
