"""Owner-only no-follow protected-file reads for Core secret references."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from pathlib import Path


def read_protected_file(path: Path, allowed_lengths: frozenset[int]) -> bytearray:
    """Read a bounded regular file owned by this process without following links."""
    if not allowed_lengths or min(allowed_lengths) <= 0:
        msg = "protected file length policy is invalid"
        raise ValueError(msg)
    return _read_protected(path, max(allowed_lengths), allowed_lengths)


def read_protected_document(path: Path, maximum_length: int) -> bytes:
    """Read one non-empty owner-only control document without following links."""
    if maximum_length <= 0:
        msg = "protected document length policy is invalid"
        raise ValueError(msg)
    temporary = _read_protected(path, maximum_length, None)
    try:
        return bytes(temporary)
    finally:
        _zero(temporary)


def require_private_directory(path: Path) -> None:
    """Require an existing owner-only directory without following a symlink."""
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OperationError(ErrorCode.FORBIDDEN, "private directory is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077 != 0
    ):
        raise OperationError(ErrorCode.FORBIDDEN, "private directory ownership is unsafe")


def _read_protected(
    path: Path,
    maximum_length: int,
    allowed_lengths: frozenset[int] | None,
) -> bytearray:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OperationError(
            ErrorCode.FORBIDDEN, "protected secret source is unavailable"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077 != 0
            or metadata.st_size <= 0
            or metadata.st_size > maximum_length
            or (allowed_lengths is not None and metadata.st_size not in allowed_lengths)
        ):
            raise OperationError(ErrorCode.FORBIDDEN, "protected secret source is unsafe")
        value = _read_descriptor(descriptor, maximum_length)
        if len(value) != metadata.st_size or (
            allowed_lengths is not None and len(value) not in allowed_lengths
        ):
            _zero(value)
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "protected secret has invalid length"
            )
        confirmation = _read_descriptor(descriptor, maximum_length)
        after = os.fstat(descriptor)
        if value != confirmation or not _same_file_state(metadata, after):
            _zero(value)
            _zero(confirmation)
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "protected secret changed during read"
            )
        _zero(confirmation)
        return value
    finally:
        os.close(descriptor)


def zero_secret(value: bytearray) -> None:
    """Best-effort overwrite of a temporary mutable secret buffer."""
    _zero(value)


def _read_descriptor(descriptor: int, maximum_length: int) -> bytearray:
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = bytearray()
    while len(value) <= maximum_length:
        chunk = os.read(descriptor, maximum_length + 1 - len(value))
        if not chunk:
            break
        value.extend(chunk)
    return value


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_mode == after.st_mode
        and before.st_uid == after.st_uid
        and before.st_gid == after.st_gid
        and before.st_nlink == after.st_nlink
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
