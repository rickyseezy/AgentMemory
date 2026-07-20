"""Filesystem, Git, and argv-process adapters for hookless hosts."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import os
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.errors import IngestionDependencyError, IngestionValidationError
from agentmemory.ingestion.domain.generic_adapter import (
    FileSnapshotEntry,
    GitState,
    ProcessExecutionResult,
    SourceCompletion,
    WorkspaceSnapshot,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import BinaryIO

    from agentmemory.shared.clock import Clock

_MAX_FILES = 100_000
_MAX_HASH_BYTES = 64 * 1024 * 1024
_MAX_PROCESS_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_STDIN_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 65_536
_GIT_TIMEOUT_SECONDS = 5.0
_MAX_POLICY_PATTERNS = 1_024
_MAX_POLICY_PATTERN_LENGTH = 1_024
_MAX_GIT_OUTPUT_BYTES = 8_192
_MAX_ARG_COUNT = 4_096
_MAX_ARGUMENT_LENGTH = 32_768
_DEFAULT_PRIVATE_PATTERNS = (
    ".git",
    ".git/**",
    ".agentmemory",
    ".agentmemory/**",
    ".agentmemoryignore",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/*credential*",
    "**/*credentials*",
    "**/*secret*",
    "**/*.key",
    "**/*.pem",
    "**/id_rsa*",
    "**/id_ed25519*",
)


@dataclass(frozen=True, slots=True)
class WorkspacePrivacyPolicy:
    """Closed glob policy applied before file bytes are opened."""

    ignored_patterns: tuple[str, ...] = ()
    private_patterns: tuple[str, ...] = _DEFAULT_PRIVATE_PATTERNS
    maximum_file_bytes: int = _MAX_HASH_BYTES
    maximum_files: int = _MAX_FILES

    def __post_init__(self) -> None:
        """Reject unsafe/unbounded ignore configuration."""
        patterns = (*self.ignored_patterns, *self.private_patterns)
        if len(patterns) > _MAX_POLICY_PATTERNS or any(
            not pattern or len(pattern) > _MAX_POLICY_PATTERN_LENGTH or pattern.startswith("!")
            for pattern in patterns
        ):
            msg = "workspace privacy patterns are invalid"
            raise ValueError(msg)
        if self.maximum_file_bytes < 1 or self.maximum_files < 1:
            msg = "workspace privacy bounds are invalid"
            raise ValueError(msg)

    @classmethod
    def from_workspace(cls, root: Path) -> WorkspacePrivacyPolicy:
        """Load strict additive patterns from `.agentmemoryignore` when present."""
        ignore_file = root / ".agentmemoryignore"
        if not ignore_file.is_file() or ignore_file.is_symlink():
            return cls()
        try:
            lines = ignore_file.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as error:
            msg = "workspace ignore file must be UTF-8"
            raise ValueError(msg) from error
        patterns = tuple(
            line.strip().removeprefix("/")
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        )
        return cls(ignored_patterns=patterns)

    def excludes(self, relative_path: str) -> bool:
        """Return whether the path is ignored/private before opening it."""
        return any(
            fnmatch.fnmatchcase(relative_path, pattern)
            or fnmatch.fnmatchcase(f"/{relative_path}", pattern)
            for pattern in (*self.ignored_patterns, *self.private_patterns)
        )


@dataclass(frozen=True, slots=True)
class LocalFileObserver:
    """Hash policy-authorized regular files without following symlinks."""

    clock: Clock
    policy: WorkspacePrivacyPolicy

    def snapshot(self, root: Path) -> WorkspaceSnapshot:
        """Return deterministic file metadata scoped to the exact resolved root."""
        resolved = root.resolve(strict=True)
        if not resolved.is_dir():
            field = "root"
            raise IngestionValidationError.single(field, "not_directory")
        entries: list[FileSnapshotEntry] = []
        excluded = 0
        for directory, directory_names, file_names in os.walk(resolved, followlinks=False):
            directory_path = Path(directory)
            kept_directories: list[str] = []
            for name in sorted(directory_names):
                candidate = directory_path / name
                relative = candidate.relative_to(resolved).as_posix()
                if candidate.is_symlink() or self.policy.excludes(relative):
                    excluded += 1
                else:
                    kept_directories.append(name)
            directory_names[:] = kept_directories
            for name in sorted(file_names):
                candidate = directory_path / name
                relative = candidate.relative_to(resolved).as_posix()
                if self.policy.excludes(relative) or candidate.is_symlink():
                    excluded += 1
                    continue
                try:
                    metadata = candidate.stat(follow_symlinks=False)
                    if (
                        not stat_module.S_ISREG(metadata.st_mode)
                        or metadata.st_size > self.policy.maximum_file_bytes
                    ):
                        excluded += 1
                        continue
                    content_sha256 = _hash_regular_file(
                        candidate,
                        metadata,
                        self.policy.maximum_file_bytes,
                    )
                except FileNotFoundError, PermissionError, OSError:
                    excluded += 1
                    continue
                entries.append(FileSnapshotEntry(relative, content_sha256, metadata.st_size))
                if len(entries) > self.policy.maximum_files:
                    msg = "workspace file limit exceeded"
                    raise IngestionDependencyError(msg)
        return WorkspaceSnapshot(
            tuple(sorted(entries, key=lambda entry: entry.relative_path)),
            self.clock.now(),
            excluded,
        )


@dataclass(frozen=True, slots=True)
class SubprocessGitObserver:
    """Probe Git through fixed executable/argv operations without a shell."""

    async def observe(self, root: Path) -> GitState | None:
        """Return current commit/branch and a non-path checkout fingerprint."""
        resolved = await asyncio.to_thread(root.resolve, strict=True)
        try:
            commit = await _git(resolved, "rev-parse", "--verify", "HEAD")
            branch = await _git(resolved, "rev-parse", "--abbrev-ref", "HEAD")
            common_dir = await _git(resolved, "rev-parse", "--git-common-dir")
        except _NotGitRepositoryError:
            return None
        stat = await asyncio.to_thread(resolved.stat)
        fingerprint = _framed_digest(
            "agentmemory-git-checkout-v1",
            str(stat.st_dev),
            str(stat.st_ino),
            common_dir,
        )
        return GitState(commit, None if branch == "HEAD" else branch, fingerprint)


@dataclass(frozen=True, slots=True)
class ArgvProcessExecutor:
    """Run a child directly, bounding captured bytes and termination latency."""

    clock: Clock
    environment: Mapping[str, str] | None = None
    termination_grace_seconds: float = 2.0
    inherit_stdin: bool = False
    stdout_sink: BinaryIO | None = None
    stderr_sink: BinaryIO | None = None

    async def execute(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        stdin: bytes | None,
        timeout_seconds: float | None,
    ) -> ProcessExecutionResult:
        """Execute one non-shell argv vector and classify interruption explicitly."""
        _validate_argv(argv)
        if stdin is not None and len(stdin) > _MAX_STDIN_BYTES:
            field = "stdin"
            raise IngestionValidationError.single(field, "too_large")
        resolved = await asyncio.to_thread(cwd.resolve, strict=True)
        if not await asyncio.to_thread(resolved.is_dir):
            field = "cwd"
            raise IngestionValidationError.single(field, "not_directory")
        started_at = self.clock.now()
        stdin_mode = (
            asyncio.subprocess.PIPE
            if stdin is not None
            else None
            if self.inherit_stdin
            else asyncio.subprocess.DEVNULL
        )
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=resolved,
            env=dict(self.environment) if self.environment is not None else None,
            stdin=stdin_mode,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        completion = SourceCompletion.COMPLETE
        capture = _ProcessIoCapture(self.stdout_sink, self.stderr_sink)
        try:
            try:
                communication = _communicate_and_tee(
                    process,
                    stdin,
                    capture,
                )
                if timeout_seconds is None:
                    stdout, stderr = await communication
                else:
                    async with asyncio.timeout(timeout_seconds):
                        stdout, stderr = await communication
            except TimeoutError:
                completion = SourceCompletion.ABRUPT
                process.terminate()
                try:
                    async with asyncio.timeout(self.termination_grace_seconds):
                        stdout, stderr = await _communicate_and_tee(
                            process,
                            None,
                            capture,
                        )
                except TimeoutError:
                    process.kill()
                    stdout, stderr = await _communicate_and_tee(
                        process,
                        None,
                        capture,
                    )
        except asyncio.CancelledError:
            await _kill_and_reap(process)
            raise
        except Exception:
            await _kill_and_reap(process)
            raise
        if len(stdout) > _MAX_PROCESS_OUTPUT_BYTES or len(stderr) > _MAX_PROCESS_OUTPUT_BYTES:
            msg = "process output exceeded bounded capture"
            raise IngestionDependencyError(msg)
        ended_at = self.clock.now()
        return ProcessExecutionResult(
            Path(argv[0]).name,
            _argv_digest(argv),
            process.returncode if completion is SourceCompletion.COMPLETE else None,
            stdout,
            stderr,
            started_at,
            ended_at,
            completion,
        )


class _NotGitRepositoryError(Exception):
    pass


async def _git(root: Path, *arguments: str) -> str:
    process = await asyncio.create_subprocess_exec(
        "git",
        "-C",
        str(root),
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={"LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
    )
    try:
        async with asyncio.timeout(_GIT_TIMEOUT_SECONDS):
            stdout, _ = await process.communicate()
    except TimeoutError as error:
        process.kill()
        await process.wait()
        msg = "Git observation timed out"
        raise IngestionDependencyError(msg) from error
    if process.returncode != 0:
        raise _NotGitRepositoryError
    if len(stdout) > _MAX_GIT_OUTPUT_BYTES or b"\x00" in stdout:
        msg = "Git observation returned invalid output"
        raise IngestionDependencyError(msg)
    try:
        return stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        msg = "Git observation returned non-UTF-8 output"
        raise IngestionDependencyError(msg) from error


def _hash_regular_file(
    path: Path,
    expected: os.stat_result,
    maximum_bytes: int,
) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat_module.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
            or opened.st_size != expected.st_size
            or opened.st_size > maximum_bytes
        ):
            msg = "workspace file changed before secure open"
            raise OSError(msg)
        total = 0
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            total += len(chunk)
            if total > maximum_bytes:
                msg = "workspace file exceeded bounded capture"
                raise OSError(msg)
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (final.st_size, final.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            msg = "workspace file changed during capture"
            raise OSError(msg)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


@dataclass(slots=True)
class _ProcessIoCapture:
    stdout_sink: BinaryIO | None
    stderr_sink: BinaryIO | None
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)


async def _communicate_and_tee(
    process: asyncio.subprocess.Process,
    stdin: bytes | None,
    capture: _ProcessIoCapture,
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        msg = "child process pipes are unavailable"
        raise IngestionDependencyError(msg)
    tasks = (
        asyncio.create_task(_read_and_tee(process.stdout, capture.stdout_sink, capture.stdout)),
        asyncio.create_task(_read_and_tee(process.stderr, capture.stderr_sink, capture.stderr)),
        asyncio.create_task(_write_stdin(process.stdin, stdin)),
        asyncio.create_task(process.wait()),
    )
    try:
        stdout_result, stderr_result, _, _ = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    del stdout_result, stderr_result
    return bytes(capture.stdout), bytes(capture.stderr)


async def _kill_and_reap(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        process.kill()
    await process.communicate()


async def _read_and_tee(
    stream: asyncio.StreamReader,
    sink: BinaryIO | None,
    captured: bytearray,
) -> bytes:
    while chunk := await stream.read(_READ_CHUNK_BYTES):
        if len(captured) + len(chunk) > _MAX_PROCESS_OUTPUT_BYTES:
            msg = "process output exceeded bounded capture"
            raise IngestionDependencyError(msg)
        captured.extend(chunk)
        if sink is not None:
            await asyncio.to_thread(_write_sink, sink, chunk)
    return bytes(captured)


async def _write_stdin(
    stream: asyncio.StreamWriter | None,
    value: bytes | None,
) -> None:
    if stream is None:
        return
    if value is not None:
        stream.write(value)
        await stream.drain()
    stream.close()
    await stream.wait_closed()


def _write_sink(sink: BinaryIO, value: bytes) -> None:
    sink.write(value)
    sink.flush()


def _validate_argv(argv: tuple[str, ...]) -> None:
    if (
        not argv
        or len(argv) > _MAX_ARG_COUNT
        or any(
            not argument or "\x00" in argument or len(argument) > _MAX_ARGUMENT_LENGTH
            for argument in argv
        )
    ):
        field = "argv"
        raise IngestionValidationError.single(field, "invalid")


def _argv_digest(argv: tuple[str, ...]) -> str:
    return _framed_digest("agentmemory-process-argv-v1", *argv)


def _framed_digest(namespace: str, *parts: str) -> str:
    framed = bytearray()
    for part in (namespace, *parts):
        encoded = part.encode()
        framed.extend(len(encoded).to_bytes(8, "big"))
        framed.extend(encoded)
    return hashlib.sha256(framed).hexdigest()
