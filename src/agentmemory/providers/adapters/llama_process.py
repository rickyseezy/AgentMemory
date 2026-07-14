"""Bounded supervision of the pinned llama.cpp child process."""

from __future__ import annotations

import asyncio
import os
import signal
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import httpx

from agentmemory.providers.adapters.model_artifact import (
    ModelArtifactBinding,
    verify_model_artifact,
)
from agentmemory.providers.domain.models import ProviderRole

LLAMA_CPP_REVISION: Final = "99f3dc32296f825fec94f202da1e9fede1e78cf9"
_VERSION_PREFIX = b"version: 9982 (99f3dc322)"
_STARTUP_TIMEOUT_SECONDS = 120
_SHUTDOWN_TIMEOUT_SECONDS = 20
_MAX_VERSION_OUTPUT_BYTES = 4096
_SCRATCH_DIRECTORY = "/tmp"  # nosec B108  # noqa: S108 -- owner-only Compose tmpfs


@dataclass(frozen=True, slots=True)
class LlamaProcessConfiguration:
    """Closed process inputs selected by the release-bound role."""

    role: ProviderRole
    binary: Path
    artifact: ModelArtifactBinding


class LlamaProcessSupervisor:
    """Verify, start, health-gate, and terminate one llama.cpp process group."""

    def __init__(self, configuration: LlamaProcessConfiguration) -> None:
        """Store immutable process authority without performing I/O."""
        if configuration.binary != Path("/app/llama-server"):
            msg = "llama.cpp binary path is not release-bound"
            raise ValueError(msg)
        self._configuration = configuration
        self._process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        """Verify every executable input before exposing provider HTTP."""
        if self._process is not None:
            msg = "llama.cpp process is already supervised"
            raise RuntimeError(msg)
        await asyncio.to_thread(verify_model_artifact, self._configuration.artifact)
        await self._verify_binary_revision()
        self._process = await asyncio.create_subprocess_exec(
            *self._arguments(),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            cwd=_SCRATCH_DIRECTORY,
            env=_child_environment(),
            start_new_session=True,
        )
        try:
            await self._wait_until_healthy()
        except BaseException:
            await self.stop()
            raise

    async def stop(self) -> None:
        """Terminate the complete child process group within a finite deadline."""
        process, self._process = self._process, None
        if process is None or process.returncode is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            async with asyncio.timeout(_SHUTDOWN_TIMEOUT_SECONDS):
                await process.wait()
        except TimeoutError:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()

    async def _verify_binary_revision(self) -> None:
        process = await asyncio.create_subprocess_exec(
            str(self._configuration.binary),
            "--version",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=_SCRATCH_DIRECTORY,
            env=_child_environment(),
        )
        stdout, _ = await process.communicate()
        if (
            process.returncode != 0
            or len(stdout) > _MAX_VERSION_OUTPUT_BYTES
            or not stdout.startswith(_VERSION_PREFIX)
        ):
            msg = "llama.cpp binary revision does not match the reviewed runtime"
            raise RuntimeError(msg)

    async def _wait_until_healthy(self) -> None:
        process = self._process
        if process is None:
            msg = "llama.cpp process was not started"
            raise RuntimeError(msg)
        async with httpx.AsyncClient(
            timeout=1,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with asyncio.timeout(_STARTUP_TIMEOUT_SECONDS):
                while True:
                    if process.returncode is not None:
                        msg = "llama.cpp exited before model readiness"
                        raise RuntimeError(msg)
                    try:
                        response = await client.get("http://127.0.0.1:8090/health")
                        if response.status_code == 200:  # noqa: PLR2004
                            return
                    except httpx.HTTPError:
                        pass
                    await asyncio.sleep(0.1)

    def _arguments(self) -> tuple[str, ...]:
        shared = (
            str(self._configuration.binary),
            "--model",
            str(self._configuration.artifact.path),
            "--host",
            "127.0.0.1",
            "--port",
            "8090",
            "--parallel",
            "1",
            "--threads",
            "4",
            "--threads-batch",
            "4",
            "--threads-http",
            "2",
            "--timeout",
            "8",
            "--no-webui",
            "--no-slots",
            "--log-disable",
        )
        if self._configuration.role is ProviderRole.EMBEDDING:
            return (*shared, "--ctx-size", "4096", "--embedding", "--pooling", "last")
        if self._configuration.role is ProviderRole.RERANKING:
            return (
                *shared,
                "--ctx-size",
                "4096",
                "--embedding",
                "--pooling",
                "rank",
                "--reranking",
            )
        return (
            *shared,
            "--ctx-size",
            "2048",
            "--jinja",
            "--reasoning-format",
            "deepseek",
            "--n-predict",
            "32",
        )


def _child_environment() -> dict[str, str]:
    return {
        "HOME": _SCRATCH_DIRECTORY,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LD_LIBRARY_PATH": "/app",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": _SCRATCH_DIRECTORY,
    }
