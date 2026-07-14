from __future__ import annotations

# pyright: reportPrivateUsage=false, reportAttributeAccessIssue=false
import asyncio
import hashlib
import os
import signal
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, Self, cast
from unittest.mock import AsyncMock

import httpx
import pytest
import uvicorn
from pydantic import ValidationError

from agentmemory.providers.adapters import llama_process
from agentmemory.providers.adapters.llama_cpp import LlamaCppBackend
from agentmemory.providers.adapters.llama_process import (
    LlamaProcessConfiguration,
    LlamaProcessSupervisor,
)
from agentmemory.providers.adapters.model_artifact import ModelArtifactBinding
from agentmemory.providers.domain.models import EMBEDDING_DIMENSION, ProviderRole
from agentmemory.providers.infrastructure import composition, entrypoints
from agentmemory.providers.infrastructure.configuration import ProviderSettings

REVISION = "c" * 40
DIGEST = "d" * 64
_TEMP_DIR = "/tmp"  # noqa: S108 - asserts the closed container runtime contract


def _settings(role: ProviderRole = ProviderRole.EMBEDDING) -> ProviderSettings:
    return ProviderSettings(
        role=role,
        model_revision=REVISION,
        model_sha256=DIGEST,
        model_size=123,
    )


@pytest.mark.parametrize("role", list(ProviderRole))
def test_settings_derive_all_closed_role_bindings(role: ProviderRole) -> None:
    settings = _settings(role)
    assert settings.identity.role is role
    assert settings.identity.dimension == (
        EMBEDDING_DIMENSION if role is ProviderRole.EMBEDDING else None
    )
    assert settings.artifact_binding.sha256 == DIGEST
    assert settings.capability_file.name.endswith("_capability")
    assert settings.internal_host.startswith("local-")


def test_settings_load_required_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("AM_PROVIDER_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("AM_PROVIDER_ROLE", "embedding")
    monkeypatch.setenv("AM_PROVIDER_MODEL_REVISION", REVISION)
    monkeypatch.setenv("AM_PROVIDER_MODEL_SHA256", DIGEST)
    monkeypatch.setenv("AM_PROVIDER_MODEL_SIZE", "123")
    assert ProviderSettings.from_environment().role is ProviderRole.EMBEDDING
    monkeypatch.setenv("AM_PROVIDER_PORT", "9999")
    with pytest.raises(ValidationError):
        ProviderSettings.from_environment()


def _configuration(role: ProviderRole = ProviderRole.EMBEDDING) -> LlamaProcessConfiguration:
    return LlamaProcessConfiguration(
        role=role,
        binary=Path("/app/llama-server"),
        artifact=ModelArtifactBinding(role, DIGEST, 123),
    )


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (ProviderRole.EMBEDDING, ("--embedding", "--pooling", "last")),
        (ProviderRole.RERANKING, ("--embedding", "--pooling", "rank", "--reranking")),
        (
            ProviderRole.EXTRACTION,
            ("--jinja", "--reasoning-format", "deepseek", "--n-predict", "32"),
        ),
    ],
)
def test_supervisor_builds_only_closed_role_arguments(
    role: ProviderRole,
    expected: tuple[str, ...],
) -> None:
    arguments = LlamaProcessSupervisor(_configuration(role))._arguments()
    for value in expected:
        assert value in arguments
    assert "--hf-repo" not in arguments
    assert "--model-url" not in arguments
    assert llama_process._child_environment() == {
        "HOME": _TEMP_DIR,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LD_LIBRARY_PATH": "/app",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": _TEMP_DIR,
    }
    with pytest.raises(ValueError, match="binary path"):
        LlamaProcessSupervisor(
            LlamaProcessConfiguration(role, Path("/other"), _configuration(role).artifact)
        )


class _Process:
    def __init__(self, *, returncode: int | None = None, output: bytes = b"") -> None:
        self.returncode = returncode
        self.output = output
        self.pid = 123
        self.wait_calls = 0

    async def communicate(self) -> tuple[bytes, None]:
        return self.output, None

    async def wait(self) -> int:
        self.wait_calls += 1
        self.returncode = 0
        return 0


def _as_subprocess(process: _Process) -> asyncio.subprocess.Process:
    return cast("asyncio.subprocess.Process", process)


@pytest.mark.asyncio
async def test_supervisor_start_verifies_artifact_revision_and_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = LlamaProcessSupervisor(_configuration())
    model_verified: list[ModelArtifactBinding] = []
    process = _Process()
    typed_process = _as_subprocess(process)

    def verify(binding: ModelArtifactBinding) -> str:
        model_verified.append(binding)
        return binding.sha256

    async def create(*_args: object, **_kwargs: object) -> asyncio.subprocess.Process:
        return typed_process

    monkeypatch.setattr(llama_process, "verify_model_artifact", verify)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(supervisor, "_verify_binary_revision", AsyncMock())
    monkeypatch.setattr(supervisor, "_wait_until_healthy", AsyncMock())
    await supervisor.start()
    assert model_verified == [_configuration().artifact]
    assert supervisor._process is typed_process
    with pytest.raises(RuntimeError, match="already supervised"):
        await supervisor.start()


@pytest.mark.asyncio
async def test_supervisor_start_failure_stops_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = LlamaProcessSupervisor(_configuration())
    process = _Process()
    typed_process = _as_subprocess(process)

    async def create(*_args: object, **_kwargs: object) -> asyncio.subprocess.Process:
        return typed_process

    def verify(_binding: ModelArtifactBinding) -> str:
        return DIGEST

    def ignore_kill(_pid: int, _signal: int) -> None:
        return None

    monkeypatch.setattr(llama_process, "verify_model_artifact", verify)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(supervisor, "_verify_binary_revision", AsyncMock())
    monkeypatch.setattr(
        supervisor,
        "_wait_until_healthy",
        AsyncMock(side_effect=RuntimeError("bad")),
    )
    monkeypatch.setattr(os, "killpg", ignore_kill)
    with pytest.raises(RuntimeError, match="bad"):
        await supervisor.start()
    assert supervisor._process is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("returncode", "output", "outcome"),
    [
        (0, b"version: 9982 (99f3dc322)\nbuild", "pass"),
        (1, b"version: 9982 (99f3dc322)", "fail"),
        (0, b"wrong", "fail"),
        (0, b"version: 9982 (99f3dc322)" + b"x" * 4096, "fail"),
    ],
)
async def test_binary_revision_probe_is_exact(
    returncode: int,
    output: bytes,
    outcome: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process(returncode=returncode, output=output)

    async def create(*_args: object, **_kwargs: object) -> asyncio.subprocess.Process:
        return _as_subprocess(process)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    supervisor = LlamaProcessSupervisor(_configuration())
    if outcome == "pass":
        await supervisor._verify_binary_revision()
    else:
        with pytest.raises(RuntimeError, match="revision"):
            await supervisor._verify_binary_revision()


class _HealthClient:
    responses: ClassVar[list[object]] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, _url: str) -> object:
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


@pytest.mark.asyncio
async def test_wait_until_healthy_retries_transport_then_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = LlamaProcessSupervisor(_configuration())
    supervisor._process = _as_subprocess(_Process())
    _HealthClient.responses = [
        httpx.ConnectError("not ready"),
        SimpleNamespace(status_code=503),
        SimpleNamespace(status_code=200),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", _HealthClient)
    monkeypatch.setattr(asyncio, "sleep", AsyncMock())
    await supervisor._wait_until_healthy()


@pytest.mark.asyncio
async def test_wait_until_healthy_rejects_absent_or_exited_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = LlamaProcessSupervisor(_configuration())
    with pytest.raises(RuntimeError, match="not started"):
        await supervisor._wait_until_healthy()
    supervisor._process = _as_subprocess(_Process(returncode=1))
    monkeypatch.setattr(httpx, "AsyncClient", _HealthClient)
    with pytest.raises(RuntimeError, match="exited"):
        await supervisor._wait_until_healthy()


@pytest.mark.asyncio
async def test_stop_is_idempotent_and_terminates_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = LlamaProcessSupervisor(_configuration())
    await supervisor.stop()
    supervisor._process = _as_subprocess(_Process(returncode=0))
    await supervisor.stop()
    process = _Process()
    supervisor._process = _as_subprocess(process)
    signals: list[tuple[int, int]] = []

    def record_signal(pid: int, sent: int) -> None:
        signals.append((pid, sent))

    monkeypatch.setattr(os, "killpg", record_signal)
    await supervisor.stop()
    assert signals == [(123, signal.SIGTERM)]
    assert process.wait_calls == 1


@pytest.mark.asyncio
async def test_stop_handles_missing_process_group(monkeypatch: pytest.MonkeyPatch) -> None:
    supervisor = LlamaProcessSupervisor(_configuration())
    supervisor._process = _as_subprocess(_Process())

    def missing(_pid: int, _signal: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(os, "killpg", missing)
    await supervisor.stop()
    assert supervisor._process is None


@pytest.mark.asyncio
async def test_production_composition_lifespan_starts_and_stops_exact_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = AsyncMock()
    stop = AsyncMock()
    health = AsyncMock()
    close = AsyncMock()
    monkeypatch.setattr(LlamaProcessSupervisor, "start", start)
    monkeypatch.setattr(LlamaProcessSupervisor, "stop", stop)
    monkeypatch.setattr(LlamaCppBackend, "health", health)
    monkeypatch.setattr(httpx.AsyncClient, "aclose", close)
    app = composition.create_provider_app(_settings())
    async with app.router.lifespan_context(app):
        assert any(getattr(route, "path", None) == "/v1/embed" for route in app.routes)
    start.assert_awaited_once()
    health.assert_awaited_once()
    close.assert_awaited_once()
    stop.assert_awaited_once()


def test_entrypoint_dispatches_only_closed_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings()
    monkeypatch.setattr(ProviderSettings, "from_environment", lambda: settings)
    serve: list[ProviderSettings] = []
    verify: list[ModelArtifactBinding] = []

    def record_serve(value: ProviderSettings) -> None:
        serve.append(value)

    def record_verify(binding: ModelArtifactBinding) -> str:
        verify.append(binding)
        return hashlib.sha256(b"x").hexdigest()

    monkeypatch.setattr(entrypoints, "_serve", record_serve)
    monkeypatch.setattr(
        entrypoints,
        "verify_model_artifact",
        record_verify,
    )
    monkeypatch.setattr(sys, "argv", ["agentmemory-provider", "serve"])
    entrypoints.main()
    monkeypatch.setattr(sys, "argv", ["agentmemory-provider", "verify-model"])
    entrypoints.main()
    assert serve == [settings]
    assert verify == [settings.artifact_binding]


def test_serve_uses_hardened_uvicorn_options(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def create_app(_settings: ProviderSettings) -> str:
        return "app"

    def record_run(*args: object, **kwargs: object) -> None:
        observed.append((args, kwargs))

    monkeypatch.setattr(entrypoints, "create_provider_app", create_app)
    monkeypatch.setattr(uvicorn, "run", record_run)
    entrypoints._serve(_settings())
    assert observed[0][0] == ("app",)
    assert observed[0][1]["proxy_headers"] is False
    assert observed[0][1]["access_log"] is False
