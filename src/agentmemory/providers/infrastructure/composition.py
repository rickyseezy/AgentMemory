"""Production composition root for one local-provider process."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from agentmemory.providers.adapters.llama_cpp import LlamaCppBackend
from agentmemory.providers.adapters.llama_process import (
    LlamaProcessConfiguration,
    LlamaProcessSupervisor,
)
from agentmemory.providers.application.service import ProviderService
from agentmemory.providers.infrastructure.http_api import HttpBoundary, create_app

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastapi import FastAPI

    from agentmemory.providers.infrastructure.configuration import ProviderSettings


def create_provider_app(settings: ProviderSettings) -> FastAPI:
    """Compose only the verified llama.cpp adapter; no test backend is reachable."""
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(7, connect=1),
        limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
        follow_redirects=False,
        trust_env=False,
    )
    backend = LlamaCppBackend(client)
    service = ProviderService(settings.identity, backend)
    supervisor = LlamaProcessSupervisor(
        LlamaProcessConfiguration(
            role=settings.role,
            binary=Path(settings.llama_binary),
            artifact=settings.artifact_binding,
        )
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        await supervisor.start()
        try:
            await backend.health()
            yield
        finally:
            await client.aclose()
            await supervisor.stop()

    return create_app(
        service,
        HttpBoundary(
            internal_host=settings.internal_host,
            capability_file=settings.capability_file,
        ),
        lifespan,
    )
