"""Closed command surface for the provider container."""

from __future__ import annotations

import argparse
import asyncio

import httpx
import uvicorn

from agentmemory.providers.adapters.model_artifact import verify_model_artifact
from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.infrastructure.composition import create_provider_app
from agentmemory.providers.infrastructure.configuration import ProviderSettings

_HEALTHY_STATUS = 200


def main() -> None:
    """Dispatch one exact provider container command."""
    parser = argparse.ArgumentParser(prog="agentmemory-provider", allow_abbrev=False)
    parser.add_argument("command", choices=("serve", "healthcheck", "verify-model"))
    arguments = parser.parse_args()
    settings = ProviderSettings.from_environment()
    if arguments.command == "serve":
        _serve(settings)
    elif arguments.command == "healthcheck":
        asyncio.run(_healthcheck(settings))
    else:
        verify_model_artifact(settings.artifact_binding)


def _serve(settings: ProviderSettings) -> None:
    uvicorn.run(
        create_provider_app(settings),
        host=settings.listen_host,
        port=settings.port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=30,
        log_config=None,
    )


async def _healthcheck(settings: ProviderSettings) -> None:
    capability = read_capability(settings.capability_file)
    try:
        identity = settings.identity
        async with httpx.AsyncClient(
            timeout=3,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                "http://127.0.0.1:8080/v1/probe",
                headers={
                    "Host": "127.0.0.1:8080",
                    "X-AgentMemory-Capability": capability.hex(),
                },
                json={
                    "protocol_version": "1.0",
                    "role": identity.role.value,
                    "model_id": identity.model_id,
                    "model_revision": identity.model_revision,
                    "test_cancellation": False,
                },
            )
    finally:
        zero(capability)
    if response.status_code != _HEALTHY_STATUS:
        raise SystemExit(1)
