"""Closed process entrypoints for the isolated provider-egress gateway."""

from __future__ import annotations

import argparse
import asyncio

import httpx
import uvicorn

from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.infrastructure.gateway_composition import create_gateway_app
from agentmemory.providers.infrastructure.gateway_configuration import ProviderGatewaySettings

_HEALTHY_STATUS = 204


def main() -> None:
    """Dispatch the exact gateway serve or local healthcheck command."""
    parser = argparse.ArgumentParser(prog="agentmemory-provider-gateway", allow_abbrev=False)
    parser.add_argument("command", choices=("serve", "healthcheck"))
    arguments = parser.parse_args()
    settings = ProviderGatewaySettings.from_environment()
    if arguments.command == "serve":
        _serve(settings)
    else:
        asyncio.run(_healthcheck(settings))


def _serve(settings: ProviderGatewaySettings) -> None:
    uvicorn.run(
        create_gateway_app(settings),
        host=settings.listen_host,
        port=settings.port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=30,
        log_config=None,
    )


async def _healthcheck(settings: ProviderGatewaySettings) -> None:
    capability = read_capability(settings.client_capability_file)
    try:
        async with httpx.AsyncClient(
            timeout=3,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = await client.post(
                "http://127.0.0.1:8080/v1/health",
                content=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Host": "provider-gateway:8080",
                    "X-AgentMemory-Capability": capability.hex(),
                },
            )
    finally:
        zero(capability)
    if response.status_code != _HEALTHY_STATUS:
        raise SystemExit(1)
