"""PRO-009 closed provider-gateway process entrypoint tests."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import sys
from typing import TYPE_CHECKING, Self

import httpx
import pytest

import agentmemory.providers.infrastructure.gateway_entrypoints as gateway_entrypoints  # noqa: PLR0402
from tests.providers.test_pro009_gateway_composition import settings

if TYPE_CHECKING:
    from pathlib import Path


def test_gateway_main_dispatches_only_serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = settings(tmp_path)
    served: list[object] = []
    monkeypatch.setattr(sys, "argv", ["agentmemory-provider-gateway", "serve"])
    monkeypatch.setattr(
        (
            "agentmemory.providers.infrastructure.gateway_entrypoints."
            "ProviderGatewaySettings.from_environment"
        ),
        lambda: configured,
    )
    monkeypatch.setattr(gateway_entrypoints, "_serve", served.append)

    gateway_entrypoints.main()

    assert served == [configured]


def test_gateway_main_dispatches_only_healthcheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = settings(tmp_path)
    awaited: list[object] = []
    monkeypatch.setattr(sys, "argv", ["agentmemory-provider-gateway", "healthcheck"])
    monkeypatch.setattr(
        (
            "agentmemory.providers.infrastructure.gateway_entrypoints."
            "ProviderGatewaySettings.from_environment"
        ),
        lambda: configured,
    )

    def run(coroutine: object) -> None:
        awaited.append(coroutine)
        coroutine.close()  # type: ignore[attr-defined]

    monkeypatch.setattr(
        "agentmemory.providers.infrastructure.gateway_entrypoints.asyncio.run",
        run,
    )

    gateway_entrypoints.main()

    assert len(awaited) == 1


@pytest.mark.asyncio
async def test_gateway_healthcheck_fails_closed_on_nonhealthy_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client:
        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def post(self, *_args: object, **_kwargs: object) -> httpx.Response:
            return httpx.Response(503)

    def client_factory(**_kwargs: object) -> Client:
        return Client()

    monkeypatch.setattr(
        "agentmemory.providers.infrastructure.gateway_entrypoints.httpx.AsyncClient",
        client_factory,
    )

    with pytest.raises(SystemExit) as caught:
        await gateway_entrypoints._healthcheck(settings(tmp_path))

    assert caught.value.code == 1
