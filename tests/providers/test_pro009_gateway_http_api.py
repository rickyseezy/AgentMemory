"""PRO-009 authenticated internal gateway protocol tests."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest

from agentmemory.providers.adapters.gateway_http_api import create_provider_gateway_app
from agentmemory.providers.domain.containment import (
    ExecuteProviderEgress,
    ProviderEgressHttpResponse,
)
from agentmemory.providers.domain.errors import ProviderContainmentDeniedError

if TYPE_CHECKING:
    from pathlib import Path

_CAPABILITY = b"c" * 32
_ERR_DENIED = "denied"


@dataclass
class Handler:
    commands: list[ExecuteProviderEgress] = field(default_factory=list[ExecuteProviderEgress])
    denied: bool = False
    oversized: bool = False

    async def execute(self, command: ExecuteProviderEgress) -> ProviderEgressHttpResponse:
        self.commands.append(command)
        if self.denied:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        return ProviderEgressHttpResponse(
            201,
            (("content-type", "application/json"), ("set-cookie", "never-return")),
            b"x" * (8 * 1024 * 1024 + 1) if self.oversized else b'{"result":"vector"}',
            123_456,
        )


def capability_file(tmp_path: Path) -> Path:
    path = tmp_path / "gateway-capability"
    path.write_bytes(_CAPABILITY)
    path.chmod(0o600)
    return path


def payload() -> bytes:
    return (
        b'{"body_base64":"c2FmZQ==","path":"/v1/embeddings",'
        b'"permit_token":"c2lnbmVk.cGVybWl0","schema_version":1}'
    )


@pytest.mark.asyncio
async def test_internal_api_authenticates_strict_envelope_and_omits_upstream_headers(
    tmp_path: Path,
) -> None:
    handler = Handler()
    app = create_provider_gateway_app(handler, capability_file(tmp_path))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://provider-gateway:8080",
    ) as client:
        response = await client.post(
            "/v1/provider-operations/execute",
            content=payload(),
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "body_base64": base64.b64encode(b'{"result":"vector"}').decode(),
        "retry_after_microseconds": 123_456,
        "schema_version": 1,
        "status_code": 201,
    }
    assert response.headers["cache-control"] == "no-store"
    assert "never-return" not in response.text
    assert len(handler.commands) == 1
    assert handler.commands[0].path == "/v1/embeddings"
    assert handler.commands[0].body == bytearray(b"safe")


@pytest.mark.asyncio
async def test_authentication_or_host_failure_never_parses_or_dispatches_body(
    tmp_path: Path,
) -> None:
    handler = Handler()
    app = create_provider_gateway_app(handler, capability_file(tmp_path))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://provider-gateway:8080",
    ) as client:
        for headers in (
            {"Content-Type": "application/json"},
            {
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": (b"x" * 32).hex(),
            },
            {
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
                "Host": "evil.example",
            },
        ):
            response = await client.post(
                "/v1/provider-operations/execute",
                content=b'{"secret":"must-not-parse"}',
                headers=headers,
            )
            assert response.status_code in {400, 401, 403}
    assert handler.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":1,"permit_token":"a.b","path":"/x","body_base64":"!!!"}',
        b'{"schema_version":1,"permit_token":"a.b","path":"/x","body_base64":"eA==","x":1}',
        b"[]",
    ],
)
async def test_ambiguous_or_unknown_envelope_is_rejected(
    tmp_path: Path,
    raw: bytes,
) -> None:
    handler = Handler()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=create_provider_gateway_app(handler, capability_file(tmp_path))
        ),
        base_url="http://provider-gateway:8080",
    ) as client:
        response = await client.post(
            "/v1/provider-operations/execute",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )
    assert response.status_code == 400
    assert handler.commands == []


@pytest.mark.asyncio
async def test_application_denial_maps_to_content_free_forbidden_response(tmp_path: Path) -> None:
    handler = Handler(denied=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=create_provider_gateway_app(handler, capability_file(tmp_path))
        ),
        base_url="http://provider-gateway:8080",
    ) as client:
        response = await client.post(
            "/v1/provider-operations/execute",
            content=payload(),
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )
    assert response.status_code == 403
    assert response.json() == {"detail": "provider gateway request denied"}


@pytest.mark.asyncio
async def test_authenticated_health_probe_is_local_and_never_dispatches_provider_egress(
    tmp_path: Path,
) -> None:
    handler = Handler()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=create_provider_gateway_app(handler, capability_file(tmp_path))
        ),
        base_url="http://provider-gateway:8080",
    ) as client:
        response = await client.post(
            "/v1/health",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )

    assert response.status_code == 204
    assert response.content == b""
    assert handler.commands == []


@pytest.mark.asyncio
async def test_health_probe_rejects_authentication_failure_and_nonempty_contract(
    tmp_path: Path,
) -> None:
    handler = Handler()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=create_provider_gateway_app(handler, capability_file(tmp_path))
        ),
        base_url="http://provider-gateway:8080",
    ) as client:
        unauthenticated = await client.post(
            "/v1/health",
            content=b"{}",
            headers={"Content-Type": "application/json"},
        )
        nonempty = await client.post(
            "/v1/health",
            content=b'{"probe":true}',
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )

    assert unauthenticated.status_code == 401
    assert nonempty.status_code == 400
    assert handler.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b'{"body_base64":"eA==","path":7,"permit_token":"a.b","schema_version":1}',
        b'{"body_base64":"eA==","path":"/x","permit_token":"invalid","schema_version":1}',
    ],
)
async def test_gateway_rejects_wrong_typed_or_invalid_tokens(
    tmp_path: Path,
    raw: bytes,
) -> None:
    handler = Handler()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=create_provider_gateway_app(handler, capability_file(tmp_path))
        ),
        base_url="http://provider-gateway:8080",
    ) as client:
        response = await client.post(
            "/v1/provider-operations/execute",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )

    assert response.status_code == 400
    assert handler.commands == []


@pytest.mark.asyncio
async def test_gateway_rejects_malformed_content_length_and_oversized_response(
    tmp_path: Path,
) -> None:
    handler = Handler(oversized=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(
            app=create_provider_gateway_app(handler, capability_file(tmp_path))
        ),
        base_url="http://provider-gateway:8080",
    ) as client:
        malformed = await client.post(
            "/v1/provider-operations/execute",
            content=payload(),
            headers={
                "Content-Length": "not-a-number",
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )
        oversized = await client.post(
            "/v1/provider-operations/execute",
            content=payload(),
            headers={
                "Content-Type": "application/json",
                "X-AgentMemory-Capability": _CAPABILITY.hex(),
            },
        )

    assert malformed.status_code == 400
    assert oversized.status_code == 502
