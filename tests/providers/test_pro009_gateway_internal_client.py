"""PRO-009 Core-to-gateway authenticated client tests."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import httpx
import pytest

from agentmemory.providers.adapters.gateway_internal_client import (
    ProviderGatewayInternalHttpClient,
)
from agentmemory.providers.domain.containment import ExecuteProviderEgress
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
)

if TYPE_CHECKING:
    from pathlib import Path

_CAPABILITY = b"c" * 32


def capability_file(tmp_path: Path) -> Path:
    path = tmp_path / "gateway-capability"
    path.write_bytes(_CAPABILITY)
    path.chmod(0o600)
    return path


def command() -> ExecuteProviderEgress:
    return ExecuteProviderEgress(
        b"c2lnbmVk.cGVybWl0",
        "/v1/embeddings",
        bytearray(b'{"input":["safe"]}'),
    )


@pytest.mark.asyncio
async def test_client_sends_only_fixed_authenticated_strict_internal_envelope(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            content=(
                b'{"body_base64":"c2FmZS1yZXN1bHQ=",'
                b'"retry_after_microseconds":123456,'
                b'"schema_version":1,"status_code":201}'
            ),
            headers={"Content-Type": "application/json"},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(respond),
        follow_redirects=False,
        trust_env=False,
    ) as http:
        response = await ProviderGatewayInternalHttpClient(
            http,
            "http://provider-gateway:8080",
            capability_file(tmp_path),
        ).execute(command())

    assert response.status_code == 201
    assert response.body == b"safe-result"
    assert response.retry_after_microseconds == 123_456
    assert len(requests) == 1
    assert requests[0].url == "http://provider-gateway:8080/v1/provider-operations/execute"
    assert requests[0].headers["x-agentmemory-capability"] == _CAPABILITY.hex()
    document = requests[0].content
    assert b"safe" not in document
    assert base64.b64encode(b'{"input":["safe"]}') in document


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "error"),
    [
        (403, ProviderContainmentDeniedError),
        (400, ProviderContainmentDependencyError),
        (503, ProviderContainmentDependencyError),
    ],
)
async def test_client_maps_gateway_failures_without_returning_remote_details(
    tmp_path: Path,
    status: int,
    error: type[Exception],
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, content=b'{"secret":"remote-detail"}')
        ),
        follow_redirects=False,
        trust_env=False,
    ) as http:
        with pytest.raises(error) as caught:
            await ProviderGatewayInternalHttpClient(
                http,
                "http://provider-gateway:8080",
                capability_file(tmp_path),
            ).execute(command())
    assert "remote-detail" not in str(caught.value)


def test_client_rejects_any_ambient_or_external_gateway_url(tmp_path: Path) -> None:
    for url in (
        "https://provider-gateway:8080",
        "http://provider-gateway:8081",
        "http://user@provider-gateway:8080",
        "http://evil.example:8080",
        "http://provider-gateway:8080/path",
    ):
        with pytest.raises(ValueError, match="URL"):
            ProviderGatewayInternalHttpClient(
                httpx.AsyncClient(),
                url,
                capability_file(tmp_path),
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "document",
    [
        {
            "body_base64": 7,
            "retry_after_microseconds": None,
            "schema_version": 1,
            "status_code": 200,
        },
        {
            "body_base64": "eA==",
            "retry_after_microseconds": None,
            "schema_version": 1,
            "status_code": True,
        },
        {
            "body_base64": "eA==",
            "retry_after_microseconds": -1,
            "schema_version": 1,
            "status_code": 200,
        },
        {
            "body_base64": "eA==",
            "retry_after_microseconds": None,
            "schema_version": 2,
            "status_code": 200,
        },
        {
            "body_base64": "eA==",
            "retry_after_microseconds": None,
            "schema_version": 1,
            "status_code": 99,
        },
    ],
)
async def test_client_rejects_malformed_or_out_of_range_success_envelopes(
    tmp_path: Path,
    document: dict[str, object],
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=document)),
        follow_redirects=False,
        trust_env=False,
    ) as http:
        with pytest.raises(ProviderContainmentDependencyError):
            await ProviderGatewayInternalHttpClient(
                http,
                "http://provider-gateway:8080",
                capability_file(tmp_path),
            ).execute(command())


@pytest.mark.asyncio
async def test_client_accepts_absent_retry_delay(tmp_path: Path) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "body_base64": "eA==",
                    "retry_after_microseconds": None,
                    "schema_version": 1,
                    "status_code": 200,
                },
            )
        ),
        follow_redirects=False,
        trust_env=False,
    ) as http:
        response = await ProviderGatewayInternalHttpClient(
            http,
            "http://provider-gateway:8080",
            capability_file(tmp_path),
        ).execute(command())

    assert response.retry_after_microseconds is None
