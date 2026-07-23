"""PRO-001 provider gateway client boundary and adversarial envelope tests."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
import pytest

from agentmemory.providers.adapters.gateway_http import ProviderGatewayHttpTransport
from agentmemory.providers.adapters.strict_json import canonical_bytes, loads, require_object
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileDependencyError,
)
from agentmemory.providers.domain.profile_ports import ProviderGatewayRequest
from tests.core.support import digest, write_secret

CAPABILITY = b"c" * 32
FINGERPRINT = digest("pro001-gateway-revision").value
ENDPOINT_FINGERPRINT = digest("pro001-gateway-endpoint").value
REFERENCE_URI = "secret://providers/openai-production"

if TYPE_CHECKING:
    from typing import Any


def _request(**changes: object) -> ProviderGatewayRequest:
    value = ProviderGatewayRequest(
        adapter_id="openai",
        endpoint_policy_ref="policy://providers/openai-production",
        secret_ref=REFERENCE_URI,
        method="POST",
        path="/v1/embeddings",
        body=canonical_bytes({"model": "test-model", "input": ["canary"]}),
        timeout_milliseconds=1000,
        max_response_bytes=4096,
    )
    return replace(value, **cast("Any", changes))


def _envelope(**changes: object) -> bytes:
    value: dict[str, object] = {
        "body_base64": base64.b64encode(b'{"ok":true}').decode(),
        "status_code": 200,
        "model_revision": "revision-2026-07",
        "revision_fingerprint": FINGERPRINT,
        "endpoint_fingerprint": ENDPOINT_FINGERPRINT,
        "cancellation_verified": True,
    }
    value.update(changes)
    return canonical_bytes(value)


@pytest.mark.parametrize(
    "base_url",
    [
        "https://provider-gateway:8080",
        "http://localhost:8080",
        "http://provider-gateway:8081",
        "http://user@provider-gateway:8080",
        "http://provider-gateway:8080/path",
        "http://provider-gateway:8080?query=true",
    ],
)
def test_gateway_transport_accepts_only_the_fixed_internal_service(base_url: str) -> None:
    with pytest.raises(ValueError, match="gateway URL"):
        ProviderGatewayHttpTransport(httpx.AsyncClient(), base_url, Path("capability"))


@pytest.mark.asyncio
@pytest.mark.security
async def test_gateway_request_uses_protected_capability_and_reference_only_envelope(
    tmp_path: Path,
) -> None:
    capability = tmp_path / "gateway.capability"
    write_secret(capability, CAPABILITY)
    observations: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observations.append(request)
        return httpx.Response(200, content=_envelope())

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        transport = ProviderGatewayHttpTransport(
            client,
            "http://provider-gateway:8080",
            capability,
        )
        response = await transport.execute(_request())
    assert response.status_code == 200
    assert response.body == b'{"ok":true}'
    assert response.revision_fingerprint == FINGERPRINT
    assert response.endpoint_fingerprint == ENDPOINT_FINGERPRINT
    assert len(observations) == 1
    observation = observations[0]
    assert str(observation.url) == ("http://provider-gateway:8080/v1/provider-operations/probe")
    assert observation.headers["X-AgentMemory-Capability"] == CAPABILITY.hex()
    outbound = require_object(loads(observation.content))
    assert outbound["endpoint_policy_ref"] == "policy://providers/openai-production"
    assert outbound["secret_ref"] == REFERENCE_URI
    assert "credential_value" not in outbound


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"path": "v1/embeddings"},
        {"path": "/v1//embeddings"},
        {"path": "/v1/../secrets"},
        {"path": "/v1\\secrets"},
        {"path": "/v1/embeddings\x00"},
        {"timeout_milliseconds": 99},
        {"timeout_milliseconds": 300_001},
        {"max_response_bytes": 0},
        {"max_response_bytes": 8 * 1024 * 1024 + 1},
        {"body": b"x" * (8 * 1024 * 1024 + 1)},
    ],
)
@pytest.mark.asyncio
async def test_invalid_gateway_request_is_rejected_before_socket_acquisition(
    tmp_path: Path,
    changes: dict[str, object],
) -> None:
    capability = tmp_path / "gateway.capability"
    write_secret(capability, CAPABILITY)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        del request
        calls += 1
        return httpx.Response(200, content=_envelope())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = ProviderGatewayHttpTransport(
            client,
            "http://provider-gateway:8080",
            capability,
        )
        with pytest.raises(ProviderAdapterError) as captured:
            await transport.execute(_request(**changes))
    assert captured.value.code is ProviderErrorCode.INVALID_CONFIGURATION
    assert calls == 0


@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b'{"body_base64":"e30=","status_code":200,"status_code":201}',
        _envelope(body_base64="not base64"),
        _envelope(status_code=True),
        _envelope(status_code=99),
        _envelope(model_revision="bad revision"),
        _envelope(revision_fingerprint="bad"),
        _envelope(endpoint_fingerprint="bad"),
        _envelope(cancellation_verified=1),
    ],
)
@pytest.mark.asyncio
async def test_gateway_response_envelope_is_strict_bounded_and_content_free_on_error(
    tmp_path: Path,
    body: bytes,
) -> None:
    capability = tmp_path / "gateway.capability"
    write_secret(capability, CAPABILITY)

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        transport = ProviderGatewayHttpTransport(
            client,
            "http://provider-gateway:8080",
            capability,
        )
        with pytest.raises(ProviderProfileDependencyError) as captured:
            await transport.execute(_request())
    assert "secret://" not in str(captured.value)
    assert body.decode(errors="ignore") not in str(captured.value)


@pytest.mark.asyncio
async def test_gateway_privacy_denial_and_missing_capability_are_typed(tmp_path: Path) -> None:
    capability = tmp_path / "gateway.capability"
    write_secret(capability, CAPABILITY)

    def denied(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(403, content=b"sensitive upstream denial")

    async with httpx.AsyncClient(transport=httpx.MockTransport(denied)) as client:
        transport = ProviderGatewayHttpTransport(
            client,
            "http://provider-gateway:8080",
            capability,
        )
        with pytest.raises(ProviderAdapterError) as captured:
            await transport.execute(_request())
        assert captured.value.code is ProviderErrorCode.PRIVACY_DENIAL

        capability.unlink()
        with pytest.raises(ProviderProfileDependencyError, match="gateway is unavailable"):
            await transport.execute(_request())
