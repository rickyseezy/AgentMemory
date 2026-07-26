"""PRO-009 provisional permit containment for remote profile probes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.providers.adapters.contained_profile_probe import (
    ContainedProviderProfileProbeTransport,
)
from agentmemory.providers.domain.containment import ProviderEgressHttpResponse
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderContainmentDeniedError,
    ProviderErrorCode,
)
from agentmemory.providers.domain.profile_ports import ProviderGatewayRequest
from tests.core.support import digest
from tests.providers.test_pro009_containment_application import permit

if TYPE_CHECKING:
    from typing import Any

    from agentmemory.providers.domain.containment import (
        ExecuteProviderEgress,
        ProviderEgressPermit,
    )

_BODY = b'{"input":["public fixed canary"],"model":"model-v1"}'
_CONFIGURATION = digest("draft-profile-configuration").value
_ERR_DENIED = "provider egress is denied"


def probe_request(**changes: object) -> ProviderGatewayRequest:
    value = ProviderGatewayRequest(
        operation_id="profile-probe:018f0000-0000-7000-8000-000000000901:1:code_document",
        brain_id="018f0000-0000-7000-8000-000000000001",
        profile_id="018f0000-0000-7000-8000-000000000901",
        profile_version=1,
        configuration_digest=_CONFIGURATION,
        adapter_id="openai",
        model_id="model-v1",
        operation_type="embedding",
        purpose="code_document",
        endpoint_policy_ref="policy://providers/openai-production",
        secret_ref="secret://providers/openai-production",  # noqa: S106 -- Opaque reference.
        method="POST",
        path="/v1/embeddings",
        body=_BODY,
        timeout_milliseconds=5_000,
        max_response_bytes=4_096,
    )
    return replace(value, **cast("Any", changes))


def provisional_permit() -> ProviderEgressPermit:
    return replace(
        permit(),
        operation_id=probe_request().operation_id,
        profile_version=1,
        profile_attestation_id=_CONFIGURATION,
        purpose="code_document",
        wire_request_digest=hashlib.sha256(_BODY).hexdigest(),
        issued_at_microseconds=1_000,
        expires_at_microseconds=10_000,
    )


@dataclass
class Authority:
    events: list[str]
    value: ProviderEgressPermit
    denied: bool = False

    async def authorize_probe(
        self,
        request: ProviderGatewayRequest,
        now_microseconds: int,
    ) -> ProviderEgressPermit:
        assert request == probe_request()
        assert now_microseconds == 2_000
        self.events.append("authorize")
        if self.denied:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        return self.value


@dataclass
class Codec:
    events: list[str]

    def encode(self, permit: ProviderEgressPermit) -> bytes:
        assert permit == provisional_permit()
        self.events.append("sign")
        return b"signed.provisional-permit"

    def decode(self, token: bytes) -> ProviderEgressPermit:
        raise AssertionError(token)


@dataclass
class Gateway:
    events: list[str]
    commands: list[ExecuteProviderEgress]

    async def execute(
        self,
        command: ExecuteProviderEgress,
    ) -> ProviderEgressHttpResponse:
        self.events.append("gateway")
        self.commands.append(command)
        return ProviderEgressHttpResponse(
            200,
            (),
            b'{"data":[],"model":"model-v1"}',
            123_456,
        )


@pytest.mark.asyncio
async def test_probe_authorizes_immediately_before_signing_and_gateway_invocation() -> None:
    events: list[str] = []
    commands: list[ExecuteProviderEgress] = []
    result = await ContainedProviderProfileProbeTransport(
        Authority(events, provisional_permit()),
        Codec(events),
        Gateway(events, commands),
        now_microseconds=lambda: 2_000,
    ).execute(probe_request())

    assert events == ["authorize", "sign", "gateway"]
    assert len(commands) == 1
    command = commands[0]
    assert command.path == "/v1/embeddings"
    assert bytes(command.body) == _BODY
    assert command.permit_token == b"signed.provisional-permit"
    assert result.status_code == 200
    assert result.model_revision == "model-v1"
    assert result.endpoint_fingerprint == provisional_permit().destination.fingerprint
    assert result.cancellation_verified
    assert result.retry_after_microseconds == 123_456


@pytest.mark.asyncio
async def test_denied_probe_never_signs_or_invokes_the_gateway() -> None:
    events: list[str] = []
    gateway = Gateway(events, [])
    with pytest.raises(ProviderAdapterError) as captured:
        await ContainedProviderProfileProbeTransport(
            Authority(events, provisional_permit(), denied=True),
            Codec(events),
            gateway,
            now_microseconds=lambda: 2_000,
        ).execute(probe_request())

    assert captured.value.code is ProviderErrorCode.PRIVACY_DENIAL
    assert events == ["authorize"]
    assert gateway.commands == []


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"path": "v1/embeddings"},
        {"path": "/v1/../credential"},
        {"path": "/v1/embeddings?redirect=true"},
        {"body": b""},
        {"timeout_milliseconds": 99},
        {"max_response_bytes": 0},
    ],
)
@pytest.mark.asyncio
async def test_invalid_probe_is_rejected_before_authorization(
    changes: dict[str, object],
) -> None:
    events: list[str] = []
    with pytest.raises(ProviderAdapterError) as captured:
        await ContainedProviderProfileProbeTransport(
            Authority(events, provisional_permit()),
            Codec(events),
            Gateway(events, []),
            now_microseconds=lambda: 2_000,
        ).execute(probe_request(**changes))

    assert captured.value.code is ProviderErrorCode.INVALID_CONFIGURATION
    assert events == []


@pytest.mark.asyncio
async def test_authority_cannot_substitute_any_provisional_permit_coordinate() -> None:
    events: list[str] = []
    substituted = replace(provisional_permit(), purpose="retrieval_query")
    with pytest.raises(ProviderAdapterError) as captured:
        await ContainedProviderProfileProbeTransport(
            Authority(events, substituted),
            Codec(events),
            Gateway(events, []),
            now_microseconds=lambda: 2_000,
        ).execute(probe_request())

    assert captured.value.code is ProviderErrorCode.PRIVACY_DENIAL
    assert events == ["authorize"]
