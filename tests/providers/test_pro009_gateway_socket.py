"""PRO-009 signed Core-to-gateway socket adapter tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters.gateway_socket import (
    SignedInternalProviderSocketGateway,
)
from agentmemory.providers.adapters.permit_codec import HmacProviderPermitCodec
from agentmemory.providers.domain.containment import (
    ExecuteProviderEgress,
    PreparedProviderWireRequest,
    ProviderEgressHttpResponse,
)
from agentmemory.providers.domain.errors import ProviderContainmentDeniedError
from agentmemory.providers.domain.idempotency import ProviderOperationOutcome
from tests.core.support import digest
from tests.providers.test_pro007_resilience_domain import endpoint
from tests.providers.test_pro009_containment_application import operation, permit

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.providers.domain.idempotency import ProviderOperationRequest
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation


@dataclass
class Wire:
    prepared: PreparedProviderWireRequest
    parsed: bool = False

    def prepare(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> PreparedProviderWireRequest:
        del endpoint, operation, payloads, downstream_idempotency_key
        return self.prepared

    def parse(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        response: ProviderEgressHttpResponse,
    ) -> ProviderOperationOutcome:
        del endpoint, operation, response
        self.parsed = True
        return ProviderOperationOutcome(
            digest("result").value,
            f"cas://sha256/{digest('result').value}",
            2,
        )


@dataclass
class Client:
    commands: list[ExecuteProviderEgress]

    async def execute(self, command: ExecuteProviderEgress) -> ProviderEgressHttpResponse:
        self.commands.append(command)
        return ProviderEgressHttpResponse(200, (), b"result")


@pytest.mark.asyncio
async def test_socket_gateway_rebuilds_exact_wire_request_and_signs_permit() -> None:
    body = bytearray(b'{"input":["safe"]}')
    wire = Wire(PreparedProviderWireRequest("/v1/embeddings", body))
    client = Client([])
    codec = HmacProviderPermitCodec(b"k" * 32)
    value = replace(permit(), wire_request_digest=hashlib.sha256(body).hexdigest())

    outcome = await SignedInternalProviderSocketGateway(codec, wire, client).execute(
        value,
        endpoint(),
        operation(),
        (bytearray(b"payload"),),
        operation().downstream_idempotency_key,
    )

    assert outcome.result_sha256 == digest("result").value
    assert wire.parsed is True
    assert len(client.commands) == 1
    assert codec.decode(client.commands[0].permit_token) == value
    assert body == bytearray(len(b'{"input":["safe"]}'))


@pytest.mark.asyncio
async def test_socket_gateway_denies_wire_drift_before_internal_gateway_call() -> None:
    body = bytearray(b"changed")
    wire = Wire(PreparedProviderWireRequest("/v1/embeddings", body))
    client = Client([])
    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        await SignedInternalProviderSocketGateway(
            HmacProviderPermitCodec(b"k" * 32),
            wire,
            client,
        ).execute(
            permit(),
            endpoint(),
            operation(),
            (bytearray(b"payload"),),
            operation().downstream_idempotency_key,
        )
    assert client.commands == []
    assert wire.parsed is False
    assert body == bytearray(len(b"changed"))
