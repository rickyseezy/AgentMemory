"""PRO-009 current-context egress request factory tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.application.gateway import ResolvedProviderEgressRequestFactory
from agentmemory.providers.domain.containment import (
    EgressDestination,
    PreparedProviderWireRequest,
    ProviderEgressOperationContext,
)
from tests.providers.test_pro007_resilience_domain import endpoint
from tests.providers.test_pro009_containment_application import operation

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.providers.domain.containment import ProviderEgressHttpResponse
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationOutcome,
        ProviderOperationRequest,
    )
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation


@dataclass
class Contexts:
    value: ProviderEgressOperationContext

    async def resolve(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
    ) -> ProviderEgressOperationContext:
        del endpoint, operation
        return self.value


@dataclass
class Wire:
    body: bytearray
    key: str | None = None

    def prepare(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> PreparedProviderWireRequest:
        del endpoint, operation, payloads
        self.key = downstream_idempotency_key
        return PreparedProviderWireRequest("/v1/embeddings", self.body)

    def parse(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        response: ProviderEgressHttpResponse,
    ) -> ProviderOperationOutcome:
        raise AssertionError((endpoint, operation, response))


def context() -> ProviderEgressOperationContext:
    return ProviderEgressOperationContext(
        project_id=None,
        destination=EgressDestination(
            scheme="https",
            hostname="api.openai.com",
            port=443,
            region="US",
            path_prefix="/v1/embeddings",
        ),
        private_block=False,
        secret_bearing=False,
        retention_days=0,
        training_allowed=False,
        policy_version=1,
        security_epoch=7,
        quota_requests_per_minute=100,
        quota_tokens_per_minute=10_000,
        budget_monthly_micros=1_000_000,
        maximum_response_bytes=4096,
        timeout_milliseconds=5000,
        token_count=2,
        estimated_cost_micros=10,
    )


@pytest.mark.asyncio
async def test_factory_binds_current_context_endpoint_operation_and_exact_wire_body() -> None:
    body = bytearray(b'{"input":["payload"]}')
    wire = Wire(body)
    value = await ResolvedProviderEgressRequestFactory(
        Contexts(context()),
        wire,
    ).create(
        endpoint(),
        operation(),
        (bytearray(b"payload"),),
    )

    assert value.brain_id == operation().brain_id
    assert value.profile_id == endpoint().profile_id
    assert value.profile_version == endpoint().profile_version
    assert value.profile_attestation_id == endpoint().capability_attestation_id
    assert value.model_revision == endpoint().output_contract.model_revision
    assert value.purpose == endpoint().output_contract.purpose.value
    assert value.operation_type == endpoint().output_contract.operation.value
    assert value.request_bytes == len(b'{"input":["payload"]}')
    assert value.wire_request_digest == hashlib.sha256(b'{"input":["payload"]}').hexdigest()
    assert wire.key == operation().downstream_idempotency_key
    assert body == bytearray(len(b'{"input":["payload"]}'))
