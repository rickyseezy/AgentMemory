"""PRO-009 ordering, denial, cleanup, and telemetry application tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.application.containment import (
    ContainedAdapterOperationHandler,
    ContainedProviderEndpointGateway,
)
from agentmemory.providers.domain.containment import (
    AdapterOperationResult,
    AdapterOperationSandbox,
    ContentTaint,
    EgressDestination,
    ProviderEgressPermit,
    ProviderEgressRequest,
    ProviderRuntimeFact,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
)
from agentmemory.providers.domain.idempotency import (
    ProviderOperationOutcome,
    ProviderOperationRequest,
    ProviderPrivacyClass,
    ProviderPurpose,
)
from tests.core.support import digest
from tests.providers.test_pro007_resilience_domain import endpoint

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation

BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
PROFILE_ID = "018f0000-0000-7000-8000-000000000901"
POLICY_ID = "018f0000-0000-7000-8000-000000000902"
ATTESTATION_ID = "018f0000-0000-7000-8000-000000000903"
PROFILE_ATTESTATION_ID = digest("profile-attestation").value
OPERATION_ID = "018f0000-0000-7000-8000-000000000904"
_ERR_DENIED = "provider egress is denied"


def operation() -> ProviderOperationRequest:
    return ProviderOperationRequest(
        operation_id=OPERATION_ID,
        idempotency_key="pro009-operation",
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        model_revision="model-v1",
        purpose=ProviderPurpose.EMBED_DOCUMENT,
        content_sha256=(digest("payload").value,),
        preprocessing_revision="canonical-v1",
        privacy_class=ProviderPrivacyClass.INTERNAL,
        project_id=None,
        private_block=False,
        secret_bearing=False,
        token_count=2,
        estimated_cost_micros=10,
    )


def request() -> ProviderEgressRequest:
    return ProviderEgressRequest(
        operation_id=OPERATION_ID,
        brain_id=BRAIN_ID,
        project_id=None,
        profile_id=PROFILE_ID,
        profile_version=3,
        profile_attestation_id=PROFILE_ATTESTATION_ID,
        model_revision="model-v1",
        purpose="retrieval_document",
        operation_type="embedding",
        destination=EgressDestination(
            scheme="https",
            hostname="api.openai.com",
            port=443,
            region="US",
            path_prefix="/v1/embeddings",
        ),
        taint=ContentTaint(
            classification=Classification.INTERNAL,
            private_block=False,
            secret_bearing=False,
        ),
        retention_days=0,
        training_allowed=False,
        policy_version=1,
        security_epoch=7,
        quota_requests_per_minute=100,
        quota_tokens_per_minute=10_000,
        budget_monthly_micros=1_000_000,
        request_bytes=7,
        maximum_response_bytes=4096,
        timeout_milliseconds=5_000,
        content_digests=(digest("payload").value,),
        wire_request_digest=digest("wire-request").value,
        token_count=2,
        estimated_cost_micros=10,
    )


def permit() -> ProviderEgressPermit:
    value = request()
    return ProviderEgressPermit(
        operation_id=value.operation_id,
        brain_id=value.brain_id,
        profile_id=value.profile_id,
        profile_version=value.profile_version,
        profile_attestation_id=value.profile_attestation_id,
        model_revision=value.model_revision,
        purpose=value.purpose,
        operation_type=value.operation_type,
        destination=value.destination,
        content_digests=value.content_digests,
        wire_request_digest=value.wire_request_digest,
        policy_id=POLICY_ID,
        policy_version=1,
        security_epoch=7,
        maximum_request_bytes=1_000_000,
        maximum_response_bytes=4096,
        timeout_milliseconds=5_000,
        quota_requests_per_minute=100,
        quota_tokens_per_minute=10_000,
        budget_monthly_micros=1_000_000,
        token_count=2,
        estimated_cost_micros=10,
        attestation_id=ATTESTATION_ID,
        attestation_digest=digest("attestation").value,
        request_digest=digest("request").value,
        issued_at_microseconds=1_000,
        expires_at_microseconds=10_000,
    )


@dataclass
class RequestFactory:
    events: list[str]

    async def create(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
    ) -> ProviderEgressRequest:
        del endpoint, operation, payloads
        self.events.append("request")
        return request()


@dataclass
class Authority:
    events: list[str]
    denied: bool = False

    async def authorize(
        self,
        request: ProviderEgressRequest,
        now_microseconds: int,
    ) -> ProviderEgressPermit:
        del request, now_microseconds
        self.events.append("authorize")
        if self.denied:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        return permit()


@dataclass
class SocketGateway:
    events: list[str]

    async def execute(
        self,
        permit: ProviderEgressPermit,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        del permit, endpoint, operation, payloads, downstream_idempotency_key
        self.events.append("socket")
        return ProviderOperationOutcome(
            result_sha256=digest("result").value,
            result_ref=f"cas://sha256/{digest('result').value}",
            usage_units=2,
        )


@pytest.mark.asyncio
async def test_gateway_authorizes_immediately_before_socket_acquisition() -> None:
    events: list[str] = []
    payload = bytearray(b"payload")
    gateway = ContainedProviderEndpointGateway(
        RequestFactory(events),
        Authority(events),
        SocketGateway(events),
        now_microseconds=lambda: 2_000,
    )

    result = await gateway.execute(
        endpoint(),
        operation(),
        (payload,),
        operation().downstream_idempotency_key,
    )

    assert result.result_sha256 == digest("result").value
    assert events == ["request", "authorize", "socket"]
    assert payload == bytearray(b"payload")


@pytest.mark.asyncio
async def test_denial_occurs_before_socket_and_destroys_payload_buffers() -> None:
    events: list[str] = []
    payload = bytearray(b"payload")
    gateway = ContainedProviderEndpointGateway(
        RequestFactory(events),
        Authority(events, denied=True),
        SocketGateway(events),
        now_microseconds=lambda: 2_000,
    )

    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        await gateway.execute(
            endpoint(),
            operation(),
            (payload,),
            operation().downstream_idempotency_key,
        )

    assert events == ["request", "authorize"]
    assert payload == bytearray(len(b"payload"))


@dataclass
class Supervisor:
    events: list[str]
    error: Exception | None = None

    async def execute(
        self,
        sandbox: AdapterOperationSandbox,
        inputs: Sequence[bytearray],
    ) -> AdapterOperationResult:
        del sandbox, inputs
        self.events.append("create")
        try:
            self.events.append("execute")
            if self.error is not None:
                raise self.error
            return AdapterOperationResult(
                operation_id=OPERATION_ID,
                result_digest=digest("adapter-result").value,
                result_ref=f"cas://sha256/{digest('adapter-result').value}",
                usage_units=3,
                exit_code=0,
                runtime_milliseconds=12,
                cleanup_digest=digest("cleanup").value,
            )
        finally:
            self.events.append("remove")


@dataclass
class Telemetry:
    events: list[str]
    facts: list[ProviderRuntimeFact] = field(default_factory=list[ProviderRuntimeFact])

    async def record(self, fact: ProviderRuntimeFact) -> None:
        self.events.append("telemetry")
        self.facts.append(fact)


def sandbox() -> AdapterOperationSandbox:
    return AdapterOperationSandbox.production(
        operation_id=OPERATION_ID,
        image="registry.example/adapter@sha256:" + digest("image").value,
        internal_network="agentmemory_0123456789abcdef0123456789abcdef_internal",
        input_source=f"/run/agentmemory/operations/{OPERATION_ID}/input",
        output_source=f"/run/agentmemory/operations/{OPERATION_ID}/output",
        timeout_seconds=30,
    )


@pytest.mark.asyncio
async def test_adapter_supervisor_records_only_closed_content_free_telemetry() -> None:
    events: list[str] = []
    telemetry = Telemetry(events)
    input_value = bytearray(b"secret input")
    result = await ContainedAdapterOperationHandler(
        Supervisor(events),
        telemetry,
        now_microseconds=lambda: 2_000,
    ).execute(sandbox(), (input_value,))

    assert result.result_digest == digest("adapter-result").value
    assert events == ["create", "execute", "remove", "telemetry"]
    assert input_value == bytearray(len(b"secret input"))
    assert telemetry.facts[0].document == {
        "adapter_image_digest": digest("image").value,
        "cleanup_digest": digest("cleanup").value,
        "occurred_at_microseconds": 2000,
        "operation_id": OPERATION_ID,
        "outcome_code": "succeeded",
        "runtime_milliseconds": 12,
    }
    assert "secret" not in repr(telemetry.facts[0]).lower()


@pytest.mark.asyncio
async def test_adapter_crash_still_cleans_up_zeros_input_and_records_safe_failure() -> None:
    events: list[str] = []
    telemetry = Telemetry(events)
    input_value = bytearray(b"secret input")
    handler = ContainedAdapterOperationHandler(
        Supervisor(events, error=RuntimeError("upstream leaked body")),
        telemetry,
        now_microseconds=lambda: 2_000,
    )

    with pytest.raises(ProviderContainmentDependencyError, match="runtime failed"):
        await handler.execute(sandbox(), (input_value,))

    assert events == ["create", "execute", "remove", "telemetry"]
    assert input_value == bytearray(len(b"secret input"))
    assert telemetry.facts[0].outcome_code == "adapter_crash"
    assert "upstream" not in repr(telemetry.facts[0])
