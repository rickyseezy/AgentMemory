"""PRO-009 independent gateway orchestration and zeroization tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters.permit_codec import HmacProviderPermitCodec
from agentmemory.providers.application.gateway import ProviderGatewayOperationHandler
from agentmemory.providers.domain.containment import (
    ExecuteProviderEgress,
    ProviderEgressDecisionFact,
    ProviderEgressHttpResponse,
    ProviderGatewayCredential,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
)
from tests.providers.test_pro009_containment_application import permit

if TYPE_CHECKING:
    from agentmemory.providers.domain.containment import ProviderEgressPermit

_ERR_USAGE = "provider gateway usage is denied"


@dataclass
class Usage:
    events: list[str]
    denied: bool = False

    async def authorize(
        self,
        permit: ProviderEgressPermit,
        now_microseconds: int,
    ) -> None:
        del permit, now_microseconds
        self.events.append("usage")
        if self.denied:
            raise ProviderContainmentDeniedError(_ERR_USAGE)


@dataclass
class Broker:
    events: list[str]
    credential: ProviderGatewayCredential

    async def resolve(self, permit: ProviderEgressPermit) -> ProviderGatewayCredential:
        del permit
        self.events.append("credential")
        return self.credential


@dataclass
class Transport:
    events: list[str]
    error: Exception | None = None
    response: ProviderEgressHttpResponse = field(
        default_factory=lambda: ProviderEgressHttpResponse(
            200,
            (("content-type", "application/json"),),
            b"safe",
        )
    )
    calls: list[dict[str, object]] = field(default_factory=list[dict[str, object]])

    async def execute(  # noqa: PLR0913 -- Mirrors the explicit transport boundary.
        self,
        permit_value: ProviderEgressPermit,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        maximum_response_bytes: int,
        timeout_milliseconds: int,
    ) -> ProviderEgressHttpResponse:
        del permit_value
        self.events.append("socket")
        values: dict[str, object] = {
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "maximum_response_bytes": maximum_response_bytes,
            "timeout_milliseconds": timeout_milliseconds,
        }
        self.calls.append(values)
        if self.error is not None:
            raise self.error
        return self.response


@dataclass
class Telemetry:
    events: list[str]
    facts: list[ProviderEgressDecisionFact] = field(
        default_factory=list[ProviderEgressDecisionFact]
    )

    async def record_egress(self, fact: ProviderEgressDecisionFact) -> None:
        self.events.append("telemetry")
        self.facts.append(fact)


def command(codec: HmacProviderPermitCodec, body: bytearray) -> ExecuteProviderEgress:
    value = replace(
        permit(),
        wire_request_digest=hashlib.sha256(bytes(body)).hexdigest(),
    )
    return ExecuteProviderEgress(
        codec.encode(value),
        "/v1/embeddings",
        body,
    )


@pytest.mark.asyncio
async def test_gateway_verifies_reserves_brokers_then_opens_socket_and_zeroes_secrets() -> None:
    events: list[str] = []
    key = HmacProviderPermitCodec(b"k" * 32)
    body = bytearray(b'{"input":["safe"]}')
    credential = ProviderGatewayCredential(
        header_name="Authorization",
        value=bytearray(b"Bearer opaque"),
    )
    transport = Transport(events)
    telemetry = Telemetry(events)
    handler = ProviderGatewayOperationHandler(
        key,
        Usage(events),
        Broker(events, credential),
        transport,
        telemetry,
        now_microseconds=lambda: 2_000,
    )

    response = await handler.execute(command(key, body))

    assert response.body == b"safe"
    assert events == ["usage", "credential", "socket", "telemetry"]
    assert body == bytearray(len(b'{"input":["safe"]}'))
    assert credential.value == bytearray(len(b"Bearer opaque"))
    assert transport.calls[0]["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer opaque",
        "Content-Type": "application/json",
    }
    fact = telemetry.facts[0]
    assert fact.outcome_code == "succeeded"
    assert set(fact.document) == {
        "destination_fingerprint",
        "occurred_at_microseconds",
        "operation_id",
        "outcome_code",
        "permit_digest",
        "request_bytes",
        "response_bytes",
        "status_code",
    }
    assert "opaque" not in str(fact.document)
    assert "safe" not in str(fact.document)


@pytest.mark.asyncio
async def test_wire_digest_or_usage_denial_occurs_before_credential_and_socket() -> None:
    for mismatch, denied in ((True, False), (False, True)):
        events: list[str] = []
        key = HmacProviderPermitCodec(b"k" * 32)
        body = bytearray(b"authorized")
        value = command(key, body)
        if mismatch:
            value.body[:] = b"tampered!"
        telemetry = Telemetry(events)
        with pytest.raises(ProviderContainmentDeniedError):
            await ProviderGatewayOperationHandler(
                key,
                Usage(events, denied=denied),
                Broker(
                    events,
                    ProviderGatewayCredential(
                        header_name="Authorization",
                        value=bytearray(b"Bearer opaque"),
                    ),
                ),
                Transport(events),
                telemetry,
                now_microseconds=lambda: 2_000,
            ).execute(value)
        assert "credential" not in events
        assert "socket" not in events
        assert events[-1] == "telemetry"
        assert value.body == bytearray(len(value.body))
        assert telemetry.facts[0].outcome_code == "denied"


@pytest.mark.asyncio
async def test_arbitrary_broker_or_socket_failure_is_content_free_and_zeroized() -> None:
    events: list[str] = []
    key = HmacProviderPermitCodec(b"k" * 32)
    body = bytearray(b'{"input":["safe"]}')
    credential = ProviderGatewayCredential(
        header_name="Authorization",
        value=bytearray(b"Bearer opaque"),
    )
    with pytest.raises(ProviderContainmentDependencyError, match="unavailable") as caught:
        await ProviderGatewayOperationHandler(
            key,
            Usage(events),
            Broker(events, credential),
            Transport(events, error=RuntimeError("opaque safe credential")),
            Telemetry(events),
            now_microseconds=lambda: 2_000,
        ).execute(command(key, body))
    assert "opaque" not in str(caught.value)
    assert "safe" not in str(caught.value)
    assert credential.value == bytearray(len(b"Bearer opaque"))
    assert body == bytearray(len(b'{"input":["safe"]}'))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("5", 6_000_000),
        (
            format_datetime(datetime.fromtimestamp(6, tz=UTC), usegmt=True),
            6_000_000,
        ),
        ("not-a-delay", None),
        (str(8 * 24 * 60 * 60), None),
    ],
)
async def test_gateway_normalizes_only_bounded_retry_after(
    header: str,
    expected: int | None,
) -> None:
    events: list[str] = []
    key = HmacProviderPermitCodec(b"k" * 32)
    body = bytearray(b'{"input":["safe"]}')
    transport = Transport(
        events,
        response=ProviderEgressHttpResponse(
            429,
            (("retry-after", header), ("set-cookie", "secret")),
            b"safe",
        ),
    )
    handler = ProviderGatewayOperationHandler(
        key,
        Usage(events),
        Broker(
            events,
            ProviderGatewayCredential(
                header_name="Authorization",
                value=bytearray(b"Bearer opaque"),
            ),
        ),
        transport,
        Telemetry(events),
        now_microseconds=lambda: 1_000_000,
    )

    response = await handler.execute(command(key, body))

    assert response.headers == ()
    assert response.retry_after_microseconds == expected


@pytest.mark.asyncio
async def test_gateway_rejects_ambiguous_retry_after_without_forwarding_headers() -> None:
    events: list[str] = []
    key = HmacProviderPermitCodec(b"k" * 32)
    body = bytearray(b'{"input":["safe"]}')
    transport = Transport(
        events,
        response=ProviderEgressHttpResponse(
            429,
            (("retry-after", "1"), ("Retry-After", "2")),
            b"safe",
        ),
    )
    handler = ProviderGatewayOperationHandler(
        key,
        Usage(events),
        Broker(
            events,
            ProviderGatewayCredential(
                header_name="Authorization",
                value=bytearray(b"Bearer opaque"),
            ),
        ),
        transport,
        Telemetry(events),
        now_microseconds=lambda: 1_000_000,
    )

    response = await handler.execute(command(key, body))

    assert response.headers == ()
    assert response.retry_after_microseconds is None
