"""ADP-005 batch Core boundary and strict loopback uploader tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.adapters.inbound.http_api import create_agent_event_router
from agentmemory.ingestion.adapters.outbound.spool_batch_http import HttpSpoolBatchUploader
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
)
from agentmemory.ingestion.domain.spool_reconciliation import (
    SpoolRecord,
    SpoolUploadDisposition,
)
from tests.ingestion.adp002_support import event

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.agent_event import AgentEvent

EVENT_IDS = tuple(f"018f0000-0000-7000-8000-{value:012d}" for value in range(601, 608))


class _Auth:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.calls = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        assert authorization == "Bearer local"
        if self.denied:
            message = "denied"
            raise IngestionAuthorizationError(message)


@dataclass
class _BatchHandler:
    outcomes: dict[str, object]
    calls: list[str] = field(default_factory=list[str])

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        self.calls.append(event.event_id)
        outcome = self.outcomes[event.event_id]
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, AppendDisposition)
        return AppendAgentEventResult(event.event_id, outcome, 2_000_000, -123)


def _canonical(event_id: str, sequence: int) -> bytes:
    return AgentEventEnvelopeV1.from_domain(
        event(event_id=event_id, sequence=sequence)
    ).to_canonical_json()


def _batch(*documents: bytes) -> bytes:
    return b'{"events":[' + b",".join(documents) + b"]}"


async def _post_batch(auth: _Auth, handler: _BatchHandler, body: bytes) -> httpx.Response:
    app = FastAPI()
    app.include_router(create_agent_event_router(auth, handler))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
    ) as client:
        return await client.post(
            "/v1/agent-events:append-batch",
            content=body,
            headers={"Authorization": "Bearer local", "Content-Type": "application/json"},
        )


@pytest.mark.asyncio
async def test_batch_returns_ordered_per_item_outcomes_and_time_evidence() -> None:
    outcomes: dict[str, object] = {
        EVENT_IDS[0]: AppendDisposition.ACCEPTED,
        EVENT_IDS[1]: AppendDisposition.DUPLICATE,
        EVENT_IDS[2]: IngestionConflictError("conflict"),
        EVENT_IDS[3]: IngestionDependencyError("offline"),
        EVENT_IDS[4]: IngestionAuthorizationError("scope"),
        EVENT_IDS[5]: AppendDisposition.IGNORED,
        EVENT_IDS[6]: AppendDisposition.DEFERRED,
    }
    auth = _Auth()
    handler = _BatchHandler(outcomes)

    response = await _post_batch(
        auth,
        handler,
        _batch(*(_canonical(event_id, index) for index, event_id in enumerate(EVENT_IDS, 1))),
    )

    assert response.status_code == 200
    assert auth.calls == 1
    assert handler.calls == list(EVENT_IDS)
    assert response.json()["results"] == [
        {
            "event_id": EVENT_IDS[0],
            "status": "accepted",
            "ingested_at_microseconds": 2_000_000,
            "clock_skew_microseconds": -123,
        },
        {
            "event_id": EVENT_IDS[1],
            "status": "duplicate",
            "ingested_at_microseconds": 2_000_000,
            "clock_skew_microseconds": -123,
        },
        {"event_id": EVENT_IDS[2], "status": "conflict"},
        {"event_id": EVENT_IDS[3], "status": "retryable"},
        {"event_id": EVENT_IDS[4], "status": "rejected"},
        {
            "event_id": EVENT_IDS[5],
            "status": "accepted",
            "ingested_at_microseconds": 2_000_000,
            "clock_skew_microseconds": -123,
        },
        {"event_id": EVENT_IDS[6], "status": "retryable"},
    ]


@pytest.mark.asyncio
async def test_batch_prevalidates_every_item_before_any_side_effect() -> None:
    handler = _BatchHandler({EVENT_IDS[0]: AppendDisposition.ACCEPTED})
    invalid = json.loads(_canonical(EVENT_IDS[1], 2))
    invalid["unknown"] = True

    response = await _post_batch(
        _Auth(),
        handler,
        _batch(_canonical(EVENT_IDS[0], 1), json.dumps(invalid).encode()),
    )

    assert response.status_code == 422
    assert handler.calls == []


@pytest.mark.asyncio
async def test_batch_global_authorization_failure_has_no_item_side_effect() -> None:
    handler = _BatchHandler({EVENT_IDS[0]: AppendDisposition.ACCEPTED})

    response = await _post_batch(_Auth(denied=True), handler, _batch(_canonical(EVENT_IDS[0], 1)))

    assert response.status_code == 403
    assert handler.calls == []


def _record(event_id: str, sequence: int) -> SpoolRecord:
    return SpoolRecord(event_id, "ordering-key", sequence, sequence, _canonical(event_id, sequence))


@pytest.mark.asyncio
async def test_uploader_posts_exact_canonical_batch_and_strictly_maps_results() -> None:
    records = (_record(EVENT_IDS[0], 1), _record(EVENT_IDS[1], 2))

    async def transport(request: httpx.Request) -> httpx.Response:
        assert request.url == "http://127.0.0.1:9411/v1/agent-events:append-batch"
        assert request.headers["Authorization"] == f"Bearer {(b'k' * 32).hex()}"
        assert request.content == _batch(*(item.canonical_event for item in records))
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "event_id": EVENT_IDS[0],
                        "status": "accepted",
                        "ingested_at_microseconds": 100,
                        "clock_skew_microseconds": -5,
                    },
                    {"event_id": EVENT_IDS[1], "status": "retryable"},
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        results = await HttpSpoolBatchUploader(
            client,
            "http://127.0.0.1:9411",
            b"k" * 32,
        ).upload(records)

    assert [item.disposition for item in results] == [
        SpoolUploadDisposition.ACCEPTED,
        SpoolUploadDisposition.RETRYABLE,
    ]
    assert results[0].clock_skew_microseconds == -5


@pytest.mark.asyncio
async def test_uploader_maps_whole_request_failures_without_ack_evidence() -> None:
    async def transport(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    record = _record(EVENT_IDS[0], 1)
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        results = await HttpSpoolBatchUploader(
            client,
            "http://[::1]:9411",
            b"k" * 32,
        ).upload((record,))

    assert results[0].disposition is SpoolUploadDisposition.RETRYABLE
    assert results[0].ingested_at_microseconds is None


@pytest.mark.asyncio
async def test_uploader_rejects_malformed_or_mismatched_receipts() -> None:
    async def transport(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b'{"results":[{"event_id":"wrong","status":"accepted",'
            b'"ingested_at_microseconds":1,"clock_skew_microseconds":0}]}',
        )

    record = _record(EVENT_IDS[0], 1)
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        uploader = HttpSpoolBatchUploader(client, "http://127.0.0.1:9411", b"k" * 32)
        with pytest.raises(IngestionDependencyError, match="invalid replay receipt"):
            await uploader.upload((record,))


@pytest.mark.parametrize(
    ("endpoint", "credential"),
    [
        ("https://127.0.0.1:9411", b"k" * 32),
        ("http://localhost:9411", b"k" * 32),
        ("http://127.0.0.1:9411/path", b"k" * 32),
        ("http://127.0.0.1:9411", b"short"),
    ],
)
def test_uploader_refuses_unsafe_endpoint_or_credential(endpoint: str, credential: bytes) -> None:
    with pytest.raises(ValueError, match="endpoint or credential"):
        HttpSpoolBatchUploader(httpx.AsyncClient(), endpoint, credential)
