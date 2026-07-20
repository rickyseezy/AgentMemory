"""ADP-002 minimal authenticated loopback append API tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.adapters.inbound.http_api import create_agent_event_router
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionCapacityError, IngestionDependencyError
from tests.ingestion.adp002_support import EVENT_ID, event

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.agent_event import AgentEvent


class _Auth:
    def __init__(self) -> None:
        self.values: list[str | None] = []

    async def authenticate(self, authorization: str | None) -> None:
        self.values.append(authorization)


@dataclass
class _Handler:
    disposition: AppendDisposition = AppendDisposition.ACCEPTED
    dependency_failure: bool = False
    capacity_failure: bool = False
    calls: int = 0

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        self.calls += 1
        assert event.event_id == EVENT_ID
        if self.dependency_failure:
            message = "unavailable"
            raise IngestionDependencyError(message)
        if self.capacity_failure:
            reason = "disk_hard_limit"
            raise IngestionCapacityError(reason, retryable=True)
        return AppendAgentEventResult(EVENT_ID, self.disposition, 42)


async def _request(auth: _Auth, handler: _Handler, body: bytes) -> httpx.Response:
    app = FastAPI()
    app.include_router(create_agent_event_router(auth, handler))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
    ) as client:
        return await client.post(
            "/v1/agent-events:append",
            content=body,
            headers={"Authorization": "Bearer token", "Content-Type": "application/json"},
        )


@pytest.mark.asyncio
async def test_endpoint_authenticates_and_returns_only_durable_capture_metadata() -> None:
    auth = _Auth()
    handler = _Handler()
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    response = await _request(auth, handler, raw)
    assert response.status_code == 201
    assert response.json() == {
        "event_id": EVENT_ID,
        "status": "accepted",
        "ingested_at_microseconds": 42,
        "clock_skew_microseconds": 0,
    }
    assert auth.values == ["Bearer token"]
    assert handler.calls == 1
    assert "secret" not in response.text


@pytest.mark.asyncio
async def test_duplicate_key_is_rejected_before_handler() -> None:
    auth = _Auth()
    handler = _Handler()
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    duplicate = raw[:-1] + b',"id":"duplicate"}'
    response = await _request(auth, handler, duplicate)
    assert response.status_code == 422
    assert handler.calls == 0
    assert response.json()["fields"] == [{"field": "$json", "code": "duplicate_key"}]


@pytest.mark.asyncio
async def test_dependency_failure_is_retryable_and_content_free() -> None:
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    response = await _request(_Auth(), _Handler(dependency_failure=True), raw)
    assert response.status_code == 503
    assert response.json()["code"] == "AM_DEPENDENCY_UNAVAILABLE"
    assert response.json()["retryable"] is True
    assert "secret" not in response.text


@pytest.mark.asyncio
async def test_hard_capacity_failure_is_fast_retryable_and_content_free() -> None:
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    response = await _request(_Auth(), _Handler(capacity_failure=True), raw)
    assert response.status_code == 507
    assert response.json() == {
        "code": "AM_CAPACITY_EXHAUSTED",
        "retryable": True,
        "detail": "AgentEvent capture was rejected",
    }
    assert "disk_hard_limit" not in response.text


@pytest.mark.asyncio
async def test_empty_body_is_rejected_before_handler() -> None:
    handler = _Handler()
    response = await _request(_Auth(), handler, b"")
    assert response.status_code == 422
    assert handler.calls == 0
