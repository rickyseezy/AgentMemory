"""MEM-002 authenticated ExplainMemoryQuery HTTP contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.memory.adapters.inbound.http_api import (
    create_contract_memory_router,
    create_memory_router,
)
from agentmemory.memory.application.explain_memory import ExplainMemoryHandler
from agentmemory.memory.domain.explanation import EvidenceAvailability, MemoryExplanation
from agentmemory.operations.adapters.inbound.http_api import export_openapi_schema
from tests.core.support import FixedClock
from tests.memory.test_mem002_provenance_domain_application import (
    ACTOR_ID,
    BRAIN_ID,
    EVENT_ONE,
    EVENT_TWO,
    GRANT_ID,
    MEMORY_ID,
    NOW,
    _evidence,  # pyright: ignore[reportPrivateUsage]
    _memory,  # pyright: ignore[reportPrivateUsage]
)


def _auth_calls() -> list[str | None]:
    return []


@dataclass
class _Auth:
    calls: list[str | None] = field(default_factory=_auth_calls)

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)


@dataclass
class _Repository:
    value: MemoryExplanation | None

    async def explain_authorized(
        self,
        access: object,
    ) -> MemoryExplanation | None:
        del access
        return self.value


def _explanation() -> MemoryExplanation:
    return MemoryExplanation.create(
        _memory(),
        (
            _evidence(EVENT_ONE, EvidenceAvailability.AVAILABLE),
            _evidence(EVENT_TWO, EvidenceAvailability.PURGED),
        ),
        NOW,
        NOW + timedelta(hours=1),
    )


def _app(value: MemoryExplanation | None = None) -> tuple[FastAPI, _Auth]:
    auth = _Auth()
    application = FastAPI()
    application.include_router(
        create_memory_router(
            auth,
            ExplainMemoryHandler(_Repository(value), FixedClock(NOW + timedelta(days=1))),
            FixedClock(NOW),
        )
    )
    return application, auth


@pytest.mark.asyncio
async def test_explain_endpoint_exposes_complete_provenance_time_hashes_and_evidence() -> None:
    application, auth = _app(_explanation())
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            f"/memories/{MEMORY_ID}",
            params={
                "brain_id": BRAIN_ID,
                "actor_id": ACTOR_ID,
                "grant_id": GRANT_ID,
                "valid_at": "2026-07-21T10:00:00.000000Z",
                "recorded_at": "2026-07-21T11:00:00.000000Z",
            },
            headers={"Authorization": "Bearer test"},
        )
    assert response.status_code == 200
    body = response.json()
    assert auth.calls == ["Bearer test"]
    assert body["memory_id"] == MEMORY_ID
    assert body["scope"] == {
        "brain_id": BRAIN_ID,
        "checkout_id": None,
        "project_id": "018f0000-0000-7000-8000-000000000010",
        "repository_id": "018f0000-0000-7000-8000-000000000020",
    }
    assert body["status"] == "active"
    assert body["valid_time"]["from"] == "2026-07-21T10:00:00.000000Z"
    assert body["recorded_time"]["from"] == "2026-07-21T11:00:00.000000Z"
    assert body["provenance"]["actor_id"] == ACTOR_ID
    assert body["provenance"]["agent_id"] == "agentmemory.local-extractor"
    assert body["provenance"]["extractor"]["model_revision"] == "qwen3-4b-q4_k_m-r1"
    assert len(body["provenance"]["provenance_sha256"]) == 64
    assert body["evidence"][0]["availability"] == "available"
    assert body["evidence"][1] == {
        "availability": "purged",
        "canonical_event_sha256": "c" * 64,
        "event_id": EVENT_TWO,
        "event_type": None,
        "occurred_at": None,
        "resource_uri": None,
    }


@pytest.mark.asyncio
async def test_explain_endpoint_returns_same_not_found_for_absent_or_unauthorized_target() -> None:
    application, _ = _app(None)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            f"/memories/{MEMORY_ID}",
            params={
                "brain_id": BRAIN_ID,
                "actor_id": ACTOR_ID,
                "grant_id": GRANT_ID,
                "valid_at": "2026-07-21T10:00:00.000000Z",
                "recorded_at": "2026-07-21T11:00:00.000000Z",
            },
        )
    assert response.status_code == 404
    assert response.json() == {
        "code": "AM_NOT_FOUND",
        "detail": "memory is unavailable",
        "retryable": False,
    }


@pytest.mark.asyncio
async def test_explain_endpoint_rejects_non_utc_or_malformed_coordinates_before_repository() -> (
    None
):
    application, _ = _app(_explanation())
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            f"/memories/{MEMORY_ID}",
            params={
                "brain_id": BRAIN_ID,
                "actor_id": ACTOR_ID,
                "grant_id": GRANT_ID,
                "valid_at": "2026-07-21T10:00:00",
                "recorded_at": "2026-07-21T11:00:00.000000Z",
            },
        )
    assert response.status_code == 422


def test_contract_router_exports_deterministic_explain_memory_operation() -> None:
    schema = export_openapi_schema((create_contract_memory_router(),))
    encoded = json.dumps(schema, separators=(",", ":"), sort_keys=True)
    assert '"/memories/{memory_id}"' in encoded
    assert '"operationId":"ExplainMemoryQuery"' in encoded
    assert '"$ref":"#/components/schemas/ExplainMemoryResponse"' in encoded
