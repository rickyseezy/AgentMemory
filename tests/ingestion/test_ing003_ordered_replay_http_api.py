"""ING-003 authenticated strict replay command/status HTTP tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.ingestion.adapters.inbound.ordered_replay_http_api import (
    create_ordered_replay_router,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
)
from agentmemory.ingestion.domain.ordered_replay import OrderedReplayRun, ReplayRunRequest
from tests.ingestion.test_ing003_replay_application import (
    CODE_FINGERPRINT,
    GENERATION_ID,
    GRANT_ID,
    OPERATION_ID,
    replay_run,
)


@dataclass
class _Auth:
    values: list[str | None] = field(default_factory=list[str | None])
    error: Exception | None = None

    async def authenticate(self, authorization: str | None) -> None:
        self.values.append(authorization)
        if self.error is not None:
            raise self.error


@dataclass
class _Start:
    error: Exception | None = None
    requests: list[ReplayRunRequest] = field(default_factory=list[ReplayRunRequest])

    async def execute(self, request: ReplayRunRequest) -> OrderedReplayRun:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return replay_run()


class _Get:
    async def execute(self, operation_id: str) -> OrderedReplayRun:
        assert operation_id == OPERATION_ID
        return replay_run()


def _document() -> dict[str, object]:
    selected = replay_run().request
    return {
        "operation_id": OPERATION_ID,
        "brain_id": selected.brain_id,
        "actor_id": selected.actor_id,
        "grant_id": GRANT_ID,
        "projection_name": selected.projection_name,
        "projection_generation": GENERATION_ID,
        "code_fingerprint": CODE_FINGERPRINT,
    }


async def _post(
    start: _Start,
    document: dict[str, object],
    *,
    idempotency_key: str | None = OPERATION_ID,
) -> tuple[httpx.Response, _Auth]:
    auth = _Auth()
    app = FastAPI()
    app.include_router(create_ordered_replay_router(auth, start, _Get()))
    headers = {"Authorization": "Bearer local-token"}
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
    ) as client:
        return await client.post("/v1/ordered-replays", json=document, headers=headers), auth


@pytest.mark.asyncio
async def test_start_authenticates_binds_idempotency_and_returns_no_source_content() -> None:
    start = _Start()
    response, auth = await _post(start, _document())
    queued = replay_run()
    watermark_time = queued.source_watermark_ingested_at_microseconds
    assert response.status_code == 202
    assert response.json() == {
        "operation_id": OPERATION_ID,
        "brain_id": queued.request.brain_id,
        "projection_name": "canonical-event-projection-v1",
        "projection_generation": GENERATION_ID,
        "code_fingerprint": CODE_FINGERPRINT,
        "state": "queued",
        "source_watermark_ingested_at_microseconds": watermark_time,
        "source_watermark_event_id": queued.source_watermark_event_id,
        "source_count": 2,
        "processed_count": 0,
        "cursor_ingested_at_microseconds": None,
        "cursor_event_id": None,
        "shadow_digest": None,
        "live_digest": None,
        "failure_code": None,
        "created_at_microseconds": queued.created_at_microseconds,
        "updated_at_microseconds": queued.updated_at_microseconds,
        "completed_at_microseconds": None,
    }
    assert auth.values == ["Bearer local-token"]
    assert start.requests == [queued.request]
    assert "secret" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("idempotency_key", [None, "018f0000-0000-7000-8000-000000000999"])
async def test_start_rejects_missing_or_divergent_idempotency_before_command(
    idempotency_key: str | None,
) -> None:
    start = _Start()
    response, _ = await _post(start, _document(), idempotency_key=idempotency_key)
    assert response.status_code == 422
    assert response.json()["fields"] == [{"field": "Idempotency-Key", "code": "mismatch"}]
    assert start.requests == []


@pytest.mark.asyncio
async def test_strict_unknown_field_and_conflict_are_content_free() -> None:
    invalid = _document() | {"unknown": "secret"}
    response, _ = await _post(_Start(), invalid)
    assert response.status_code == 422
    assert "secret" not in response.text
    conflict, _ = await _post(
        _Start(IngestionConflictError("conflict with secret source content")),
        _document(),
    )
    assert conflict.status_code == 409
    assert conflict.json()["code"] == "AM_CONFLICT"
    assert "secret" not in conflict.text


@pytest.mark.asyncio
async def test_status_authenticates_and_returns_content_free_progress() -> None:
    auth = _Auth()
    app = FastAPI()
    app.include_router(create_ordered_replay_router(auth, _Start(), _Get()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.get(
            f"/v1/ordered-replays/{OPERATION_ID}",
            headers={"Authorization": "Bearer local-token"},
        )
    assert response.status_code == 200
    assert response.json()["state"] == "queued"
    assert auth.values == ["Bearer local-token"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status_code", "code"),
    [
        (IngestionDependencyError("secret outage"), 503, "AM_DEPENDENCY_UNAVAILABLE"),
        (IngestionIntegrityError("secret corruption"), 500, "AM_INTEGRITY"),
    ],
)
async def test_typed_command_failures_return_only_closed_problem_codes(
    error: Exception,
    status_code: int,
    code: str,
) -> None:
    response, _ = await _post(_Start(error), _document())
    assert response.status_code == status_code
    assert response.json()["code"] == code
    assert "secret" not in response.text


@pytest.mark.asyncio
async def test_authentication_failure_prevents_request_parsing_and_command() -> None:
    auth = _Auth(error=IngestionAuthorizationError("secret token"))
    start = _Start()
    app = FastAPI()
    app.include_router(create_ordered_replay_router(auth, start, _Get()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/v1/ordered-replays",
            content=b"secret invalid json",
            headers={"Authorization": "Bearer bad", "Idempotency-Key": OPERATION_ID},
        )
    assert response.status_code == 403
    assert response.json()["code"] == "AM_FORBIDDEN"
    assert start.requests == []
    assert "secret" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [b"", b"x" * (64 * 1024 + 1)])
async def test_request_body_size_is_bounded_before_schema_validation(content: bytes) -> None:
    auth = _Auth()
    start = _Start()
    app = FastAPI()
    app.include_router(create_ordered_replay_router(auth, start, _Get()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/v1/ordered-replays",
            content=content,
            headers={"Authorization": "Bearer local", "Idempotency-Key": OPERATION_ID},
        )
    assert response.status_code == 422
    assert response.json()["fields"] == [{"field": "$body", "code": "invalid_size"}]
    assert start.requests == []
