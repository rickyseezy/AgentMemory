# pyright: reportPrivateUsage=false
"""MEM-004 authenticated correction and history HTTP contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.memory.adapters.inbound.correction_http_api import (
    create_contract_memory_correction_router,
    create_memory_correction_router,
)
from agentmemory.memory.adapters.outbound.sqlite_correction import (
    SqliteMemoryCorrectionRepository,
    SqliteMemoryCorrectionUnitOfWorkFactory,
)
from agentmemory.memory.application.correct_memory import CorrectMemoryHandler
from agentmemory.memory.application.query_memory_corrections import (
    GetMemoryCorrectionHistoryHandler,
    MemoryCorrectionHistoryQuery,
    MemoryCorrectionHistoryView,
)
from agentmemory.memory.domain.correction import (
    MemoryCorrectionHistory,
    MemoryCorrectionPlan,
    MemoryCorrectionResult,
    MemoryPrecedencePolicy,
    correction_idempotency_key,
)
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
    MemoryConflictError,
    MemoryDependencyError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from agentmemory.operations.adapters.inbound.http_api import export_openapi_schema
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.memory.test_mem002_sqlite_repository import _persist_memory
from tests.memory.test_mem004_correction_application import CAUSATION_ID, CORRELATION_ID
from tests.memory.test_mem004_correction_domain import (
    ACTOR_ID,
    BRAIN_ID,
    CHECKOUT_ID,
    CORRECTION_ID,
    GRANT_ID,
    MEMORY_ID,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
    _target,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.memory.application.correct_memory import CorrectMemoryCommand


def _auth_calls() -> list[str | None]:
    return []


@dataclass
class _Auth:
    calls: list[str | None] = field(default_factory=_auth_calls)

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)


@dataclass
class _CorrectionHandler:
    result: MemoryCorrectionResult
    command: CorrectMemoryCommand | None = None
    error: Exception | None = None

    async def execute(self, command: CorrectMemoryCommand) -> MemoryCorrectionResult:
        self.command = command
        if self.error is not None:
            raise self.error
        return self.result


@dataclass
class _HistoryHandler:
    result: MemoryCorrectionHistoryView
    query: MemoryCorrectionHistoryQuery | None = None
    error: Exception | None = None

    async def execute(self, query: MemoryCorrectionHistoryQuery) -> MemoryCorrectionHistoryView:
        self.query = query
        if self.error is not None:
            raise self.error
        return self.result


def _fixtures() -> tuple[MemoryCorrectionResult, MemoryCorrectionHistoryView]:
    target = _target("Use PostgreSQL")
    plan = MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=1,
        statement="Use SQLite",
        scope=target.scope,
        valid_from=NOW,
        valid_to=None,
        reason="user_correction",
        evidence=(),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )
    key = correction_idempotency_key(CORRECTION_ID, MEMORY_ID, BRAIN_ID)
    result = MemoryCorrectionResult.create(key, "e" * 64, plan)
    history = MemoryCorrectionHistory(target, (plan.assertion,))
    selected = MemoryPrecedencePolicy().resolve(
        target,
        history.corrections,
        target.scope,
        valid_at=NOW + timedelta(minutes=2),
        recorded_at=NOW + timedelta(minutes=2),
    )
    return result, MemoryCorrectionHistoryView(history, selected)


def _app(
    *,
    correction_error: Exception | None = None,
    history_error: Exception | None = None,
) -> tuple[FastAPI, _Auth, _CorrectionHandler, _HistoryHandler]:
    result, history = _fixtures()
    auth = _Auth()
    correction = _CorrectionHandler(result, error=correction_error)
    history_handler = _HistoryHandler(history, error=history_error)
    application = FastAPI()
    application.include_router(
        create_memory_correction_router(
            auth,
            correction,
            history_handler,
            FixedClock(NOW + timedelta(minutes=2)),
        )
    )
    return application, auth, correction, history_handler


@pytest.mark.asyncio
async def test_correction_endpoint_authenticates_and_translates_complete_command() -> None:
    application, auth, handler, _ = _app()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/memories/{MEMORY_ID}/corrections",
            json=_request(),
            headers={"Authorization": "Bearer local"},
        )

    assert response.status_code == 201
    assert auth.calls == ["Bearer local"]
    assert handler.command is not None
    assert handler.command.assertion_id == MEMORY_ID
    assert handler.command.scope.checkout_id == CHECKOUT_ID
    assert response.json()["correction_id"] == CORRECTION_ID
    assert response.json()["source_status"] == "superseded"
    assert len(response.json()["result_sha256"]) == 64


@pytest.mark.asyncio
async def test_history_endpoint_returns_source_correction_and_effective_selection() -> None:
    application, auth, _, handler = _app()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            f"/memories/{MEMORY_ID}/corrections",
            params={
                "actor_id": ACTOR_ID,
                "brain_id": BRAIN_ID,
                "grant_id": GRANT_ID,
                "project_id": PROJECT_ID,
                "repository_id": REPOSITORY_ID,
                "valid_at": "2026-07-21T12:02:00.000000Z",
                "recorded_at": "2026-07-21T12:02:00.000000Z",
            },
            headers={"Authorization": "Bearer local"},
        )

    assert response.status_code == 200
    assert auth.calls == ["Bearer local"]
    assert handler.query is not None
    body = response.json()
    assert body["root"]["assertion_id"] == MEMORY_ID
    assert body["corrections"][0]["assertion_id"] == CORRECTION_ID
    assert body["selected"]["assertion_id"] == CORRECTION_ID
    assert body["selected"]["policy_version"] == "memory-precedence.v1"


@pytest.mark.asyncio
async def test_correction_conflict_is_content_free_and_retry_requires_refresh() -> None:
    application, _, _, _ = _app(correction_error=MemoryConflictError())
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(f"/memories/{MEMORY_ID}/corrections", json=_request())

    assert response.status_code == 409
    assert response.json() == {
        "code": "AM_CONFLICT",
        "detail": "memory assertion changed; refresh and retry",
        "retryable": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status"),
    [
        (MemoryEvidenceNotFoundError(), 404),
        (MemoryAuthorizationError(), 404),
        (MemoryValidationError.single("field", "invalid"), 422),
        (MemoryDependencyError(), 503),
        (MemoryIntegrityError(), 500),
    ],
)
async def test_correction_endpoint_maps_typed_failures_without_content(
    error: Exception,
    status: int,
) -> None:
    application, _, _, _ = _app(correction_error=error)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.post(f"/memories/{MEMORY_ID}/corrections", json=_request())
    assert response.status_code == status
    assert set(response.json()) == {"code", "detail", "retryable"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status"),
    [
        (MemoryEvidenceNotFoundError(), 404),
        (MemoryAuthorizationError(), 404),
        (MemoryValidationError.single("field", "invalid"), 422),
        (MemoryDependencyError(), 503),
        (MemoryIntegrityError(), 500),
    ],
)
async def test_history_endpoint_maps_typed_failures_without_content(
    error: Exception,
    status: int,
) -> None:
    application, _, _, _ = _app(history_error=error)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get(
            f"/memories/{MEMORY_ID}/corrections",
            params={
                "actor_id": ACTOR_ID,
                "brain_id": BRAIN_ID,
                "grant_id": GRANT_ID,
                "project_id": PROJECT_ID,
                "repository_id": REPOSITORY_ID,
                "valid_at": "2026-07-21T12:02:00.000000Z",
                "recorded_at": "2026-07-21T12:02:00.000000Z",
            },
        )
    assert response.status_code == status
    assert set(response.json()) == {"code", "detail", "retryable"}


@pytest.mark.asyncio
async def test_history_endpoint_rejects_calendar_invalid_canonical_time() -> None:
    application, _, _, _ = _app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        response = await client.get(
            f"/memories/{MEMORY_ID}/corrections",
            params={
                "actor_id": ACTOR_ID,
                "brain_id": BRAIN_ID,
                "grant_id": GRANT_ID,
                "project_id": PROJECT_ID,
                "repository_id": REPOSITORY_ID,
                "valid_at": "2026-99-21T12:02:00.000000Z",
                "recorded_at": "2026-07-21T12:02:00.000000Z",
            },
        )
    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.e2e
async def test_authorized_http_correction_persists_and_governs_history_selection(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory = commit.memories[0]
        repository = SqliteMemoryCorrectionRepository(store)
        clock_time = memory.recorded_from + timedelta(seconds=8)
        clock = FixedClock(clock_time)
        application = FastAPI()
        application.include_router(
            create_memory_correction_router(
                _Auth(),
                CorrectMemoryHandler(
                    repository,
                    SqliteMemoryCorrectionUnitOfWorkFactory(store),
                    MemoryPrecedencePolicy(),
                    clock,
                ),
                GetMemoryCorrectionHistoryHandler(
                    repository,
                    MemoryPrecedencePolicy(),
                    clock,
                ),
                clock,
            )
        )
        request = _request()
        request.update(
            {
                "actor_id": commit.actor_id,
                "brain_id": commit.scope.brain_id,
                "grant_id": commit.grant_id,
                "scope": {
                    "brain_id": commit.scope.brain_id,
                    "project_id": commit.scope.project_id,
                    "repository_id": commit.scope.repository_id,
                    "checkout_id": None,
                },
                "requested_at": _time(clock_time - timedelta(seconds=1)),
                "deadline": _time(clock_time + timedelta(minutes=1)),
                "valid_from": _time(memory.valid_from),
            }
        )
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            corrected = await client.post(
                f"/memories/{memory.memory_id}/corrections",
                json=request,
            )
            history = await client.get(
                f"/memories/{memory.memory_id}/corrections",
                params={
                    "actor_id": commit.actor_id,
                    "brain_id": commit.scope.brain_id,
                    "grant_id": commit.grant_id,
                    "project_id": commit.scope.project_id,
                    "repository_id": commit.scope.repository_id,
                    "valid_at": _time(memory.valid_from + timedelta(seconds=1)),
                    "recorded_at": _time(clock_time),
                },
            )
    finally:
        await store.close()

    assert corrected.status_code == 201
    assert history.status_code == 200, history.text
    assert history.json()["selected"]["assertion_id"] == CORRECTION_ID
    assert history.json()["root"]["statement"] == memory.statement


def test_contract_router_exports_deterministic_correction_operations() -> None:
    schema = export_openapi_schema((create_contract_memory_correction_router(),))
    encoded = json.dumps(schema, separators=(",", ":"), sort_keys=True)
    assert '"operationId":"CorrectMemoryCommand"' in encoded
    assert '"operationId":"GetMemoryCorrectionHistoryQuery"' in encoded
    assert '"$ref":"#/components/schemas/CorrectionReceiptResponse"' in encoded


def _request() -> dict[str, object]:
    return {
        "operation_id": CORRECTION_ID,
        "actor_id": ACTOR_ID,
        "grant_id": GRANT_ID,
        "brain_id": BRAIN_ID,
        "correlation_id": CORRELATION_ID,
        "causation_id": CAUSATION_ID,
        "expected_version": 1,
        "statement": "Use SQLite",
        "scope": {
            "brain_id": BRAIN_ID,
            "project_id": PROJECT_ID,
            "repository_id": REPOSITORY_ID,
            "checkout_id": CHECKOUT_ID,
        },
        "valid_from": "2026-07-21T12:00:00.000000Z",
        "valid_to": None,
        "reason": "user_correction",
        "evidence_ids": [],
        "requested_at": "2026-07-21T12:00:00.000000Z",
        "deadline": "2026-07-21T12:05:00.000000Z",
    }


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
