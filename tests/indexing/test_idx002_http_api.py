"""IDX-002 authenticated indexing-run HTTP and OpenAPI contract tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution, ScopeExplanation
from agentmemory.indexing.adapters.inbound.http_api import (
    create_contract_indexing_router,
    create_indexing_router,
)
from agentmemory.indexing.domain.incremental import IndexPlan, IndexRun
from tests.core.support import BRAIN_ID, NOW, FixedClock
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import PROJECT_ID, REPOSITORY_ID

if TYPE_CHECKING:
    from agentmemory.indexing.application.incremental_index import (
        CancelIndexRunCommand,
        GetIndexRunQuery,
        StartIndexRunCommand,
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _run() -> IndexRun:
    return IndexRun.queue(
        operation_id="index-http-1",
        brain_id=BRAIN_ID,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        base_snapshot_id=None,
        target_snapshot_id=_digest("snapshot"),
        target_commit_id="abcdef1",
        working_digest=_digest("working"),
        implementation_fingerprint=_digest("implementation"),
        plan=IndexPlan(()),
        detected_at=NOW,
    )


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        assert authorization == "Bearer local"
        self.calls += 1


@dataclass(slots=True)
class _Resolver:
    actions: list[str] = field(default_factory=list[str])

    async def execute(self, query: object) -> RetrievalScopeResolution:
        del query
        scope = _scope("indexing.run.read")
        return RetrievalScopeResolution(
            scope,
            ScopeExplanation(scope.mode, ("repository",)),
        )


@dataclass(slots=True)
class _Start:
    run: IndexRun
    calls: int = 0

    async def execute(self, command: StartIndexRunCommand) -> IndexRun:
        assert command.scope.action == "indexing.run.start"
        self.calls += 1
        return self.run


@dataclass(slots=True)
class _Get:
    run: IndexRun

    async def execute(self, query: GetIndexRunQuery) -> IndexRun:
        assert query.scope.action == "indexing.run.read"
        return self.run


@dataclass(slots=True)
class _Cancel:
    run: IndexRun

    async def execute(self, command: CancelIndexRunCommand) -> IndexRun:
        assert command.scope.action == "indexing.run.cancel"
        return self.run.request_cancel(NOW)


def _application() -> tuple[FastAPI, _Start]:
    application = FastAPI()
    start = _Start(_run())
    application.include_router(
        create_indexing_router(
            _Authenticator(),
            _Resolver(),
            start,
            _Get(start.run),
            _Cancel(start.run),
            FixedClock(),
        )
    )
    return application, start


def _scope_body() -> dict[str, object]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": _scope("indexing.run.read").principal_id.value,
        "grant_id": "018f0000-0000-7000-8000-000000000003",
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


@pytest.mark.asyncio
async def test_start_requires_matching_idempotency_and_returns_content_free_progress() -> None:
    application, start = _application()
    body = {
        **_scope_body(),
        "operation_id": "index-http-1",
        "target_commit_id": "abcdef1",
        "include_generated": False,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        missing = await client.post(
            "/v1/indexing/runs",
            json=body,
            headers={"Authorization": "Bearer local"},
        )
        response = await client.post(
            "/v1/indexing/runs",
            json=body,
            headers={
                "Authorization": "Bearer local",
                "Idempotency-Key": "index-http-1",
            },
        )

    assert missing.status_code == 422
    assert response.status_code == 202
    assert response.json()["state"] == "queued"
    assert response.json()["coverage_micros"] == 1_000_000
    assert "relative_path" not in response.text
    assert start.calls == 1


@pytest.mark.asyncio
async def test_get_and_cancel_use_exact_operation_paths_and_actions() -> None:
    application, start = _application()
    run_id = start.run.id
    params = {key: str(value) for key, value in _scope_body().items()}
    cancel_body = {**_scope_body(), "operation_id": "cancel-http-1"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        status = await client.get(
            f"/v1/indexing/runs/{run_id}",
            params=params,
            headers={"Authorization": "Bearer local"},
        )
        cancelled = await client.post(
            f"/v1/indexing/runs/{run_id}:cancel",
            json=cancel_body,
            headers={
                "Authorization": "Bearer local",
                "Idempotency-Key": "cancel-http-1",
            },
        )

    assert status.status_code == 200
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelling"


def test_contract_openapi_has_required_paths_and_use_case_operation_ids() -> None:
    application = FastAPI()
    application.include_router(create_contract_indexing_router())
    schema = application.openapi()

    assert schema["paths"]["/v1/indexing/runs"]["post"]["operationId"] == "StartIndexRunCommand"
    assert schema["paths"]["/v1/indexing/runs/{run_id}"]["get"]["operationId"] == "GetIndexRunQuery"
    assert (
        schema["paths"]["/v1/indexing/runs/{run_id}:cancel"]["post"]["operationId"]
        == "CancelIndexRunCommand"
    )
