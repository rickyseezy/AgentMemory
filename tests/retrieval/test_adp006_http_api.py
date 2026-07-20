"""ADP-006 authenticated StartSessionBriefingQuery transport tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.errors import IdentityAuthorizationError
from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.retrieval.adapters.inbound.host_delivery import (
    CertifiedDeliveryAdapterRegistry,
)
from agentmemory.retrieval.adapters.inbound.http_api import create_retrieval_router
from agentmemory.retrieval.application.start_session_briefing import (
    StartSessionBriefingHandler,
)
from agentmemory.retrieval.domain.continuity import (
    ContinuityItem,
    ContinuityKind,
    ItemProvenance,
)
from tests.core.support import FixedClock
from tests.retrieval.support import FakeContinuityRepository, FakeProcedureRepository, scope

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )

_NOW = datetime(2026, 7, 20, 10, 12, 13, tzinfo=UTC)


def _auth_values() -> list[str | None]:
    return []


def _scope_queries() -> list[ResolveRetrievalScopeQuery]:
    return []


@dataclass
class _Auth:
    values: list[str | None] = field(default_factory=_auth_values)

    async def authenticate(self, authorization: str | None) -> None:
        self.values.append(authorization)


@dataclass
class _ScopeResolver:
    denied: bool = False
    queries: list[ResolveRetrievalScopeQuery] = field(default_factory=_scope_queries)

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        self.queries.append(query)
        if self.denied:
            raise IdentityAuthorizationError
        authorized = scope()
        return RetrievalScopeResolution(
            authorized,
            ScopeExplanation(authorized.mode, ("current:project",)),
        )


def _item() -> ContinuityItem:
    return ContinuityItem(
        item_id="decision-auth",
        semantic_id="decision-auth",
        kind=ContinuityKind.DECISION,
        content="Keep auth in the shared user API client.",
        brain_id="018f0000-0000-7000-8000-000000000004",
        project_id="018f0000-0000-7000-8000-000000000010",
        repository_id="018f0000-0000-7000-8000-000000000020",
        checkout_id=None,
        branch_name="main",
        commit_sha="a" * 40,
        occurred_at=_NOW,
        ingested_at=_NOW,
        classification="internal",
        evidence_event_id="018f0000-0000-7000-8000-000000000101",
        provenance=ItemProvenance(
            "claude_code",
            "claude-sonnet",
            "agentmemory.claude-code",
            "1.0.0",
            "native",
        ),
    )


def _app(auth: _Auth, resolver: _ScopeResolver) -> FastAPI:
    app = FastAPI()
    handler = StartSessionBriefingHandler(
        FakeContinuityRepository((_item(),)), FakeProcedureRepository(())
    )
    app.include_router(
        create_retrieval_router(
            auth,
            resolver,
            CertifiedDeliveryAdapterRegistry(handler),
            FixedClock(_NOW),
        )
    )
    return app


def _request_body(consumer_host: str = "codex") -> dict[str, object]:
    return {
        "operation_id": "brief-session-1",
        "brain_id": "018f0000-0000-7000-8000-000000000004",
        "actor_id": "018f0000-0000-7000-8000-000000000002",
        "grant_id": "018f0000-0000-7000-8000-000000000003",
        "consumer_host": consumer_host,
        "consumer_platform": "darwin",
        "mode": "current",
        "current_project_id": "018f0000-0000-7000-8000-000000000010",
        "current_repository_id": "018f0000-0000-7000-8000-000000000020",
        "selected_project_ids": [],
        "budget": {"max_tokens": 1200, "max_items": 12, "max_bytes": 20480},
    }


@pytest.mark.asyncio
async def test_endpoint_authenticates_resolves_scope_and_preserves_original_provenance() -> None:
    auth = _Auth()
    resolver = _ScopeResolver()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(auth, resolver)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/recall:brief",
            json=_request_body(),
            headers={"Authorization": "Bearer local"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["consumer_host"] == "codex"
    assert body["media_type"] == "text/markdown"
    assert body["items"][0]["kind"] == "decision"
    assert body["items"][0]["provenance"] == {
        "producer_host": "claude_code",
        "model_id": "claude-sonnet",
        "adapter_id": "agentmemory.claude-code",
        "adapter_version": "1.0.0",
        "capture_method": "native",
    }
    assert "claude_code" in body["rendered_context"]
    assert auth.values == ["Bearer local"]
    assert resolver.queries[0].at == round(_NOW.timestamp() * 1_000_000)


@pytest.mark.asyncio
async def test_generic_host_receives_json_without_changing_selected_memory() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Auth(), _ScopeResolver())),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post("/recall:brief", json=_request_body("generic"))
    assert response.status_code == 200
    assert response.json()["media_type"] == "application/json"
    assert response.json()["items"][0]["item_id"] == "decision-auth"


@pytest.mark.asyncio
async def test_denied_scope_returns_content_free_forbidden() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Auth(), _ScopeResolver(denied=True))),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post("/recall:brief", json=_request_body())
    assert response.status_code == 403
    assert response.json() == {
        "code": "AM_FORBIDDEN",
        "detail": "briefing scope is not authorized",
        "retryable": False,
    }
    assert "shared user API" not in response.text


def test_openapi_exposes_normative_path_and_operation() -> None:
    schema = _app(_Auth(), _ScopeResolver()).openapi()
    operation = schema["paths"]["/recall:brief"]["post"]
    assert operation["operationId"] == "StartSessionBriefingQuery"
    assert (
        "consumer_host"
        in operation["requestBody"]["content"]["application/json"]["schema"].get("$ref", "")
        or operation["requestBody"]
    )
