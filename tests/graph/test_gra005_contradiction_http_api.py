"""GRA-005 authenticated contradiction HTTP contract tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.graph.adapters.inbound.contradiction_http_api import create_contradiction_router
from agentmemory.graph.domain.assertions import AssertionPolarity
from agentmemory.graph.domain.errors import GraphUnavailableError
from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeMode,
    RetrievalScopeResolution,
    ScopeExplanation,
)
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra005_contradiction_application import (
    _Repository,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra005_contradiction_domain import (
    EVIDENCE_B,
    LEFT,
    NOW,
    RIGHT,
    _claim,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import PROJECT_ID, REPOSITORY_ID

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


@pytest.mark.asyncio
async def test_routes_detect_abstain_and_preserve_user_resolution() -> None:
    repository = _Repository(
        candidates=(
            _claim(LEFT),
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        )
    )
    async with _client(_Authenticator(), _Resolver(), repository) as client:
        detected = await client.post(
            "/graph/contradictions/detect",
            headers={"Authorization": "Bearer local"},
            json={**_scope_body("detect-1"), "detected_at": _time(NOW)},
        )
        assert detected.status_code == 201, detected.text
        contradiction_id = detected.json()[0]["contradiction_id"]
        evaluated = await client.post(
            "/graph/contradictions/evaluate",
            json={
                **_scope_body("evaluate-1"),
                "candidates": [
                    {"assertion_id": LEFT, "rank_basis_points": 10000, "authoritative": True},
                    {"assertion_id": RIGHT, "rank_basis_points": 1, "authoritative": True},
                ],
            },
        )
        resolved = await client.post(
            "/graph/contradictions/resolve",
            json={
                **_scope_body("resolve-1"),
                "contradiction_id": contradiction_id,
                "outcome": "left_assertion",
                "reason_code": "user_confirmed",
                "evidence_ids": [
                    "019f54aa-7777-7777-8777-777777777777",
                ],
                "resolved_at": "2026-07-21T10:00:00Z",
            },
        )
    assert detected.json()[0]["state"] == "unresolved"
    assert evaluated.status_code == 200
    assert evaluated.json()["decision"] == "unknown"
    assert resolved.status_code == 200
    assert resolved.json()["state"] == "resolved"
    assert resolved.json()["resolution"]["actor_id"] == OWNER_ID


@pytest.mark.asyncio
async def test_dependency_failures_are_content_safe_and_authentication_happens_first() -> None:
    authenticator = _Authenticator()
    repository = _FailingRepository(GraphUnavailableError("secret sqlite path"))
    async with _client(authenticator, _Resolver(), repository) as client:
        response = await client.post(
            "/graph/contradictions/detect",
            headers={"Authorization": "Bearer local"},
            json={**_scope_body("detect-fail"), "detected_at": _time(NOW)},
        )
    assert response.status_code == 503
    assert response.json()["code"] == "AM_DEPENDENCY_UNAVAILABLE"
    assert "secret sqlite path" not in response.text
    assert authenticator.calls == ["Bearer local"]


def test_openapi_exposes_closed_detection_resolution_and_policy_contracts() -> None:
    schema = _app(_Authenticator(), _Resolver(), _Repository()).openapi()
    paths = schema["paths"]
    assert paths["/graph/contradictions/detect"]["post"]["operationId"] == "DetectContradictions"
    assert paths["/graph/contradictions/resolve"]["post"]["operationId"] == "ResolveContradiction"
    assert (
        paths["/graph/contradictions/evaluate"]["post"]["operationId"] == "EvaluateContradictions"
    )


def _app(authenticator: object, resolver: object, repository: object) -> FastAPI:
    app = FastAPI()
    app.include_router(
        create_contradiction_router(
            authenticator,  # type: ignore[arg-type]
            resolver,  # type: ignore[arg-type]
            repository,  # type: ignore[arg-type]
            _Clock(),
        )
    )
    return app


def _client(authenticator: object, resolver: object, repository: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(authenticator, resolver, repository)),
        base_url="http://testserver",
    )


def _scope_body(operation_id: str) -> dict[str, str]:
    return {
        "operation_id": operation_id,
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID.value,
        "repository_id": REPOSITORY_ID.value,
    }


def _time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class _Authenticator:
    calls: list[str | None] = field(default_factory=list[str | None])

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)


def _queries() -> list[ResolveRetrievalScopeQuery]:
    return []


@dataclass(slots=True)
class _Resolver:
    queries: list[ResolveRetrievalScopeQuery] = field(default_factory=_queries)

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        self.queries.append(query)
        return RetrievalScopeResolution(
            _scope("memory.recall"),
            ScopeExplanation(RetrievalScopeMode.CURRENT, (f"current:{PROJECT_ID.value}",)),
        )


@dataclass(slots=True)
class _Clock:
    def now(self) -> datetime:
        return NOW


@dataclass(slots=True)
class _FailingRepository:
    error: Exception

    async def detection_candidates(
        self, scope: AuthorizedScope, repository_id: str
    ) -> tuple[object, ...]:
        del scope, repository_id
        raise self.error
