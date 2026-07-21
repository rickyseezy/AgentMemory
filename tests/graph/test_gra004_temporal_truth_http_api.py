"""GRA-004 authenticated temporal truth HTTP contract tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.graph.adapters.inbound.temporal_truth_http_api import (
    create_temporal_truth_router,
)
from agentmemory.graph.domain.errors import GraphUnavailableError
from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeQuery,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    RetrievalScopeMode,
    RetrievalScopeResolution,
    ScopeExplanation,
)
from tests.graph.test_gra004_temporal_truth_application import (
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _Revisions,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra004_temporal_truth_domain import NOW
from tests.identity.test_checkout_observation_sqlite import PROJECT_ID, REPOSITORY_ID

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.temporal_truth import (
        EvidenceRevisionAnchor,
        ResolvedVcsRevision,
        RevisionEvidenceProof,
        TemporalAssertionCandidate,
        TemporalAssertionCriteria,
        VcsRevisionBatch,
        VcsRevisionSelector,
    )

PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
GRANT_ID = "018f0000-0000-7000-8000-000000000003"
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"


@pytest.mark.asyncio
async def test_historical_route_returns_closed_explanation_after_auth_and_scope() -> None:
    authenticator = _Authenticator()
    resolver = _Resolver()
    assertions = _Assertions((_candidate(current=False),))
    async with _client(authenticator, resolver, assertions, _Revisions()) as client:
        response = await client.get(
            "/graph/assertions/truth",
            params={
                **_parameters(),
                "mode": "historical",
                "as_of_recorded": "2026-07-21T12:00:00Z",
                "branch": "main",
                "limit": "1",
            },
            headers={"Authorization": "Bearer local"},
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["status"] == "active"
    assert body[0]["explanation"]["currency"] == "historical"
    assert body[0]["explanation"]["currently_authoritative"] is False
    resolved = body[0]["explanation"]["resolved_revision"]
    assert resolved["branch"] == "main"
    assert resolved["resolved_commit"] == "4" * 40
    assert body[0]["explanation"]["evidence_proofs"][0]["applicability"] == "reachable"
    assert authenticator.calls == ["Bearer local"]
    assert len(resolver.queries) == 1
    assert assertions.scopes[0].action == "graph.assertion.truth.query"


@pytest.mark.asyncio
async def test_route_rejects_ambiguous_time_or_revision_and_sanitizes_dependency_error() -> None:
    async with _client(_Authenticator(), _Resolver(), _Assertions(()), _Revisions()) as client:
        implicit_history = await client.get(
            "/graph/assertions/truth",
            params={**_parameters(), "mode": "historical"},
        )
        qualified_current = await client.get(
            "/graph/assertions/truth",
            params={**_parameters(), "mode": "current", "branch": "main"},
        )
        two_revisions = await client.get(
            "/graph/assertions/truth",
            params={
                **_parameters(),
                "mode": "historical",
                "branch": "main",
                "commit": "4" * 40,
            },
        )
    assert implicit_history.status_code == 422
    assert qualified_current.status_code == 422
    assert two_revisions.status_code == 422

    failing = _FailingAssertions(GraphUnavailableError("sqlite path secret"))
    async with _client(_Authenticator(), _Resolver(), failing, _Revisions()) as client:
        unavailable = await client.get(
            "/graph/assertions/truth",
            params={**_parameters(), "mode": "current"},
        )
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "AM_DEPENDENCY_UNAVAILABLE"
    assert "sqlite path secret" not in unavailable.text


def test_temporal_truth_openapi_has_closed_mode_predicates_and_stable_operation() -> None:
    schema = _app(_Authenticator(), _Resolver(), _Assertions(()), _Revisions()).openapi()
    operation = schema["paths"]["/graph/assertions/truth"]["get"]
    assert operation["operationId"] == "QueryTemporalAssertions"
    names = {item["name"] for item in operation["parameters"]}
    assert {"mode", "predicates", "as_of_valid", "as_of_recorded", "branch", "commit"} <= names
    record = schema["paths"]["/graph/revisions/observations"]["post"]
    assert record["operationId"] == "RecordVcsRevisionBatch"


@pytest.mark.asyncio
async def test_revision_observation_route_authorizes_and_returns_digest_receipt() -> None:
    revisions = _RevisionService()
    resolver = _Resolver()
    payload: dict[str, object] = {
        **_parameters(),
        "nodes": [
            {"commit_sha": "1" * 40, "parent_shas": []},
            {"commit_sha": "2" * 40, "parent_shas": ["1" * 40]},
        ],
        "refs": [
            {
                "branch_name": "main",
                "commit_sha": "2" * 40,
                "observed_at": "2026-07-21T12:00:00Z",
            }
        ],
        "impacts": [],
        "observed_at": "2026-07-21T12:00:00Z",
        "source_digest": "c" * 64,
    }
    async with _client(_Authenticator(), resolver, _Assertions(()), revisions) as client:
        response = await client.post(
            "/graph/revisions/observations",
            headers={"Authorization": "Bearer local"},
            json=payload,
        )
    assert response.status_code == 201, response.text
    assert response.json() == {
        "operation_id": "truth-query-1",
        "batch_digest": revisions.batches[0].digest,
        "node_count": 2,
        "ref_count": 1,
        "impact_count": 0,
        "observed_at": "2026-07-21T12:00:00.000000Z",
    }
    assert revisions.scopes[0].action == "graph.vcs.revision.record"
    assert len(resolver.queries) == 1


def _app(
    authenticator: _Authenticator,
    resolver: _Resolver,
    assertions: object,
    revisions: object,
) -> FastAPI:
    app = FastAPI()
    app.include_router(
        create_temporal_truth_router(
            authenticator,
            resolver,
            assertions,  # type: ignore[arg-type]
            revisions,  # type: ignore[arg-type]
            revisions,  # type: ignore[arg-type]
            _Clock(),
        )
    )
    return app


def _client(
    authenticator: _Authenticator,
    resolver: _Resolver,
    assertions: object,
    revisions: object,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(authenticator, resolver, assertions, revisions)),
        base_url="http://testserver",
    )


def _parameters() -> dict[str, str]:
    return {
        "operation_id": "truth-query-1",
        "brain_id": BRAIN_ID,
        "actor_id": PRINCIPAL_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID.value,
        "repository_id": REPOSITORY_ID.value,
    }


@dataclass(slots=True)
class _Authenticator:
    calls: list[str | None] = field(default_factory=list[str | None])

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)


@dataclass(slots=True)
class _Resolver:
    queries: list[ResolveRetrievalScopeQuery] = field(
        default_factory=list[ResolveRetrievalScopeQuery]
    )

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        self.queries.append(query)
        return RetrievalScopeResolution(
            _scope("memory.recall"),
            ScopeExplanation(RetrievalScopeMode.CURRENT, (f"current:{PROJECT_ID.value}",)),
        )


@dataclass(slots=True)
class _FailingAssertions:
    error: Exception

    async def query(
        self,
        scope: AuthorizedScope,
        criteria: TemporalAssertionCriteria,
    ) -> tuple[object, ...]:
        del scope, criteria
        raise self.error


@dataclass(slots=True)
class _Assertions:
    candidates: tuple[TemporalAssertionCandidate, ...]
    scopes: list[AuthorizedScope] = field(default_factory=list[AuthorizedScope])

    async def query(
        self,
        scope: AuthorizedScope,
        criteria: TemporalAssertionCriteria,
    ) -> tuple[TemporalAssertionCandidate, ...]:
        del criteria
        self.scopes.append(scope)
        return self.candidates


def _batch_list() -> list[VcsRevisionBatch]:
    return []


@dataclass(slots=True)
class _RevisionService:
    delegate: _Revisions = field(default_factory=_Revisions)
    batches: list[VcsRevisionBatch] = field(default_factory=_batch_list)
    scopes: list[AuthorizedScope] = field(default_factory=list[AuthorizedScope])

    async def resolve(
        self,
        scope: AuthorizedScope,
        selector: VcsRevisionSelector,
        recorded_at: datetime,
    ) -> ResolvedVcsRevision:
        return await self.delegate.resolve(scope, selector, recorded_at)

    async def prove(
        self,
        scope: AuthorizedScope,
        evidence_id: str,
        anchor: EvidenceRevisionAnchor | None,
        resolved: ResolvedVcsRevision,
        recorded_at: datetime,
    ) -> RevisionEvidenceProof:
        return await self.delegate.prove(
            scope,
            evidence_id,
            anchor,
            resolved,
            recorded_at,
        )

    async def append(self, scope: AuthorizedScope, batch: VcsRevisionBatch) -> str:
        self.scopes.append(scope)
        self.batches.append(batch)
        return batch.digest


@dataclass(slots=True)
class _Clock:
    def now(self) -> datetime:
        return NOW
