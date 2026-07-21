"""GRA-001 authenticated exact-entity HTTP boundary tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.graph.adapters.inbound.http_api import create_graph_router
from agentmemory.graph.domain.errors import GraphUnavailableError
from agentmemory.graph.domain.models import (
    GraphClassification,
    GraphEntity,
    GraphEntityQuery,
    GraphEntityType,
)
from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeQuery,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    RetrievalScopeResolution,
    ScopeExplanation,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from agentmemory.graph.domain.ports import AuthorizedGraphQuery, GraphProjectionWriter

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
GRANT_ID = "018f0000-0000-7000-8000-000000000003"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
ENTITY_ID = "018f0000-0000-7000-8000-000000000030"


@pytest.mark.asyncio
async def test_exact_entity_route_authenticates_resolves_scope_and_returns_closed_schema() -> None:
    repository = _Repository(_entity())
    authenticator = _Authenticator()
    resolver = _Resolver()
    async with _client(repository, authenticator, resolver) as client:
        response = await client.get(
            f"/graph/entities/{ENTITY_ID}",
            params=_parameters(),
            headers={"Authorization": "Bearer local"},
        )
    assert response.status_code == 200
    assert response.json() == {
        "id": ENTITY_ID,
        "brain_id": BRAIN_ID,
        "entity_type": "File",
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "checkout_id": None,
        "schema_version": 1,
        "created_at": "2026-07-21T12:00:00.000000Z",
        "recorded_from": "2026-07-21T12:00:00.000000Z",
        "recorded_to": None,
        "classification": "internal",
        "content_fingerprint": "a" * 64,
        "revision_id": _entity().revision_id,
    }
    assert authenticator.calls == ["Bearer local"]
    assert len(resolver.queries) == 1
    assert repository.scopes[0].action == "graph.read"
    assert repository.queries[0].entity_type is GraphEntityType.FILE


@pytest.mark.asyncio
async def test_not_found_malicious_label_and_dependency_errors_are_content_safe() -> None:
    async with _client(_Repository(None), _Authenticator(), _Resolver()) as client:
        not_found = await client.get(f"/graph/entities/{ENTITY_ID}", params=_parameters())
    assert not_found.status_code == 404
    assert not_found.json()["code"] == "AM_NOT_FOUND"

    parameters = _parameters()
    parameters["entity_type"] = "File) MATCH (secret) RETURN secret //"
    async with _client(_Repository(None), _Authenticator(), _Resolver()) as client:
        malicious = await client.get(f"/graph/entities/{ENTITY_ID}", params=parameters)
    assert malicious.status_code == 422

    async with _client(
        _Repository(GraphUnavailableError("bolt secret")), _Authenticator(), _Resolver()
    ) as client:
        unavailable = await client.get(f"/graph/entities/{ENTITY_ID}", params=_parameters())
    assert unavailable.status_code == 503
    assert unavailable.json() == {
        "code": "AM_DEPENDENCY_UNAVAILABLE",
        "detail": "graph dependency is unavailable",
        "retryable": True,
    }
    assert "bolt secret" not in unavailable.text


def test_graph_openapi_uses_application_operation_id_and_closed_label_enum() -> None:
    schema = _app(_Repository(None), _Authenticator(), _Resolver()).openapi()
    operation = schema["paths"]["/graph/entities/{entity_id}"]["get"]
    assert operation["operationId"] == "GetGraphEntityQuery"
    entity_parameter = next(
        item for item in operation["parameters"] if item["name"] == "entity_type"
    )
    assert "$ref" in entity_parameter["schema"]


def _app(
    repository: _Repository,
    authenticator: _Authenticator,
    resolver: _Resolver,
) -> FastAPI:
    app = FastAPI()
    app.include_router(create_graph_router(authenticator, resolver, repository, _Clock()))
    return app


def _client(
    repository: _Repository,
    authenticator: _Authenticator,
    resolver: _Resolver,
) -> httpx.AsyncClient:
    app = _app(repository, authenticator, resolver)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


def _parameters() -> dict[str, str]:
    return {
        "entity_type": "File",
        "operation_id": "graph-read-1",
        "brain_id": BRAIN_ID,
        "actor_id": PRINCIPAL_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _entity() -> GraphEntity:
    return GraphEntity.create(
        entity_id=ENTITY_ID,
        brain_id=BRAIN_ID,
        entity_type=GraphEntityType.FILE,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        checkout_id=None,
        schema_version=1,
        created_at=NOW,
        recorded_from=NOW,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint="a" * 64,
    )


def _scope() -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(PRINCIPAL_ID),
        role=RetrievalRole.READER,
        mode=RetrievalScopeMode.CURRENT,
        members=(ScopeMember(StableId(PROJECT_ID), (StableId(REPOSITORY_ID),), ()),),
        classification_ceiling=Classification.INTERNAL,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action="memory.recall",
        purpose="interactive_recall",
    )


@dataclass
class _Authenticator:
    calls: list[str | None] = field(default_factory=list[str | None])

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)


@dataclass
class _Resolver:
    queries: list[ResolveRetrievalScopeQuery] = field(
        default_factory=list[ResolveRetrievalScopeQuery]
    )

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        self.queries.append(query)
        return RetrievalScopeResolution(
            _scope(),
            ScopeExplanation(RetrievalScopeMode.CURRENT, (f"current:{PROJECT_ID}",)),
        )


@dataclass
class _Repository:
    result: GraphEntity | Exception | None
    scopes: list[AuthorizedScope] = field(default_factory=list[AuthorizedScope])
    queries: list[GraphEntityQuery] = field(default_factory=list[GraphEntityQuery])

    def writer(self, scope: AuthorizedScope) -> GraphProjectionWriter:
        self.scopes.append(scope)
        return cast("GraphProjectionWriter", self)

    def query(self, scope: AuthorizedScope) -> AuthorizedGraphQuery:
        self.scopes.append(scope)
        return cast("AuthorizedGraphQuery", self)

    async def get_entity(self, query: GraphEntityQuery) -> GraphEntity | None:
        self.queries.append(query)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@dataclass
class _Clock:
    def now(self) -> datetime:
        return NOW
