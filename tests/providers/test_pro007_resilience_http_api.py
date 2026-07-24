"""PRO-007 authenticated endpoint-equivalence HTTP contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema
from agentmemory.providers.adapters.resilience_http_api import (
    create_contract_provider_resilience_router,
    create_provider_resilience_router,
)
from agentmemory.providers.domain.errors import (
    ProviderResilienceAuthorizationError,
    ProviderResilienceConflictError,
    ProviderResilienceDependencyError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID, FixedClock
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro007_resilience_domain import equivalent_endpoints

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.providers.application.resilience import (
        GetEquivalentEndpointSetQuery,
        PublishEquivalentEndpointSetCommand,
    )
    from agentmemory.providers.domain.resilience import (
        EquivalentEndpointSet,
        ProviderEndpointAttestation,
    )


def _empty_publish_commands() -> list[PublishEquivalentEndpointSetCommand]:
    return []


def _empty_get_queries() -> list[GetEquivalentEndpointSetQuery]:
    return []


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            message = "provider resilience is not authorized"
            raise ProviderResilienceAuthorizationError(message)


@dataclass(slots=True)
class _Resolver:
    calls: int = 0

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        self.calls += 1
        resolved = scope("provider.profile.read")
        return RetrievalScopeResolution(
            resolved,
            ScopeExplanation(resolved.mode, ("brain_owner",)),
        )


@dataclass(slots=True)
class _Publish:
    result: EquivalentEndpointSet = field(default_factory=equivalent_endpoints)
    commands: list[PublishEquivalentEndpointSetCommand] = field(
        default_factory=_empty_publish_commands
    )
    error: Exception | None = None

    async def execute(
        self,
        command: PublishEquivalentEndpointSetCommand,
    ) -> EquivalentEndpointSet:
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


@dataclass(slots=True)
class _Get:
    result: EquivalentEndpointSet | None = field(default_factory=equivalent_endpoints)
    queries: list[GetEquivalentEndpointSetQuery] = field(default_factory=_empty_get_queries)
    error: Exception | None = None

    async def execute(
        self,
        query: GetEquivalentEndpointSetQuery,
    ) -> EquivalentEndpointSet | None:
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        return self.result


def _scope_fields() -> dict[str, object]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _endpoint_document(endpoint: ProviderEndpointAttestation) -> dict[str, object]:
    contract = endpoint.output_contract
    return {
        "profile_id": endpoint.profile_id,
        "profile_version": endpoint.profile_version,
        "capability_attestation_id": endpoint.capability_attestation_id,
        "endpoint_fingerprint": endpoint.endpoint_fingerprint,
        "configuration_digest": endpoint.configuration_digest,
        "adapter_digest": endpoint.adapter_digest,
        "output_contract": contract.document,
    }


def _publication_body() -> dict[str, object]:
    endpoints = equivalent_endpoints()
    return _scope_fields() | {
        "operation_id": "publish-equivalent-endpoints-1",
        "primary": _endpoint_document(endpoints.primary),
        "fallbacks": [_endpoint_document(item) for item in endpoints.fallbacks],
    }


def _app(
    authenticator: _Authenticator,
    resolver: _Resolver,
    publish: _Publish,
    get: _Get,
) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_provider_resilience_router(
            authenticator,
            resolver,
            publish,
            get,
            FixedClock(),
        )
    )
    return application


@pytest.mark.asyncio
async def test_publish_authenticates_resolves_action_and_returns_safe_evidence() -> None:
    authenticator = _Authenticator()
    resolver = _Resolver()
    publish = _Publish()
    app = _app(authenticator, resolver, publish, _Get())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/equivalent-endpoint-sets",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "publish-equivalent-endpoints-1",
            },
            json=_publication_body(),
        )

    assert response.status_code == 201
    body = response.json()
    assert body["set_id"] == equivalent_endpoints().set_id
    assert body["output_contract_digest"] == (equivalent_endpoints().primary.output_contract.digest)
    assert body["primary"]["attestation_digest"] == equivalent_endpoints().primary.digest
    assert len(body["fallbacks"]) == 1
    serialized = json.dumps(body).lower()
    assert "secret" not in serialized
    assert "credential" not in serialized
    assert "payload" not in serialized
    assert authenticator.calls == 1
    assert resolver.calls == 1
    assert publish.commands[0].scope.action == "provider.resilience.publish"
    assert publish.commands[0].scope.purpose == "provider_resilience"
    assert publish.commands[0].endpoints == equivalent_endpoints()


@pytest.mark.asyncio
async def test_authentication_and_idempotency_precede_scope_and_publication() -> None:
    resolver = _Resolver()
    publish = _Publish()
    app = _app(_Authenticator(), resolver, publish, _Get())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        unauthenticated = await client.post(
            "/v1/providers/equivalent-endpoint-sets",
            headers={"Idempotency-Key": "publish-equivalent-endpoints-1"},
            json=_publication_body(),
        )
        wrong_key = await client.post(
            "/v1/providers/equivalent-endpoint-sets",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "wrong",
            },
            json=_publication_body(),
        )

    assert unauthenticated.status_code == 403
    assert wrong_key.status_code == 422
    assert resolver.calls == 0
    assert publish.commands == []


@pytest.mark.asyncio
async def test_read_is_brain_scoped_content_free_and_missing_is_not_found() -> None:
    get = _Get()
    app = _app(_Authenticator(), _Resolver(), _Publish(), get)
    query = "&".join(f"{key}={value}" for key, value in _scope_fields().items())
    set_id = equivalent_endpoints().set_id

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        found = await client.get(
            f"/v1/providers/equivalent-endpoint-sets/{set_id}?{query}",
            headers={"Authorization": "Bearer valid"},
        )
        get.result = None
        missing = await client.get(
            f"/v1/providers/equivalent-endpoint-sets/{set_id}?{query}",
            headers={"Authorization": "Bearer valid"},
        )

    assert found.status_code == 200
    assert found.json()["set_id"] == set_id
    assert get.queries[0].scope.action == "provider.resilience.read"
    assert get.queries[0].scope.purpose == "provider_resilience"
    assert missing.status_code == 404
    assert missing.json()["detail"] == "provider endpoint equivalence was not found"


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (ProviderResilienceAuthorizationError("sensitive-auth-detail"), 403, "forbidden"),
        (ProviderResilienceConflictError("sensitive-conflict-detail"), 409, "conflict"),
        (
            ProviderResilienceDependencyError("sensitive-dependency-detail"),
            503,
            "dependency_unavailable",
        ),
    ],
)
@pytest.mark.asyncio
async def test_publication_maps_only_typed_content_free_problems(
    error: Exception,
    status: int,
    code: str,
) -> None:
    app = _app(
        _Authenticator(),
        _Resolver(),
        _Publish(error=error),
        _Get(),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/equivalent-endpoint-sets",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "publish-equivalent-endpoints-1",
            },
            json=_publication_body(),
        )

    assert response.status_code == status
    assert response.json()["type"] == f"urn:agentmemory:provider-resilience:{code}"
    assert str(error) not in response.text


def test_contract_router_is_deterministic_strict_and_declares_authentication() -> None:
    first = FastAPI()
    first.include_router(create_contract_provider_resilience_router())
    second = FastAPI()
    second.include_router(create_contract_provider_resilience_router())

    first_schema = first.openapi()
    assert first_schema == second.openapi()
    path = first_schema["paths"]["/v1/providers/equivalent-endpoint-sets"]["post"]
    assert path["operationId"] == "PublishEquivalentEndpointSetCommand"
    assert path["security"] == [{"AgentMemoryBearer": []}]
    request_schema = first_schema["components"]["schemas"][
        "PublishEquivalentEndpointSetRequestModel"
    ]
    assert request_schema["additionalProperties"] is False
    complete_paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert "/v1/providers/equivalent-endpoint-sets" in complete_paths
    assert "/v1/providers/equivalent-endpoint-sets/{set_id}" in complete_paths
