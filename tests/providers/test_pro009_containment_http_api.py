"""PRO-009 authenticated provider-egress policy HTTP contract tests."""

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
from agentmemory.providers.adapters.containment_http_api import (
    create_contract_provider_containment_router,
    create_provider_containment_router,
)
from agentmemory.providers.domain.errors import ProviderContainmentAuthorizationError
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID, FixedClock, digest
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro009_containment_domain import policy

_ERR_AUTH = "private detail"

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.providers.application.containment import (
        GetProviderEgressPolicyQuery,
        PublishProviderEgressPolicyCommand,
    )
    from agentmemory.providers.domain.containment import ProviderEgressPolicy


def _commands() -> list[PublishProviderEgressPolicyCommand]:
    return []


def _queries() -> list[GetProviderEgressPolicyQuery]:
    return []


@dataclass(slots=True)
class Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            raise ProviderContainmentAuthorizationError(_ERR_AUTH)


@dataclass(slots=True)
class Resolver:
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
class Publish:
    commands: list[PublishProviderEgressPolicyCommand] = field(default_factory=_commands)

    async def execute(
        self,
        command: PublishProviderEgressPolicyCommand,
    ) -> ProviderEgressPolicy:
        self.commands.append(command)
        return command.policy


@dataclass(slots=True)
class Get:
    result: ProviderEgressPolicy | None
    queries: list[GetProviderEgressPolicyQuery] = field(default_factory=_queries)

    async def execute(
        self,
        query: GetProviderEgressPolicyQuery,
    ) -> ProviderEgressPolicy | None:
        self.queries.append(query)
        return self.result


def value() -> ProviderEgressPolicy:
    return policy(brain_id=BRAIN_ID)


def scope_fields() -> dict[str, object]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def publication() -> dict[str, object]:
    return {
        **scope_fields(),
        **value().document,
        "operation_id": "publish-egress-policy-1",
        "request_digest": digest("policy-request").value,
    }


def app(
    authenticator: Authenticator,
    resolver: Resolver,
    publish: Publish,
    get: Get,
) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_provider_containment_router(
            authenticator,
            resolver,
            publish,
            get,
            FixedClock(),
        )
    )
    return application


@pytest.mark.asyncio
async def test_publish_authenticates_resolves_exact_action_and_returns_safe_policy() -> None:
    authenticator = Authenticator()
    resolver = Resolver()
    publish = Publish()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app(authenticator, resolver, publish, Get(value()))),
        base_url="http://test",
    ) as client:
        response = await client.put(
            "/v1/providers/egress-policy",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "publish-egress-policy-1",
            },
            json=publication(),
        )

    assert response.status_code == 200
    assert response.json()["policy_digest"] == value().digest
    assert publish.commands[0].scope.action == "provider.containment.manage"
    assert publish.commands[0].scope.purpose == "provider_containment"
    assert publish.commands[0].request_digest == digest("policy-request").value
    assert authenticator.calls == 1
    assert resolver.calls == 1
    serialized = json.dumps(response.json()).lower()
    assert "credential" not in serialized
    assert "payload" not in serialized
    assert "raw_vector" not in serialized


@pytest.mark.asyncio
async def test_authentication_and_idempotency_fail_before_scope_or_repository() -> None:
    resolver = Resolver()
    publish = Publish()
    application = app(Authenticator(), resolver, publish, Get(value()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        unauthenticated = await client.put(
            "/v1/providers/egress-policy",
            headers={"Idempotency-Key": "publish-egress-policy-1"},
            json=publication(),
        )
        wrong_key = await client.put(
            "/v1/providers/egress-policy",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "wrong"},
            json=publication(),
        )

    assert unauthenticated.status_code == 403
    assert "private detail" not in unauthenticated.text
    assert wrong_key.status_code == 422
    assert resolver.calls == 0
    assert publish.commands == []


@pytest.mark.asyncio
async def test_read_is_authorized_and_missing_policy_is_explicit() -> None:
    get = Get(value())
    query = "&".join(f"{key}={value}" for key, value in scope_fields().items())
    application = app(Authenticator(), Resolver(), Publish(), get)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        found = await client.get(
            f"/v1/providers/egress-policy?{query}",
            headers={"Authorization": "Bearer valid"},
        )
        get.result = None
        missing = await client.get(
            f"/v1/providers/egress-policy?{query}",
            headers={"Authorization": "Bearer valid"},
        )

    assert found.status_code == 200
    assert get.queries[0].scope.action == "provider.containment.read"
    assert missing.status_code == 404
    assert missing.json()["detail"] == "provider egress policy was not found"


def test_contract_is_strict_deterministic_authenticated_and_in_complete_openapi() -> None:
    first = FastAPI()
    first.include_router(create_contract_provider_containment_router())
    second = FastAPI()
    second.include_router(create_contract_provider_containment_router())

    schema = first.openapi()
    assert schema == second.openapi()
    operation = schema["paths"]["/v1/providers/egress-policy"]["put"]
    assert operation["operationId"] == "PublishProviderEgressPolicyCommand"
    assert operation["security"] == [{"AgentMemoryBearer": []}]
    request_schema = schema["components"]["schemas"]["PublishProviderEgressPolicyRequestModel"]
    assert request_schema["additionalProperties"] is False
    complete_paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert "/v1/providers/egress-policy" in complete_paths
