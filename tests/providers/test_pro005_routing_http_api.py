"""PRO-005 authenticated routing HTTP and deterministic OpenAPI tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.providers.adapters.routing_http_api import (
    create_contract_provider_routing_router,
    create_provider_routing_router,
)
from agentmemory.providers.domain.errors import (
    ProviderRoutingAuthorizationError,
    ProviderRoutingConflictError,
    ProviderRoutingDependencyError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID, FixedClock
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro005_routing_domain import (
    policy,
    profile,
    request,
    restriction,
)

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.providers.application.routing import (
        CreateProviderRouteCommand,
        ResolveProviderRouteQuery,
        RestrictProviderRoutingCommand,
    )
    from agentmemory.providers.domain.routing import (
        ProviderRoutingPolicy,
        RepositoryRoutingRestriction,
        RouteDecision,
    )


def _create_commands() -> list[CreateProviderRouteCommand]:
    return []


def _restriction_commands() -> list[RestrictProviderRoutingCommand]:
    return []


def _resolve_queries() -> list[ResolveProviderRouteQuery]:
    return []


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            message = "provider routing action is not authorized"
            raise ProviderRoutingAuthorizationError(message)


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
class _Create:
    result: ProviderRoutingPolicy = field(default_factory=policy)
    error: Exception | None = None
    commands: list[CreateProviderRouteCommand] = field(default_factory=_create_commands)

    async def execute(
        self,
        command: CreateProviderRouteCommand,
    ) -> ProviderRoutingPolicy:
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


@dataclass(slots=True)
class _Restrict:
    result: RepositoryRoutingRestriction = field(
        default_factory=lambda: replace(
            restriction(),
            repository_id=REPOSITORY_ID,
        )
    )
    commands: list[RestrictProviderRoutingCommand] = field(default_factory=_restriction_commands)

    async def execute(
        self,
        command: RestrictProviderRoutingCommand,
    ) -> RepositoryRoutingRestriction:
        self.commands.append(command)
        return self.result


@dataclass(slots=True)
class _Resolve:
    result: RouteDecision = field(default_factory=lambda: policy().decide(request(), (profile(),)))
    commands: list[ResolveProviderRouteQuery] = field(default_factory=_resolve_queries)

    async def execute(self, query: ResolveProviderRouteQuery) -> RouteDecision:
        self.commands.append(query)
        return self.result


def _scope_body(operation_id: str) -> dict[str, object]:
    return {
        "operation_id": operation_id,
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _policy_body() -> dict[str, object]:
    return _scope_body("publish-routing-001") | {
        "expected_current_version": 0,
        "guard": {
            "allow_remote": True,
            "allowed_remote_residencies": ["AE", "global"],
            "remote_classification_ceiling": "confidential",
        },
        "routes": [
            {
                "draft_key": "code.interactive",
                "profile_id": profile().profile_id,
                "operation": "embedding",
                "selector": {
                    "corpus": "code",
                    "language": "python",
                    "purpose": "code_query",
                    "workload": "interactive",
                },
                "enabled": True,
                "reason": "code.interactive",
            }
        ],
    }


def _restriction_body() -> dict[str, object]:
    return _scope_body("restrict-routing-001") | {
        "expected_current_version": 0,
        "allow_remote": True,
        "allowed_remote_residencies": ["AE"],
        "remote_classification_ceiling": "internal",
        "allowed_profile_ids": [profile().profile_id],
        "allowed_purposes": ["code_query"],
        "allowed_workloads": ["interactive"],
    }


def _resolve_body() -> dict[str, object]:
    return _scope_body("resolve-routing-001") | {
        "operation": "embedding",
        "corpus": "code",
        "language": "python",
        "classification": "internal",
        "purpose": "code_query",
        "workload": "interactive",
    }


def _app(
    authenticator: _Authenticator,
    resolver: _Resolver,
    create_handler: _Create,
    restrict_handler: _Restrict,
    resolve_handler: _Resolve,
) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_provider_routing_router(
            authenticator,
            resolver,
            create_handler,
            restrict_handler,
            resolve_handler,
            FixedClock(),
        )
    )
    return application


@pytest.mark.asyncio
async def test_policy_publication_authenticates_binds_scope_and_returns_safe_contract() -> None:
    create_handler = _Create()
    app = _app(_Authenticator(), _Resolver(), create_handler, _Restrict(), _Resolve())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/routing/policies",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "publish-routing-001",
            },
            json=_policy_body(),
        )
    assert response.status_code == 201
    body = response.json()
    result = create_handler.result
    assert body == {
        "policy_id": result.policy_id,
        "brain_id": result.brain_id,
        "version": result.version,
        "policy_digest": result.digest,
        "guard": {
            "allow_remote": result.guard.allow_remote,
            "allowed_remote_residencies": list(result.guard.allowed_remote_residencies),
            "remote_classification_ceiling": result.guard.remote_classification_ceiling.value,
        },
        "rules": [
            {
                "rule_id": rule.rule_id,
                "profile_id": rule.profile_id,
                "profile_version": rule.profile_version,
                "profile_snapshot_digest": rule.profile_snapshot_digest,
                "operation": rule.operation.value,
                "selector": rule.selector.document,
                "enabled": rule.enabled,
                "reason": rule.reason,
                "precedence": list(rule.selector.precedence),
            }
            for rule in result.rules
        ],
        "created_at": result.created_at.isoformat(),
    }
    assert "credential" not in json.dumps(body).lower()
    command = create_handler.commands[0]
    assert command.operation_id == "publish-routing-001"
    assert command.expected_current_version == 0
    assert command.scope.action == "provider.route.publish"
    assert command.scope.purpose == "provider_routing_administration"
    assert command.guard.document == {
        "allow_remote": True,
        "allowed_remote_residencies": ["AE", "global"],
        "remote_classification_ceiling": "confidential",
    }
    assert len(command.routes) == 1
    draft = command.routes[0]
    assert draft.draft_key == "code.interactive"
    assert draft.profile_id == profile().profile_id
    assert draft.operation.value == "embedding"
    assert draft.selector.document == {
        "project_id": None,
        "corpus": "code",
        "language": "python",
        "classification": None,
        "purpose": "code_query",
        "workload": "interactive",
    }
    assert draft.enabled is True
    assert draft.reason == "code.interactive"


@pytest.mark.asyncio
async def test_restriction_and_resolution_expose_exact_versioned_contracts() -> None:
    restrict_handler = _Restrict()
    resolve_handler = _Resolve()
    app = _app(
        _Authenticator(),
        _Resolver(),
        _Create(),
        restrict_handler,
        resolve_handler,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        restricted = await client.post(
            "/v1/providers/routing/repository-restrictions",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "restrict-routing-001",
            },
            json=_restriction_body(),
        )
        resolved = await client.post(
            "/v1/providers/routes:resolve",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "resolve-routing-001",
            },
            json=_resolve_body(),
        )
    assert restricted.status_code == 201
    restriction_result = restrict_handler.result
    assert restricted.json() == {
        "restriction_id": restriction_result.restriction_id,
        "brain_id": restriction_result.brain_id,
        "repository_id": restriction_result.repository_id,
        "version": restriction_result.version,
        "restriction_digest": restriction_result.digest,
        "allow_remote": restriction_result.allow_remote,
        "allowed_remote_residencies": list(restriction_result.allowed_remote_residencies),
        "remote_classification_ceiling": (restriction_result.remote_classification_ceiling.value),
        "allowed_profile_ids": list(restriction_result.allowed_profile_ids),
        "allowed_purposes": [value.value for value in restriction_result.allowed_purposes],
        "allowed_workloads": [value.value for value in restriction_result.allowed_workloads],
    }
    assert resolved.status_code == 200
    decision = resolve_handler.result
    assert resolved.json() == {
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "rule_id": decision.rule_id,
        "profile_id": decision.profile_id,
        "profile_version": decision.profile_version,
        "profile_snapshot_digest": decision.profile_snapshot_digest,
        "precedence": list(decision.precedence),
        "reason": decision.reason,
        "request_digest": decision.request_digest,
    }
    assert resolve_handler.commands[0].request.repository_id == REPOSITORY_ID
    assert resolve_handler.commands[0].scope.action == "provider.route.resolve"
    restriction_command = restrict_handler.commands[0]
    assert restriction_command.operation_id == "restrict-routing-001"
    assert restriction_command.repository_id == REPOSITORY_ID
    assert restriction_command.expected_current_version == 0
    assert restriction_command.allow_remote is True
    assert restriction_command.allowed_remote_residencies == ("AE",)
    assert restriction_command.remote_classification_ceiling.value == "internal"
    assert restriction_command.allowed_profile_ids == (profile().profile_id,)
    assert tuple(value.value for value in restriction_command.allowed_purposes) == ("code_query",)
    assert tuple(value.value for value in restriction_command.allowed_workloads) == ("interactive",)
    route_query = resolve_handler.commands[0]
    assert route_query.operation_id == "resolve-routing-001"
    assert route_query.request.document == {
        "brain_id": BRAIN_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "operation": "embedding",
        "corpus": "code",
        "language": "python",
        "classification": "internal",
        "purpose": "code_query",
        "workload": "interactive",
    }


@pytest.mark.asyncio
async def test_bad_idempotency_stops_before_scope_and_handler() -> None:
    resolver = _Resolver()
    create_handler = _Create()
    app = _app(_Authenticator(), resolver, create_handler, _Restrict(), _Resolve())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/routing/policies",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "wrong",
            },
            json=_policy_body(),
        )
    assert response.status_code == 422
    assert resolver.calls == 0
    assert create_handler.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/v1/providers/routing/repository-restrictions",
            _restriction_body,
        ),
        (
            "/v1/providers/routes:resolve",
            _resolve_body,
        ),
    ],
)
async def test_every_routing_endpoint_requires_exact_idempotency(
    path: str,
    body: object,
) -> None:
    resolver = _Resolver()
    app = _app(_Authenticator(), resolver, _Create(), _Restrict(), _Resolve())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            path,
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "wrong",
            },
            json=body(),  # type: ignore[operator]
        )
    assert response.status_code == 422
    assert resolver.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (ProviderRoutingAuthorizationError("raw authority"), 403, "forbidden"),
        (ProviderRoutingConflictError("raw routing document"), 409, "conflict"),
        (
            ProviderRoutingDependencyError("raw sqlite failure"),
            503,
            "dependency_unavailable",
        ),
    ],
)
async def test_typed_failures_are_content_free(
    error: Exception,
    status: int,
    code: str,
) -> None:
    create_handler = _Create(error=error)
    app = _app(_Authenticator(), _Resolver(), create_handler, _Restrict(), _Resolve())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/routing/policies",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "publish-routing-001",
            },
            json=_policy_body(),
        )
    assert response.status_code == status
    body = response.json()
    assert body == {
        "type": f"urn:agentmemory:provider-routing:{code}",
        "title": code.replace("_", " "),
        "status": status,
        "detail": "provider routing operation could not be completed",
    }
    encoded = json.dumps(body, sort_keys=True)
    assert str(error) not in encoded
    assert "routes" not in encoded


def test_contract_router_publishes_all_strict_content_free_routes() -> None:
    application = FastAPI()
    application.include_router(create_contract_provider_routing_router())
    first = json.dumps(application.openapi(), separators=(",", ":"), sort_keys=True)
    application.openapi_schema = None
    second = json.dumps(application.openapi(), separators=(",", ":"), sort_keys=True)
    assert first == second
    schema = json.loads(first)
    assert {
        "/v1/providers/routing/policies",
        "/v1/providers/routing/repository-restrictions",
        "/v1/providers/routes:resolve",
    } <= set(schema["paths"])
    assert (
        schema["paths"]["/v1/providers/routing/policies"]["post"]["operationId"]
        == "CreateProviderRouteCommand"
    )
    responses = {
        name: value
        for name, value in schema["components"]["schemas"].items()
        if "Response" in name or "Decision" in name
    }
    assert "credential" not in json.dumps(responses).lower()
