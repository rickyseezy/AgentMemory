"""PRO-006 authenticated scheduling HTTP and deterministic contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.providers.adapters.scheduling_http_api import (
    create_contract_provider_scheduling_router,
    create_provider_scheduling_router,
)
from agentmemory.providers.application.scheduling import (
    CancelProviderWorkCommand,
    EnqueueProviderWorkCommand,
    GetProviderWorkQuery,
)
from agentmemory.providers.domain.errors import (
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingConflictError,
    ProviderSchedulingDependencyError,
)
from agentmemory.providers.domain.scheduling import ProviderWorkState
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID, FixedClock
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro006_scheduling_domain import item

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.providers.domain.scheduling import ProviderWorkItem


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            message = "provider scheduling is not authorized"
            raise ProviderSchedulingAuthorizationError(message)


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
class _Enqueue:
    result: ProviderWorkItem = field(default_factory=lambda: item(0))
    commands: list[EnqueueProviderWorkCommand] = field(
        default_factory=list[EnqueueProviderWorkCommand]
    )

    async def execute(self, command: EnqueueProviderWorkCommand) -> ProviderWorkItem:
        self.commands.append(command)
        return self.result


@dataclass(slots=True)
class _Get:
    result: ProviderWorkItem | None = field(default_factory=lambda: item(0))
    queries: list[GetProviderWorkQuery] = field(default_factory=list[GetProviderWorkQuery])

    async def execute(self, query: GetProviderWorkQuery) -> ProviderWorkItem | None:
        self.queries.append(query)
        return self.result


@dataclass(slots=True)
class _Cancel:
    result: ProviderWorkItem = field(
        default_factory=lambda: item(0).with_state(ProviderWorkState.CANCELLED)
    )
    commands: list[CancelProviderWorkCommand] = field(
        default_factory=list[CancelProviderWorkCommand]
    )

    async def execute(self, command: CancelProviderWorkCommand) -> ProviderWorkItem:
        self.commands.append(command)
        return self.result


def _scope_fields() -> dict[str, object]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _enqueue_body() -> dict[str, object]:
    work = item(0)
    return _scope_fields() | {
        "operation_id": "enqueue-provider-work-1",
        "profile_id": work.batch_key.profile_id,
        "profile_version": work.batch_key.profile_version,
        "space_id": work.batch_key.space_id,
        "space_fingerprint": work.batch_key.space_fingerprint,
        "classification": work.batch_key.classification.value,
        "purpose": work.batch_key.purpose.value,
        "retention_policy_digest": work.batch_key.retention_policy_digest,
        "preprocessing_digest": work.batch_key.preprocessing_digest,
        "deadline_class": work.batch_key.deadline_class.value,
        "workload": work.batch_key.workload.value,
        "ordinal": work.ordinal,
        "payload_ref": work.payload_ref,
        "content_digest": work.content_digest,
        "token_count": work.token_count,
        "byte_count": work.byte_count,
        "estimated_cost_micros": work.estimated_cost_micros,
        "deadline_at_microseconds": 1_900_000_000_000_000,
    }


def _app(
    authenticator: _Authenticator,
    resolver: _Resolver,
    enqueue: _Enqueue,
    get: _Get,
    cancel: _Cancel,
) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_provider_scheduling_router(
            authenticator,
            resolver,
            enqueue,
            get,
            cancel,
            FixedClock(),
        )
    )
    return application


@pytest.mark.asyncio
async def test_enqueue_authenticates_resolves_scope_and_returns_content_free_progress() -> None:
    enqueue = _Enqueue()
    app = _app(_Authenticator(), _Resolver(), enqueue, _Get(), _Cancel())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/work-items",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "enqueue-provider-work-1",
            },
            json=_enqueue_body(),
        )
    assert response.status_code == 202
    body = response.json()
    assert body["item_id"] == enqueue.result.item_id
    assert body["state"] == "queued"
    assert "payload_ref" not in body
    assert "content_digest" not in body
    assert "credential" not in json.dumps(body).lower()
    command = enqueue.commands[0]
    assert command.scope.action == "provider.schedule.enqueue"
    assert command.scope.purpose == "provider_scheduling"
    assert command.batch_key.document == item(0).batch_key.document
    assert command.deadline_at_microseconds == 1_900_000_000_000_000


@pytest.mark.asyncio
async def test_read_and_cancel_use_exact_actions_and_content_free_contract() -> None:
    get = _Get()
    cancel = _Cancel()
    app = _app(_Authenticator(), _Resolver(), _Enqueue(), get, cancel)
    query = "&".join(f"{key}={value}" for key, value in _scope_fields().items())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        read = await client.get(
            f"/v1/providers/work-items/{item(0).item_id}?{query}",
            headers={"Authorization": "Bearer valid"},
        )
        cancelled = await client.post(
            f"/v1/providers/work-items/{item(0).item_id}:cancel",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "cancel-provider-work-1",
            },
            json=_scope_fields() | {"operation_id": "cancel-provider-work-1"},
        )
    assert read.status_code == 200
    assert read.json()["state"] == "queued"
    assert get.queries[0].scope.action == "provider.schedule.read"
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    assert cancel.commands[0].scope.action == "provider.schedule.cancel"


@pytest.mark.asyncio
async def test_missing_item_is_not_found_without_cross_brain_detail() -> None:
    app = _app(_Authenticator(), _Resolver(), _Enqueue(), _Get(result=None), _Cancel())
    query = "&".join(f"{key}={value}" for key, value in _scope_fields().items())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.get(
            f"/v1/providers/work-items/{item(0).item_id}?{query}",
            headers={"Authorization": "Bearer valid"},
        )
    assert response.status_code == 404
    assert response.json()["detail"] == "provider work item was not found"


@pytest.mark.asyncio
async def test_authentication_and_idempotency_precede_scope_and_handlers() -> None:
    resolver = _Resolver()
    enqueue = _Enqueue()
    app = _app(_Authenticator(), resolver, enqueue, _Get(), _Cancel())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        unauthenticated = await client.post(
            "/v1/providers/work-items",
            headers={"Idempotency-Key": "enqueue-provider-work-1"},
            json=_enqueue_body(),
        )
        wrong_key = await client.post(
            "/v1/providers/work-items",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "wrong",
            },
            json=_enqueue_body(),
        )
    assert unauthenticated.status_code == 403
    assert wrong_key.status_code == 422
    assert resolver.calls == 0
    assert enqueue.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status"),
    [
        (ProviderSchedulingAuthorizationError("sensitive-auth-row-17"), 403),
        (ProviderSchedulingConflictError("sensitive-conflict-row-18"), 409),
        (ProviderSchedulingDependencyError("sensitive-dependency-row-19"), 503),
    ],
)
async def test_typed_errors_map_once_without_internal_details(
    error: Exception,
    status: int,
) -> None:
    @dataclass(slots=True)
    class _Failing:
        async def execute(self, command: EnqueueProviderWorkCommand) -> ProviderWorkItem:
            del command
            raise error

    app = _app(
        _Authenticator(),
        _Resolver(),
        _Failing(),  # type: ignore[arg-type]
        _Get(),
        _Cancel(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/work-items",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "enqueue-provider-work-1",
            },
            json=_enqueue_body(),
        )
    assert response.status_code == status
    assert str(error) not in response.text


def test_contract_router_is_side_effect_free_and_closed() -> None:
    application = FastAPI()
    application.include_router(create_contract_provider_scheduling_router())
    document = application.openapi()
    assert set(document["paths"]) == {
        "/v1/providers/work-items",
        "/v1/providers/work-items/{item_id}",
        "/v1/providers/work-items/{item_id}:cancel",
    }
    assert document["paths"]["/v1/providers/work-items"]["post"]["operationId"] == (
        "EnqueueProviderWorkCommand"
    )
