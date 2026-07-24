"""PRO-008 authenticated migration HTTP and deterministic OpenAPI tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema
from agentmemory.providers.adapters.migration_http_api import (
    create_contract_embedding_migration_router,
    create_embedding_migration_router,
)
from agentmemory.providers.domain.errors import (
    EmbeddingMigrationAuthorizationError,
    EmbeddingMigrationConflictError,
    EmbeddingMigrationDependencyError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID, FixedClock
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro008_migration_domain import (
    MIGRATION_ID,
    SOURCE_GENERATION_ID,
    TARGET_GENERATION_ID,
    migration,
)

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.application.migration import (
        ActivateEmbeddingMigrationCommand,
        GetEmbeddingMigrationQuery,
        PlanEmbeddingMigrationByIdCommand,
    )
    from agentmemory.providers.domain.migration import EmbeddingGenerationMigration


def _plan_commands() -> list[PlanEmbeddingMigrationByIdCommand]:
    return []


def _get_queries() -> list[GetEmbeddingMigrationQuery]:
    return []


def _runner_calls() -> list[tuple[AuthorizedScope, str]]:
    return []


def _commands() -> list[object]:
    return []


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            message = "private auth"
            raise EmbeddingMigrationAuthorizationError(message)


@dataclass(slots=True)
class _Resolver:
    calls: int = 0

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        self.calls += 1
        resolved = scope("provider.embedding_migration.read")
        return RetrievalScopeResolution(
            resolved,
            ScopeExplanation(resolved.mode, ("brain_owner",)),
        )


@dataclass(slots=True)
class _Planner:
    result: EmbeddingGenerationMigration = field(default_factory=migration)
    commands: list[PlanEmbeddingMigrationByIdCommand] = field(default_factory=_plan_commands)
    error: Exception | None = None

    async def execute(
        self,
        command: PlanEmbeddingMigrationByIdCommand,
    ) -> EmbeddingGenerationMigration:
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


@dataclass(slots=True)
class _Getter:
    result: EmbeddingGenerationMigration | None = field(default_factory=migration)
    queries: list[GetEmbeddingMigrationQuery] = field(default_factory=_get_queries)

    async def execute(
        self,
        query: GetEmbeddingMigrationQuery,
    ) -> EmbeddingGenerationMigration | None:
        self.queries.append(query)
        return self.result


@dataclass(slots=True)
class _Runner:
    calls: list[tuple[AuthorizedScope, str]] = field(default_factory=_runner_calls)

    async def execute(
        self,
        scope: AuthorizedScope,
        migration_id: str,
    ) -> EmbeddingGenerationMigration:
        self.calls.append((scope, migration_id))
        return migration()


@dataclass(slots=True)
class _Commands:
    commands: list[object] = field(default_factory=_commands)

    async def execute(self, command: object) -> EmbeddingGenerationMigration:
        self.commands.append(command)
        return migration()


class _ScopedCommand(Protocol):
    scope: AuthorizedScope


def _scope_fields() -> dict[str, object]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _start_body() -> dict[str, object]:
    return _scope_fields() | {
        "operation_id": "pro008-start",
        "source_generation_id": SOURCE_GENERATION_ID,
        "target_generation_id": TARGET_GENERATION_ID,
    }


def _app(  # noqa: PLR0913 -- Test composition mirrors the explicit router boundary.
    authenticator: _Authenticator,
    resolver: _Resolver,
    planner: _Planner,
    getter: _Getter,
    runner: _Runner | None = None,
    commands: _Commands | None = None,
) -> FastAPI:
    application = FastAPI()
    lifecycle = commands or _Commands()
    application.include_router(
        create_embedding_migration_router(
            authenticator,
            resolver,
            planner,
            getter,
            runner or _Runner(),
            lifecycle,
            lifecycle,
            lifecycle,
            lifecycle,
            lifecycle,
            FixedClock(),
        )
    )
    return application


@pytest.mark.asyncio
async def test_start_authenticates_resolves_bindings_and_returns_safe_state() -> None:
    authenticator = _Authenticator()
    resolver = _Resolver()
    planner = _Planner()
    app = _app(authenticator, resolver, planner, _Getter())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/embedding-migrations",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "pro008-start",
            },
            json=_start_body(),
        )

    assert response.status_code == 201
    assert response.headers["etag"] == f'"embedding-migration:{MIGRATION_ID}:1"'
    assert response.json()["progress"]["source_watermark"] == 100
    assert planner.commands[0].scope.action == "provider.embedding_migration.plan"
    assert planner.commands[0].source_generation_id == SOURCE_GENERATION_ID
    serialized = json.dumps(response.json()).lower()
    assert "content_ref" not in serialized
    assert "vector" not in serialized
    assert "credential" not in serialized
    assert authenticator.calls == 1
    assert resolver.calls == 1


@pytest.mark.asyncio
async def test_status_and_every_lifecycle_route_bind_the_reviewed_action() -> None:
    runner = _Runner()
    commands = _Commands()
    getter = _Getter()
    app = _app(_Authenticator(), _Resolver(), _Planner(), getter, runner, commands)
    mutation = _scope_fields()
    query = "&".join(f"{key}={value}" for key, value in mutation.items())
    headers = {
        "Authorization": "Bearer valid",
        "If-Match": f'"embedding-migration:{MIGRATION_ID}:1"',
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        found = await client.get(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}?{query}",
            headers={"Authorization": "Bearer valid"},
        )
        run = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:run",
            headers={"Authorization": "Bearer valid"},
            json=mutation,
        )
        pause = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:pause",
            headers=headers,
            json=mutation,
        )
        resume = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:resume",
            headers=headers,
            json=mutation,
        )
        cutover = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:cutover",
            headers=headers
            | {
                "Idempotency-Key": "pro008-cutover",
            },
            json=mutation
            | {
                "operation_id": "pro008-cutover",
                "approval_id": GRANT_ID,
            },
        )
        rollback = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:rollback",
            headers={"Authorization": "Bearer valid"},
            json=mutation,
        )
        deletion = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:delete-source",
            headers={"Authorization": "Bearer valid"},
            json=mutation,
        )

    assert all(
        response.status_code == 200
        for response in (found, run, pause, resume, cutover, rollback, deletion)
    )
    assert getter.queries[0].scope.action == "provider.embedding_migration.read"
    assert runner.calls[0][0].action == "provider.embedding_migration.run"
    actions = [cast("_ScopedCommand", command).scope.action for command in commands.commands]
    assert actions == [
        "provider.embedding_migration.pause",
        "provider.embedding_migration.resume",
        "provider.embedding_migration.activate",
        "provider.embedding_migration.rollback",
        "provider.embedding_migration.delete",
    ]
    activation = cast("ActivateEmbeddingMigrationCommand", commands.commands[2])
    assert activation.expected_version == 1
    assert activation.approval_id == GRANT_ID


@pytest.mark.asyncio
async def test_authentication_idempotency_and_if_match_fail_before_use_cases() -> None:
    resolver = _Resolver()
    planner = _Planner()
    commands = _Commands()
    app = _app(_Authenticator(), resolver, planner, _Getter(), commands=commands)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        unauthenticated = await client.post(
            "/v1/providers/embedding-migrations",
            headers={"Idempotency-Key": "pro008-start"},
            json=_start_body(),
        )
        wrong_key = await client.post(
            "/v1/providers/embedding-migrations",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "wrong",
            },
            json=_start_body(),
        )
        stale_shape = await client.post(
            f"/v1/providers/embedding-migrations/{MIGRATION_ID}:pause",
            headers={
                "Authorization": "Bearer valid",
                "If-Match": '"embedding-migration:wrong:1"',
            },
            json=_scope_fields(),
        )

    assert unauthenticated.status_code == 403
    assert wrong_key.status_code == 422
    assert stale_shape.status_code == 422
    assert resolver.calls == 0
    assert planner.commands == []
    assert commands.commands == []


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (EmbeddingMigrationAuthorizationError("private"), 403, "forbidden"),
        (EmbeddingMigrationConflictError("private"), 409, "conflict"),
        (
            EmbeddingMigrationDependencyError("private"),
            503,
            "dependency_unavailable",
        ),
    ],
)
@pytest.mark.asyncio
async def test_typed_failures_are_content_free(
    error: Exception,
    status: int,
    code: str,
) -> None:
    app = _app(
        _Authenticator(),
        _Resolver(),
        _Planner(error=error),
        _Getter(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/embedding-migrations",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "pro008-start",
            },
            json=_start_body(),
        )

    assert response.status_code == status
    assert response.json()["type"].endswith(code)
    assert str(error) not in response.text


def test_contract_is_deterministic_strict_and_in_complete_core_openapi() -> None:
    first = FastAPI()
    first.include_router(create_contract_embedding_migration_router())
    second = FastAPI()
    second.include_router(create_contract_embedding_migration_router())
    schema = first.openapi()
    assert schema == second.openapi()
    start = schema["paths"]["/v1/providers/embedding-migrations"]["post"]
    assert start["operationId"] == "StartEmbeddingMigrationCommand"
    assert start["security"] == [{"AgentMemoryBearer": []}]
    request = schema["components"]["schemas"]["StartEmbeddingMigrationRequestModel"]
    assert request["additionalProperties"] is False
    paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    for path in schema["paths"]:
        assert path in paths
