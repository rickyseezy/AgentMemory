"""PRO-004 authenticated embedding-space HTTP and OpenAPI contract tests."""

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
from agentmemory.providers.adapters.embedding_space_http_api import (
    create_contract_embedding_space_router,
    create_embedding_space_router,
)
from agentmemory.providers.application.embedding_spaces import EnsureIndexGenerationCommand
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, NOW, OWNER_ID, FixedClock, digest
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro004_embedding_spaces_domain import (
    PROFILE_ID,
    descriptor,
    generation,
    space,
)

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.providers.domain.embedding_spaces import IndexGeneration


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            message = "embedding space action is not authorized"
            raise EmbeddingSpaceAuthorizationError(message)


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
class _Ensure:
    result: IndexGeneration = field(default_factory=lambda: generation(space()))
    error: Exception | None = None
    commands: list[EnsureIndexGenerationCommand] = field(
        default_factory=list[EnsureIndexGenerationCommand]
    )

    async def execute(self, command: EnsureIndexGenerationCommand) -> IndexGeneration:
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


def _body() -> dict[str, object]:
    descriptor_document = dict(descriptor().document)
    descriptor_document.pop("descriptor_version")
    descriptor_document.pop("operation")
    return {
        "operation_id": "ensure-space-001",
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "profile_id": PROFILE_ID,
        "capability_attestation_id": digest("attestation").value,
        "descriptor": descriptor_document,
    }


def _app(
    authenticator: _Authenticator,
    resolver: _Resolver,
    handler: _Ensure,
) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_embedding_space_router(authenticator, resolver, handler, FixedClock())
    )
    return application


@pytest.mark.asyncio
async def test_ensure_generation_authenticates_resolves_admin_scope_and_returns_safe_contract() -> (
    None
):
    authenticator = _Authenticator()
    resolver = _Resolver()
    handler = _Ensure()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(authenticator, resolver, handler)),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/embedding-spaces/generations",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "ensure-space-001",
            },
            json=_body(),
        )
    assert response.status_code == 201
    assert response.json() == {
        "generation_id": handler.result.generation_id,
        "brain_id": handler.result.brain_id,
        "space_id": handler.result.space_id,
        "space_fingerprint": handler.result.space_fingerprint,
        "generated_label": handler.result.names.label,
        "vector_index_name": handler.result.names.vector_index,
        "vector_property": "embedding",
        "dimension": 2,
        "similarity": "cosine",
        "state": "populating",
        "created_at": NOW.isoformat(),
    }
    assert authenticator.calls == 1
    assert resolver.calls == 1
    command = handler.commands[0]
    assert command.scope.action == "provider.embedding_space.ensure"
    assert command.scope.purpose == "embedding_space_administration"
    assert command.descriptor == descriptor()


@pytest.mark.asyncio
async def test_ensure_generation_rejects_bad_idempotency_before_scope_or_handler() -> None:
    authenticator = _Authenticator()
    resolver = _Resolver()
    handler = _Ensure()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(authenticator, resolver, handler)),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/embedding-spaces/generations",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "wrong"},
            json=_body(),
        )
    assert response.status_code == 422
    assert response.json()["detail"] == "embedding-space operation could not be completed"
    assert resolver.calls == 0
    assert handler.commands == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status"),
    [
        (EmbeddingSpaceAuthorizationError("raw authorization evidence"), 403),
        (EmbeddingSpaceConflictError("raw graph index metadata"), 409),
        (EmbeddingSpaceDependencyError("raw driver exception"), 503),
    ],
)
async def test_ensure_generation_maps_typed_failures_without_leaking_details(
    error: Exception,
    status: int,
) -> None:
    handler = _Ensure(error=error)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Authenticator(), _Resolver(), handler)),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/providers/embedding-spaces/generations",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "ensure-space-001",
            },
            json=_body(),
        )
    assert response.status_code == status
    encoded = json.dumps(response.json(), sort_keys=True)
    assert str(error) not in encoded
    assert "descriptor" not in encoded


def test_contract_router_publishes_strict_content_free_openapi() -> None:
    application = FastAPI()
    application.include_router(create_contract_embedding_space_router())
    first = json.dumps(application.openapi(), separators=(",", ":"), sort_keys=True)
    application.openapi_schema = None
    second = json.dumps(application.openapi(), separators=(",", ":"), sort_keys=True)
    assert first == second
    schema = json.loads(first)
    operation = schema["paths"]["/v1/providers/embedding-spaces/generations"]["post"]
    assert operation["operationId"] == "EnsureIndexGenerationCommand"
    response_schema = schema["components"]["schemas"]["EmbeddingGenerationResponseModel"]
    assert "credential" not in json.dumps(response_schema).lower()
