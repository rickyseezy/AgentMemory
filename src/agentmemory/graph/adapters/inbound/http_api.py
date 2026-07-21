"""Authenticated GRA-001 exact graph-entity HTTP adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Path, Query, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict

from agentmemory.graph.application.project_entity import (
    GetGraphEntityHandler,
    GetGraphEntityQuery,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
    GraphValidationError,
)
from agentmemory.graph.domain.models import GraphEntityType  # noqa: TC001 -- Pydantic runtime type.
from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeQuery,
)
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, RetrievalScopeMode
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.models import GraphEntity
    from agentmemory.graph.domain.ports import ScopedGraphRepositoryFactory
    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class GraphEntityResponseModel(_StrictModel):
    """Closed schema metadata for one authorized graph entity."""

    id: str
    brain_id: str
    entity_type: GraphEntityType
    project_id: str | None
    repository_id: str | None
    checkout_id: str | None
    schema_version: int
    created_at: str
    recorded_from: str
    recorded_to: str | None
    classification: str
    content_fingerprint: str
    revision_id: str


class GetGraphEntityRequestModel(_StrictModel):
    """Explicit identity and workspace scope claims for an exact graph read."""

    # HTTP query parameters arrive as text; Pydantic may only perform the closed-enum
    # conversion at this transport boundary. Domain construction remains strict.
    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    entity_type: GraphEntityType
    operation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class AuthenticatorPort(Protocol):
    """Authenticate a local capability before scope resolution."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve an immutable authorization-first identity scope."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return an authorized explicit scope and explanation."""
        ...


def create_graph_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    repositories: ScopedGraphRepositoryFactory,
    clock: Clock,
) -> APIRouter:
    """Create the strict exact-entity route; raw Cypher is never an input."""
    router = APIRouter()
    handler = GetGraphEntityHandler(repositories)

    @router.get(
        "/graph/entities/{entity_id}",
        operation_id="GetGraphEntityQuery",
        response_model=GraphEntityResponseModel,
    )
    async def get_graph_entity(
        entity_id: Annotated[str, Path(min_length=36, max_length=36)],
        request: Annotated[GetGraphEntityRequestModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> GraphEntityResponseModel | JSONResponse:
        """Resolve explicit scope, narrow it to graph read, then execute a closed query."""
        try:
            await authenticator.authenticate(authorization)
            requested_at = clock.now()
            resolution = await scope_resolver.execute(
                _scope_query(
                    request.operation_id,
                    request.brain_id,
                    request.actor_id,
                    request.grant_id,
                    request.project_id,
                    request.repository_id,
                    requested_at,
                )
            )
            entity = await handler.execute(
                GetGraphEntityQuery(_graph_scope(resolution.scope), request.entity_type, entity_id)
            )
            if entity is None:
                return _problem("AM_NOT_FOUND", 404, "graph entity was not found")
            return _response(entity)
        except (
            IdentityAuthorizationError,
            IdentityConflictError,
            IdentityDependencyError,
            IdentityValidationError,
            GraphAuthorizationError,
            GraphConflictError,
            GraphIntegrityError,
            GraphUnavailableError,
            GraphValidationError,
        ) as error:
            return _error_problem(error)

    registered_routes = (get_graph_entity,)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractScopeResolver:
    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        msg = "contract-only resolver cannot resolve graph scope"
        raise RuntimeError(msg)


class _ContractRepositories:
    def writer(self, scope: AuthorizedScope) -> object:
        del scope
        msg = "contract-only graph repository cannot write"
        raise RuntimeError(msg)

    def query(self, scope: AuthorizedScope) -> object:
        del scope
        msg = "contract-only graph repository cannot query"
        raise RuntimeError(msg)


class _ContractClock:
    def now(self) -> datetime:
        msg = "contract-only graph clock cannot read time"
        raise RuntimeError(msg)


def create_contract_graph_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_graph_router(
        _ContractAuthenticator(),
        _ContractScopeResolver(),
        cast("ScopedGraphRepositoryFactory", _ContractRepositories()),
        _ContractClock(),
    )


def _scope_query(  # noqa: PLR0913 -- HTTP claims map one-to-one to identity authorization.
    operation_id: str,
    brain_id: str,
    actor_id: str,
    grant_id: str,
    project_id: str,
    repository_id: str,
    requested_at: datetime,
) -> ResolveRetrievalScopeQuery:
    return ResolveRetrievalScopeQuery(
        operation_id,
        StableId(brain_id),
        StableId(actor_id),
        StableId(grant_id),
        RetrievalScopeMode.CURRENT,
        StableId(project_id),
        StableId(repository_id),
        None,
        (),
        round(requested_at.timestamp() * 1_000_000),
    )


def _graph_scope(scope: AuthorizedScope) -> AuthorizedScope:
    """Preserve authorization dimensions while binding a graph-specific action and cache key."""
    return AuthorizedScope.create(
        brain_id=scope.brain_id,
        principal_id=scope.principal_id,
        role=scope.role,
        mode=scope.mode,
        members=scope.members,
        classification_ceiling=scope.classification_ceiling,
        temporal_scope=scope.temporal_scope,
        grant_version=scope.grant_version,
        policy_version=scope.policy_version,
        security_epoch=scope.security_epoch,
        action="graph.read",
        purpose="graph_query",
    )


def _response(entity: GraphEntity) -> GraphEntityResponseModel:
    return GraphEntityResponseModel(
        id=entity.id,
        brain_id=entity.brain_id,
        entity_type=entity.entity_type,
        project_id=entity.project_id,
        repository_id=entity.repository_id,
        checkout_id=entity.checkout_id,
        schema_version=entity.schema_version,
        created_at=_time(entity.created_at),
        recorded_from=_time(entity.recorded_from),
        recorded_to=None if entity.recorded_to is None else _time(entity.recorded_to),
        classification=entity.classification.value,
        content_fingerprint=entity.content_fingerprint,
        revision_id=entity.revision_id,
    )


def _time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _problem(code: str, status: int, detail: str, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"code": code, "detail": detail, "retryable": retryable},
        media_type="application/problem+json",
    )


def _error_problem(error: Exception) -> JSONResponse:
    mappings: tuple[tuple[tuple[type[Exception], ...], str, int, str, bool], ...] = (
        (
            (IdentityAuthorizationError, GraphAuthorizationError),
            "AM_FORBIDDEN",
            403,
            "graph scope is not authorized",
            False,
        ),
        (
            (IdentityConflictError, GraphConflictError),
            "AM_CONFLICT",
            409,
            "graph request conflicts",
            False,
        ),
        (
            (IdentityValidationError, GraphValidationError),
            "AM_VALIDATION",
            422,
            "graph request is invalid",
            False,
        ),
        (
            (IdentityDependencyError, GraphUnavailableError),
            "AM_DEPENDENCY_UNAVAILABLE",
            503,
            "graph dependency is unavailable",
            True,
        ),
        (
            (GraphIntegrityError,),
            "AM_INTEGRITY_VIOLATION",
            500,
            "graph evidence failed verification",
            False,
        ),
    )
    for error_types, code, status, detail, retryable in mappings:
        if isinstance(error, error_types):
            return _problem(code, status, detail, retryable=retryable)
    raise AssertionError from error
