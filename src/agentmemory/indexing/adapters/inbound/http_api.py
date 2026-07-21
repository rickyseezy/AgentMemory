"""Authenticated IDX-002 indexing-run start, progress, and cancellation API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Body, Header, Query, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

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
from agentmemory.indexing.application.incremental_index import (
    CancelIndexRunCommand,
    GetIndexRunQuery,
    StartIndexRunCommand,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.incremental import IndexRun
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class IndexScopeModel(_StrictModel):
    """Exact current Repository authority for one indexing operation."""

    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class StartIndexRunRequestModel(IndexScopeModel):
    """Start one immutable commit or dirty-worktree indexing run."""

    operation_id: str = Field(min_length=1, max_length=128)
    target_commit_id: str | None = Field(
        default=None,
        min_length=7,
        max_length=64,
        pattern=r"^[0-9a-f]+$",
    )
    include_generated: bool = False


class CancelIndexRunRequestModel(IndexScopeModel):
    """Cancel one run at its next atomic file boundary."""

    operation_id: str = Field(min_length=1, max_length=128)


class IndexRunResponseModel(_StrictModel):
    """Content-free progress, coverage, failures, and freshness for one run."""

    run_id: str
    operation_id: str
    brain_id: str
    project_id: str
    repository_id: str
    base_snapshot_id: str | None
    target_snapshot_id: str
    target_commit_id: str | None
    revision_context: str
    state: str
    total_operations: int
    changed_operations: int
    cursor: int
    indexed_count: int
    reused_count: int
    deleted_count: int
    failed_count: int
    coverage_micros: int
    failure_code: str | None
    detected_at: str
    started_at: str | None
    updated_at: str
    completed_at: str | None
    freshness_milliseconds: int | None


class AuthenticatorPort(Protocol):
    """Authenticate the local capability before scope resolution."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate without returning secret material."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current canonical Brain/Project/Repository authority."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Resolve one exact current scope."""
        ...


class StartIndexRunPort(Protocol):
    """Queue one incremental run."""

    async def execute(self, command: StartIndexRunCommand) -> IndexRun:
        """Return the durable queued or replayed run."""
        ...


class GetIndexRunPort(Protocol):
    """Read current run progress."""

    async def execute(self, query: GetIndexRunQuery) -> IndexRun:
        """Return current durable state."""
        ...


class CancelIndexRunPort(Protocol):
    """Request cancellation."""

    async def execute(self, command: CancelIndexRunCommand) -> IndexRun:
        """Return current cancellation state."""
        ...


def create_indexing_router(  # noqa: PLR0913 -- Explicit inbound capabilities.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    start_handler: StartIndexRunPort,
    get_handler: GetIndexRunPort,
    cancel_handler: CancelIndexRunPort,
    clock: Clock,
) -> APIRouter:
    """Create the complete authenticated indexing-run operation map."""
    router = APIRouter()

    @router.post(
        "/v1/indexing/runs",
        operation_id="StartIndexRunCommand",
        response_model=IndexRunResponseModel,
        status_code=202,
    )
    async def start(
        body: Annotated[StartIndexRunRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> IndexRunResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, body, at, "indexing.run.start")
            run = await start_handler.execute(
                StartIndexRunCommand(
                    body.operation_id,
                    scope,
                    body.target_commit_id,
                    body.include_generated,
                    at,
                )
            )
            return _response(run)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/indexing/runs/{run_id}",
        operation_id="GetIndexRunQuery",
        response_model=IndexRunResponseModel,
    )
    async def get(
        run_id: str,
        scope_model: Annotated[IndexScopeModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> IndexRunResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, scope_model, at, "indexing.run.read")
            return _response(await get_handler.execute(GetIndexRunQuery(scope, run_id)))
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/indexing/runs/{run_id}:cancel",
        operation_id="CancelIndexRunCommand",
        response_model=IndexRunResponseModel,
    )
    async def cancel(
        run_id: str,
        body: Annotated[CancelIndexRunRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> IndexRunResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, body, at, "indexing.run.cancel")
            return _response(
                await cancel_handler.execute(
                    CancelIndexRunCommand(body.operation_id, scope, run_id, at)
                )
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (start, get, cancel)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        message = "contract dependency cannot execute"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read time"
        raise RuntimeError(message)


def create_contract_indexing_router() -> APIRouter:
    """Create a side-effect-free router for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_indexing_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("StartIndexRunPort", dependency),
        cast("GetIndexRunPort", dependency),
        cast("CancelIndexRunPort", dependency),
        _ContractClock(),
    )


async def _resolve_scope(
    resolver: RetrievalScopeResolverPort,
    request: IndexScopeModel,
    requested_at: datetime,
    action: str,
) -> AuthorizedScope:
    resolution = await resolver.execute(
        ResolveRetrievalScopeQuery(
            getattr(request, "operation_id", f"index-read-{round(requested_at.timestamp())}"),
            StableId(request.brain_id),
            StableId(request.actor_id),
            StableId(request.grant_id),
            RetrievalScopeMode.CURRENT,
            StableId(request.project_id),
            StableId(request.repository_id),
            None,
            (),
            round(requested_at.timestamp() * 1_000_000),
        )
    )
    scope = resolution.scope
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
        action=action,
        purpose="code_indexing",
    )


def _response(run: IndexRun) -> IndexRunResponseModel:
    coverage = (
        1_000_000 if run.total_operations == 0 else run.cursor * 1_000_000 // run.total_operations
    )
    freshness = run.freshness_seconds
    return IndexRunResponseModel(
        run_id=run.id,
        operation_id=run.operation_id,
        brain_id=run.brain_id,
        project_id=run.project_id,
        repository_id=run.repository_id,
        base_snapshot_id=run.base_snapshot_id,
        target_snapshot_id=run.target_snapshot_id,
        target_commit_id=run.target_commit_id,
        revision_context=run.revision_context.value,
        state=run.state.value,
        total_operations=run.total_operations,
        changed_operations=run.changed_operations,
        cursor=run.cursor,
        indexed_count=run.indexed_count,
        reused_count=run.reused_count,
        deleted_count=run.deleted_count,
        failed_count=run.failed_count,
        coverage_micros=coverage,
        failure_code=run.failure_code,
        detected_at=run.detected_at.isoformat(),
        started_at=None if run.started_at is None else run.started_at.isoformat(),
        updated_at=run.updated_at.isoformat(),
        completed_at=None if run.completed_at is None else run.completed_at.isoformat(),
        freshness_milliseconds=None if freshness is None else round(freshness * 1_000),
    )


def _require_idempotency(supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise IndexingValidationError(_ERR_IDEMPOTENCY)


_HANDLED_ERRORS = (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(error, (IndexingAuthorizationError, IdentityAuthorizationError)):
        status, code = 403, "forbidden"
    elif isinstance(error, (IndexingConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(error, (IndexingUnavailableError, IdentityDependencyError)):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:indexing:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "indexing operation could not be completed",
        },
    )
