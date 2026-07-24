"""Authenticated PRO-008 live embedding-generation migration API."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Body, Header, Query, Response, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.providers.adapters.profile_http_api import (
    ProviderScopeModel,
    RetrievalScopeResolverPort,
    resolve_provider_scope,
)
from agentmemory.providers.application.migration import (
    ActivateEmbeddingMigrationCommand,
    DeleteExpiredEmbeddingGenerationCommand,
    GetEmbeddingMigrationQuery,
    PauseEmbeddingMigrationCommand,
    PlanEmbeddingMigrationByIdCommand,
    ResumeEmbeddingMigrationCommand,
    RollbackEmbeddingMigrationCommand,
)
from agentmemory.providers.domain.errors import (
    EmbeddingMigrationAuthorizationError,
    EmbeddingMigrationConflictError,
    EmbeddingMigrationDependencyError,
    EmbeddingMigrationValidationError,
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.migration import EmbeddingGenerationMigration
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ETAG = re.compile(r'^"embedding-migration:([0-9a-f-]{36}):([1-9][0-9]{0,18})"$')
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_NOT_FOUND = "embedding migration was not found"
_ERR_PRECONDITION = "embedding migration precondition is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class StartEmbeddingMigrationRequestModel(ProviderScopeModel):
    """Plan one exact source-to-target generation migration."""

    operation_id: str = Field(min_length=1, max_length=128)
    source_generation_id: str
    target_generation_id: str


class MigrationMutationRequestModel(ProviderScopeModel):
    """Current workspace authority for one versioned lifecycle mutation."""


class ActivateEmbeddingMigrationRequestModel(MigrationMutationRequestModel):
    """Explicit grant approval and idempotent activation identity."""

    operation_id: str = Field(min_length=1, max_length=128)
    approval_id: str = Field(min_length=1, max_length=128)


class MigrationProgressResponseModel(_StrictModel):
    """Content-free stable replay progress."""

    source_watermark: int
    backfill_cursor: int
    catchup_watermark: int
    catchup_cursor: int


class EmbeddingMigrationResponseModel(_StrictModel):
    """Content-safe migration state and rollback evidence."""

    migration_id: str
    brain_id: str
    source_space_id: str
    source_generation_id: str
    target_space_id: str
    target_generation_id: str
    state: str
    resume_state: str | None
    progress: MigrationProgressResponseModel
    validation_digest: str | None
    rollback_until_microseconds: int | None
    source_retired_at_microseconds: int | None
    source_deleted_at_microseconds: int | None
    version: int
    created_at_microseconds: int
    updated_at_microseconds: int


class AuthenticatorPort(Protocol):
    """Authenticate before any migration or generation existence access."""

    async def authenticate(self, authorization: str | None) -> None:
        """Validate the local capability credential."""
        ...


class PlanEmbeddingMigrationPort(Protocol):
    """Plan one migration from generation identities."""

    async def execute(
        self,
        command: PlanEmbeddingMigrationByIdCommand,
    ) -> EmbeddingGenerationMigration:
        """Create or exactly replay the plan."""
        ...


class GetEmbeddingMigrationPort(Protocol):
    """Read one Brain-scoped migration."""

    async def execute(
        self,
        query: GetEmbeddingMigrationQuery,
    ) -> EmbeddingGenerationMigration | None:
        """Return an authorized content-free snapshot."""
        ...


class RunEmbeddingMigrationPort(Protocol):
    """Advance one resumable migration until Ready, Paused, or Failed."""

    async def execute(
        self,
        scope: AuthorizedScope,
        migration_id: str,
    ) -> EmbeddingGenerationMigration:
        """Run committed idempotent migration phases."""
        ...


class MigrationCommandPort[CommandT](Protocol):
    """Execute one typed migration lifecycle command."""

    async def execute(self, command: CommandT) -> EmbeddingGenerationMigration:
        """Return the resulting snapshot."""
        ...


def create_embedding_migration_router(  # noqa: PLR0913 -- Explicit composition root.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    planner: PlanEmbeddingMigrationPort,
    getter: GetEmbeddingMigrationPort,
    runner: RunEmbeddingMigrationPort,
    pauser: MigrationCommandPort[PauseEmbeddingMigrationCommand],
    resumer: MigrationCommandPort[ResumeEmbeddingMigrationCommand],
    activator: MigrationCommandPort[ActivateEmbeddingMigrationCommand],
    rollback: MigrationCommandPort[RollbackEmbeddingMigrationCommand],
    deleter: MigrationCommandPort[DeleteExpiredEmbeddingGenerationCommand],
    clock: Clock,
) -> APIRouter:
    """Create the complete PRO-008 administration and operation contract."""
    router = APIRouter()

    @router.post(
        "/v1/providers/embedding-migrations",
        operation_id="StartEmbeddingMigrationCommand",
        response_model=EmbeddingMigrationResponseModel,
        status_code=201,
    )
    async def start(
        body: Annotated[StartEmbeddingMigrationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _idempotency(idempotency_key, body.operation_id)
            now = clock.now()
            scope = await _scope(
                scope_resolver,
                body,
                now,
                "provider.embedding_migration.plan",
            )
            migration = await planner.execute(
                PlanEmbeddingMigrationByIdCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    source_generation_id=body.source_generation_id,
                    target_generation_id=body.target_generation_id,
                    requested_at=now,
                )
            )
            return _respond(response, migration)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/providers/embedding-migrations/{migration_id}",
        operation_id="GetEmbeddingMigrationQuery",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def get(
        migration_id: str,
        scope_model: Annotated[ProviderScopeModel, Query()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            scope = await _scope(
                scope_resolver,
                scope_model,
                now,
                "provider.embedding_migration.read",
            )
            migration = await getter.execute(GetEmbeddingMigrationQuery(scope, migration_id, now))
            if migration is None:
                return _not_found()
            return _respond(response, migration)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/embedding-migrations/{migration_id}:run",
        operation_id="RunEmbeddingMigrationCommand",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def run(
        migration_id: str,
        body: Annotated[MigrationMutationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _scope(
                scope_resolver,
                body,
                clock.now(),
                "provider.embedding_migration.run",
            )
            return _respond(response, await runner.execute(scope, migration_id))
        except _HANDLED_ERRORS as error:
            return _problem(error)

    _register_versioned_lifecycle_routes(
        router,
        authenticator,
        scope_resolver,
        pauser,
        resumer,
        activator,
        rollback,
        deleter,
        clock,
    )
    registered = (start, get, run)
    del registered
    return router


def _register_versioned_lifecycle_routes(  # noqa: PLR0913 -- Router dependencies.
    router: APIRouter,
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    pauser: MigrationCommandPort[PauseEmbeddingMigrationCommand],
    resumer: MigrationCommandPort[ResumeEmbeddingMigrationCommand],
    activator: MigrationCommandPort[ActivateEmbeddingMigrationCommand],
    rollback: MigrationCommandPort[RollbackEmbeddingMigrationCommand],
    deleter: MigrationCommandPort[DeleteExpiredEmbeddingGenerationCommand],
    clock: Clock,
) -> None:
    @router.post(
        "/v1/providers/embedding-migrations/{migration_id}:pause",
        operation_id="PauseEmbeddingMigrationCommand",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def pause(
        migration_id: str,
        body: Annotated[MigrationMutationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        return await _versioned_command(
            authenticator,
            scope_resolver,
            pauser,
            body,
            response,
            authorization,
            if_match,
            migration_id,
            "provider.embedding_migration.pause",
            PauseEmbeddingMigrationCommand,
            clock,
        )

    @router.post(
        "/v1/providers/embedding-migrations/{migration_id}:resume",
        operation_id="ResumeEmbeddingMigrationCommand",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def resume(
        migration_id: str,
        body: Annotated[MigrationMutationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        return await _versioned_command(
            authenticator,
            scope_resolver,
            resumer,
            body,
            response,
            authorization,
            if_match,
            migration_id,
            "provider.embedding_migration.resume",
            ResumeEmbeddingMigrationCommand,
            clock,
        )

    @router.post(
        "/v1/providers/embedding-migrations/{migration_id}:cutover",
        operation_id="ActivateIndexGenerationCommand",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def cutover(  # noqa: PLR0913 -- FastAPI binds distinct transport fields.
        migration_id: str,
        body: Annotated[ActivateEmbeddingMigrationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _idempotency(idempotency_key, body.operation_id)
            expected = _expected_version(if_match, migration_id)
            scope = await _scope(
                scope_resolver,
                body,
                clock.now(),
                "provider.embedding_migration.activate",
            )
            migration = await activator.execute(
                ActivateEmbeddingMigrationCommand(
                    body.operation_id,
                    scope,
                    migration_id,
                    body.approval_id,
                    expected,
                )
            )
            return _respond(response, migration)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/embedding-migrations/{migration_id}:rollback",
        operation_id="RollbackIndexGenerationCommand",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def rollback_generation(
        migration_id: str,
        body: Annotated[MigrationMutationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _scope(
                scope_resolver,
                body,
                clock.now(),
                "provider.embedding_migration.rollback",
            )
            migration = await rollback.execute(
                RollbackEmbeddingMigrationCommand(scope, migration_id)
            )
            return _respond(response, migration)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/embedding-migrations/{migration_id}:delete-source",
        operation_id="DeleteExpiredEmbeddingGenerationCommand",
        response_model=EmbeddingMigrationResponseModel,
    )
    async def delete_source(
        migration_id: str,
        body: Annotated[MigrationMutationRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> EmbeddingMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _scope(
                scope_resolver,
                body,
                clock.now(),
                "provider.embedding_migration.delete",
            )
            migration = await deleter.execute(
                DeleteExpiredEmbeddingGenerationCommand(scope, migration_id)
            )
            return _respond(response, migration)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    registered = (pause, resume, cutover, rollback_generation, delete_source)
    del registered


async def _versioned_command[CommandT](  # noqa: PLR0913 -- Transport coordinates.
    authenticator: AuthenticatorPort,
    resolver: RetrievalScopeResolverPort,
    handler: MigrationCommandPort[CommandT],
    body: MigrationMutationRequestModel,
    response: Response,
    authorization: str | None,
    if_match: str | None,
    migration_id: str,
    action: str,
    command_type: Callable[[AuthorizedScope, str, int], CommandT],
    clock: Clock,
) -> EmbeddingMigrationResponseModel | JSONResponse:
    try:
        await authenticator.authenticate(authorization)
        expected = _expected_version(if_match, migration_id)
        scope = await _scope(resolver, body, clock.now(), action)
        migration = await handler.execute(command_type(scope, migration_id, expected))
        return _respond(response, migration)
    except _HANDLED_ERRORS as error:
        return _problem(error)


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, *values: object) -> object:  # pragma: no mutate block
        del values
        raise RuntimeError(_ERR_CONTRACT_DEPENDENCY)


class _ContractClock:
    def now(self) -> object:  # pragma: no mutate block
        raise RuntimeError(_ERR_CONTRACT_CLOCK)


def create_contract_embedding_migration_router() -> APIRouter:
    """Create a side-effect-free PRO-008 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_embedding_migration_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("PlanEmbeddingMigrationPort", dependency),
        cast("GetEmbeddingMigrationPort", dependency),
        cast("RunEmbeddingMigrationPort", dependency),
        cast("MigrationCommandPort[PauseEmbeddingMigrationCommand]", dependency),
        cast("MigrationCommandPort[ResumeEmbeddingMigrationCommand]", dependency),
        cast("MigrationCommandPort[ActivateEmbeddingMigrationCommand]", dependency),
        cast("MigrationCommandPort[RollbackEmbeddingMigrationCommand]", dependency),
        cast(
            "MigrationCommandPort[DeleteExpiredEmbeddingGenerationCommand]",
            dependency,
        ),
        cast("Clock", _ContractClock()),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    model: ProviderScopeModel,
    at: datetime,
    action: str,
) -> AuthorizedScope:
    return await resolve_provider_scope(
        resolver,
        model,
        at,
        action,
        purpose="embedding_migration_administration",
    )


def _expected_version(if_match: str | None, migration_id: str) -> int:
    match = None if if_match is None else _ETAG.fullmatch(if_match)
    if match is None or match.group(1) != migration_id:
        raise EmbeddingMigrationValidationError(_ERR_PRECONDITION)
    return int(match.group(2))


def _idempotency(value: str | None, expected: str) -> None:
    if value != expected:
        raise EmbeddingMigrationValidationError(_ERR_IDEMPOTENCY)


def _respond(
    response: Response,
    migration: EmbeddingGenerationMigration,
) -> EmbeddingMigrationResponseModel:
    response.headers["ETag"] = f'"embedding-migration:{migration.migration_id}:{migration.version}"'
    return EmbeddingMigrationResponseModel(
        migration_id=migration.migration_id,
        brain_id=migration.brain_id,
        source_space_id=migration.source_space_id,
        source_generation_id=migration.source_generation_id,
        target_space_id=migration.target_space_id,
        target_generation_id=migration.target_generation_id,
        state=migration.state.value,
        resume_state=(None if migration.resume_state is None else migration.resume_state.value),
        progress=MigrationProgressResponseModel(
            source_watermark=migration.source_watermark,
            backfill_cursor=migration.progress.backfill_cursor,
            catchup_watermark=migration.progress.catchup_watermark,
            catchup_cursor=migration.progress.catchup_cursor,
        ),
        validation_digest=migration.validation_digest,
        rollback_until_microseconds=migration.rollback_until_microseconds,
        source_retired_at_microseconds=migration.source_retired_at_microseconds,
        source_deleted_at_microseconds=migration.source_deleted_at_microseconds,
        version=migration.version,
        created_at_microseconds=migration.created_at_microseconds,
        updated_at_microseconds=migration.updated_at_microseconds,
    )


_HANDLED_ERRORS = (
    EmbeddingMigrationAuthorizationError,
    EmbeddingMigrationConflictError,
    EmbeddingMigrationDependencyError,
    EmbeddingMigrationValidationError,
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _not_found() -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "type": "urn:agentmemory:provider-embedding-migration:not_found",
            "title": "not found",
            "status": 404,
            "detail": _ERR_NOT_FOUND,
        },
    )


def _problem(error: Exception) -> JSONResponse:
    if isinstance(
        error,
        (
            EmbeddingMigrationAuthorizationError,
            EmbeddingSpaceAuthorizationError,
            IdentityAuthorizationError,
        ),
    ):
        status, code = 403, "forbidden"
    elif isinstance(
        error,
        (
            EmbeddingMigrationConflictError,
            EmbeddingSpaceConflictError,
            IdentityConflictError,
        ),
    ):
        status, code = 409, "conflict"
    elif isinstance(
        error,
        (
            EmbeddingMigrationDependencyError,
            EmbeddingSpaceDependencyError,
            IdentityDependencyError,
        ),
    ):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-embedding-migration:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "embedding migration operation could not be completed",
        },
    )
