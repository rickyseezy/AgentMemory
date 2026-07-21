"""Authenticated GRA-006 graph migration, integrity, and repair HTTP adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Body, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.graph.application.graph_integrity import (
    RepairGraphFindingCommand,
    RunGraphMigrationCommand,
    StartGraphMigrationCommand,
    ValidateGraphIntegrityQuery,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
    GraphValidationError,
)
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

    from agentmemory.graph.domain.graph_integrity import (
        GraphIntegrityFinding,
        GraphMigrationRun,
        GraphRepairPlan,
    )
    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)


class GraphIntegrityScopeRequestModel(_StrictModel):
    """Common current-scope authority for every graph integrity operation."""

    operation_id: str = Field(min_length=1, max_length=128)
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class StartGraphMigrationRequestModel(GraphIntegrityScopeRequestModel):
    """Start one registered, checksum-bound, bounded graph migration."""

    migration_id: str = Field(min_length=1, max_length=128)
    migration_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    batch_size: int = Field(ge=1, le=4096)


class RunGraphMigrationRequestModel(GraphIntegrityScopeRequestModel):
    """Resume one migration from its externally durable cursor."""


class ValidateGraphIntegrityRequestModel(GraphIntegrityScopeRequestModel):
    """Inspect the current generation without returning projection content."""

    current_generation_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class RepairGraphFindingRequestModel(GraphIntegrityScopeRequestModel):
    """Execute one closed repair plan with optional explicit rebuild approval."""

    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    destructive: bool = False
    approval_id: str | None = None


class GraphMigrationResponseModel(_StrictModel):
    """Content-free durable migration progress and checksum evidence."""

    operation_id: str
    brain_id: str
    migration_id: str
    migration_checksum: str
    source_watermark: int
    batch_size: int
    cursor: int
    scanned_count: int
    changed_count: int
    quarantined_count: int
    state: str
    started_at: str
    updated_at: str


class GraphIntegrityFindingResponseModel(_StrictModel):
    """Content-free evidence for one exact projection integrity defect."""

    finding_id: str
    kind: str
    projection_id: str
    projection_kind: str
    brain_id: str
    project_id: str
    repository_id: str
    canonical_id: str | None
    observed_generation_id: str
    expected_generation_id: str
    projection_digest: str
    checked_at: str


class GraphRepairResponseModel(_StrictModel):
    """Closed repair decision and explicit approval authority."""

    finding_id: str
    action: str
    approval_id: str | None


class AuthenticatorPort(Protocol):
    """Authenticate a local operator credential."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate before resolving or accessing graph scope."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current Brain, Project, and Repository authority."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Resolve current canonical authorization."""
        ...


class StartMigrationPort(Protocol):
    """Start a checksum-bound graph migration."""

    async def execute(self, command: StartGraphMigrationCommand) -> GraphMigrationRun:
        """Start a registered migration."""
        ...


class RunMigrationPort(Protocol):
    """Resume a durable graph migration."""

    async def execute(self, command: RunGraphMigrationCommand) -> GraphMigrationRun:
        """Resume a registered migration."""
        ...


class ValidateIntegrityPort(Protocol):
    """Scan and journal graph integrity findings."""

    async def execute(
        self, query: ValidateGraphIntegrityQuery
    ) -> tuple[GraphIntegrityFinding, ...]:
        """Validate one current graph generation."""
        ...


class RepairFindingPort(Protocol):
    """Execute a governed finding repair."""

    async def execute(self, command: RepairGraphFindingCommand) -> GraphRepairPlan:
        """Repair one journaled finding."""
        ...


def create_graph_integrity_router(  # noqa: PLR0913 -- Explicit adapter capabilities.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    start_migration: StartMigrationPort,
    run_migration: RunMigrationPort,
    validate_integrity: ValidateIntegrityPort,
    repair_finding: RepairFindingPort,
    clock: Clock,
) -> APIRouter:
    """Create strict, content-free graph integrity operator routes."""
    router = APIRouter()

    @router.post(
        "/graph/integrity/migrations/start",
        operation_id="StartGraphMigration",
        response_model=GraphMigrationResponseModel,
        status_code=201,
    )
    async def start(
        request: Annotated[StartGraphMigrationRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> GraphMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, request, at, "graph.integrity.migrate")
            result = await start_migration.execute(
                StartGraphMigrationCommand(
                    request.operation_id,
                    scope,
                    request.migration_id,
                    request.migration_checksum,
                    request.batch_size,
                    at,
                )
            )
            return _migration_response(result)
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    @router.post(
        "/graph/integrity/migrations/run",
        operation_id="RunGraphMigration",
        response_model=GraphMigrationResponseModel,
    )
    async def run(
        request: Annotated[RunGraphMigrationRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> GraphMigrationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, request, at, "graph.integrity.migrate")
            return _migration_response(
                await run_migration.execute(
                    RunGraphMigrationCommand(request.operation_id, scope, at)
                )
            )
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    @router.post(
        "/graph/integrity/validate",
        operation_id="ValidateGraphIntegrity",
        response_model=tuple[GraphIntegrityFindingResponseModel, ...],
    )
    async def validate(
        request: Annotated[ValidateGraphIntegrityRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> tuple[GraphIntegrityFindingResponseModel, ...] | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, request, at, "graph.integrity.validate")
            findings = await validate_integrity.execute(
                ValidateGraphIntegrityQuery(scope, request.current_generation_id, at)
            )
            return tuple(_finding_response(item) for item in findings)
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    @router.post(
        "/graph/integrity/repair",
        operation_id="RepairGraphFinding",
        response_model=GraphRepairResponseModel,
    )
    async def repair(
        request: Annotated[RepairGraphFindingRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> GraphRepairResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, request, at, "graph.integrity.repair")
            plan = await repair_finding.execute(
                RepairGraphFindingCommand(
                    request.operation_id,
                    scope,
                    request.finding_id,
                    at,
                    request.destructive,
                    request.approval_id,
                )
            )
            return GraphRepairResponseModel(
                finding_id=plan.finding_id,
                action=plan.action.value,
                approval_id=plan.approval_id,
            )
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    routes = (start, run, validate, repair)
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


def create_contract_graph_integrity_router() -> APIRouter:
    """Create a side-effect-free router for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_graph_integrity_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("StartMigrationPort", dependency),
        cast("RunMigrationPort", dependency),
        cast("ValidateIntegrityPort", dependency),
        cast("RepairFindingPort", dependency),
        _ContractClock(),
    )


async def _resolve_scope(
    resolver: RetrievalScopeResolverPort,
    request: GraphIntegrityScopeRequestModel,
    requested_at: datetime,
    action: str,
) -> AuthorizedScope:
    resolution = await resolver.execute(
        ResolveRetrievalScopeQuery(
            request.operation_id,
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
        purpose="graph_integrity",
    )


def _migration_response(value: GraphMigrationRun) -> GraphMigrationResponseModel:
    return GraphMigrationResponseModel(
        operation_id=value.operation_id,
        brain_id=value.brain_id,
        migration_id=value.migration_id,
        migration_checksum=value.migration_checksum,
        source_watermark=value.source_watermark,
        batch_size=value.batch_size,
        cursor=value.cursor,
        scanned_count=value.scanned_count,
        changed_count=value.changed_count,
        quarantined_count=value.quarantined_count,
        state=value.state.value,
        started_at=_time(value.started_at),
        updated_at=_time(value.updated_at),
    )


def _finding_response(value: GraphIntegrityFinding) -> GraphIntegrityFindingResponseModel:
    return GraphIntegrityFindingResponseModel(
        finding_id=value.id,
        kind=value.kind.value,
        projection_id=value.projection_id,
        projection_kind=value.projection_kind.value,
        brain_id=value.brain_id,
        project_id=value.project_id,
        repository_id=value.repository_id,
        canonical_id=value.canonical_id,
        observed_generation_id=value.observed_generation_id,
        expected_generation_id=value.expected_generation_id,
        projection_digest=value.projection_digest,
        checked_at=_time(value.checked_at),
    )


def _time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


_HANDLED_ERRORS = (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
    GraphValidationError,
    ValueError,
)


def _error_problem(error: Exception) -> JSONResponse:
    if isinstance(error, (IdentityAuthorizationError, GraphAuthorizationError)):
        return _problem("AM_FORBIDDEN", 403, "graph integrity scope is not authorized")
    if isinstance(error, (IdentityConflictError, GraphConflictError)):
        return _problem("AM_CONFLICT", 409, "graph integrity request conflicts")
    if isinstance(error, (IdentityDependencyError, GraphUnavailableError)):
        return _problem(
            "AM_DEPENDENCY_UNAVAILABLE",
            503,
            "graph integrity dependency is unavailable",
            retryable=True,
        )
    if isinstance(error, GraphIntegrityError):
        return _problem(
            "AM_INTEGRITY_VIOLATION", 500, "graph integrity evidence failed verification"
        )
    return _problem("AM_VALIDATION", 422, "graph integrity request is invalid")


def _problem(code: str, status: int, detail: str, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"code": code, "detail": detail, "retryable": retryable},
        media_type="application/problem+json",
    )
