"""Authenticated IDX-003 source-history and evidence-lineage HTTP adapter."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- Pydantic runtime field.
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
from agentmemory.indexing.application.revision_history import (
    QuerySourceRevisionHistoryQuery,
    RegisterEvidenceLineageCommand,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.revision_history import SourceRevisionHistoryEntry
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_SCOPE = "source revision scope is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class SourceRevisionHistoryRequestModel(_StrictModel):
    """Exact authorized source path and immutable revision selector."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    operation_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str
    relative_path: str = Field(min_length=1, max_length=4_096)
    recorded_at: datetime
    branch_name: str | None = Field(default=None, min_length=1, max_length=1_024)
    commit_sha: str | None = Field(
        default=None,
        min_length=40,
        max_length=64,
        pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$",
    )
    include_stale: bool = True
    limit: int = Field(default=100, ge=1, le=1_000)


class RegisterEvidenceLineageRequestModel(_StrictModel):
    """One idempotent source-revision → evidence → assertion registration."""

    operation_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str
    context_id: str
    evidence_id: str
    assertion_id: str


class SourceRevisionHistoryResponseModel(_StrictModel):
    """Content-free retained source context with replayable graph proof IDs."""

    context_id: str
    source_file_id: str
    file_revision_id: str | None
    snapshot_id: str
    relative_path: str
    commit_sha: str
    content_digest: str | None
    change_kind: str
    applicability: str
    invalidating_commit_shas: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    reintroduced_from_context_id: str | None
    graph_digest: str
    graph_answer_ids: tuple[str, ...]
    observed_at: str


class EvidenceLineageReceiptModel(_StrictModel):
    """Exact replay receipt for one reverse lineage edge."""

    operation_id: str
    registration_digest: str
    context_id: str
    evidence_id: str
    assertion_id: str
    registered_at: str


class AuthenticatorPort(Protocol):
    """Authenticate the local credential before any request claim is inspected."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, expired, malformed, or revoked credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current exact repository authority."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return the canonical authorized scope."""
        ...


class QuerySourceRevisionHistoryPort(Protocol):
    """Query branch-aware retained source history."""

    async def execute(
        self, query: QuerySourceRevisionHistoryQuery
    ) -> tuple[SourceRevisionHistoryEntry, ...]:
        """Return authorized entries with graph proof identities."""
        ...


class RegisterEvidenceLineagePort(Protocol):
    """Register reverse source evidence lineage."""

    async def execute(self, command: RegisterEvidenceLineageCommand) -> str:
        """Append or replay one exact lineage edge."""
        ...


def create_revision_history_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    history: QuerySourceRevisionHistoryPort,
    lineage: RegisterEvidenceLineagePort,
    clock: Clock,
) -> APIRouter:
    """Create strict source history and lineage registration routes."""
    router = APIRouter()

    @router.get(
        "/v1/indexing/source-revisions/history",
        operation_id="QuerySourceRevisionHistoryQuery",
        response_model=tuple[SourceRevisionHistoryResponseModel, ...],
    )
    async def query_history(
        request: Annotated[SourceRevisionHistoryRequestModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> tuple[SourceRevisionHistoryResponseModel, ...] | JSONResponse:
        """Authenticate, authorize, pin one ref/commit, and return retained history."""
        try:
            await authenticator.authenticate(authorization)
            scope = await _scope(
                scope_resolver,
                request,
                request.recorded_at,
                "indexing.revision.history.read",
            )
            entries = await history.execute(
                QuerySourceRevisionHistoryQuery(
                    scope,
                    request.repository_id,
                    request.relative_path,
                    request.recorded_at,
                    request.branch_name,
                    request.commit_sha,
                    request.include_stale,
                    request.limit,
                )
            )
            return tuple(_history_response(item) for item in entries)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/indexing/source-revisions/lineage",
        operation_id="RegisterEvidenceLineageCommand",
        response_model=EvidenceLineageReceiptModel,
        status_code=201,
    )
    async def register_lineage(
        request: Annotated[RegisterEvidenceLineageRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> EvidenceLineageReceiptModel | JSONResponse:
        """Authenticate and append one exact source/evidence/assertion reverse edge."""
        try:
            await authenticator.authenticate(authorization)
            if idempotency_key != request.operation_id:
                raise IndexingValidationError(_ERR_IDEMPOTENCY)
            registered_at = clock.now()
            scope = await _scope(
                scope_resolver,
                request,
                registered_at,
                "indexing.revision.lineage.register",
            )
            digest = await lineage.execute(
                RegisterEvidenceLineageCommand(
                    request.operation_id,
                    scope,
                    request.context_id,
                    request.evidence_id,
                    request.assertion_id,
                    registered_at,
                )
            )
            return EvidenceLineageReceiptModel(
                operation_id=request.operation_id,
                registration_digest=digest,
                context_id=request.context_id,
                evidence_id=request.evidence_id,
                assertion_id=request.assertion_id,
                registered_at=registered_at.isoformat(),
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (query_history, register_lineage)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        message = "contract dependency cannot execute revision history"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read revision history time"
        raise RuntimeError(message)


def create_contract_revision_history_router() -> APIRouter:
    """Create side-effect-free IDX-003 routes for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_revision_history_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("QuerySourceRevisionHistoryPort", dependency),
        cast("RegisterEvidenceLineagePort", dependency),
        _ContractClock(),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    request: SourceRevisionHistoryRequestModel | RegisterEvidenceLineageRequestModel,
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
    if request.repository_id not in {item.value for item in scope.repository_ids}:
        raise IndexingAuthorizationError(_ERR_SCOPE)
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
        purpose="source_revision_history",
    )


def _history_response(item: SourceRevisionHistoryEntry) -> SourceRevisionHistoryResponseModel:
    candidate = item.candidate
    return SourceRevisionHistoryResponseModel(
        context_id=candidate.context_id,
        source_file_id=candidate.source_file_id,
        file_revision_id=candidate.file_revision_id,
        snapshot_id=candidate.snapshot_id,
        relative_path=candidate.relative_path,
        commit_sha=candidate.commit_sha,
        content_digest=candidate.content_digest,
        change_kind=candidate.kind.value,
        applicability=item.applicability.value,
        invalidating_commit_shas=item.reachable_invalidating_commits,
        evidence_ids=candidate.evidence_ids,
        assertion_ids=candidate.assertion_ids,
        reintroduced_from_context_id=candidate.reintroduced_from_context_id,
        graph_digest=item.graph_digest,
        graph_answer_ids=item.graph_answer_ids,
        observed_at=candidate.observed_at.isoformat(),
    )


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
            "detail": "source revision operation could not be completed",
        },
    )
