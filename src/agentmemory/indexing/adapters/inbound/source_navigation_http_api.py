"""Authenticated IDX-007 immutable source-evidence link HTTP adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Query, Security
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
from agentmemory.indexing.application.source_navigation import ResolveSourceEvidenceQuery
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.code_entities import SourceSpan
    from agentmemory.indexing.domain.source_navigation import (
        CurrentWorktreeMapping,
        SourceLink,
    )
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_SCOPE = "source navigation scope is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class SourceNavigationScopeModel(_StrictModel):
    """Exact current Repository authority for one evidence resolution."""

    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class SourceSpanModel(_StrictModel):
    """Half-open UTF-8 byte and zero-based byte-column range."""

    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int


class CurrentWorktreeMappingModel(_StrictModel):
    """Optional uniquely verified current-worktree mapping."""

    relative_path: str
    span: SourceSpanModel
    content_digest: str
    kind: str


class SourceLinkResponseModel(_StrictModel):
    """Complete revision-bound evidence with explicit checkout mismatch state."""

    evidence_id: str
    evidence_kind: str
    brain_id: str
    project_id: str
    repository_id: str
    snapshot_id: str
    commit_id: str | None
    source_file_id: str
    file_revision_id: str
    relative_path: str
    symbol_id: str
    symbol_stable_key: str
    symbol_display_name: str
    symbol_kind: str
    occurrence_role: str | None
    span: SourceSpanModel
    content_digest: str
    byte_length: int
    parser_version: str
    grammar_revision: str
    query_pack_digest: str
    semantic_source: str
    immutable_revision_uri: str
    checkout_resolution: str
    checkout_commit_id: str | None
    checkout_dirty: bool | None
    checkout_mismatch: bool
    historical_blob_available: bool
    current_mapping: CurrentWorktreeMappingModel | None


class AuthenticatorPort(Protocol):
    """Authenticate the local capability before inspecting claims."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve canonical current Repository authority."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return one exact authorized scope."""
        ...


class ResolveSourceEvidencePort(Protocol):
    """Resolve exact source evidence against trusted local bytes."""

    async def execute(self, query: ResolveSourceEvidenceQuery) -> SourceLink:
        """Return a verified immutable link and optional safe worktree mapping."""
        ...


def create_source_navigation_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    handler: ResolveSourceEvidencePort,
    clock: Clock,
) -> APIRouter:
    """Create the authenticated source-evidence resolution contract."""
    router = APIRouter()

    @router.get(
        "/v1/indexing/source-evidence/{evidence_id}",
        operation_id="ResolveSourceEvidenceQuery",
        response_model=SourceLinkResponseModel,
    )
    async def resolve(
        evidence_id: str,
        request: Annotated[SourceNavigationScopeModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> SourceLinkResponseModel | JSONResponse:
        """Authenticate, resolve current scope, then verify revision-bound evidence."""
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _scope(scope_resolver, request, at)
            return _response(await handler.execute(ResolveSourceEvidenceQuery(scope, evidence_id)))
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (resolve,)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        message = "contract dependency cannot resolve source evidence"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read source navigation time"
        raise RuntimeError(message)


def create_contract_source_navigation_router() -> APIRouter:
    """Create side-effect-free IDX-007 routes for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_source_navigation_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("ResolveSourceEvidencePort", dependency),
        _ContractClock(),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    request: SourceNavigationScopeModel,
    requested_at: datetime,
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
        action="indexing.source.navigate",
        purpose="source_navigation",
    )


def _response(link: SourceLink) -> SourceLinkResponseModel:
    evidence = link.evidence
    return SourceLinkResponseModel(
        evidence_id=evidence.evidence_id,
        evidence_kind=evidence.kind.value,
        brain_id=evidence.brain_id,
        project_id=evidence.project_id,
        repository_id=evidence.repository_id,
        snapshot_id=evidence.snapshot_id,
        commit_id=evidence.commit_id,
        source_file_id=evidence.source_file_id,
        file_revision_id=evidence.file_revision_id,
        relative_path=evidence.relative_path,
        symbol_id=evidence.symbol_id,
        symbol_stable_key=evidence.symbol_stable_key,
        symbol_display_name=evidence.symbol_display_name,
        symbol_kind=evidence.symbol_kind.value,
        occurrence_role=None
        if evidence.occurrence_role is None
        else evidence.occurrence_role.value,
        span=_span(evidence.span),
        content_digest=evidence.content_digest,
        byte_length=evidence.byte_length,
        parser_version=evidence.parser_version,
        grammar_revision=evidence.grammar_revision,
        query_pack_digest=evidence.query_pack_digest,
        semantic_source=evidence.semantic_source.value,
        immutable_revision_uri=link.immutable_revision_uri,
        checkout_resolution=link.checkout_resolution.value,
        checkout_commit_id=link.checkout_commit_id,
        checkout_dirty=link.checkout_dirty,
        checkout_mismatch=link.checkout_mismatch,
        historical_blob_available=link.historical_blob_available,
        current_mapping=_mapping(link.current_mapping),
    )


def _mapping(value: CurrentWorktreeMapping | None) -> CurrentWorktreeMappingModel | None:
    if value is None:
        return None
    return CurrentWorktreeMappingModel(
        relative_path=value.relative_path,
        span=_span(value.span),
        content_digest=value.content_digest,
        kind=value.kind.value,
    )


def _span(value: SourceSpan) -> SourceSpanModel:
    return SourceSpanModel(
        start_byte=value.start_byte,
        end_byte=value.end_byte,
        start_line=value.start_line,
        start_column=value.start_column,
        end_line=value.end_line,
        end_column=value.end_column,
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
            "detail": "source evidence could not be resolved",
        },
    )
