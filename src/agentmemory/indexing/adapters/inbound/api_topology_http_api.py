"""Authenticated IDX-004 extraction and cross-project API topology HTTP adapter."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime  # noqa: TC003 -- Pydantic runtime field.
from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Body, Header, Security
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
from agentmemory.indexing.application.api_topology import (
    ExtractAndRegisterApiTopologyCommand,
    LinkApiTopologyCommand,
)
from agentmemory.indexing.domain.api_topology import (
    ApiTopologyEvidence,
    ApiTopologyMatch,
    ApiTopologySourceArtifact,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.api_topology import (
        ApiTopologyCandidateBatch,
        ApiTopologyLinkDecision,
    )
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_CONTENT = "API topology source content is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ExtractApiTopologyRequestModel(_StrictModel):
    """Canonical evidence coordinates and ephemeral base64 source for one plugin."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str
    source_file_id: str
    source_revision_context_id: str
    source_semantic_id: str
    evidence_id: str
    relative_path: str = Field(min_length=1, max_length=4_096)
    classification: str
    commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    content_base64: str = Field(min_length=1, max_length=11_184_812)
    service_hint: str | None = None
    observed_at: datetime


class LinkApiTopologyRequestModel(_StrictModel):
    """Explicit authorized project selection and one client-call candidate identity."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    brain_id: str
    actor_id: str
    grant_id: str
    current_project_id: str
    current_repository_id: str
    selected_project_ids: tuple[str, ...] = Field(min_length=1, max_length=500)
    client_call_id: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class ExtractApiTopologyResponseModel(_StrictModel):
    """Content-free complete plugin registration receipt."""

    operation_id: str
    batch_id: str
    plugin_kind: str
    plugin_version: str
    endpoint_count: int
    client_call_count: int
    contract_binding_count: int
    service_ownership_count: int
    registered_at: str


class ApiTopologyMatchResponseModel(_StrictModel):
    """One exact explainable client-to-server candidate path."""

    match_id: str
    rank: int
    endpoint_id: str
    client_entity_id: str
    endpoint_entity_id: str
    rule: str
    rule_version: str
    disposition: str
    confidence_basis_points: int
    client_evidence_id: str
    server_evidence_id: str
    supporting_candidate_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    qualification_codes: tuple[str, ...]


class LinkApiTopologyResponseModel(_StrictModel):
    """Complete deterministic ranked answer for one consumer call."""

    operation_id: str
    client_call_id: str
    candidate_universe_digest: str
    decision_digest: str
    matches: tuple[ApiTopologyMatchResponseModel, ...]
    linked_at: str


class AuthenticatorPort(Protocol):
    """Authenticate a local bearer capability before request processing."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked local credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve request claims against current durable authorization."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return an immutable authorization-derived project selection."""
        ...


class ExtractApiTopologyPort(Protocol):
    """Inbound extraction use-case boundary."""

    async def execute(
        self, command: ExtractAndRegisterApiTopologyCommand
    ) -> ApiTopologyCandidateBatch:
        """Extract and durably register one complete plugin batch."""
        ...


class LinkApiTopologyPort(Protocol):
    """Inbound cross-project linking use-case boundary."""

    async def execute(self, command: LinkApiTopologyCommand) -> ApiTopologyLinkDecision:
        """Return or exactly replay one complete cross-project topology decision."""
        ...


def create_api_topology_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    extraction: ExtractApiTopologyPort,
    linking: LinkApiTopologyPort,
    clock: Clock,
) -> APIRouter:
    """Create authenticated extraction and explainable cross-project link routes."""
    router = APIRouter()

    @router.post(
        "/v1/indexing/api-topology/extractions",
        operation_id="ExtractAndRegisterApiTopologyCommand",
        response_model=ExtractApiTopologyResponseModel,
        status_code=201,
    )
    async def extract(
        request: Annotated[ExtractApiTopologyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ExtractApiTopologyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _idempotency(request.operation_id, idempotency_key)
            registered_at = clock.now()
            scope = await _scope(
                scope_resolver,
                request,
                registered_at,
                "indexing.api_topology.register",
            )
            batch = await extraction.execute(
                ExtractAndRegisterApiTopologyCommand(
                    request.operation_id,
                    scope,
                    _artifact(request),
                    registered_at,
                )
            )
            return ExtractApiTopologyResponseModel(
                operation_id=request.operation_id,
                batch_id=batch.digest,
                plugin_kind=batch.plugin_kind.value,
                plugin_version=batch.plugin_version,
                endpoint_count=len(batch.endpoints),
                client_call_count=len(batch.client_calls),
                contract_binding_count=len(batch.contract_bindings),
                service_ownership_count=len(batch.service_ownership),
                registered_at=registered_at.isoformat(),
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/indexing/api-topology/links",
        operation_id="LinkApiTopologyCommand",
        response_model=LinkApiTopologyResponseModel,
        status_code=201,
    )
    async def link(
        request: Annotated[LinkApiTopologyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> LinkApiTopologyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _idempotency(request.operation_id, idempotency_key)
            linked_at = clock.now()
            scope = await _scope(
                scope_resolver,
                request,
                linked_at,
                "indexing.api_topology.link",
            )
            decision = await linking.execute(
                LinkApiTopologyCommand(
                    request.operation_id,
                    scope,
                    request.client_call_id,
                    linked_at,
                )
            )
            return LinkApiTopologyResponseModel(
                operation_id=request.operation_id,
                client_call_id=decision.client_call_id,
                candidate_universe_digest=decision.candidate_universe_digest,
                decision_digest=decision.digest,
                matches=tuple(_match(item) for item in decision.matches),
                linked_at=linked_at.isoformat(),
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (extract, link)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        message = "contract dependency cannot execute API topology"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read API topology time"
        raise RuntimeError(message)


def create_contract_api_topology_router() -> APIRouter:
    """Create side-effect-free IDX-004 routes for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_api_topology_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("ExtractApiTopologyPort", dependency),
        cast("LinkApiTopologyPort", dependency),
        _ContractClock(),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    request: ExtractApiTopologyRequestModel | LinkApiTopologyRequestModel,
    requested_at: datetime,
    action: str,
) -> AuthorizedScope:
    if isinstance(request, ExtractApiTopologyRequestModel):
        mode = RetrievalScopeMode.CURRENT
        current_project = request.project_id
        current_repository = request.repository_id
        selected: tuple[str, ...] = ()
    else:
        mode = RetrievalScopeMode.SELECTED
        current_project = request.current_project_id
        current_repository = request.current_repository_id
        selected = request.selected_project_ids
    resolution = await resolver.execute(
        ResolveRetrievalScopeQuery(
            request.operation_id,
            StableId(request.brain_id),
            StableId(request.actor_id),
            StableId(request.grant_id),
            mode,
            StableId(current_project),
            StableId(current_repository),
            None,
            tuple(StableId(item) for item in selected),
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
        purpose="api_topology",
    )


def _artifact(request: ExtractApiTopologyRequestModel) -> ApiTopologySourceArtifact:
    try:
        content = base64.b64decode(request.content_base64, validate=True)
    except (binascii.Error, ValueError) as error:
        raise IndexingValidationError(_ERR_CONTENT) from error
    evidence = ApiTopologyEvidence(
        request.brain_id,
        request.project_id,
        request.repository_id,
        request.source_file_id,
        request.source_revision_context_id,
        request.source_semantic_id,
        request.evidence_id,
        request.relative_path,
        request.classification,
        request.observed_at,
    )
    return ApiTopologySourceArtifact(evidence, request.commit_sha, content, request.service_hint)


def _match(item: ApiTopologyMatch) -> ApiTopologyMatchResponseModel:
    return ApiTopologyMatchResponseModel(
        match_id=item.id,
        rank=item.rank,
        endpoint_id=item.endpoint_id,
        client_entity_id=item.client_entity_id,
        endpoint_entity_id=item.endpoint_entity_id,
        rule=item.rule.value,
        rule_version=item.rule_version,
        disposition=item.disposition.value,
        confidence_basis_points=item.confidence_basis_points,
        client_evidence_id=item.client_evidence_id,
        server_evidence_id=item.server_evidence_id,
        supporting_candidate_ids=item.supporting_candidate_ids,
        supporting_evidence_ids=item.supporting_evidence_ids,
        qualification_codes=item.qualification_codes,
    )


def _idempotency(operation_id: str, key: str | None) -> None:
    if key != operation_id:
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
            "detail": "API topology operation could not be completed",
        },
    )
