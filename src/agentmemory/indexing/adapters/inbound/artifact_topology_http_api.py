"""Authenticated IDX-005 artifact topology extraction and temporal query HTTP adapter."""

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
from agentmemory.indexing.application.artifact_topology import (
    ExtractAndRegisterArtifactTopologyCommand,
    QueryArtifactTopologyCommand,
)
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyEvidence,
    ArtifactTopologySourceArtifact,
    TopologyCandidate,
    TopologyRelationCandidate,
    UnknownTopologyEvidence,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.artifact_topology import (
        ArtifactTopologyBatch,
        ArtifactTopologySnapshot,
    )
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_CONTENT = "artifact topology source content is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ExtractArtifactTopologyRequestModel(_StrictModel):
    """Canonical source coordinates and ephemeral base64 artifact bytes."""

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
    observed_at: datetime


class QueryArtifactTopologyRequestModel(_StrictModel):
    """Explicit project selection and temporal cutoff for a topology snapshot."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    brain_id: str
    actor_id: str
    grant_id: str
    current_project_id: str
    current_repository_id: str
    selected_project_ids: tuple[str, ...] = Field(min_length=1, max_length=500)
    cutoff: datetime


class ExtractArtifactTopologyResponseModel(_StrictModel):
    """Content-free complete parser registration receipt."""

    operation_id: str
    batch_id: str
    plugin_kind: str
    plugin_version: str
    candidate_count: int
    relation_count: int
    unknown_evidence_count: int
    registered_at: str


class TopologyCandidateResponseModel(_StrictModel):
    """One value-free evidence-backed topology entity observation."""

    candidate_id: str
    entity_id: str
    entity_kind: str
    name: str
    version: str | None
    environment_reference: str | None
    sensitivity: str | None
    qualifiers: tuple[str, ...]
    evidence_id: str
    project_id: str
    repository_id: str
    observed_at: str


class TopologyRelationResponseModel(_StrictModel):
    """One temporal topology relation without collapsed conflicting observations."""

    relation_id: str
    subject_entity_id: str
    relation: str
    object_entity_id: str
    environment_reference: str | None
    valid_from: str
    valid_to: str | None
    evidence_id: str
    project_id: str
    repository_id: str


class UnknownTopologyEvidenceResponseModel(_StrictModel):
    """Digest-only unsupported construct coordinate."""

    unknown_id: str
    reason: str
    fragment_digest: str
    start_line: int
    end_line: int
    evidence_id: str
    relative_path: str


class QueryArtifactTopologyResponseModel(_StrictModel):
    """Complete authorized latest-per-source temporal topology."""

    cutoff: str
    candidates: tuple[TopologyCandidateResponseModel, ...]
    relations: tuple[TopologyRelationResponseModel, ...]
    unknown_evidence: tuple[UnknownTopologyEvidenceResponseModel, ...]


class AuthenticatorPort(Protocol):
    """Authenticate a local bearer capability before request processing."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked local credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve request claims against current durable authorization."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return an immutable authorization-derived selection."""
        ...


class ExtractArtifactTopologyPort(Protocol):
    """Inbound deterministic artifact extraction boundary."""

    async def execute(
        self, command: ExtractAndRegisterArtifactTopologyCommand
    ) -> ArtifactTopologyBatch:
        """Parse, persist, and project one complete artifact output."""
        ...


class QueryArtifactTopologyPort(Protocol):
    """Inbound temporal artifact topology query boundary."""

    async def execute(self, command: QueryArtifactTopologyCommand) -> ArtifactTopologySnapshot:
        """Return a complete authorized snapshot."""
        ...


def create_artifact_topology_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    extraction: ExtractArtifactTopologyPort,
    query: QueryArtifactTopologyPort,
    clock: Clock,
) -> APIRouter:
    """Create authenticated extraction and temporal topology query routes."""
    router = APIRouter()

    @router.post(
        "/v1/indexing/artifact-topology/extractions",
        operation_id="ExtractAndRegisterArtifactTopologyCommand",
        response_model=ExtractArtifactTopologyResponseModel,
        status_code=201,
    )
    async def extract(
        request: Annotated[ExtractArtifactTopologyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ExtractArtifactTopologyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _idempotency(request.operation_id, idempotency_key)
            registered_at = clock.now()
            scope = await _scope(
                scope_resolver,
                request,
                registered_at,
                "indexing.artifact_topology.register",
            )
            batch = await extraction.execute(
                ExtractAndRegisterArtifactTopologyCommand(
                    request.operation_id,
                    scope,
                    _artifact(request),
                    registered_at,
                )
            )
            return ExtractArtifactTopologyResponseModel(
                operation_id=request.operation_id,
                batch_id=batch.digest,
                plugin_kind=batch.plugin_kind.value,
                plugin_version=batch.plugin_version,
                candidate_count=len(batch.candidates),
                relation_count=len(batch.relations),
                unknown_evidence_count=len(batch.unknown_evidence),
                registered_at=registered_at.isoformat(),
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/indexing/artifact-topology/queries",
        operation_id="QueryArtifactTopologyCommand",
        response_model=QueryArtifactTopologyResponseModel,
    )
    async def topology_query(
        request: Annotated[QueryArtifactTopologyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> QueryArtifactTopologyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            requested_at = clock.now()
            scope = await _scope(
                scope_resolver,
                request,
                requested_at,
                "indexing.artifact_topology.read",
            )
            snapshot = await query.execute(QueryArtifactTopologyCommand(scope, request.cutoff))
            return QueryArtifactTopologyResponseModel(
                cutoff=snapshot.cutoff.isoformat(),
                candidates=tuple(_candidate(item) for item in snapshot.candidates),
                relations=tuple(_relation(item) for item in snapshot.relations),
                unknown_evidence=tuple(_unknown(item) for item in snapshot.unknown_evidence),
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (extract, topology_query)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        message = "contract dependency cannot execute artifact topology"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read artifact topology time"
        raise RuntimeError(message)


def create_contract_artifact_topology_router() -> APIRouter:
    """Create side-effect-free IDX-005 routes for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_artifact_topology_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("ExtractArtifactTopologyPort", dependency),
        cast("QueryArtifactTopologyPort", dependency),
        _ContractClock(),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    request: ExtractArtifactTopologyRequestModel | QueryArtifactTopologyRequestModel,
    requested_at: datetime,
    action: str,
) -> AuthorizedScope:
    if isinstance(request, ExtractArtifactTopologyRequestModel):
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
        purpose="artifact_topology",
    )


def _artifact(request: ExtractArtifactTopologyRequestModel) -> ArtifactTopologySourceArtifact:
    try:
        content = base64.b64decode(request.content_base64, validate=True)
    except (binascii.Error, ValueError) as error:
        raise IndexingValidationError(_ERR_CONTENT) from error
    evidence = ArtifactTopologyEvidence(
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
    return ArtifactTopologySourceArtifact(evidence, request.commit_sha, content)


def _candidate(item: TopologyCandidate) -> TopologyCandidateResponseModel:
    return TopologyCandidateResponseModel(
        candidate_id=item.id,
        entity_id=item.entity_id,
        entity_kind=item.kind.value,
        name=item.name,
        version=item.version,
        environment_reference=item.environment_reference,
        sensitivity=None if item.sensitivity is None else item.sensitivity.value,
        qualifiers=item.qualifiers,
        evidence_id=item.evidence.evidence_id,
        project_id=item.evidence.project_id,
        repository_id=item.evidence.repository_id,
        observed_at=item.evidence.observed_at.isoformat(),
    )


def _relation(item: TopologyRelationCandidate) -> TopologyRelationResponseModel:
    return TopologyRelationResponseModel(
        relation_id=item.id,
        subject_entity_id=item.subject_entity_id,
        relation=item.relation.value,
        object_entity_id=item.object_entity_id,
        environment_reference=item.environment_reference,
        valid_from=item.valid_from.isoformat(),
        valid_to=None if item.valid_to is None else item.valid_to.isoformat(),
        evidence_id=item.evidence.evidence_id,
        project_id=item.evidence.project_id,
        repository_id=item.evidence.repository_id,
    )


def _unknown(item: UnknownTopologyEvidence) -> UnknownTopologyEvidenceResponseModel:
    return UnknownTopologyEvidenceResponseModel(
        unknown_id=item.id,
        reason=item.reason.value,
        fragment_digest=item.fragment_digest,
        start_line=item.start_line,
        end_line=item.end_line,
        evidence_id=item.evidence.evidence_id,
        relative_path=item.evidence.relative_path,
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
            "detail": "Artifact topology operation could not be completed",
        },
    )
