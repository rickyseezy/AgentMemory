"""Authenticated GRA-004 bitemporal and branch-aware assertion HTTP adapter."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- Pydantic runtime type.
from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Body, Query, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict

from agentmemory.graph.application.temporal_truth import (
    QueryTemporalAssertionsHandler,
    QueryTemporalAssertionsQuery,
    RecordVcsRevisionBatchCommand,
    RecordVcsRevisionBatchHandler,
)
from agentmemory.graph.domain.assertions import AssertionPredicate  # noqa: TC001
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
    GraphValidationError,
)
from agentmemory.graph.domain.temporal_truth import (
    EvidenceRevisionImpact,
    TemporalTruthMode,
    TruthTemporalScope,
    VcsRefObservation,
    VcsRevisionBatch,
    VcsRevisionNode,
    VcsRevisionSelector,
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
    from agentmemory.graph.domain.temporal_truth import TemporalAssertionResult
    from agentmemory.graph.domain.temporal_truth_ports import (
        TemporalAssertionRepository,
        VcsRevisionBatchRepository,
        VcsRevisionPort,
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
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class TemporalTruthRequestModel(_StrictModel):
    """Closed query parameters for one authorization-first temporal truth read."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    operation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str
    mode: TemporalTruthMode
    as_of_valid: datetime | None = None
    as_of_recorded: datetime | None = None
    branch: str | None = None
    commit: str | None = None
    assertion_id: str | None = None
    subject_id: str | None = None
    predicates: tuple[AssertionPredicate, ...] = ()
    limit: int = 100


class RevisionProofResponseModel(_StrictModel):
    """Content-free reachability evidence for one assertion evidence item."""

    evidence_id: str
    applicability: str
    evidence_commit_sha: str | None
    target_commit_sha: str
    invalidating_commit_shas: tuple[str, ...]
    graph_digest: str


class ResolvedRevisionResponseModel(_StrictModel):
    """Concrete immutable revision selected by a mutable branch or commit request."""

    repository_id: str
    branch: str | None
    requested_commit: str | None
    resolved_commit: str
    graph_digest: str
    observed_at: str
    ref_observation_id: str | None
    force_pushed: bool


class TemporalTruthExplanationResponseModel(_StrictModel):
    """Bitemporal authority and VCS evidence accompanying one assertion."""

    lifecycle_event_id: str
    currency: str
    valid_at: str
    recorded_at: str
    currently_authoritative: bool
    resolved_revision: ResolvedRevisionResponseModel | None
    evidence_proofs: tuple[RevisionProofResponseModel, ...]


class TemporalAssertionResponseModel(_StrictModel):
    """Stable public DTO for one selected canonical assertion revision."""

    assertion_id: str
    assertion_revision_id: str
    subject_id: str
    predicate: str
    polarity: str
    object_id: str
    status: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    classification: str
    valid_from: str
    valid_to: str | None
    recorded_from: str
    recorded_to: str | None
    evidence_ids: tuple[str, ...]
    explanation: TemporalTruthExplanationResponseModel


class VcsRevisionNodeRequestModel(_StrictModel):
    """One immutable commit and its canonical sorted direct-parent set."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    commit_sha: str
    parent_shas: tuple[str, ...] = ()


class VcsRefObservationRequestModel(_StrictModel):
    """One capture-time branch-to-commit observation."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    branch_name: str
    commit_sha: str
    observed_at: datetime


class EvidenceRevisionImpactRequestModel(_StrictModel):
    """One evidence lineage invalidated from an immutable commit onward."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    evidence_id: str
    invalidating_commit_sha: str
    changed_at: datetime


class RecordVcsRevisionBatchRequestModel(_StrictModel):
    """Canonical authorized request for an idempotent VCS observation batch."""

    model_config = ConfigDict(strict=False, extra="forbid", frozen=True)

    operation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str
    nodes: tuple[VcsRevisionNodeRequestModel, ...]
    refs: tuple[VcsRefObservationRequestModel, ...] = ()
    impacts: tuple[EvidenceRevisionImpactRequestModel, ...] = ()
    observed_at: datetime
    source_digest: str


class VcsRevisionBatchReceiptModel(_StrictModel):
    """Content-free receipt binding the exact accepted immutable observation."""

    operation_id: str
    batch_digest: str
    node_count: int
    ref_count: int
    impact_count: int
    observed_at: str


class AuthenticatorPort(Protocol):
    """Authenticate the loopback credential before processing request claims."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current canonical access before any temporal candidate lookup."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return an immutable authorized scope and explanation."""
        ...


def create_temporal_truth_router(  # noqa: PLR0913 -- Explicit adapter dependencies.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    assertions: TemporalAssertionRepository,
    revisions: VcsRevisionPort,
    revision_batches: VcsRevisionBatchRepository,
    clock: Clock,
) -> APIRouter:
    """Create the strict temporal truth route with no raw SQL or Cypher input."""
    router = APIRouter()
    handler = QueryTemporalAssertionsHandler(assertions, revisions)
    recorder = RecordVcsRevisionBatchHandler(revision_batches)

    @router.get(
        "/graph/assertions/truth",
        operation_id="QueryTemporalAssertions",
        response_model=tuple[TemporalAssertionResponseModel, ...],
    )
    async def query_temporal_truth(
        request: Annotated[TemporalTruthRequestModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> tuple[TemporalAssertionResponseModel, ...] | JSONResponse:
        """Authorize current access, then select an explicitly scoped historical/current view."""
        try:
            await authenticator.authenticate(authorization)
            evaluated_at = clock.now()
            resolution = await scope_resolver.execute(_scope_query(request, evaluated_at))
            results = await handler.execute(
                QueryTemporalAssertionsQuery(
                    _truth_scope(resolution.scope),
                    _temporal_scope(request),
                    request.assertion_id,
                    request.subject_id,
                    request.predicates,
                    request.limit,
                ),
                evaluated_at,
            )
            return tuple(_response(item) for item in results)
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

    @router.post(
        "/graph/revisions/observations",
        operation_id="RecordVcsRevisionBatch",
        response_model=VcsRevisionBatchReceiptModel,
        status_code=201,
    )
    async def record_vcs_revision_batch(
        request: Annotated[RecordVcsRevisionBatchRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> VcsRevisionBatchReceiptModel | JSONResponse:
        """Authorize repository access and append one exact DAG/ref/impact observation."""
        try:
            await authenticator.authenticate(authorization)
            requested_at = clock.now()
            resolution = await scope_resolver.execute(_record_scope_query(request, requested_at))
            batch = _revision_batch(request)
            digest = await recorder.execute(
                RecordVcsRevisionBatchCommand(_record_scope(resolution.scope), batch)
            )
            return VcsRevisionBatchReceiptModel(
                operation_id=batch.operation_id,
                batch_digest=digest,
                node_count=len(batch.nodes),
                ref_count=len(batch.refs),
                impact_count=len(batch.impacts),
                observed_at=_time(batch.observed_at),
            )
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

    registered_routes = (query_temporal_truth, record_vcs_revision_batch)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractScopeResolver:
    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        message = "contract-only resolver cannot resolve temporal scope"
        raise RuntimeError(message)


class _ContractAssertions:
    async def query(self, scope: object, criteria: object) -> tuple[object, ...]:
        del scope, criteria
        message = "contract-only repository cannot query temporal assertions"
        raise RuntimeError(message)


class _ContractRevisions:
    async def resolve(self, scope: object, selector: object, recorded_at: object) -> object:
        del scope, selector, recorded_at
        message = "contract-only repository cannot resolve revisions"
        raise RuntimeError(message)

    async def prove(
        self,
        scope: object,
        evidence_id: str,
        anchor: object,
        resolved: object,
        recorded_at: object,
    ) -> object:
        del scope, evidence_id, anchor, resolved, recorded_at
        message = "contract-only repository cannot prove revisions"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract-only clock cannot read time"
        raise RuntimeError(message)


def create_contract_temporal_truth_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_temporal_truth_router(
        _ContractAuthenticator(),
        _ContractScopeResolver(),
        cast("TemporalAssertionRepository", _ContractAssertions()),
        cast("VcsRevisionPort", _ContractRevisions()),
        cast("VcsRevisionBatchRepository", _ContractRevisions()),
        _ContractClock(),
    )


def _scope_query(
    request: TemporalTruthRequestModel,
    requested_at: datetime,
) -> ResolveRetrievalScopeQuery:
    return ResolveRetrievalScopeQuery(
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


def _record_scope_query(
    request: RecordVcsRevisionBatchRequestModel,
    requested_at: datetime,
) -> ResolveRetrievalScopeQuery:
    return ResolveRetrievalScopeQuery(
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


def _truth_scope(scope: AuthorizedScope) -> AuthorizedScope:
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
        action="graph.assertion.truth.query",
        purpose="temporal_truth_query",
    )


def _record_scope(scope: AuthorizedScope) -> AuthorizedScope:
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
        action="graph.vcs.revision.record",
        purpose="vcs_revision_observation",
    )


def _temporal_scope(request: TemporalTruthRequestModel) -> TruthTemporalScope:
    revision = None
    if request.branch is not None or request.commit is not None:
        revision = VcsRevisionSelector(
            request.repository_id,
            branch_name=request.branch,
            commit_sha=request.commit,
        )
    return TruthTemporalScope(
        request.mode,
        request.as_of_valid,
        request.as_of_recorded,
        revision,
    )


def _revision_batch(request: RecordVcsRevisionBatchRequestModel) -> VcsRevisionBatch:
    return VcsRevisionBatch(
        request.operation_id,
        request.brain_id,
        request.repository_id,
        tuple(VcsRevisionNode(item.commit_sha, item.parent_shas) for item in request.nodes),
        tuple(
            VcsRefObservation(item.branch_name, item.commit_sha, item.observed_at)
            for item in request.refs
        ),
        tuple(
            EvidenceRevisionImpact(
                item.evidence_id,
                item.invalidating_commit_sha,
                item.changed_at,
            )
            for item in request.impacts
        ),
        request.observed_at,
        request.source_digest,
    )


def _response(result: TemporalAssertionResult) -> TemporalAssertionResponseModel:
    assertion = result.assertion
    explanation = result.explanation
    resolved = explanation.resolved_revision
    resolved_response = None
    if resolved is not None:
        resolved_response = ResolvedRevisionResponseModel(
            repository_id=resolved.selector.repository_id,
            branch=resolved.selector.branch_name,
            requested_commit=resolved.selector.commit_sha,
            resolved_commit=resolved.commit_sha,
            graph_digest=resolved.graph_digest,
            observed_at=_time(resolved.observed_at),
            ref_observation_id=resolved.ref_observation_id,
            force_pushed=resolved.force_pushed,
        )
    return TemporalAssertionResponseModel(
        assertion_id=assertion.id,
        assertion_revision_id=assertion.revision_id,
        subject_id=assertion.subject_id,
        predicate=assertion.predicate.value,
        polarity=assertion.polarity.value,
        object_id=assertion.object_id,
        status=assertion.status.value,
        project_id=assertion.scope.project_id,
        repository_id=assertion.scope.repository_id,
        checkout_id=assertion.scope.checkout_id,
        classification=assertion.scope.classification,
        valid_from=_time(assertion.temporal.valid_from),
        valid_to=(
            None if assertion.temporal.valid_to is None else _time(assertion.temporal.valid_to)
        ),
        recorded_from=_time(assertion.temporal.recorded_from),
        recorded_to=(
            None
            if assertion.temporal.recorded_to is None
            else _time(assertion.temporal.recorded_to)
        ),
        evidence_ids=tuple(item.evidence_id for item in assertion.evidence),
        explanation=TemporalTruthExplanationResponseModel(
            lifecycle_event_id=explanation.lifecycle_event_id,
            currency=explanation.currency.value,
            valid_at=_time(explanation.valid_at),
            recorded_at=_time(explanation.recorded_at),
            currently_authoritative=explanation.currently_authoritative,
            resolved_revision=resolved_response,
            evidence_proofs=tuple(
                RevisionProofResponseModel(
                    evidence_id=item.evidence_id,
                    applicability=item.applicability.value,
                    evidence_commit_sha=item.evidence_commit_sha,
                    target_commit_sha=item.target_commit_sha,
                    invalidating_commit_shas=item.invalidating_commit_shas,
                    graph_digest=item.graph_digest,
                )
                for item in explanation.evidence_proofs
            ),
        ),
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
            "temporal truth scope is not authorized",
            False,
        ),
        (
            (IdentityConflictError, GraphConflictError),
            "AM_CONFLICT",
            409,
            "temporal truth request conflicts",
            False,
        ),
        (
            (IdentityValidationError, GraphValidationError),
            "AM_VALIDATION",
            422,
            "temporal truth request is invalid",
            False,
        ),
        (
            (IdentityDependencyError, GraphUnavailableError),
            "AM_DEPENDENCY_UNAVAILABLE",
            503,
            "temporal truth dependency is unavailable",
            True,
        ),
        (
            (GraphIntegrityError,),
            "AM_INTEGRITY_VIOLATION",
            500,
            "temporal truth evidence failed verification",
            False,
        ),
    )
    for error_types, code, status, detail, retryable in mappings:
        if isinstance(error, error_types):
            return _problem(code, status, detail, retryable=retryable)
    raise AssertionError from error
