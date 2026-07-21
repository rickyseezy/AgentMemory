"""Authenticated GRA-005 contradiction detection, resolution, and policy HTTP adapter."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- Pydantic runtime type.
from typing import TYPE_CHECKING, Annotated, Protocol, cast

from fastapi import APIRouter, Body, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict

from agentmemory.graph.application.contradictions import (
    DetectContradictionsCommand,
    DetectContradictionsHandler,
    EvaluateContradictionsHandler,
    EvaluateContradictionsQuery,
    ResolveContradictionCommand,
    ResolveContradictionHandler,
)
from agentmemory.graph.domain.contradictions import (
    Contradiction,
    ContradictionResolutionOutcome,
    RetrievalAssertionCandidate,
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
    from agentmemory.graph.domain.contradiction_ports import ContradictionRepository
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


class ContradictionScopeRequestModel(_StrictModel):
    """Common authorization coordinates for contradiction operations."""

    operation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class DetectContradictionsRequestModel(ContradictionScopeRequestModel):
    """Request deterministic conflict detection over current canonical assertions."""

    detected_at: datetime


class ResolveContradictionRequestModel(ContradictionScopeRequestModel):
    """Request an explicit evidence-backed user resolution."""

    contradiction_id: str
    outcome: ContradictionResolutionOutcome
    reason_code: str
    evidence_ids: tuple[str, ...]
    resolved_at: datetime


class RetrievalCandidateRequestModel(_StrictModel):
    """One candidate after fusion; rank remains relevance rather than truth."""

    assertion_id: str
    rank_basis_points: int
    authoritative: bool


class EvaluateContradictionsRequestModel(ContradictionScopeRequestModel):
    """Apply contradiction policy before retrieval response synthesis."""

    candidates: tuple[RetrievalCandidateRequestModel, ...]


class ContradictionResolutionResponseModel(_StrictModel):
    """Content-free resolving authority and evidence."""

    outcome: str
    actor_id: str
    grant_id: str
    reason_code: str
    evidence_ids: tuple[str, ...]
    resolved_at: str
    resolution_digest: str


class ContradictionResponseModel(_StrictModel):
    """Stable public representation of one dispute and optional resolution."""

    contradiction_id: str
    left_assertion_id: str
    right_assertion_id: str
    predicate: str
    dimension: str
    valid_from: str
    valid_to: str | None
    evidence_ids: tuple[str, ...]
    detected_at: str
    state: str
    detection_digest: str
    resolution: ContradictionResolutionResponseModel | None


class ContradictionPolicyResponseModel(_StrictModel):
    """Truth decision consumed by retrieval synthesis."""

    decision: str
    selected_assertion_ids: tuple[str, ...]
    disputed_assertion_ids: tuple[str, ...]
    contradiction_ids: tuple[str, ...]


class AuthenticatorPort(Protocol):
    """Authenticate the local bearer credential."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate the local bearer capability before request processing."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current canonical authorization."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Resolve current canonical authorization scope."""
        ...


def create_contradiction_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    repository: ContradictionRepository,
    clock: Clock,
) -> APIRouter:
    """Create strict contradiction routes without source content or dynamic query input."""
    router = APIRouter()
    detector = DetectContradictionsHandler(repository)
    resolver = ResolveContradictionHandler(repository)
    evaluator = EvaluateContradictionsHandler(repository)

    @router.post(
        "/graph/contradictions/detect",
        operation_id="DetectContradictions",
        response_model=tuple[ContradictionResponseModel, ...],
        status_code=201,
    )
    async def detect(
        request: Annotated[DetectContradictionsRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> tuple[ContradictionResponseModel, ...] | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _resolve_scope(
                scope_resolver, request, clock.now(), "graph.contradiction.detect"
            )
            values = await detector.execute(
                DetectContradictionsCommand(
                    request.operation_id,
                    scope,
                    request.repository_id,
                    request.detected_at,
                )
            )
            return tuple(_contradiction_response(item) for item in values)
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    @router.post(
        "/graph/contradictions/resolve",
        operation_id="ResolveContradiction",
        response_model=ContradictionResponseModel,
    )
    async def resolve(
        request: Annotated[ResolveContradictionRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ContradictionResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _resolve_scope(
                scope_resolver, request, clock.now(), "graph.contradiction.resolve"
            )
            value = await resolver.execute(
                ResolveContradictionCommand(
                    request.operation_id,
                    scope,
                    request.contradiction_id,
                    request.grant_id,
                    request.outcome,
                    request.reason_code,
                    request.evidence_ids,
                    request.resolved_at,
                )
            )
            return _contradiction_response(value)
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    @router.post(
        "/graph/contradictions/evaluate",
        operation_id="EvaluateContradictions",
        response_model=ContradictionPolicyResponseModel,
    )
    async def evaluate(
        request: Annotated[EvaluateContradictionsRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ContradictionPolicyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _resolve_scope(
                scope_resolver, request, clock.now(), "graph.contradiction.query"
            )
            result = await evaluator.execute(
                EvaluateContradictionsQuery(
                    scope,
                    tuple(
                        RetrievalAssertionCandidate(
                            item.assertion_id,
                            item.rank_basis_points,
                            item.authoritative,
                        )
                        for item in request.candidates
                    ),
                )
            )
            return ContradictionPolicyResponseModel(
                decision=result.decision.value,
                selected_assertion_ids=result.selected_assertion_ids,
                disputed_assertion_ids=result.disputed_assertion_ids,
                contradiction_ids=result.contradiction_ids,
            )
        except _HANDLED_ERRORS as error:
            return _error_problem(error)

    routes = (detect, resolve, evaluate)
    del routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractResolver:
    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        message = "contract resolver cannot resolve scope"
        raise RuntimeError(message)


class _ContractRepository:
    async def detection_candidates(self, scope: object, repository_id: str) -> tuple[object, ...]:
        del scope, repository_id
        message = "contract repository cannot load candidates"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read time"
        raise RuntimeError(message)


def create_contract_contradiction_router() -> APIRouter:
    """Create a side-effect-free router for deterministic OpenAPI export."""
    return create_contradiction_router(
        _ContractAuthenticator(),
        _ContractResolver(),
        cast("ContradictionRepository", _ContractRepository()),
        _ContractClock(),
    )


async def _resolve_scope(
    resolver: RetrievalScopeResolverPort,
    request: ContradictionScopeRequestModel,
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
        purpose="contradiction_policy",
    )


def _contradiction_response(value: Contradiction) -> ContradictionResponseModel:
    resolution = value.resolution
    response = None
    if resolution is not None:
        response = ContradictionResolutionResponseModel(
            outcome=resolution.outcome.value,
            actor_id=resolution.actor_id,
            grant_id=resolution.grant_id,
            reason_code=resolution.reason_code,
            evidence_ids=resolution.evidence_ids,
            resolved_at=_time(resolution.resolved_at),
            resolution_digest=resolution.resolution_digest,
        )
    return ContradictionResponseModel(
        contradiction_id=value.id,
        left_assertion_id=value.left_assertion_id,
        right_assertion_id=value.right_assertion_id,
        predicate=value.predicate.value,
        dimension=value.dimension.value,
        valid_from=_time(value.valid_from),
        valid_to=None if value.valid_to is None else _time(value.valid_to),
        evidence_ids=value.evidence_ids,
        detected_at=_time(value.detected_at),
        state=value.state.value,
        detection_digest=value.detection_digest,
        resolution=response,
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
        return _problem("AM_FORBIDDEN", 403, "contradiction scope is not authorized")
    if isinstance(error, (IdentityConflictError, GraphConflictError)):
        return _problem("AM_CONFLICT", 409, "contradiction request conflicts")
    if isinstance(error, (IdentityDependencyError, GraphUnavailableError)):
        return _problem(
            "AM_DEPENDENCY_UNAVAILABLE",
            503,
            "contradiction dependency is unavailable",
            retryable=True,
        )
    if isinstance(error, GraphIntegrityError):
        return _problem("AM_INTEGRITY_VIOLATION", 500, "contradiction evidence failed verification")
    return _problem("AM_VALIDATION", 422, "contradiction request is invalid")


def _problem(code: str, status: int, detail: str, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"code": code, "detail": detail, "retryable": retryable},
        media_type="application/problem+json",
    )
