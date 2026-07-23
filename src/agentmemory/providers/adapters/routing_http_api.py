"""Authenticated PRO-005 provider-routing administration and resolution API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

from fastapi import APIRouter, Body, Header, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.adapters.profile_http_api import (
    ProviderScopeModel,
    RetrievalScopeResolverPort,
    resolve_provider_scope,
)
from agentmemory.providers.application.routing import (
    CreateProviderRouteCommand,
    ResolveProviderRouteQuery,
    RestrictProviderRoutingCommand,
)
from agentmemory.providers.domain.errors import (
    ProviderRoutingAuthorizationError,
    ProviderRoutingCapabilityError,
    ProviderRoutingConflictError,
    ProviderRoutingDeniedError,
    ProviderRoutingDependencyError,
    ProviderRoutingValidationError,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose, ProviderOperation
from agentmemory.providers.domain.routing import (
    ProviderCorpus,
    ProviderRouteDraft,
    ProviderRouteRequest,
    ProviderRouteSelector,
    ProviderRoutingGuard,
    ProviderRoutingPolicy,
    ProviderWorkload,
    RepositoryRoutingRestriction,
    RouteDecision,
)

if TYPE_CHECKING:
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"

PurposeLiteral = Literal[
    "retrieval_query",
    "retrieval_document",
    "code_query",
    "code_document",
    "semantic_similarity",
    "classification",
    "clustering",
]
ClassificationLiteral = Literal[
    "public",
    "internal",
    "confidential",
    "restricted",
    "local_only",
]
WorkloadLiteral = Literal[
    "interactive",
    "capture",
    "backfill",
    "evaluation",
    "maintenance",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ProviderRoutingGuardModel(_StrictModel):
    """Brain-owned egress, residency, and classification ceiling."""

    allow_remote: bool
    allowed_remote_residencies: list[str] = Field(max_length=256)
    remote_classification_ceiling: ClassificationLiteral


class ProviderRouteSelectorModel(_StrictModel):
    """Optional route match dimensions; omitted fields are wildcards."""

    project_id: str | None = None
    corpus: Literal["code", "memory", "document"] | None = None
    language: str | None = Field(default=None, min_length=1, max_length=32)
    classification: ClassificationLiteral | None = None
    purpose: PurposeLiteral | None = None
    workload: WorkloadLiteral | None = None


class ProviderRouteDraftModel(_StrictModel):
    """One administrator-authored route before exact profile binding."""

    draft_key: str = Field(min_length=1, max_length=64)
    profile_id: str
    operation: Literal["embedding", "reranking"]
    selector: ProviderRouteSelectorModel
    enabled: bool
    reason: str = Field(min_length=1, max_length=64)


class CreateProviderRoutingPolicyRequestModel(ProviderScopeModel):
    """Complete immutable replacement policy publication."""

    operation_id: str = Field(min_length=1, max_length=128)
    expected_current_version: int = Field(ge=0, le=2**31 - 2)
    guard: ProviderRoutingGuardModel
    routes: list[ProviderRouteDraftModel] = Field(min_length=1, max_length=10_000)


class RestrictProviderRoutingRequestModel(ProviderScopeModel):
    """Repository filter publication that may only narrow Brain policy."""

    operation_id: str = Field(min_length=1, max_length=128)
    expected_current_version: int = Field(ge=0, le=2**31 - 2)
    allow_remote: bool
    allowed_remote_residencies: list[str] = Field(max_length=256)
    remote_classification_ceiling: ClassificationLiteral
    allowed_profile_ids: list[str] = Field(max_length=10_000)
    allowed_purposes: list[PurposeLiteral] = Field(max_length=7)
    allowed_workloads: list[WorkloadLiteral] = Field(max_length=5)


class ResolveProviderRouteRequestModel(ProviderScopeModel):
    """Complete content-free routing coordinates."""

    operation_id: str = Field(min_length=1, max_length=128)
    operation: Literal["embedding", "reranking"]
    corpus: Literal["code", "memory", "document"]
    language: str | None = Field(default=None, min_length=1, max_length=32)
    classification: ClassificationLiteral
    purpose: PurposeLiteral
    workload: WorkloadLiteral


class ProviderRouteRuleResponseModel(_StrictModel):
    """Immutable exact-profile route returned after publication."""

    rule_id: str
    profile_id: str
    profile_version: int
    profile_snapshot_digest: str
    operation: str
    selector: ProviderRouteSelectorModel
    enabled: bool
    reason: str
    precedence: list[int]


class ProviderRoutingPolicyResponseModel(_StrictModel):
    """Content-free immutable routing policy."""

    policy_id: str
    brain_id: str
    version: int
    policy_digest: str
    guard: ProviderRoutingGuardModel
    rules: list[ProviderRouteRuleResponseModel]
    created_at: str


class RepositoryRoutingRestrictionResponseModel(_StrictModel):
    """Content-free immutable repository routing filter."""

    restriction_id: str
    brain_id: str
    repository_id: str
    version: int
    restriction_digest: str
    allow_remote: bool
    allowed_remote_residencies: list[str]
    remote_classification_ceiling: str
    allowed_profile_ids: list[str]
    allowed_purposes: list[str]
    allowed_workloads: list[str]


class RouteDecisionResponseModel(_StrictModel):
    """Reviewable content-free decision bound to policy/profile versions."""

    policy_id: str
    policy_version: int
    rule_id: str
    profile_id: str
    profile_version: int
    profile_snapshot_digest: str
    precedence: list[int]
    reason: str
    request_digest: str


class AuthenticatorPort(Protocol):
    """Authenticate the local API capability before routing work."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate before resolving scope or reading routing authority."""
        ...


class CreateProviderRoutePort(Protocol):
    """Publish one immutable provider routing policy."""

    async def execute(
        self,
        command: CreateProviderRouteCommand,
    ) -> ProviderRoutingPolicy:
        """Publish or exactly replay the policy."""
        ...


class RestrictProviderRoutingPort(Protocol):
    """Publish one repository restriction."""

    async def execute(
        self,
        command: RestrictProviderRoutingCommand,
    ) -> RepositoryRoutingRestriction:
        """Publish or exactly replay the restriction."""
        ...


class ResolveProviderRoutePort(Protocol):
    """Resolve and journal one provider route."""

    async def execute(self, query: ResolveProviderRouteQuery) -> RouteDecision:
        """Resolve one deterministic route."""
        ...


def create_provider_routing_router(  # noqa: PLR0913 -- Explicit hexagonal composition.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    create_handler: CreateProviderRoutePort,
    restrict_handler: RestrictProviderRoutingPort,
    resolve_handler: ResolveProviderRoutePort,
    clock: Clock,
) -> APIRouter:
    """Create the complete PRO-005 policy, restriction, and decision API."""
    router = APIRouter()

    @router.post(
        "/v1/providers/routing/policies",
        operation_id="CreateProviderRouteCommand",
        response_model=ProviderRoutingPolicyResponseModel,
        status_code=201,
    )
    async def create(
        body: Annotated[CreateProviderRoutingPolicyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProviderRoutingPolicyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            if idempotency_key != body.operation_id:
                raise ProviderRoutingValidationError(_ERR_IDEMPOTENCY)
            at = clock.now()
            authorized_scope = await resolve_provider_scope(
                scope_resolver,
                body,
                at,
                "provider.route.publish",
                purpose="provider_routing_administration",
            )
            routes = tuple(
                sorted(
                    (_draft(value) for value in body.routes),
                    key=lambda value: value.draft_key,
                )
            )
            result = await create_handler.execute(
                CreateProviderRouteCommand(
                    operation_id=body.operation_id,
                    scope=authorized_scope,
                    expected_current_version=body.expected_current_version,
                    guard=_guard(body.guard),
                    routes=routes,
                    created_at=at,
                )
            )
            return _policy_response(result)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/routing/repository-restrictions",
        operation_id="RestrictProviderRoutingCommand",
        response_model=RepositoryRoutingRestrictionResponseModel,
        status_code=201,
    )
    async def restrict(
        body: Annotated[RestrictProviderRoutingRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> RepositoryRoutingRestrictionResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            if idempotency_key != body.operation_id:
                raise ProviderRoutingValidationError(_ERR_IDEMPOTENCY)
            at = clock.now()
            authorized_scope = await resolve_provider_scope(
                scope_resolver,
                body,
                at,
                "provider.route.restrict",
                purpose="provider_routing_administration",
            )
            result = await restrict_handler.execute(
                RestrictProviderRoutingCommand(
                    operation_id=body.operation_id,
                    scope=authorized_scope,
                    repository_id=body.repository_id,
                    expected_current_version=body.expected_current_version,
                    allow_remote=body.allow_remote,
                    allowed_remote_residencies=tuple(sorted(set(body.allowed_remote_residencies))),
                    remote_classification_ceiling=Classification(
                        body.remote_classification_ceiling
                    ),
                    allowed_profile_ids=tuple(sorted(set(body.allowed_profile_ids))),
                    allowed_purposes=tuple(
                        sorted(
                            {CanonicalPurpose(value) for value in body.allowed_purposes},
                            key=str,
                        )
                    ),
                    allowed_workloads=tuple(
                        sorted(
                            {ProviderWorkload(value) for value in body.allowed_workloads},
                            key=str,
                        )
                    ),
                    created_at=at,
                )
            )
            return _restriction_response(result)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/routes:resolve",
        operation_id="ResolveProviderRouteQuery",
        response_model=RouteDecisionResponseModel,
    )
    async def resolve(
        body: Annotated[ResolveProviderRouteRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> RouteDecisionResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            if idempotency_key != body.operation_id:
                raise ProviderRoutingValidationError(_ERR_IDEMPOTENCY)
            at = clock.now()
            authorized_scope = await resolve_provider_scope(
                scope_resolver,
                body,
                at,
                "provider.route.resolve",
                purpose="provider_route_resolution",
            )
            result = await resolve_handler.execute(
                ResolveProviderRouteQuery(
                    operation_id=body.operation_id,
                    scope=authorized_scope,
                    request=ProviderRouteRequest(
                        brain_id=body.brain_id,
                        project_id=body.project_id,
                        repository_id=body.repository_id,
                        operation=ProviderOperation(body.operation),
                        corpus=ProviderCorpus(body.corpus),
                        language=body.language,
                        classification=Classification(body.classification),
                        purpose=CanonicalPurpose(body.purpose),
                        workload=ProviderWorkload(body.workload),
                    ),
                    requested_at=at,
                )
            )
            return _decision_response(result)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (create, restrict, resolve)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:  # pragma: no mutate block
        del value
        raise RuntimeError(_ERR_CONTRACT_DEPENDENCY)


class _ContractClock:
    def now(self) -> object:  # pragma: no mutate block
        raise RuntimeError(_ERR_CONTRACT_CLOCK)


def create_contract_provider_routing_router() -> APIRouter:
    """Create a side-effect-free PRO-005 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_provider_routing_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("CreateProviderRoutePort", dependency),
        cast("RestrictProviderRoutingPort", dependency),
        cast("ResolveProviderRoutePort", dependency),
        cast("Clock", _ContractClock()),
    )


def _guard(model: ProviderRoutingGuardModel) -> ProviderRoutingGuard:
    return ProviderRoutingGuard(
        allow_remote=model.allow_remote,
        allowed_remote_residencies=tuple(sorted(set(model.allowed_remote_residencies))),
        remote_classification_ceiling=Classification(model.remote_classification_ceiling),
    )


def _draft(model: ProviderRouteDraftModel) -> ProviderRouteDraft:
    selector = model.selector
    return ProviderRouteDraft(
        draft_key=model.draft_key,
        profile_id=model.profile_id,
        operation=ProviderOperation(model.operation),
        selector=ProviderRouteSelector(
            project_id=selector.project_id,
            corpus=None if selector.corpus is None else ProviderCorpus(selector.corpus),
            language=selector.language,
            classification=(
                None if selector.classification is None else Classification(selector.classification)
            ),
            purpose=(None if selector.purpose is None else CanonicalPurpose(selector.purpose)),
            workload=(None if selector.workload is None else ProviderWorkload(selector.workload)),
        ),
        enabled=model.enabled,
        reason=model.reason,
    )


def _policy_response(
    policy: ProviderRoutingPolicy,
) -> ProviderRoutingPolicyResponseModel:
    return ProviderRoutingPolicyResponseModel(
        policy_id=policy.policy_id,
        brain_id=policy.brain_id,
        version=policy.version,
        policy_digest=policy.digest,
        guard=ProviderRoutingGuardModel.model_validate(policy.guard.document),
        rules=[
            ProviderRouteRuleResponseModel(
                rule_id=rule.rule_id,
                profile_id=rule.profile_id,
                profile_version=rule.profile_version,
                profile_snapshot_digest=rule.profile_snapshot_digest,
                operation=rule.operation.value,
                selector=ProviderRouteSelectorModel.model_validate(rule.selector.document),
                enabled=rule.enabled,
                reason=rule.reason,
                precedence=list(rule.selector.precedence),
            )
            for rule in policy.rules
        ],
        created_at=policy.created_at.isoformat(),
    )


def _restriction_response(
    value: RepositoryRoutingRestriction,
) -> RepositoryRoutingRestrictionResponseModel:
    return RepositoryRoutingRestrictionResponseModel(
        restriction_id=value.restriction_id,
        brain_id=value.brain_id,
        repository_id=value.repository_id,
        version=value.version,
        restriction_digest=value.digest,
        allow_remote=value.allow_remote,
        allowed_remote_residencies=list(value.allowed_remote_residencies),
        remote_classification_ceiling=value.remote_classification_ceiling.value,
        allowed_profile_ids=list(value.allowed_profile_ids),
        allowed_purposes=[item.value for item in value.allowed_purposes],
        allowed_workloads=[item.value for item in value.allowed_workloads],
    )


def _decision_response(value: RouteDecision) -> RouteDecisionResponseModel:
    return RouteDecisionResponseModel(
        policy_id=value.policy_id,
        policy_version=value.policy_version,
        rule_id=value.rule_id,
        profile_id=value.profile_id,
        profile_version=value.profile_version,
        profile_snapshot_digest=value.profile_snapshot_digest,
        precedence=list(value.precedence),
        reason=value.reason,
        request_digest=value.request_digest,
    )


_HANDLED_ERRORS = (
    ProviderRoutingAuthorizationError,
    ProviderRoutingCapabilityError,
    ProviderRoutingConflictError,
    ProviderRoutingDeniedError,
    ProviderRoutingDependencyError,
    ProviderRoutingValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(
        error,
        (
            ProviderRoutingAuthorizationError,
            ProviderRoutingDeniedError,
            IdentityAuthorizationError,
        ),
    ):
        status, code = 403, "forbidden"
    elif isinstance(error, (ProviderRoutingConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(
        error,
        (ProviderRoutingDependencyError, IdentityDependencyError),
    ):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-routing:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "provider routing operation could not be completed",
        },
    )
