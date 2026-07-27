"""Authenticated PRO-010 provider observability administration and status API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

from fastapi import APIRouter, Body, Header, Query, Security
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
from agentmemory.providers.application.observability import (
    GetProviderStatusQuery,
    PublishBudgetPolicyCommand,
    PublishPricingSnapshotCommand,
    RegisterDriftCanaryCommand,
    RunDriftProbeCommand,
)
from agentmemory.providers.domain.errors import (
    ProviderObservabilityAuthorizationError,
    ProviderObservabilityConflictError,
    ProviderObservabilityDependencyError,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.observability import (
    BudgetExhaustionBehavior,
    DriftCanary,
    DriftEvaluation,
    PricingSnapshot,
    ProviderBudgetPolicy,
    ProviderStatusSnapshot,
)
from agentmemory.providers.domain.profiles import ProviderOperation

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class PricingSnapshotRequestModel(ProviderScopeModel):
    """Versioned administrator-supplied provider price authority."""

    operation_id: str = Field(min_length=1, max_length=128)
    profile_id: str
    profile_version: int = Field(ge=1, le=2**31 - 1)
    version: int = Field(ge=1, le=2**31 - 1)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    operation: Literal["embedding", "reranking"]
    request_micros: int = Field(ge=0, le=10**15)
    input_micros_per_million: int = Field(ge=0, le=10**15)
    output_micros_per_million: int = Field(ge=0, le=10**15)
    effective_from_microseconds: int = Field(ge=0)
    effective_until_microseconds: int = Field(ge=1)
    created_at_microseconds: int = Field(ge=0)


class PricingSnapshotResponseModel(_StrictModel):
    """Committed immutable pricing version."""

    snapshot_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    version: int
    currency: str
    operation: Literal["embedding", "reranking"]
    request_micros: int
    input_micros_per_million: int
    output_micros_per_million: int
    effective_from_microseconds: int
    effective_until_microseconds: int
    created_at_microseconds: int


class BudgetPolicyRequestModel(ProviderScopeModel):
    """Finite versioned provider budget and explicit exhaustion behavior."""

    operation_id: str = Field(min_length=1, max_length=128)
    profile_id: str
    profile_version: int = Field(ge=1, le=2**31 - 1)
    version: int = Field(ge=1, le=2**31 - 1)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    limit_micros: int = Field(ge=0, le=10**15)
    behavior: Literal["queue", "degrade"]
    degraded_channels: list[Literal["exact", "lexical", "graph"]] = Field(
        min_length=1,
        max_length=3,
    )
    period_start_microseconds: int = Field(ge=0)
    period_end_microseconds: int = Field(ge=1)
    created_at_microseconds: int = Field(ge=0)


class BudgetPolicyResponseModel(_StrictModel):
    """Committed content-addressed budget authority."""

    policy_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    version: int
    currency: str
    limit_micros: int
    behavior: Literal["queue", "degrade"]
    degraded_channels: list[Literal["exact", "lexical", "graph"]]
    period_start_microseconds: int
    period_end_microseconds: int
    created_at_microseconds: int


class DriftCanaryRequestModel(ProviderScopeModel):
    """Safe aggregate baseline for one pinned generation."""

    operation_id: str = Field(min_length=1, max_length=128)
    canary_id: str
    profile_id: str
    profile_version: int = Field(ge=1, le=2**31 - 1)
    space_id: str
    generation_id: str
    capability_attestation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    revision_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    vector_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_item_ids: list[str] = Field(min_length=2, max_length=100)
    norms_micros: list[int] = Field(min_length=2, max_length=100)
    distance_order: list[str] = Field(min_length=2, max_length=100)
    norm_tolerance_ppm: int = Field(ge=0, le=1_000_000)
    maximum_order_inversions: int = Field(ge=0)
    interval_microseconds: int = Field(ge=1, le=2_678_400_000_000)
    next_probe_at_microseconds: int = Field(ge=0)
    created_at_microseconds: int = Field(ge=0)


class DriftCanaryResponseModel(_StrictModel):
    """Committed content-free canary aggregate."""

    canary_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    space_id: str
    generation_id: str
    capability_attestation_id: str
    revision_fingerprint: str
    canary_set_digest: str
    vector_fingerprint: str
    canary_item_ids: list[str]
    norms_micros: list[int]
    distance_order: list[str]
    norm_tolerance_ppm: int
    maximum_order_inversions: int
    interval_microseconds: int
    next_probe_at_microseconds: int
    created_at_microseconds: int


class DriftProbeRequestModel(ProviderScopeModel):
    """Authority context for an immediate canary execution."""


class DriftProbeResponseModel(_StrictModel):
    """Safe drift verdict containing no vector or provider payload."""

    verdict: Literal["stable", "drifted"]
    reason_code: str | None
    suspend_writes: bool
    requires_new_space: bool


class ProviderHealthResponseModel(_StrictModel):
    """Bounded profile health and usage aggregate."""

    profile_id: str
    profile_version: int
    status: Literal["healthy", "degraded", "unavailable", "suspended"]
    circuit_counts: list[int]
    requests: int
    items: int
    input_units: int
    output_units: int
    cost_micros: int
    latency_p50_microseconds: int
    latency_p95_microseconds: int
    latency_p99_microseconds: int
    safe_errors: list[tuple[str, int]]


class ProviderQueueStatusResponseModel(_StrictModel):
    """Content-free provider queue aggregate."""

    queued: int
    leased: int
    retry_scheduled: int
    failed: int
    dead_lettered: int
    oldest_queued_at_microseconds: int | None


class ProviderBudgetStatusResponseModel(_StrictModel):
    """Current finite balance for one profile budget."""

    profile_id: str
    policy_id: str
    currency: str
    limit_micros: int
    spent_micros: int
    reserved_micros: int
    remaining_micros: int
    behavior: Literal["queue", "degrade"]


class ProviderGenerationStatusResponseModel(_StrictModel):
    """Active/rollback generation and model pin state."""

    space_id: str
    active_generation_id: str
    rollback_generation_id: str | None
    pin_state: Literal["pinned", "unpinned", "drift_suspected"]
    write_suspended: bool
    suspension_reason: str | None


class ProviderStatusResponseModel(_StrictModel):
    """Complete Brain-scoped operator status."""

    brain_id: str
    observed_at_microseconds: int
    health: list[ProviderHealthResponseModel]
    queues: ProviderQueueStatusResponseModel
    budgets: list[ProviderBudgetStatusResponseModel]
    generations: list[ProviderGenerationStatusResponseModel]
    retry_count: int
    dead_letter_count: int
    active_alert_count: int


class AuthenticatorPort(Protocol):
    """Authenticate local Core access before reading any request authority."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate one local request."""
        ...


class PublishPricingPort(Protocol):
    """Publish immutable provider pricing authority."""

    async def execute(self, command: PublishPricingSnapshotCommand) -> PricingSnapshot:
        """Publish or replay one pricing version."""
        ...


class PublishBudgetPort(Protocol):
    """Publish finite provider budget authority."""

    async def execute(self, command: PublishBudgetPolicyCommand) -> ProviderBudgetPolicy:
        """Publish or replay one budget policy."""
        ...


class RegisterCanaryPort(Protocol):
    """Register safe drift canary aggregates."""

    async def execute(self, command: RegisterDriftCanaryCommand) -> DriftCanary:
        """Register or replay one safe canary baseline."""
        ...


class RunDriftProbePort(Protocol):
    """Run one immediate drift probe."""

    async def execute(self, command: RunDriftProbeCommand) -> DriftEvaluation:
        """Execute one immediate safe drift comparison."""
        ...


class GetProviderStatusPort(Protocol):
    """Read the complete operator status."""

    async def execute(self, query: GetProviderStatusQuery) -> ProviderStatusSnapshot:
        """Return one complete authorized status snapshot."""
        ...


def create_provider_observability_router(  # noqa: C901,PLR0913 -- Explicit HTTP composition.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    publish_pricing: PublishPricingPort,
    publish_budget: PublishBudgetPort,
    register_canary: RegisterCanaryPort,
    run_probe: RunDriftProbePort,
    get_status: GetProviderStatusPort,
    clock: Clock,
) -> APIRouter:
    """Create strict authenticated PRO-010 administration and status routes."""
    router = APIRouter()

    @router.put(
        "/v1/providers/pricing-snapshots",
        operation_id="PublishPricingSnapshotCommand",
        response_model=PricingSnapshotResponseModel,
    )
    async def pricing(
        body: Annotated[PricingSnapshotRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> PricingSnapshotResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _check_idempotency(idempotency_key, body.operation_id)
            scope = await _scope(
                scope_resolver,
                body,
                clock,
                "provider.observability.pricing.publish",
            )
            value = await publish_pricing.execute(
                PublishPricingSnapshotCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    snapshot=PricingSnapshot.create(
                        brain_id=body.brain_id,
                        profile_id=body.profile_id,
                        profile_version=body.profile_version,
                        version=body.version,
                        currency=body.currency,
                        operation=ProviderOperation(body.operation),
                        request_micros=body.request_micros,
                        input_micros_per_million=body.input_micros_per_million,
                        output_micros_per_million=body.output_micros_per_million,
                        effective_from_microseconds=body.effective_from_microseconds,
                        effective_until_microseconds=body.effective_until_microseconds,
                        created_at_microseconds=body.created_at_microseconds,
                    ),
                )
            )
            return PricingSnapshotResponseModel.model_validate(value.document)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.put(
        "/v1/providers/budget-policies",
        operation_id="PublishProviderBudgetPolicyCommand",
        response_model=BudgetPolicyResponseModel,
    )
    async def budget(
        body: Annotated[BudgetPolicyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> BudgetPolicyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _check_idempotency(idempotency_key, body.operation_id)
            scope = await _scope(
                scope_resolver,
                body,
                clock,
                "provider.observability.budget.publish",
            )
            value = await publish_budget.execute(
                PublishBudgetPolicyCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    policy=ProviderBudgetPolicy.create(
                        brain_id=body.brain_id,
                        profile_id=body.profile_id,
                        profile_version=body.profile_version,
                        version=body.version,
                        currency=body.currency,
                        limit_micros=body.limit_micros,
                        behavior=BudgetExhaustionBehavior(body.behavior),
                        degraded_channels=tuple(body.degraded_channels),
                        period_start_microseconds=body.period_start_microseconds,
                        period_end_microseconds=body.period_end_microseconds,
                        created_at_microseconds=body.created_at_microseconds,
                    ),
                )
            )
            return BudgetPolicyResponseModel.model_validate(
                {**value.creation_document, "policy_id": value.policy_id}
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.put(
        "/v1/providers/drift-canaries",
        operation_id="RegisterProviderDriftCanaryCommand",
        response_model=DriftCanaryResponseModel,
    )
    async def canary(
        body: Annotated[DriftCanaryRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> DriftCanaryResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _check_idempotency(idempotency_key, body.operation_id)
            scope = await _scope(
                scope_resolver,
                body,
                clock,
                "provider.observability.drift.register",
            )
            value = await register_canary.execute(
                RegisterDriftCanaryCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    canary=_canary(body),
                )
            )
            return DriftCanaryResponseModel.model_validate(value.document)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/drift-canaries/{canary_id}:probe",
        operation_id="RunProviderDriftProbeCommand",
        response_model=DriftProbeResponseModel,
    )
    async def probe(
        canary_id: str,
        body: Annotated[DriftProbeRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> DriftProbeResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            scope = await _scope(
                scope_resolver,
                body,
                clock,
                "provider.observability.drift.run",
            )
            value = await run_probe.execute(RunDriftProbeCommand(scope=scope, canary_id=canary_id))
            return DriftProbeResponseModel.model_validate(
                {
                    "verdict": value.verdict.value,
                    "reason_code": value.reason_code,
                    "suspend_writes": value.suspend_writes,
                    "requires_new_space": value.requires_new_space,
                }
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/providers/status",
        operation_id="GetProviderObservabilityStatusQuery",
        response_model=ProviderStatusResponseModel,
    )
    async def status(
        scope_model: Annotated[ProviderScopeModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ProviderStatusResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                scope_model,
                now,
                "provider.observability.status.read",
                purpose="provider_observability",
            )
            value = await get_status.execute(GetProviderStatusQuery(scope=scope, observed_at=now))
            return _status_response(value)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    registered = pricing, budget, canary, probe, status
    del registered
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


def create_contract_provider_observability_router() -> APIRouter:
    """Create a side-effect-free PRO-010 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_provider_observability_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("PublishPricingPort", dependency),
        cast("PublishBudgetPort", dependency),
        cast("RegisterCanaryPort", dependency),
        cast("RunDriftProbePort", dependency),
        cast("GetProviderStatusPort", dependency),
        cast("Clock", _ContractClock()),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    body: ProviderScopeModel,
    clock: Clock,
    action: str,
) -> AuthorizedScope:
    return await resolve_provider_scope(
        resolver,
        body,
        clock.now(),
        action,
        purpose="provider_observability",
    )


def _check_idempotency(value: str | None, operation_id: str) -> None:
    if value != operation_id:
        raise ProviderObservabilityValidationError(_ERR_IDEMPOTENCY)


def _canary(body: DriftCanaryRequestModel) -> DriftCanary:
    return DriftCanary.create(
        canary_id=body.canary_id,
        brain_id=body.brain_id,
        profile_id=body.profile_id,
        profile_version=body.profile_version,
        space_id=body.space_id,
        generation_id=body.generation_id,
        capability_attestation_id=body.capability_attestation_id,
        revision_fingerprint=body.revision_fingerprint,
        canary_set_digest=body.canary_set_digest,
        vector_fingerprint=body.vector_fingerprint,
        canary_item_ids=tuple(body.canary_item_ids),
        norms_micros=tuple(body.norms_micros),
        distance_order=tuple(body.distance_order),
        norm_tolerance_ppm=body.norm_tolerance_ppm,
        maximum_order_inversions=body.maximum_order_inversions,
        interval_microseconds=body.interval_microseconds,
        next_probe_at_microseconds=body.next_probe_at_microseconds,
        created_at_microseconds=body.created_at_microseconds,
    )


def _status_response(value: ProviderStatusSnapshot) -> ProviderStatusResponseModel:
    return ProviderStatusResponseModel.model_validate(
        {
            "brain_id": value.brain_id,
            "observed_at_microseconds": value.observed_at_microseconds,
            "health": [
                {
                    "profile_id": item.profile_id,
                    "profile_version": item.profile_version,
                    "status": item.status.value,
                    "circuit_counts": list(item.circuit_counts),
                    "requests": item.requests,
                    "items": item.items,
                    "input_units": item.input_units,
                    "output_units": item.output_units,
                    "cost_micros": item.cost_micros,
                    "latency_p50_microseconds": item.latency_p50_microseconds,
                    "latency_p95_microseconds": item.latency_p95_microseconds,
                    "latency_p99_microseconds": item.latency_p99_microseconds,
                    "safe_errors": [(code.value, count) for code, count in item.safe_errors],
                }
                for item in value.health
            ],
            "queues": {
                "queued": value.queues.queued,
                "leased": value.queues.leased,
                "retry_scheduled": value.queues.retry_scheduled,
                "failed": value.queues.failed,
                "dead_lettered": value.queues.dead_lettered,
                "oldest_queued_at_microseconds": value.queues.oldest_queued_at_microseconds,
            },
            "budgets": [
                {
                    "profile_id": item.profile_id,
                    "policy_id": item.policy_id,
                    "currency": item.currency,
                    "limit_micros": item.limit_micros,
                    "spent_micros": item.spent_micros,
                    "reserved_micros": item.reserved_micros,
                    "remaining_micros": item.remaining_micros,
                    "behavior": item.behavior.value,
                }
                for item in value.budgets
            ],
            "generations": [
                {
                    "space_id": item.space_id,
                    "active_generation_id": item.active_generation_id,
                    "rollback_generation_id": item.rollback_generation_id,
                    "pin_state": item.pin_state.value,
                    "write_suspended": item.write_suspended,
                    "suspension_reason": item.suspension_reason,
                }
                for item in value.generations
            ],
            "retry_count": value.retry_count,
            "dead_letter_count": value.dead_letter_count,
            "active_alert_count": value.active_alert_count,
        }
    )


_HANDLED_ERRORS = (
    ProviderObservabilityAuthorizationError,
    ProviderObservabilityConflictError,
    ProviderObservabilityDependencyError,
    ProviderObservabilityValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(error, (ProviderObservabilityAuthorizationError, IdentityAuthorizationError)):
        status, code = 403, "forbidden"
    elif isinstance(error, (ProviderObservabilityConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(error, (ProviderObservabilityDependencyError, IdentityDependencyError)):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-observability:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "provider observability request was rejected",
        },
    )
