"""Authenticated PRO-006 provider scheduling API."""

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
from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.adapters.profile_http_api import (
    ProviderScopeModel,
    RetrievalScopeResolverPort,
    resolve_provider_scope,
)
from agentmemory.providers.application.scheduling import (
    CancelProviderWorkCommand,
    EnqueueProviderWorkCommand,
    GetProviderWorkQuery,
)
from agentmemory.providers.domain.errors import (
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingCapacityError,
    ProviderSchedulingConflictError,
    ProviderSchedulingDependencyError,
    ProviderSchedulingValidationError,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose
from agentmemory.providers.domain.routing import ProviderWorkload
from agentmemory.providers.domain.scheduling import (
    ProviderBatchKey,
    ProviderDeadlineClass,
    ProviderWorkItem,
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
_ERR_NOT_FOUND = "provider work item was not found"
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
DeadlineLiteral = Literal["interactive", "online", "background"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class EnqueueProviderWorkRequestModel(ProviderScopeModel):
    """Complete content-free provider child metadata."""

    operation_id: str = Field(min_length=1, max_length=128)
    profile_id: str
    profile_version: int = Field(ge=1, le=2**31 - 1)
    space_id: str
    space_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    classification: ClassificationLiteral
    purpose: PurposeLiteral
    retention_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    preprocessing_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deadline_class: DeadlineLiteral
    workload: WorkloadLiteral
    ordinal: int = Field(ge=0, le=2**63 - 1)
    payload_ref: str = Field(min_length=7, max_length=512)
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    token_count: int = Field(ge=1, le=1_000_000)
    byte_count: int = Field(ge=1, le=8 * 1024 * 1024)
    estimated_cost_micros: int = Field(ge=0, le=10**15)
    deadline_at_microseconds: int = Field(ge=1)


class CancelProviderWorkRequestModel(ProviderScopeModel):
    """One idempotent cancellation under current workspace authority."""

    operation_id: str = Field(min_length=1, max_length=128)


class ProviderWorkResponseModel(_StrictModel):
    """Content-free scheduling progress safe for agents and operators."""

    item_id: str
    operation_id: str
    brain_id: str
    profile_id: str
    profile_version: int
    space_id: str
    purpose: str
    classification: str
    workload: str
    deadline_class: str
    ordinal: int
    token_count: int
    byte_count: int
    estimated_cost_micros: int
    state: str
    attempts: int
    enqueued_at_microseconds: int
    deadline_at_microseconds: int


class AuthenticatorPort(Protocol):
    """Authenticate the local capability before scheduling work."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate before scope resolution or queue access."""
        ...


class EnqueueProviderWorkPort(Protocol):
    """Queue one exact provider item."""

    async def execute(self, command: EnqueueProviderWorkCommand) -> ProviderWorkItem:
        """Queue or exactly replay one child."""
        ...


class GetProviderWorkPort(Protocol):
    """Read one exact provider item."""

    async def execute(self, query: GetProviderWorkQuery) -> ProviderWorkItem | None:
        """Return content-free progress or ``None``."""
        ...


class CancelProviderWorkPort(Protocol):
    """Cancel one provider item."""

    async def execute(self, command: CancelProviderWorkCommand) -> ProviderWorkItem:
        """Cancel or exactly replay one cancellation."""
        ...


def create_provider_scheduling_router(  # noqa: PLR0913 -- Explicit hexagonal composition.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    enqueue_handler: EnqueueProviderWorkPort,
    get_handler: GetProviderWorkPort,
    cancel_handler: CancelProviderWorkPort,
    clock: Clock,
) -> APIRouter:
    """Create enqueue, progress, and cancellation contracts for PRO-006."""
    router = APIRouter()

    @router.post(
        "/v1/providers/work-items",
        operation_id="EnqueueProviderWorkCommand",
        response_model=ProviderWorkResponseModel,
        status_code=202,
    )
    async def enqueue(
        body: Annotated[EnqueueProviderWorkRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProviderWorkResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                body,
                now,
                "provider.schedule.enqueue",
                purpose="provider_scheduling",
            )
            work = await enqueue_handler.execute(
                EnqueueProviderWorkCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    batch_key=_key(body),
                    ordinal=body.ordinal,
                    payload_ref=body.payload_ref,
                    content_digest=body.content_digest,
                    token_count=body.token_count,
                    byte_count=body.byte_count,
                    estimated_cost_micros=body.estimated_cost_micros,
                    deadline_at_microseconds=body.deadline_at_microseconds,
                    enqueued_at=now,
                )
            )
            return _response(work)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/providers/work-items/{item_id}",
        operation_id="GetProviderWorkQuery",
        response_model=ProviderWorkResponseModel,
    )
    async def get(  # noqa: PLR0913 -- GET scope is represented by exact query coordinates.
        item_id: str,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        brain_id: Annotated[str, Query()],
        actor_id: Annotated[str, Query()],
        grant_id: Annotated[str, Query()],
        project_id: Annotated[str, Query()],
        repository_id: Annotated[str, Query()],
    ) -> ProviderWorkResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            request = ProviderScopeModel(
                brain_id=brain_id,
                actor_id=actor_id,
                grant_id=grant_id,
                project_id=project_id,
                repository_id=repository_id,
            )
            scope = await resolve_provider_scope(
                scope_resolver,
                request,
                now,
                "provider.schedule.read",
                purpose="provider_scheduling",
            )
            work = await get_handler.execute(GetProviderWorkQuery(scope=scope, item_id=item_id))
            if work is None:
                return JSONResponse(
                    status_code=404,
                    content={
                        "type": "urn:agentmemory:provider-scheduling:not_found",
                        "title": "not found",
                        "status": 404,
                        "detail": _ERR_NOT_FOUND,
                    },
                )
            return _response(work)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/work-items/{item_id}:cancel",
        operation_id="CancelProviderWorkCommand",
        response_model=ProviderWorkResponseModel,
    )
    async def cancel(
        item_id: str,
        body: Annotated[CancelProviderWorkRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProviderWorkResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                body,
                now,
                "provider.schedule.cancel",
                purpose="provider_scheduling",
            )
            work = await cancel_handler.execute(
                CancelProviderWorkCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    item_id=item_id,
                    cancelled_at=now,
                )
            )
            return _response(work)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    registered = (enqueue, get, cancel)
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


def create_contract_provider_scheduling_router() -> APIRouter:
    """Create a side-effect-free PRO-006 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_provider_scheduling_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("EnqueueProviderWorkPort", dependency),
        cast("GetProviderWorkPort", dependency),
        cast("CancelProviderWorkPort", dependency),
        cast("Clock", _ContractClock()),
    )


def _key(body: EnqueueProviderWorkRequestModel) -> ProviderBatchKey:
    return ProviderBatchKey(
        brain_id=body.brain_id,
        project_id=body.project_id,
        repository_id=body.repository_id,
        classification=Classification(body.classification),
        profile_id=body.profile_id,
        profile_version=body.profile_version,
        space_id=body.space_id,
        space_fingerprint=body.space_fingerprint,
        purpose=CanonicalPurpose(body.purpose),
        retention_policy_digest=body.retention_policy_digest,
        preprocessing_digest=body.preprocessing_digest,
        deadline_class=ProviderDeadlineClass(body.deadline_class),
        workload=ProviderWorkload(body.workload),
    )


def _response(work: ProviderWorkItem) -> ProviderWorkResponseModel:
    key = work.batch_key
    return ProviderWorkResponseModel(
        item_id=work.item_id,
        operation_id=work.operation_id,
        brain_id=key.brain_id,
        profile_id=key.profile_id,
        profile_version=key.profile_version,
        space_id=key.space_id,
        purpose=key.purpose.value,
        classification=key.classification.value,
        workload=key.workload.value,
        deadline_class=key.deadline_class.value,
        ordinal=work.ordinal,
        token_count=work.token_count,
        byte_count=work.byte_count,
        estimated_cost_micros=work.estimated_cost_micros,
        state=work.state.value,
        attempts=work.attempts,
        enqueued_at_microseconds=work.enqueued_at_microseconds,
        deadline_at_microseconds=work.deadline_at_microseconds,
    )


def _require_idempotency(supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise ProviderSchedulingValidationError(_ERR_IDEMPOTENCY)


_HANDLED_ERRORS = (
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingCapacityError,
    ProviderSchedulingConflictError,
    ProviderSchedulingDependencyError,
    ProviderSchedulingValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(
        error,
        (ProviderSchedulingAuthorizationError, IdentityAuthorizationError),
    ):
        status, code = 403, "forbidden"
    elif isinstance(error, (ProviderSchedulingConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(
        error,
        (
            ProviderSchedulingCapacityError,
            ProviderSchedulingDependencyError,
            IdentityDependencyError,
        ),
    ):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-scheduling:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "provider scheduling request was rejected",
        },
    )
