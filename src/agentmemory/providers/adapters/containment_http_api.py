"""Authenticated PRO-009 provider-egress policy administration API."""

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
from agentmemory.providers.application.containment import (
    GetProviderEgressPolicyQuery,
    PublishProviderEgressPolicyCommand,
)
from agentmemory.providers.domain.containment import (
    EgressDestination,
    ProviderEgressPolicy,
    ProviderEgressRoute,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentAuthorizationError,
    ProviderContainmentConflictError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
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
_ERR_NOT_FOUND = "provider egress policy was not found"
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"

PurposeLiteral = Literal[
    "retrieval_query",
    "retrieval_document",
    "code_query",
    "code_document",
    "semantic_similarity",
    "classification",
    "clustering",
]
OperationLiteral = Literal["embedding", "reranking"]
ClassificationLiteral = Literal[
    "public",
    "internal",
    "confidential",
    "restricted",
    "local_only",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class EgressDestinationModel(_StrictModel):
    """One exact HTTPS provider authority."""

    scheme: Literal["https"]
    hostname: str = Field(min_length=4, max_length=253)
    port: int = Field(ge=1, le=65_535)
    region: str = Field(min_length=2, max_length=32)
    path_prefix: str = Field(min_length=2, max_length=512)


class ProviderEgressRouteModel(_StrictModel):
    """One non-combinable profile capability and destination route."""

    profile_id: str
    profile_version: int = Field(ge=1, le=2**31 - 1)
    profile_attestation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_revision: str = Field(min_length=1, max_length=256)
    operation_type: OperationLiteral
    purpose: PurposeLiteral
    destination: EgressDestinationModel


class PublishProviderEgressPolicyRequestModel(ProviderScopeModel):
    """Complete immutable owner-approved egress policy."""

    operation_id: str = Field(min_length=1, max_length=128)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_id: str
    version: int = Field(ge=1, le=2**31 - 1)
    security_epoch: int = Field(ge=1, le=2**63 - 1)
    classification_ceiling: ClassificationLiteral
    allowed_destinations: list[EgressDestinationModel] = Field(min_length=1, max_length=1000)
    allowed_profile_ids: list[str] = Field(min_length=1, max_length=1000)
    allowed_purposes: list[PurposeLiteral] = Field(min_length=1, max_length=7)
    allowed_operation_types: list[OperationLiteral] = Field(min_length=1, max_length=2)
    allowed_routes: list[ProviderEgressRouteModel] = Field(min_length=1, max_length=1000)
    maximum_retention_days: int = Field(ge=0, le=3650)
    training_allowed: bool
    maximum_request_bytes: int = Field(ge=1, le=8 * 1024 * 1024)
    maximum_response_bytes: int = Field(ge=1, le=8 * 1024 * 1024)
    maximum_timeout_milliseconds: int = Field(ge=100, le=300_000)
    maximum_requests_per_minute: int = Field(ge=1, le=1_000_000_000)
    maximum_tokens_per_minute: int = Field(ge=1, le=1_000_000_000)
    maximum_monthly_cost_micros: int = Field(ge=0, le=10**15)
    attestation_id: str
    attestation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    valid_from_microseconds: int = Field(ge=0)
    valid_until_microseconds: int = Field(ge=1)


class ProviderEgressPolicyResponseModel(_StrictModel):
    """Content-free active policy and its canonical integrity digest."""

    policy_id: str
    brain_id: str
    version: int
    security_epoch: int
    classification_ceiling: ClassificationLiteral
    allowed_destinations: list[EgressDestinationModel]
    allowed_profile_ids: list[str]
    allowed_purposes: list[PurposeLiteral]
    allowed_operation_types: list[OperationLiteral]
    allowed_routes: list[ProviderEgressRouteModel]
    maximum_retention_days: int
    training_allowed: bool
    maximum_request_bytes: int
    maximum_response_bytes: int
    maximum_timeout_milliseconds: int
    maximum_requests_per_minute: int
    maximum_tokens_per_minute: int
    maximum_monthly_cost_micros: int
    attestation_id: str
    attestation_digest: str
    valid_from_microseconds: int
    valid_until_microseconds: int
    policy_digest: str


class AuthenticatorPort(Protocol):
    """Authenticate local Core access before policy administration."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate one local request."""
        ...


class PublishProviderEgressPolicyPort(Protocol):
    """Publish one exact immutable egress policy."""

    async def execute(
        self,
        command: PublishProviderEgressPolicyCommand,
    ) -> ProviderEgressPolicy:
        """Return the committed policy or exact replay."""
        ...


class GetProviderEgressPolicyPort(Protocol):
    """Read the active policy under current authority."""

    async def execute(
        self,
        query: GetProviderEgressPolicyQuery,
    ) -> ProviderEgressPolicy | None:
        """Return the active policy or ``None``."""
        ...


def create_provider_containment_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    publish_handler: PublishProviderEgressPolicyPort,
    get_handler: GetProviderEgressPolicyPort,
    clock: Clock,
) -> APIRouter:
    """Create the owner/admin policy publication and lookup boundary."""
    router = APIRouter()

    @router.put(
        "/v1/providers/egress-policy",
        operation_id="PublishProviderEgressPolicyCommand",
        response_model=ProviderEgressPolicyResponseModel,
    )
    async def publish(
        body: Annotated[PublishProviderEgressPolicyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProviderEgressPolicyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            if idempotency_key != body.operation_id:
                raise ProviderContainmentValidationError(_ERR_IDEMPOTENCY)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                body,
                now,
                "provider.containment.manage",
                purpose="provider_containment",
            )
            value = await publish_handler.execute(
                PublishProviderEgressPolicyCommand(
                    scope=scope,
                    operation_id=body.operation_id,
                    request_digest=body.request_digest,
                    policy=_policy(body),
                    published_at_microseconds=round(now.timestamp() * 1_000_000),
                )
            )
            return _response(value)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/providers/egress-policy",
        operation_id="GetProviderEgressPolicyQuery",
        response_model=ProviderEgressPolicyResponseModel,
    )
    async def get(
        scope_model: Annotated[ProviderScopeModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ProviderEgressPolicyResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                scope_model,
                now,
                "provider.containment.read",
                purpose="provider_containment",
            )
            value = await get_handler.execute(
                GetProviderEgressPolicyQuery(
                    scope=scope,
                    requested_at_microseconds=round(now.timestamp() * 1_000_000),
                )
            )
            if value is None:
                return JSONResponse(
                    status_code=404,
                    content={
                        "type": "urn:agentmemory:provider-containment:not_found",
                        "title": "not found",
                        "status": 404,
                        "detail": _ERR_NOT_FOUND,
                    },
                )
            return _response(value)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    registered = publish, get
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


def create_contract_provider_containment_router() -> APIRouter:
    """Create a side-effect-free PRO-009 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_provider_containment_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("PublishProviderEgressPolicyPort", dependency),
        cast("GetProviderEgressPolicyPort", dependency),
        cast("Clock", _ContractClock()),
    )


def _policy(body: PublishProviderEgressPolicyRequestModel) -> ProviderEgressPolicy:
    return ProviderEgressPolicy(
        policy_id=body.policy_id,
        brain_id=body.brain_id,
        version=body.version,
        security_epoch=body.security_epoch,
        classification_ceiling=Classification(body.classification_ceiling),
        allowed_destinations=tuple(_destination(value) for value in body.allowed_destinations),
        allowed_profile_ids=tuple(body.allowed_profile_ids),
        allowed_purposes=tuple(body.allowed_purposes),
        allowed_operation_types=tuple(body.allowed_operation_types),
        allowed_routes=tuple(_route(value) for value in body.allowed_routes),
        maximum_retention_days=body.maximum_retention_days,
        training_allowed=body.training_allowed,
        maximum_request_bytes=body.maximum_request_bytes,
        maximum_response_bytes=body.maximum_response_bytes,
        maximum_timeout_milliseconds=body.maximum_timeout_milliseconds,
        maximum_requests_per_minute=body.maximum_requests_per_minute,
        maximum_tokens_per_minute=body.maximum_tokens_per_minute,
        maximum_monthly_cost_micros=body.maximum_monthly_cost_micros,
        attestation_id=body.attestation_id,
        attestation_digest=body.attestation_digest,
        valid_from_microseconds=body.valid_from_microseconds,
        valid_until_microseconds=body.valid_until_microseconds,
    )


def _route(value: ProviderEgressRouteModel) -> ProviderEgressRoute:
    return ProviderEgressRoute(
        profile_id=value.profile_id,
        profile_version=value.profile_version,
        profile_attestation_id=value.profile_attestation_id,
        model_revision=value.model_revision,
        operation_type=value.operation_type,
        purpose=value.purpose,
        destination=_destination(value.destination),
    )


def _destination(value: EgressDestinationModel) -> EgressDestination:
    return EgressDestination(
        scheme=value.scheme,
        hostname=value.hostname,
        port=value.port,
        region=value.region,
        path_prefix=value.path_prefix,
    )


def _response(policy: ProviderEgressPolicy) -> ProviderEgressPolicyResponseModel:
    document = policy.document
    return ProviderEgressPolicyResponseModel.model_validate(
        {
            **document,
            "policy_digest": policy.digest,
        }
    )


_HANDLED_ERRORS = (
    ProviderContainmentAuthorizationError,
    ProviderContainmentConflictError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(error, (ProviderContainmentAuthorizationError, IdentityAuthorizationError)):
        status, code = 403, "forbidden"
    elif isinstance(error, (ProviderContainmentConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(error, (ProviderContainmentDependencyError, IdentityDependencyError)):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-containment:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "provider containment request was rejected",
        },
    )
