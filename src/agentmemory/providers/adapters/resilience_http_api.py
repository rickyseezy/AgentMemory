"""Authenticated PRO-007 endpoint-equivalence administration API."""

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
from agentmemory.providers.application.resilience import (
    GetEquivalentEndpointSetQuery,
    PublishEquivalentEndpointSetCommand,
)
from agentmemory.providers.domain.errors import (
    ProviderResilienceAuthorizationError,
    ProviderResilienceConflictError,
    ProviderResilienceDependencyError,
    ProviderResilienceValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)
from agentmemory.providers.domain.resilience import (
    EquivalentEndpointSet,
    ProviderEndpointAttestation,
    ProviderOutputContract,
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
_ERR_NOT_FOUND = "provider endpoint equivalence was not found"
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"

OperationLiteral = Literal["embedding", "reranking"]
PurposeLiteral = Literal[
    "retrieval_query",
    "retrieval_document",
    "code_query",
    "code_document",
    "semantic_similarity",
    "classification",
    "clustering",
]
DtypeLiteral = Literal["float16", "float32", "float64"]
NormalizationLiteral = Literal["none", "l2", "provider_defined"]
SimilarityLiteral = Literal["cosine", "dot_product"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ProviderOutputContractModel(_StrictModel):
    """Complete content-free semantic output identity."""

    space_id: str
    space_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_revision: str = Field(min_length=1, max_length=256)
    revision_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: OperationLiteral
    purpose: PurposeLiteral
    preprocessing_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    dimension: int | None = Field(default=None, ge=1, le=65_536)
    dtype: DtypeLiteral | None = None
    normalization: NormalizationLiteral | None = None
    similarity: SimilarityLiteral | None = None
    suite_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProviderEndpointAttestationModel(_StrictModel):
    """One live provider profile and capability attestation."""

    profile_id: str
    profile_version: int = Field(ge=1, le=2**31 - 1)
    capability_attestation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    adapter_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_contract: ProviderOutputContractModel


class PublishEquivalentEndpointSetRequestModel(ProviderScopeModel):
    """One immutable ordered endpoint-equivalence publication."""

    operation_id: str = Field(min_length=1, max_length=128)
    primary: ProviderEndpointAttestationModel
    fallbacks: list[ProviderEndpointAttestationModel] = Field(max_length=99)


class ProviderEndpointAttestationResponseModel(ProviderEndpointAttestationModel):
    """Content-addressed endpoint evidence returned to an operator."""

    attestation_digest: str


class EquivalentEndpointSetResponseModel(_StrictModel):
    """Content-free immutable equivalence evidence."""

    set_id: str
    output_contract_digest: str
    primary: ProviderEndpointAttestationResponseModel
    fallbacks: list[ProviderEndpointAttestationResponseModel]


class AuthenticatorPort(Protocol):
    """Authenticate the local capability before resilience administration."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate before scope or provider evidence access."""
        ...


class PublishEquivalentEndpointSetPort(Protocol):
    """Publish one exact endpoint-equivalence set."""

    async def execute(
        self,
        command: PublishEquivalentEndpointSetCommand,
    ) -> EquivalentEndpointSet:
        """Publish or exactly replay one immutable set."""
        ...


class GetEquivalentEndpointSetPort(Protocol):
    """Read one Brain-scoped endpoint-equivalence set."""

    async def execute(
        self,
        query: GetEquivalentEndpointSetQuery,
    ) -> EquivalentEndpointSet | None:
        """Return an authorized set or ``None``."""
        ...


def create_provider_resilience_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    publish_handler: PublishEquivalentEndpointSetPort,
    get_handler: GetEquivalentEndpointSetPort,
    clock: Clock,
) -> APIRouter:
    """Create endpoint-equivalence publication and lookup contracts."""
    router = APIRouter()

    @router.post(
        "/v1/providers/equivalent-endpoint-sets",
        operation_id="PublishEquivalentEndpointSetCommand",
        response_model=EquivalentEndpointSetResponseModel,
        status_code=201,
    )
    async def publish(
        body: Annotated[PublishEquivalentEndpointSetRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> EquivalentEndpointSetResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                body,
                now,
                "provider.resilience.publish",
                purpose="provider_resilience",
            )
            endpoints = await publish_handler.execute(
                PublishEquivalentEndpointSetCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    endpoints=_endpoint_set(body),
                    created_at=now,
                )
            )
            return _response(endpoints)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/providers/equivalent-endpoint-sets/{set_id}",
        operation_id="GetEquivalentEndpointSetQuery",
        response_model=EquivalentEndpointSetResponseModel,
    )
    async def get(
        set_id: str,
        scope_model: Annotated[ProviderScopeModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> EquivalentEndpointSetResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                scope_model,
                now,
                "provider.resilience.read",
                purpose="provider_resilience",
            )
            endpoints = await get_handler.execute(
                GetEquivalentEndpointSetQuery(scope=scope, set_id=set_id)
            )
            if endpoints is None:
                return JSONResponse(
                    status_code=404,
                    content={
                        "type": "urn:agentmemory:provider-resilience:not_found",
                        "title": "not found",
                        "status": 404,
                        "detail": _ERR_NOT_FOUND,
                    },
                )
            return _response(endpoints)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    registered = (publish, get)
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


def create_contract_provider_resilience_router() -> APIRouter:
    """Create a side-effect-free PRO-007 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_provider_resilience_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("PublishEquivalentEndpointSetPort", dependency),
        cast("GetEquivalentEndpointSetPort", dependency),
        cast("Clock", _ContractClock()),
    )


def _endpoint_set(
    body: PublishEquivalentEndpointSetRequestModel,
) -> EquivalentEndpointSet:
    return EquivalentEndpointSet(
        _endpoint(body.primary),
        tuple(_endpoint(item) for item in body.fallbacks),
    )


def _endpoint(model: ProviderEndpointAttestationModel) -> ProviderEndpointAttestation:
    contract = model.output_contract
    return ProviderEndpointAttestation(
        profile_id=model.profile_id,
        profile_version=model.profile_version,
        capability_attestation_id=model.capability_attestation_id,
        endpoint_fingerprint=model.endpoint_fingerprint,
        configuration_digest=model.configuration_digest,
        adapter_digest=model.adapter_digest,
        output_contract=ProviderOutputContract(
            space_id=contract.space_id,
            space_fingerprint=contract.space_fingerprint,
            model_revision=contract.model_revision,
            revision_fingerprint=contract.revision_fingerprint,
            operation=ProviderOperation(contract.operation),
            purpose=CanonicalPurpose(contract.purpose),
            preprocessing_digest=contract.preprocessing_digest,
            dimension=contract.dimension,
            dtype=None if contract.dtype is None else VectorDtype(contract.dtype),
            normalization=(
                None
                if contract.normalization is None
                else VectorNormalization(contract.normalization)
            ),
            similarity=(
                None if contract.similarity is None else SimilarityMetric(contract.similarity)
            ),
            suite_digest=contract.suite_digest,
            canary_digest=contract.canary_digest,
            validation_digest=contract.validation_digest,
        ),
    )


def _response(endpoints: EquivalentEndpointSet) -> EquivalentEndpointSetResponseModel:
    return EquivalentEndpointSetResponseModel(
        set_id=endpoints.set_id,
        output_contract_digest=endpoints.primary.output_contract.digest,
        primary=_endpoint_response(endpoints.primary),
        fallbacks=[_endpoint_response(item) for item in endpoints.fallbacks],
    )


def _endpoint_response(
    endpoint: ProviderEndpointAttestation,
) -> ProviderEndpointAttestationResponseModel:
    contract = endpoint.output_contract
    return ProviderEndpointAttestationResponseModel(
        profile_id=endpoint.profile_id,
        profile_version=endpoint.profile_version,
        capability_attestation_id=endpoint.capability_attestation_id,
        endpoint_fingerprint=endpoint.endpoint_fingerprint,
        configuration_digest=endpoint.configuration_digest,
        adapter_digest=endpoint.adapter_digest,
        output_contract=ProviderOutputContractModel(
            space_id=contract.space_id,
            space_fingerprint=contract.space_fingerprint,
            model_revision=contract.model_revision,
            revision_fingerprint=contract.revision_fingerprint,
            operation=contract.operation.value,
            purpose=contract.purpose.value,
            preprocessing_digest=contract.preprocessing_digest,
            dimension=contract.dimension,
            dtype=None if contract.dtype is None else contract.dtype.value,
            normalization=(
                None if contract.normalization is None else contract.normalization.value
            ),
            similarity=None if contract.similarity is None else contract.similarity.value,
            suite_digest=contract.suite_digest,
            canary_digest=contract.canary_digest,
            validation_digest=contract.validation_digest,
        ),
        attestation_digest=endpoint.digest,
    )


def _require_idempotency(supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise ProviderResilienceValidationError(_ERR_IDEMPOTENCY)


_HANDLED_ERRORS = (
    ProviderResilienceAuthorizationError,
    ProviderResilienceConflictError,
    ProviderResilienceDependencyError,
    ProviderResilienceValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(
        error,
        (ProviderResilienceAuthorizationError, IdentityAuthorizationError),
    ):
        status, code = 403, "forbidden"
    elif isinstance(error, (ProviderResilienceConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(
        error,
        (ProviderResilienceDependencyError, IdentityDependencyError),
    ):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-resilience:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "provider resilience request was rejected",
        },
    )
