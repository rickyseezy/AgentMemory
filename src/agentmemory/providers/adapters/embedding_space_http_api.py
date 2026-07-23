"""Authenticated PRO-004 immutable embedding-space administration API."""

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
from agentmemory.providers.adapters.profile_http_api import (
    ProviderScopeModel,
    RetrievalScopeResolverPort,
    resolve_provider_scope,
)
from agentmemory.providers.application.embedding_spaces import (
    EnsureIndexGenerationCommand,
)
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpaceDescriptor,
    IndexGeneration,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class EmbeddingSpaceDescriptorModel(_StrictModel):
    """Complete V1 semantic identity with no mutable provider state or credential."""

    adapter_id: str = Field(min_length=1, max_length=256)
    adapter_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    adapter_version: str = Field(min_length=1, max_length=256)
    endpoint_class: str = Field(min_length=1, max_length=128)
    model_id: str = Field(min_length=1, max_length=256)
    model_revision: str | None = Field(default=None, min_length=1, max_length=256)
    model_weight_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    tokenizer_id: str = Field(min_length=1, max_length=256)
    tokenizer_revision: str = Field(min_length=1, max_length=256)
    tokenizer_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    pooling: str = Field(min_length=1, max_length=256)
    preprocessing_version: str = Field(min_length=1, max_length=256)
    unicode_normalization: str = Field(min_length=1, max_length=256)
    line_normalization: str = Field(min_length=1, max_length=256)
    chunking_contract: str = Field(min_length=1, max_length=256)
    truncation_policy: str = Field(min_length=1, max_length=256)
    dimension: int = Field(ge=1, le=4096)
    dtype: Literal["float16", "float32", "float64"]
    vector_encoding: str = Field(min_length=1, max_length=256)
    normalization: Literal["none", "l2"]
    similarity: Literal["cosine", "euclidean"]
    quantization: str = Field(min_length=1, max_length=256)
    inference_settings_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    purpose: Literal[
        "retrieval_query",
        "retrieval_document",
        "code_query",
        "code_document",
        "semantic_similarity",
        "classification",
        "clustering",
    ]
    asymmetry_mapping: str = Field(min_length=1, max_length=256)
    instruction_template_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_image_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_inference: bool
    execution_class: Literal["local", "remote"]
    residency_class: str = Field(min_length=2, max_length=32)


class EnsureEmbeddingGenerationRequestModel(ProviderScopeModel):
    """Idempotent request for one space-specific physical generation."""

    operation_id: str = Field(min_length=1, max_length=128)
    profile_id: str
    capability_attestation_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    descriptor: EmbeddingSpaceDescriptorModel


class EmbeddingGenerationResponseModel(_StrictModel):
    """Content-free immutable generation coordinates."""

    generation_id: str
    brain_id: str
    space_id: str
    space_fingerprint: str
    generated_label: str
    vector_index_name: str
    vector_property: str
    dimension: int
    similarity: str
    state: str
    created_at: str


class AuthenticatorPort(Protocol):
    """Authenticate the local API capability before provider administration."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate before resolving scope or touching either store."""
        ...


class EnsureIndexGenerationPort(Protocol):
    """Ensure one immutable semantic space and exact physical generation."""

    async def execute(self, command: EnsureIndexGenerationCommand) -> IndexGeneration:
        """Execute one idempotent generation request."""
        ...


def create_embedding_space_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    ensure_handler: EnsureIndexGenerationPort,
    clock: Clock,
) -> APIRouter:
    """Create the complete PRO-004 generation-administration API."""
    router = APIRouter()

    @router.post(
        "/v1/providers/embedding-spaces/generations",
        operation_id="EnsureIndexGenerationCommand",
        response_model=EmbeddingGenerationResponseModel,
        status_code=201,
    )
    async def ensure(
        body: Annotated[EnsureEmbeddingGenerationRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> EmbeddingGenerationResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            if idempotency_key != body.operation_id:
                raise EmbeddingSpaceValidationError(_ERR_IDEMPOTENCY)
            requested_at = clock.now()
            scope = await resolve_provider_scope(
                scope_resolver,
                body,
                requested_at,
                "provider.embedding_space.ensure",
                purpose="embedding_space_administration",
            )
            generation = await ensure_handler.execute(
                EnsureIndexGenerationCommand(
                    operation_id=body.operation_id,
                    scope=scope,
                    profile_id=body.profile_id,
                    capability_attestation_id=body.capability_attestation_id,
                    descriptor=_descriptor(body.descriptor),
                    requested_at=requested_at,
                )
            )
            return _response(generation)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    del ensure
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


def create_contract_embedding_space_router() -> APIRouter:
    """Create a side-effect-free PRO-004 router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_embedding_space_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("EnsureIndexGenerationPort", dependency),
        cast("Clock", _ContractClock()),
    )


def _descriptor(model: EmbeddingSpaceDescriptorModel) -> EmbeddingSpaceDescriptor:
    values = model.model_dump()
    values["dtype"] = VectorDtype(model.dtype)
    values["normalization"] = VectorNormalization(model.normalization)
    values["purpose"] = CanonicalPurpose(model.purpose)
    values["execution_class"] = ProviderExecutionClass(model.execution_class)
    return EmbeddingSpaceDescriptor(**values)


def _response(generation: IndexGeneration) -> EmbeddingGenerationResponseModel:
    return EmbeddingGenerationResponseModel(
        generation_id=generation.generation_id,
        brain_id=generation.brain_id,
        space_id=generation.space_id,
        space_fingerprint=generation.space_fingerprint,
        generated_label=generation.names.label,
        vector_index_name=generation.names.vector_index,
        vector_property=generation.names.vector_property,
        dimension=generation.dimension,
        similarity=generation.similarity,
        state=generation.state.value,
        created_at=generation.created_at.isoformat(),
    )


_HANDLED_ERRORS = (
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(error, (EmbeddingSpaceAuthorizationError, IdentityAuthorizationError)):
        status, code = 403, "forbidden"
    elif isinstance(error, (EmbeddingSpaceConflictError, IdentityConflictError)):
        status, code = 409, "conflict"
    elif isinstance(error, (EmbeddingSpaceDependencyError, IdentityDependencyError)):
        status, code = 503, "dependency_unavailable"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider-embedding-space:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "embedding-space operation could not be completed",
        },
    )
