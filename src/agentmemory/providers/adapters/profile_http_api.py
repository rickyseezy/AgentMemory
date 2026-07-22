"""Authenticated PRO-001 provider-profile administration API."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

from fastapi import APIRouter, Body, Header, Query, Response, Security
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
from agentmemory.providers.application.profiles import (
    CreateProviderProfileCommand,
    GetProviderProfileQuery,
    ProbeProviderCommand,
)
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderModelDriftError,
    ProviderProfileAuthorizationError,
    ProviderProfileConflictError,
    ProviderProfileDependencyError,
    ProviderProfileValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderBudget,
    ProviderDataPolicy,
    ProviderExecutionClass,
    ProviderLimits,
    ProviderOperation,
    ProviderProfileConfiguration,
    ProviderQuota,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.providers.domain.profiles import ProviderProfile
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"
_ERR_REQUEST = "provider profile request is invalid"
_ERR_CONTRACT_DEPENDENCY = "contract dependency cannot execute"
_ERR_CONTRACT_CLOCK = "contract clock cannot read time"
_ERR_PRECONDITION = "provider profile precondition is invalid"
_ETAG = re.compile(r'^"provider-profile:([0-9a-f-]{36}):([1-9][0-9]{0,9}):([0-9a-f]{64})"$')


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ProviderScopeModel(_StrictModel):
    """Current workspace used to prove Brain-wide owner/admin authority."""

    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class ProviderLimitsModel(_StrictModel):
    """Bounded profile limits that may only narrow a manifest."""

    max_items: int = Field(ge=1, le=1000)
    max_input_bytes: int = Field(ge=1, le=8 * 1024 * 1024)
    max_item_tokens: int = Field(ge=1, le=1_000_000)
    max_request_tokens: int = Field(ge=1, le=1_000_000)
    timeout_milliseconds: int = Field(ge=100, le=300_000)


class ProviderDataPolicyModel(_StrictModel):
    """Explicit provider data handling declaration."""

    declaration_version: str = Field(min_length=1, max_length=256)
    retention_days: int = Field(ge=0, le=3650)
    training_allowed: bool
    residency: str = Field(min_length=2, max_length=32)


class ProviderQuotaModel(_StrictModel):
    """Explicit remote request and token ceilings."""

    requests_per_minute: int = Field(ge=1, le=1_000_000)
    tokens_per_minute: int = Field(ge=1, le=1_000_000_000)
    monthly_tokens: int = Field(ge=1, le=10**15)


class ProviderBudgetModel(_StrictModel):
    """Explicit monthly monetary ceiling in integer micros."""

    currency: str = Field(min_length=3, max_length=3)
    monthly_micros: int = Field(ge=1, le=10**15)


class RemoteProviderPolicyModel(_StrictModel):
    """Every authority required before a remote profile may be probed."""

    endpoint_policy_ref: str = Field(min_length=10, max_length=264)
    secret_ref: str = Field(min_length=10, max_length=264)
    egress_approval_ref: str = Field(min_length=12, max_length=266)
    data_policy: ProviderDataPolicyModel
    quota: ProviderQuotaModel
    budget: ProviderBudgetModel


class CreateProviderProfileRequestModel(ProviderScopeModel):
    """Complete local or remote profile configuration without credential values."""

    operation_id: str = Field(min_length=1, max_length=128)
    adapter_id: str = Field(min_length=1, max_length=128)
    operation: Literal["embedding", "reranking"]
    model_id: str = Field(min_length=1, max_length=256)
    purposes: list[
        Literal[
            "retrieval_query",
            "retrieval_document",
            "code_query",
            "code_document",
            "semantic_similarity",
            "classification",
            "clustering",
        ]
    ] = Field(min_length=1, max_length=7)
    execution_class: Literal["local", "remote"]
    limits: ProviderLimitsModel
    remote_policy: RemoteProviderPolicyModel | None = None


class ProbeProviderRequestModel(ProviderScopeModel):
    """Idempotent live-probe request."""

    operation_id: str = Field(min_length=1, max_length=128)


class ProviderProbeResponseModel(_StrictModel):
    """Content-free active probe evidence."""

    evidence_id: str
    model_revision: str
    revision_fingerprint: str
    dimension: int | None
    dtype: str | None
    cancellation_verified: bool
    probed_at: str


class ProviderProfileResponseModel(_StrictModel):
    """Content-free profile response that deliberately omits every credential reference."""

    profile_id: str
    brain_id: str
    adapter_id: str
    operation: str
    model_id: str
    purposes: list[str]
    execution_class: str
    limits: ProviderLimitsModel
    remote_policy_configured: bool
    credential_configured: bool
    manifest_digest: str
    status: str
    version: int
    created_at: str
    updated_at: str
    active_probe: ProviderProbeResponseModel | None


class AuthenticatorPort(Protocol):
    """Authenticate the local API capability before any provider work."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate before scope or provider access."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current workspace authorization."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Resolve one current workspace scope."""
        ...


class CreateProviderProfilePort(Protocol):
    """Create one validated provider profile."""

    async def execute(self, command: CreateProviderProfileCommand) -> ProviderProfile:
        """Create one validated draft."""
        ...


class ProbeProviderPort(Protocol):
    """Probe and activate one provider profile."""

    async def execute(self, command: ProbeProviderCommand) -> ProviderProfile:
        """Probe and activate one draft/current profile."""
        ...


class GetProviderProfilePort(Protocol):
    """Read one authorized provider profile."""

    async def execute(self, query: GetProviderProfileQuery) -> ProviderProfile:
        """Read one current profile."""
        ...


def create_provider_profile_router(  # noqa: PLR0913 -- Router wires five narrow ports and clock.
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    create_handler: CreateProviderProfilePort,
    probe_handler: ProbeProviderPort,
    get_handler: GetProviderProfilePort,
    clock: Clock,
) -> APIRouter:
    """Create the complete provider-profile lifecycle API."""
    router = APIRouter()

    @router.post(
        "/v1/providers/profiles",
        operation_id="CreateProviderProfileCommand",
        response_model=ProviderProfileResponseModel,
        status_code=201,
    )
    async def create(
        body: Annotated[CreateProviderProfileRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProviderProfileResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            now = clock.now()
            scope = await _scope(scope_resolver, body, now, "provider.profile.create")
            profile = await create_handler.execute(
                CreateProviderProfileCommand(
                    body.operation_id,
                    scope,
                    _configuration(body),
                    now,
                )
            )
            response.headers["ETag"] = _profile_etag(profile)
            return _response(profile)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.post(
        "/v1/providers/profiles/{profile_id}/probe",
        operation_id="ProbeProviderCommand",
        response_model=ProviderProfileResponseModel,
    )
    async def probe(  # noqa: PLR0913 -- HTTP contract has two required headers and Response.
        profile_id: str,
        body: Annotated[ProbeProviderRequestModel, Body()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProviderProfileResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            expected_version, expected_digest = _require_if_match(if_match, profile_id)
            now = clock.now()
            scope = await _scope(scope_resolver, body, now, "provider.profile.probe")
            profile = await probe_handler.execute(
                ProbeProviderCommand(
                    body.operation_id,
                    scope,
                    profile_id,
                    expected_version,
                    expected_digest,
                    now,
                )
            )
            response.headers["ETag"] = _profile_etag(profile)
            return _response(profile)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/providers/profiles/{profile_id}",
        operation_id="GetProviderProfileQuery",
        response_model=ProviderProfileResponseModel,
    )
    async def get(
        profile_id: str,
        scope_model: Annotated[ProviderScopeModel, Query()],
        response: Response,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ProviderProfileResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            scope = await _scope(scope_resolver, scope_model, now, "provider.profile.read")
            profile = await get_handler.execute(GetProviderProfileQuery(scope, profile_id, now))
            response.headers["ETag"] = _profile_etag(profile)
            return _response(profile)
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (create, probe, get)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        raise RuntimeError(_ERR_CONTRACT_DEPENDENCY)


class _ContractClock:
    def now(self) -> datetime:
        raise RuntimeError(_ERR_CONTRACT_CLOCK)


def create_contract_provider_profile_router() -> APIRouter:
    """Create a side-effect-free provider router for deterministic OpenAPI."""
    dependency = _ContractDependency()
    return create_provider_profile_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("CreateProviderProfilePort", dependency),
        cast("ProbeProviderPort", dependency),
        cast("GetProviderProfilePort", dependency),
        _ContractClock(),
    )


def _configuration(body: CreateProviderProfileRequestModel) -> ProviderProfileConfiguration:
    if len(body.purposes) != len(set(body.purposes)):
        raise ProviderProfileValidationError(_ERR_REQUEST)
    remote = body.remote_policy
    return ProviderProfileConfiguration(
        brain_id=body.brain_id,
        adapter_id=body.adapter_id,
        operation=ProviderOperation(body.operation),
        model_id=body.model_id,
        purposes=tuple(sorted((CanonicalPurpose(item) for item in body.purposes), key=str)),
        limits=ProviderLimits(**body.limits.model_dump()),
        execution_class=ProviderExecutionClass(body.execution_class),
        endpoint_policy_ref=None if remote is None else remote.endpoint_policy_ref,
        secret_ref=None if remote is None else remote.secret_ref,
        egress_approval_ref=None if remote is None else remote.egress_approval_ref,
        data_policy=(
            None if remote is None else ProviderDataPolicy(**remote.data_policy.model_dump())
        ),
        quota=None if remote is None else ProviderQuota(**remote.quota.model_dump()),
        budget=None if remote is None else ProviderBudget(**remote.budget.model_dump()),
    )


async def _scope(
    resolver: RetrievalScopeResolverPort,
    request: ProviderScopeModel,
    at: datetime,
    action: str,
) -> AuthorizedScope:
    operation_id = getattr(request, "operation_id", f"provider-read-{round(at.timestamp())}")
    resolution = await resolver.execute(
        ResolveRetrievalScopeQuery(
            operation_id,
            StableId(request.brain_id),
            StableId(request.actor_id),
            StableId(request.grant_id),
            RetrievalScopeMode.CURRENT,
            StableId(request.project_id),
            StableId(request.repository_id),
            None,
            (),
            round(at.timestamp() * 1_000_000),
        )
    )
    source = resolution.scope
    return AuthorizedScope.create(
        brain_id=source.brain_id,
        principal_id=source.principal_id,
        role=source.role,
        mode=source.mode,
        members=source.members,
        classification_ceiling=source.classification_ceiling,
        temporal_scope=source.temporal_scope,
        grant_version=source.grant_version,
        policy_version=source.policy_version,
        security_epoch=source.security_epoch,
        action=action,
        purpose="provider_administration",
    )


def _response(profile: ProviderProfile) -> ProviderProfileResponseModel:
    configuration = profile.configuration
    probe = profile.active_probe
    return ProviderProfileResponseModel(
        profile_id=profile.profile_id,
        brain_id=configuration.brain_id,
        adapter_id=configuration.adapter_id,
        operation=configuration.operation.value,
        model_id=configuration.model_id,
        purposes=[item.value for item in configuration.purposes],
        execution_class=configuration.execution_class.value,
        limits=ProviderLimitsModel(**configuration.limits.document),
        remote_policy_configured=configuration.data_policy is not None,
        credential_configured=configuration.secret_ref is not None,
        manifest_digest=profile.manifest_digest,
        status=profile.status.value,
        version=profile.version,
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
        active_probe=(
            None
            if probe is None
            else ProviderProbeResponseModel(
                evidence_id=probe.evidence_id,
                model_revision=probe.result.model_revision,
                revision_fingerprint=probe.result.revision_fingerprint,
                dimension=probe.result.dimension,
                dtype=None if probe.result.dtype is None else probe.result.dtype.value,
                cancellation_verified=probe.result.cancellation_verified,
                probed_at=probe.probed_at.isoformat(),
            )
        ),
    )


def _require_idempotency(supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise ProviderProfileValidationError(_ERR_IDEMPOTENCY)


def _profile_etag(profile: ProviderProfile) -> str:
    return f'"provider-profile:{profile.profile_id}:{profile.version}:{profile.snapshot_digest}"'


def _require_if_match(supplied: str | None, profile_id: str) -> tuple[int, str]:
    matched = None if supplied is None else _ETAG.fullmatch(supplied)
    if matched is None or matched.group(1) != profile_id:
        raise ProviderProfileValidationError(_ERR_PRECONDITION)
    return int(matched.group(2)), matched.group(3)


_HANDLED_ERRORS = (
    ProviderAdapterError,
    ProviderModelDriftError,
    ProviderProfileAuthorizationError,
    ProviderProfileConflictError,
    ProviderProfileDependencyError,
    ProviderProfileValidationError,
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)


def _problem(error: Exception) -> JSONResponse:
    if isinstance(error, (ProviderProfileAuthorizationError, IdentityAuthorizationError)):
        status, code = 403, "forbidden"
    elif isinstance(
        error, (ProviderModelDriftError, ProviderProfileConflictError, IdentityConflictError)
    ):
        status, code = 409, "conflict"
    elif isinstance(error, (ProviderProfileDependencyError, IdentityDependencyError)):
        status, code = 503, "dependency_unavailable"
    elif isinstance(error, ProviderAdapterError):
        status, code = 422, "provider_rejected"
    else:
        status, code = 422, "validation_failed"
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:agentmemory:provider:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": "provider profile operation could not be completed",
        },
    )
