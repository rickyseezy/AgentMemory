"""Authenticated IDX-006 policy activation and reconciliation status API."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

from fastapi import APIRouter, Body, Header, Query, Security
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
from agentmemory.indexing.application.content_policy import (
    ActivateIndexPolicyCommand,
    GetIndexPolicyChangeQuery,
)
from agentmemory.indexing.domain.content_policy import (
    IndexPolicyRevision,
    PolicyAction,
    PolicyLayer,
    PolicyRule,
    PolicyRuleSource,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.content_policy_ports import PolicyChangeResult
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_ERR_IDEMPOTENCY = "Idempotency-Key is invalid"


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class PolicyScopeModel(_StrictModel):
    """Exact current Repository authority for one content-policy operation."""

    brain_id: str
    actor_id: str
    grant_id: str
    project_id: str
    repository_id: str


class PolicyRuleModel(_StrictModel):
    """One ordered highest-precedence Brain path rule."""

    rule_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9._-]*$")
    pattern: str = Field(min_length=1, max_length=1024)
    action: Literal["include", "exclude"]


class PrivateBlockModel(_StrictModel):
    """One exact private-block delimiter pair."""

    start: str = Field(min_length=1, max_length=512)
    end: str = Field(min_length=1, max_length=512)


class ActivatePolicyRequestModel(PolicyScopeModel):
    """Complete immutable policy revision supplied by a local administrator."""

    operation_id: str = Field(min_length=1, max_length=128)
    policy_id: str
    version: int = Field(ge=2, le=2**31 - 1)
    rules: list[PolicyRuleModel] = Field(max_length=2048)
    max_file_bytes: int = Field(ge=1, le=64 * 1024 * 1024)
    private_blocks: list[PrivateBlockModel] = Field(min_length=1, max_length=64)
    exclude_binary: bool = True
    exclude_generated: bool = True
    exclude_encrypted: bool = True


class PolicyChangeResponseModel(_StrictModel):
    """Content-free policy activation and reconciliation counts."""

    change_id: str
    operation_id: str
    brain_id: str
    repository_id: str
    previous_policy_digest: str | None
    current_policy_digest: str
    delete_count: int
    reindex_count: int
    activated_at: str


class AuthenticatorPort(Protocol):
    """Authenticate the local capability before scope resolution."""

    async def authenticate(self, authorization: str | None) -> None:
        """Authenticate without returning credential material."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve current canonical Brain/Project/Repository authority."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Resolve one exact current scope."""
        ...


class ActivatePolicyPort(Protocol):
    """Activate one policy revision."""

    async def execute(self, command: ActivateIndexPolicyCommand) -> PolicyChangeResult:
        """Return the activation and scheduled-work summary."""
        ...


class GetPolicyChangePort(Protocol):
    """Read one policy change."""

    async def execute(self, query: GetIndexPolicyChangeQuery) -> PolicyChangeResult:
        """Return the currently authorized summary."""
        ...


def create_content_policy_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    activate_handler: ActivatePolicyPort,
    get_handler: GetPolicyChangePort,
    clock: Clock,
) -> APIRouter:
    """Create the complete authenticated content-policy operation map."""
    router = APIRouter()

    @router.post(
        "/v1/indexing/content-policies/revisions",
        operation_id="ActivateIndexPolicyCommand",
        response_model=PolicyChangeResponseModel,
        status_code=202,
    )
    async def activate(
        body: Annotated[ActivatePolicyRequestModel, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> PolicyChangeResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            _require_idempotency(idempotency_key, body.operation_id)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, body, at, "indexing.policy.activate")
            revision = _revision(body, at)
            return _response(
                await activate_handler.execute(
                    ActivateIndexPolicyCommand(body.operation_id, scope, revision, at)
                )
            )
        except _HANDLED_ERRORS as error:
            return _problem(error)

    @router.get(
        "/v1/indexing/content-policies/changes/{change_id}",
        operation_id="GetIndexPolicyChangeQuery",
        response_model=PolicyChangeResponseModel,
    )
    async def get(
        change_id: str,
        scope_model: Annotated[PolicyScopeModel, Query()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> PolicyChangeResponseModel | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            at = clock.now()
            scope = await _resolve_scope(scope_resolver, scope_model, at, "indexing.policy.read")
            return _response(await get_handler.execute(GetIndexPolicyChangeQuery(scope, change_id)))
        except _HANDLED_ERRORS as error:
            return _problem(error)

    routes = (activate, get)
    del routes
    return router


class _ContractDependency:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization

    async def execute(self, value: object) -> object:
        del value
        message = "contract dependency cannot execute"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract clock cannot read time"
        raise RuntimeError(message)


def create_contract_content_policy_router() -> APIRouter:
    """Create a side-effect-free router for deterministic OpenAPI export."""
    dependency = _ContractDependency()
    return create_content_policy_router(
        dependency,
        cast("RetrievalScopeResolverPort", dependency),
        cast("ActivatePolicyPort", dependency),
        cast("GetPolicyChangePort", dependency),
        _ContractClock(),
    )


def _revision(body: ActivatePolicyRequestModel, activated_at: datetime) -> IndexPolicyRevision:
    rules = tuple(
        PolicyRule(
            PolicyLayer.BRAIN,
            rule.rule_id,
            body.version,
            rule.pattern,
            PolicyAction(rule.action),
        )
        for rule in body.rules
    )
    return IndexPolicyRevision(
        policy_id=body.policy_id,
        version=body.version,
        brain_id=body.brain_id,
        repository_id=body.repository_id,
        brain_rules=PolicyRuleSource.create(PolicyLayer.BRAIN, body.version, rules),
        max_file_bytes=body.max_file_bytes,
        private_block_pairs=tuple((pair.start, pair.end) for pair in body.private_blocks),
        exclude_binary=body.exclude_binary,
        exclude_generated=body.exclude_generated,
        exclude_encrypted=body.exclude_encrypted,
        activated_at=activated_at,
    )


async def _resolve_scope(
    resolver: RetrievalScopeResolverPort,
    request: PolicyScopeModel,
    requested_at: datetime,
    action: str,
) -> AuthorizedScope:
    resolution = await resolver.execute(
        ResolveRetrievalScopeQuery(
            getattr(request, "operation_id", f"policy-read-{round(requested_at.timestamp())}"),
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
        purpose="code_indexing",
    )


def _response(result: PolicyChangeResult) -> PolicyChangeResponseModel:
    return PolicyChangeResponseModel(
        change_id=result.change_id,
        operation_id=result.operation_id,
        brain_id=result.brain_id,
        repository_id=result.repository_id,
        previous_policy_digest=result.previous_policy_digest,
        current_policy_digest=result.current_policy_digest,
        delete_count=result.delete_count,
        reindex_count=result.reindex_count,
        activated_at=result.activated_at.isoformat(),
    )


def _require_idempotency(supplied: str | None, expected: str) -> None:
    if supplied != expected:
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
            "detail": "indexing operation could not be completed",
        },
    )
