"""Authenticated ADP-006 session briefing HTTP adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast

from fastapi import APIRouter, Security
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
from agentmemory.identity.domain.retrieval_scope import RetrievalScopeMode
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.retrieval.adapters.inbound.host_delivery import BriefingDeliveryRequest
from agentmemory.retrieval.domain.continuity import AgentHost, BriefingBudget
from agentmemory.retrieval.domain.errors import (
    RetrievalAuthorizationError,
    RetrievalConflictError,
    RetrievalDependencyError,
    RetrievalIntegrityError,
    RetrievalValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.retrieval.adapters.inbound.host_delivery import (
        BriefingDeliveryAdapter,
        DeliveredBriefing,
        DeliveryAdapterRegistry,
    )
    from agentmemory.retrieval.domain.continuity import ContinuityItem
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class BriefingBudgetModel(_StrictModel):
    """Strict bounded context request using ADR-012 defaults."""

    max_tokens: int = Field(default=1_200, ge=64, le=8_192)
    max_items: int = Field(default=12, ge=1, le=100)
    max_bytes: int = Field(default=20_480, ge=512, le=1_048_576)

    def to_domain(self) -> BriefingBudget:
        """Create the framework-independent budget."""
        return BriefingBudget(self.max_tokens, self.max_items, self.max_bytes)


class StartSessionBriefingRequestModel(_StrictModel):
    """Explicit identity, consumer, scope, time, and context bounds."""

    operation_id: str = Field(min_length=1, max_length=128)
    brain_id: str
    actor_id: str
    grant_id: str
    consumer_host: Literal["claude_code", "codex", "gemini_cli", "cursor_compatible", "generic"]
    consumer_platform: Literal["darwin", "linux", "windows"]
    mode: Literal["current", "related", "selected", "global"] = "current"
    current_project_id: str | None = None
    current_repository_id: str | None = None
    current_checkout_id: str | None = None
    selected_project_ids: list[str] = Field(default_factory=list, max_length=500)
    max_related_depth: int = Field(default=3, ge=1, le=3)
    max_related_cost: int = Field(default=10, ge=1, le=100)
    temporal_from: int | None = Field(default=None, ge=0)
    temporal_to: int | None = Field(default=None, ge=1)
    budget: BriefingBudgetModel = Field(default_factory=BriefingBudgetModel)

    def scope_query(self, at: int) -> ResolveRetrievalScopeQuery:
        """Resolve every claimed ID before any canonical event read."""
        return ResolveRetrievalScopeQuery(
            self.operation_id,
            StableId(self.brain_id),
            StableId(self.actor_id),
            StableId(self.grant_id),
            RetrievalScopeMode(self.mode),
            _optional_id(self.current_project_id),
            _optional_id(self.current_repository_id),
            _optional_id(self.current_checkout_id),
            tuple(StableId(value) for value in self.selected_project_ids),
            at,
            self.max_related_depth,
            self.max_related_cost,
            self.temporal_from,
            self.temporal_to,
        )


class ItemProvenanceResponseModel(_StrictModel):
    """Original producer provenance, never rewritten as consumer provenance."""

    producer_host: str
    model_id: str
    adapter_id: str
    adapter_version: str
    capture_method: str


class ContinuityItemResponseModel(_StrictModel):
    """One evidence-backed atomic briefing item."""

    item_id: str
    semantic_id: str
    kind: Literal["fact", "decision", "change", "failure", "next_step"]
    content: str
    category: Literal[
        "safety_constraint",
        "blocker",
        "unresolved_work",
        "decision",
        "failure",
        "validation",
        "change",
        "supporting",
    ]
    freshness: Literal["current", "stale"]
    revision_compatibility: Literal["compatible", "unknown", "branch_incompatible"]
    rank: int = Field(ge=1)
    classification: str
    evidence_event_id: str
    occurred_at: str
    provenance: ItemProvenanceResponseModel


class ProcedureResponseModel(_StrictModel):
    """One authorized and environment-compatible procedure."""

    procedure_id: str
    content: str


class ExcludedProcedureResponseModel(_StrictModel):
    """Content-free incompatible procedure explanation."""

    procedure_id: str
    reason: str


class ExcludedContinuityItemResponseModel(_StrictModel):
    """Content-free reason an otherwise authorized candidate was omitted."""

    item_id: str
    reason: Literal["branch_incompatible", "stale_beyond_horizon"]


class StartSessionBriefingResponseModel(_StrictModel):
    """Structured briefing plus exact host-specific context serialization."""

    consumer_host: Literal["claude_code", "codex", "gemini_cli", "cursor_compatible", "generic"]
    media_type: Literal["application/json", "text/markdown"]
    rendered_context: str
    items: tuple[ContinuityItemResponseModel, ...]
    procedures: tuple[ProcedureResponseModel, ...]
    excluded_procedures: tuple[ExcludedProcedureResponseModel, ...]
    excluded_items: tuple[ExcludedContinuityItemResponseModel, ...]
    used_tokens: int
    used_items: int
    used_bytes: int
    truncated: bool
    scope_fingerprint: str
    status: Literal["ready", "no_answer"]
    context_event_id: str
    policy_version: str


class AuthenticatorPort(Protocol):
    """Authenticate a local capability before resolving scope."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class RetrievalScopeResolverPort(Protocol):
    """Resolve an immutable authorization-first identity scope."""

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Return an authorized explicit scope and explanation."""
        ...


def create_retrieval_router(
    authenticator: AuthenticatorPort,
    scope_resolver: RetrievalScopeResolverPort,
    delivery_adapters: DeliveryAdapterRegistry,
    clock: Clock,
) -> APIRouter:
    """Create the strict cross-agent briefing transport."""
    router = APIRouter()

    @router.post(
        "/recall:brief",
        operation_id="StartSessionBriefingQuery",
        response_model=StartSessionBriefingResponseModel,
    )
    async def start_session_briefing(
        request: StartSessionBriefingRequestModel,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> StartSessionBriefingResponseModel | JSONResponse:
        """Recall host-neutral memories and render only at the final host boundary."""
        try:
            await authenticator.authenticate(authorization)
            requested_at = clock.now()
            at = round(requested_at.timestamp() * 1_000_000)
            resolution = await scope_resolver.execute(request.scope_query(at))
            adapter = delivery_adapters.get(
                AgentHost(request.consumer_host), request.consumer_platform
            )
            delivered = await adapter.deliver(
                BriefingDeliveryRequest(
                    resolution.scope,
                    request.budget.to_domain(),
                    request.operation_id,
                    requested_at,
                )
            )
            return _response(delivered)
        except IdentityAuthorizationError, RetrievalAuthorizationError:
            return _problem("AM_FORBIDDEN", 403, "briefing scope is not authorized")
        except IdentityConflictError, RetrievalConflictError:
            return _problem("AM_CONFLICT", 409, "briefing request conflicts")
        except IdentityValidationError, RetrievalValidationError:
            return _problem("AM_VALIDATION", 422, "briefing request is invalid")
        except IdentityDependencyError, RetrievalDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "briefing dependency is unavailable",
                retryable=True,
            )
        except RetrievalIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "briefing evidence failed verification")

    registered_routes = (start_session_briefing,)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractScopeResolver:
    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        msg = "contract-only resolver cannot resolve scope"
        raise RuntimeError(msg)


class _ContractDeliveryRegistry:
    def get(self, host: AgentHost, platform: str) -> BriefingDeliveryAdapter:
        del host, platform
        msg = "contract-only registry cannot deliver"
        raise RuntimeError(msg)


class _ContractClock:
    def now(self) -> datetime:
        msg = "contract-only clock cannot read time"
        raise RuntimeError(msg)


def create_contract_retrieval_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_retrieval_router(
        _ContractAuthenticator(),
        _ContractScopeResolver(),
        _ContractDeliveryRegistry(),
        _ContractClock(),
    )


def _response(delivered: DeliveredBriefing) -> StartSessionBriefingResponseModel:
    briefing = delivered.briefing
    if briefing.context_event_id is None:
        raise RetrievalIntegrityError
    return StartSessionBriefingResponseModel(
        consumer_host=delivered.consumer_host.value,
        media_type=cast("Literal['application/json', 'text/markdown']", delivered.media_type),
        rendered_context=delivered.rendered_context,
        items=tuple(
            ContinuityItemResponseModel(
                item_id=item.item_id,
                semantic_id=item.semantic_id,
                kind=item.kind.value,
                content=item.content,
                category=_response_category(item),
                freshness=item.freshness.value,
                revision_compatibility=item.revision_compatibility.value,
                rank=item.rank,
                classification=item.classification,
                evidence_event_id=item.evidence_event_id,
                occurred_at=item.occurred_at.isoformat().replace("+00:00", "Z"),
                provenance=ItemProvenanceResponseModel(
                    producer_host=item.provenance.producer_host,
                    model_id=item.provenance.model_id,
                    adapter_id=item.provenance.adapter_id,
                    adapter_version=item.provenance.adapter_version,
                    capture_method=item.provenance.capture_method,
                ),
            )
            for item in briefing.items
        ),
        procedures=tuple(
            ProcedureResponseModel(
                procedure_id=procedure.procedure_id,
                content=procedure.content,
            )
            for procedure in briefing.procedures
        ),
        excluded_procedures=tuple(
            ExcludedProcedureResponseModel(
                procedure_id=procedure.procedure_id,
                reason=procedure.reason,
            )
            for procedure in briefing.excluded_procedures
        ),
        excluded_items=tuple(
            ExcludedContinuityItemResponseModel(
                item_id=item.item_id,
                reason=cast(
                    "Literal['branch_incompatible','stale_beyond_horizon']",
                    item.reason,
                ),
            )
            for item in briefing.excluded_items
        ),
        used_tokens=briefing.used_tokens,
        used_items=briefing.used_items,
        used_bytes=briefing.used_bytes,
        truncated=briefing.truncated,
        scope_fingerprint=briefing.scope_fingerprint,
        status=briefing.status.value,
        context_event_id=briefing.context_event_id,
        policy_version=briefing.policy_version,
    )


def _response_category(
    item: ContinuityItem,
) -> Literal[
    "safety_constraint",
    "blocker",
    "unresolved_work",
    "decision",
    "failure",
    "validation",
    "change",
    "supporting",
]:
    if item.category is None:
        raise RetrievalIntegrityError
    return item.category.value


def _optional_id(value: str | None) -> StableId | None:
    return None if value is None else StableId(value)


def _problem(code: str, status: int, detail: str, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        {"code": code, "detail": detail, "retryable": retryable}, status_code=status
    )
