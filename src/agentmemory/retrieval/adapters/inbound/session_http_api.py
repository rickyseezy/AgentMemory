"""PF-005 session-credential boundary for cross-agent continuity recall."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Annotated, Literal, Protocol

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse
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
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.retrieval.adapters.inbound.host_delivery import BriefingDeliveryRequest
from agentmemory.retrieval.adapters.inbound.http_api import (
    BriefingBudgetModel,
    StartSessionBriefingResponseModel,
    briefing_response,
)
from agentmemory.retrieval.domain.continuity import AgentHost
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
    from agentmemory.operations.domain.mcp_session import McpSession, McpSessionRegistration
    from agentmemory.retrieval.adapters.inbound.host_delivery import (
        BriefingDeliveryAdapter,
        DeliveryAdapterRegistry,
    )
    from agentmemory.shared.clock import Clock


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class SessionBriefingRequestModel(_StrictModel):
    """Scope-free request whose authorization coordinates come from the lease."""

    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    mode: Literal["current", "related", "global"] = "current"
    max_related_depth: int = Field(default=3, ge=1, le=3)
    max_related_cost: int = Field(default=10, ge=1, le=100)
    temporal_from: int | None = Field(default=None, ge=0)
    temporal_to: int | None = Field(default=None, ge=1)
    budget: BriefingBudgetModel = Field(default_factory=BriefingBudgetModel)


class SessionAuthenticatorPort(Protocol):
    """Authenticate one exact session secret and return its canonical lease."""

    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        """Reject absent, expired, revoked, stale-epoch, or foreign authority."""
        ...


class SessionScopeResolverPort(Protocol):
    """Resolve only IDs derived from an authenticated MCP session."""

    async def execute_session_scoped(
        self,
        query: ResolveRetrievalScopeQuery,
    ) -> RetrievalScopeResolution:
        """Return current, related, or internally expanded global authority."""
        ...


def create_session_retrieval_router(
    authenticator: SessionAuthenticatorPort,
    scope_resolver: SessionScopeResolverPort,
    delivery_adapters: DeliveryAdapterRegistry,
    clock: Clock,
) -> APIRouter:
    """Create a strict recall route that accepts no caller-controlled identity IDs."""
    router = APIRouter()

    @router.post(
        "/v1/session/recall:brief",
        operation_id="StartMcpSessionBriefingQuery",
        response_model=StartSessionBriefingResponseModel,
    )
    async def start_session_briefing(  # noqa: PLR0911 -- Closed transport error mapping.
        request: SessionBriefingRequestModel,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        session_id: Annotated[
            str | None,
            Header(alias="X-AgentMemory-Session-ID"),
        ] = None,
    ) -> StartSessionBriefingResponseModel | JSONResponse:
        """Recall continuity under the exact authenticated session scope."""
        try:
            session = await authenticator.authenticate(authorization, session_id or "")
            registration = session.registration
            project_id, repository_id, checkout_id = _required_registration_scope(registration)
            requested_at = clock.now()
            operation_id = _bound_operation_id(
                registration.session_id.value,
                request.operation_id,
            )
            resolution = await scope_resolver.execute_session_scoped(
                ResolveRetrievalScopeQuery(
                    operation_id=operation_id,
                    brain_id=StableId(registration.brain_id.value),
                    actor_id=StableId(registration.actor_id.value),
                    grant_id=StableId(registration.grant_id.value),
                    mode=RetrievalScopeMode(request.mode),
                    current_project_id=project_id,
                    current_repository_id=repository_id,
                    current_checkout_id=checkout_id,
                    selected_project_ids=(),
                    at=round(requested_at.timestamp() * 1_000_000),
                    max_related_depth=request.max_related_depth,
                    max_related_cost=request.max_related_cost,
                    temporal_from=request.temporal_from,
                    temporal_to=request.temporal_to,
                )
            )
            # MCP consumes structured JSON consistently across every host. The
            # generic delivery profile also prevents host-platform procedures from
            # being inferred from the Linux bridge container.
            delivered = await delivery_adapters.get(AgentHost.GENERIC, "linux").deliver(
                BriefingDeliveryRequest(
                    resolution.scope,
                    request.budget.to_domain(),
                    operation_id,
                    requested_at,
                )
            )
            return briefing_response(delivered)
        except OperationError as error:
            if error.code is ErrorCode.UNAUTHENTICATED:
                return _problem("AM_UNAUTHENTICATED", 401, "session authentication is required")
            return _problem("AM_FORBIDDEN", 403, "session recall is not authorized")
        except IdentityAuthorizationError, RetrievalAuthorizationError:
            return _problem("AM_FORBIDDEN", 403, "session recall is not authorized")
        except IdentityConflictError, RetrievalConflictError:
            return _problem("AM_CONFLICT", 409, "session recall conflicts")
        except IdentityValidationError, RetrievalValidationError:
            return _problem("AM_VALIDATION", 422, "session recall is invalid")
        except IdentityDependencyError, RetrievalDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "session recall dependency is unavailable",
                retryable=True,
            )
        except RetrievalIntegrityError:
            return _problem(
                "AM_INTEGRITY_VIOLATION",
                500,
                "session recall evidence failed verification",
            )

    registered_routes = (start_session_briefing,)
    del registered_routes
    return router


class _ContractSessionAuthenticator:
    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        del authorization, session_id
        msg = "contract-only authenticator cannot authenticate a session"
        raise RuntimeError(msg)


class _ContractSessionScopeResolver:
    async def execute_session_scoped(
        self,
        query: ResolveRetrievalScopeQuery,
    ) -> RetrievalScopeResolution:
        del query
        msg = "contract-only resolver cannot resolve a session scope"
        raise RuntimeError(msg)


class _ContractDeliveryRegistry:
    def get(self, host: AgentHost, platform: str) -> BriefingDeliveryAdapter:
        del host, platform
        msg = "contract-only delivery registry cannot deliver"
        raise RuntimeError(msg)


class _ContractClock:
    def now(self) -> datetime:
        msg = "contract-only clock cannot read time"
        raise RuntimeError(msg)


def create_contract_session_retrieval_router() -> APIRouter:
    """Return the side-effect-free PF-005 session recall OpenAPI contract."""
    return create_session_retrieval_router(
        _ContractSessionAuthenticator(),
        _ContractSessionScopeResolver(),
        _ContractDeliveryRegistry(),
        _ContractClock(),
    )


def _bound_operation_id(session_id: str, operation_id: str) -> str:
    digest = hashlib.sha256(f"pf005-recall-v1\0{session_id}\0{operation_id}".encode()).hexdigest()
    return f"pf005-recall-{digest}"


def _required_registration_scope(
    registration: McpSessionRegistration,
) -> tuple[StableId, StableId, StableId | None]:
    if registration.project_id is None or registration.repository_id is None:
        raise RetrievalIntegrityError
    return (
        StableId(registration.project_id.value),
        StableId(registration.repository_id.value),
        None if registration.checkout_id is None else StableId(registration.checkout_id.value),
    )


def _problem(code: str, status: int, detail: str, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        {"code": code, "detail": detail, "retryable": retryable},
        status_code=status,
    )
