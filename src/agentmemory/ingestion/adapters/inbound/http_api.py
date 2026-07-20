"""Authenticated minimal loopback AgentEvent append endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Protocol

from fastapi import APIRouter, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict

from agentmemory.ingestion.adapters.inbound.agent_event_schema import (
    agent_event_json_schema,
    parse_agent_event_json,
)
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionValidationError,
)

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.capture import AppendAgentEventResult

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_MAX_REQUEST_BYTES = 96 * 1024


class Authenticator(Protocol):
    """Authenticate the local session/installation capability."""

    async def authenticate(self, authorization: str | None) -> None:
        """Raise unless the exact capability is active."""
        ...


class CaptureHandler(Protocol):
    """Admit and durably append one canonical event."""

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        """Return only after accepted/duplicate durability is known."""
        ...


class AppendAgentEventResponse(BaseModel):
    """Content-free durable capture status safe for hook output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    event_id: str
    status: AppendDisposition
    ingested_at_microseconds: int


def create_agent_event_router(
    authenticator: Authenticator,
    handler: CaptureHandler,
) -> APIRouter:
    """Create the strict capture router with explicit dependencies."""
    router = APIRouter()

    @router.post(
        "/v1/agent-events:append",
        response_model=AppendAgentEventResponse,
        status_code=status.HTTP_201_CREATED,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": agent_event_json_schema()}},
            }
        },
    )
    async def append_agent_event(
        request: Request,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> JSONResponse:
        """Authenticate, strictly parse, and ACK only after the durable commit."""
        try:
            await authenticator.authenticate(authorization)
            raw = await request.body()
            if not raw or len(raw) > _MAX_REQUEST_BYTES:
                field = "$body"
                raise IngestionValidationError.single(field, "invalid_size")
            result = await handler.execute(parse_agent_event_json(raw))
        except IngestionValidationError as error:
            return _problem(
                "AM_VALIDATION",
                422,
                fields=[{"field": item.field, "code": item.code} for item in error.violations],
            )
        except IngestionAuthorizationError:
            return _problem("AM_FORBIDDEN", 403)
        except IngestionConflictError:
            return _problem("AM_CONFLICT", 409)
        except IngestionDependencyError:
            return _problem("AM_DEPENDENCY_UNAVAILABLE", 503, retryable=True)
        response_status = (
            status.HTTP_201_CREATED
            if result.disposition is AppendDisposition.ACCEPTED
            else status.HTTP_200_OK
        )
        return JSONResponse(
            {
                "event_id": result.event_id,
                "status": result.disposition.value,
                "ingested_at_microseconds": result.ingested_at_microseconds,
            },
            status_code=response_status,
        )

    registered_routes = (append_agent_event,)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractCaptureHandler:
    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        del event
        msg = "contract-only handler cannot append"
        raise RuntimeError(msg)


def create_contract_agent_event_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_agent_event_router(_ContractAuthenticator(), _ContractCaptureHandler())


def _problem(
    code: str,
    http_status: int,
    *,
    retryable: bool = False,
    fields: list[dict[str, str]] | None = None,
) -> JSONResponse:
    document: dict[str, object] = {
        "code": code,
        "retryable": retryable,
        "detail": "AgentEvent capture was rejected",
    }
    if fields is not None:
        document["fields"] = fields
    return JSONResponse(document, status_code=http_status)
