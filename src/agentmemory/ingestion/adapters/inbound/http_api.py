"""Authenticated minimal loopback AgentEvent append endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Protocol

from fastapi import APIRouter, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict

from agentmemory.ingestion.adapters.inbound.agent_event_schema import (
    agent_event_json_schema,
    parse_agent_event_batch_json,
    parse_agent_event_json,
)
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.spool_reconciliation import SpoolUploadDisposition

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
_MAX_BATCH_REQUEST_BYTES = 1024 * 1024 + 1024


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
    clock_skew_microseconds: int


class AppendAgentEventBatchItemResponse(BaseModel):
    """One content-free replay outcome with evidence only when durable."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    event_id: str
    status: SpoolUploadDisposition
    ingested_at_microseconds: int | None = None
    clock_skew_microseconds: int | None = None


class AppendAgentEventBatchResponse(BaseModel):
    """Ordered per-item outcomes for a bounded interruption replay."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    results: tuple[AppendAgentEventBatchItemResponse, ...]


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
                "clock_skew_microseconds": result.clock_skew_microseconds,
            },
            status_code=response_status,
        )

    @router.post(
        "/v1/agent-events:append-batch",
        response_model=AppendAgentEventBatchResponse,
        status_code=status.HTTP_200_OK,
    )
    async def append_agent_event_batch(
        request: Request,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> JSONResponse:
        """Authenticate once, prevalidate all items, then return one outcome per item."""
        return await _process_batch_request(request, authorization, authenticator, handler)

    registered_routes = (append_agent_event, append_agent_event_batch)
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


def _batch_item(
    event_id: str,
    disposition: SpoolUploadDisposition,
    *,
    ingested_at_microseconds: int | None = None,
    clock_skew_microseconds: int | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {"event_id": event_id, "status": disposition.value}
    if disposition.durable:
        document["ingested_at_microseconds"] = ingested_at_microseconds
        document["clock_skew_microseconds"] = clock_skew_microseconds
    return document


async def _process_batch_request(
    request: Request,
    authorization: str | None,
    authenticator: Authenticator,
    handler: CaptureHandler,
) -> JSONResponse:
    try:
        await authenticator.authenticate(authorization)
        raw = await request.body()
        if not raw or len(raw) > _MAX_BATCH_REQUEST_BYTES:
            field = "$body"
            raise IngestionValidationError.single(field, "invalid_size")
        events = parse_agent_event_batch_json(raw)
    except IngestionValidationError as error:
        return _problem(
            "AM_VALIDATION",
            422,
            fields=[{"field": item.field, "code": item.code} for item in error.violations],
        )
    except IngestionAuthorizationError:
        return _problem("AM_FORBIDDEN", 403)
    return JSONResponse(
        {"results": [await _execute_batch_item(handler, event) for event in events]},
        status_code=status.HTTP_200_OK,
    )


async def _execute_batch_item(
    handler: CaptureHandler,
    event: AgentEvent,
) -> dict[str, object]:
    try:
        receipt = await handler.execute(event)
    except IngestionValidationError, IngestionAuthorizationError:
        return _batch_item(event.event_id, SpoolUploadDisposition.REJECTED)
    except IngestionConflictError:
        return _batch_item(event.event_id, SpoolUploadDisposition.CONFLICT)
    except IngestionDependencyError:
        return _batch_item(event.event_id, SpoolUploadDisposition.RETRYABLE)
    if receipt.disposition is AppendDisposition.ACCEPTED:
        disposition = SpoolUploadDisposition.ACCEPTED
    elif receipt.disposition is AppendDisposition.DUPLICATE:
        disposition = SpoolUploadDisposition.DUPLICATE
    else:
        return _batch_item(event.event_id, SpoolUploadDisposition.RETRYABLE)
    return _batch_item(
        event.event_id,
        disposition,
        ingested_at_microseconds=receipt.ingested_at_microseconds,
        clock_skew_microseconds=receipt.clock_skew_microseconds,
    )
