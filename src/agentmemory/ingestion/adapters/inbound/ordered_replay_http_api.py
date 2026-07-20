"""Authenticated ING-003 replay command and content-free status HTTP boundary."""

from __future__ import annotations

from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, Header, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentmemory.ingestion.domain.errors import (
    FieldViolation,
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.ordered_replay import (
    OrderedReplayRun,
    ReplayRunRequest,
)

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_IDEMPOTENCY_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_FINGERPRINT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_PROJECTION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_FIELD_IDEMPOTENCY = "Idempotency-Key"
_FIELD_BODY = "$body"
_MAX_REQUEST_BYTES = 64 * 1024


class Authenticator(Protocol):
    """Authenticate the installation-local API capability."""

    async def authenticate(self, authorization: str | None) -> None:
        """Raise unless the bearer capability remains active."""
        ...


class StartReplayHandler(Protocol):
    """Application command boundary for replay creation."""

    async def execute(self, request: ReplayRunRequest) -> OrderedReplayRun:
        """Authorize and create/replay one immutable request."""
        ...


class GetReplayHandler(Protocol):
    """Application query boundary for reauthorized replay status."""

    async def execute(self, operation_id: str) -> OrderedReplayRun:
        """Return only content-free status for an active grant."""
        ...


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class OrderedReplayRequestModel(_StrictModel):
    """Strict immutable Brain/range/generation/code replay request."""

    operation_id: str = Field(pattern=_IDEMPOTENCY_PATTERN)
    brain_id: str = Field(pattern=_IDEMPOTENCY_PATTERN)
    actor_id: str = Field(pattern=_IDEMPOTENCY_PATTERN)
    grant_id: str = Field(pattern=_IDEMPOTENCY_PATTERN)
    projection_name: str = Field(pattern=_PROJECTION_PATTERN)
    projection_generation: str = Field(pattern=_IDEMPOTENCY_PATTERN)
    code_fingerprint: str = Field(pattern=_FINGERPRINT_PATTERN)
    from_ingested_at_microseconds: int | None = Field(default=None, ge=0)
    to_ingested_at_microseconds: int | None = Field(default=None, ge=0)
    from_event_id: str | None = Field(default=None, pattern=_IDEMPOTENCY_PATTERN)
    to_event_id: str | None = Field(default=None, pattern=_IDEMPOTENCY_PATTERN)

    def to_domain(self) -> ReplayRunRequest:
        """Translate strict transport data into validated domain input."""
        return ReplayRunRequest(
            self.operation_id,
            self.brain_id,
            self.actor_id,
            self.grant_id,
            self.projection_name,
            self.projection_generation,
            self.code_fingerprint,
            self.from_ingested_at_microseconds,
            self.to_ingested_at_microseconds,
            self.from_event_id,
            self.to_event_id,
        )


class OrderedReplayResponseModel(_StrictModel):
    """Content-free durable replay status and digest comparison."""

    operation_id: str
    brain_id: str
    projection_name: str
    projection_generation: str
    code_fingerprint: str
    state: Literal["queued", "building", "validating", "ready", "partial", "superseded"]
    source_watermark_ingested_at_microseconds: int
    source_watermark_event_id: str
    source_count: int
    processed_count: int
    cursor_ingested_at_microseconds: int | None
    cursor_event_id: str | None
    shadow_digest: str | None
    live_digest: str | None
    failure_code: str | None
    created_at_microseconds: int
    updated_at_microseconds: int
    completed_at_microseconds: int | None


def create_ordered_replay_router(
    authenticator: Authenticator,
    start: StartReplayHandler,
    get: GetReplayHandler,
) -> APIRouter:
    """Create strict authenticated command/query routes for causal replay."""
    router = APIRouter()

    @router.post(
        "/v1/ordered-replays",
        response_model=OrderedReplayResponseModel,
        status_code=status.HTTP_202_ACCEPTED,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": OrderedReplayRequestModel.model_json_schema()}
                },
            }
        },
    )
    async def start_replay(
        request: Request,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> OrderedReplayResponseModel | JSONResponse:
        """Authenticate, bind idempotency, authorize scope, and queue shadow replay."""
        try:
            await authenticator.authenticate(authorization)
            body = await _parse_request(request)
            if idempotency_key != body.operation_id:
                raise IngestionValidationError.single(_FIELD_IDEMPOTENCY, "mismatch")
            result = await start.execute(body.to_domain())
        except _BOUNDARY_ERRORS as error:
            return _problem(error)
        return _response(result)

    @router.get(
        "/v1/ordered-replays/{operation_id}",
        response_model=OrderedReplayResponseModel,
    )
    async def get_replay(
        operation_id: str,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> OrderedReplayResponseModel | JSONResponse:
        """Authenticate and reauthorize before returning content-free status."""
        try:
            await authenticator.authenticate(authorization)
            result = await get.execute(operation_id)
        except _BOUNDARY_ERRORS as error:
            return _problem(error)
        return _response(result)

    registered_routes = (start_replay, get_replay)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractStart:
    async def execute(self, request: ReplayRunRequest) -> OrderedReplayRun:
        del request
        message = "contract-only replay command cannot execute"
        raise RuntimeError(message)


class _ContractGet:
    async def execute(self, operation_id: str) -> OrderedReplayRun:
        del operation_id
        message = "contract-only replay query cannot execute"
        raise RuntimeError(message)


def create_contract_ordered_replay_router() -> APIRouter:
    """Return side-effect-free routes for deterministic OpenAPI export."""
    return create_ordered_replay_router(_ContractAuthenticator(), _ContractStart(), _ContractGet())


_BOUNDARY_ERRORS = (
    IngestionValidationError,
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
)


def _response(run: OrderedReplayRun) -> OrderedReplayResponseModel:
    return OrderedReplayResponseModel(
        operation_id=run.request.operation_id,
        brain_id=run.request.brain_id,
        projection_name=run.request.projection_name,
        projection_generation=run.request.projection_generation,
        code_fingerprint=run.request.code_fingerprint,
        state=run.state.value,
        source_watermark_ingested_at_microseconds=(run.source_watermark_ingested_at_microseconds),
        source_watermark_event_id=run.source_watermark_event_id,
        source_count=run.source_count,
        processed_count=run.processed_count,
        cursor_ingested_at_microseconds=run.cursor_ingested_at_microseconds,
        cursor_event_id=run.cursor_event_id,
        shadow_digest=run.shadow_digest,
        live_digest=run.live_digest,
        failure_code=run.failure_code,
        created_at_microseconds=run.created_at_microseconds,
        updated_at_microseconds=run.updated_at_microseconds,
        completed_at_microseconds=run.completed_at_microseconds,
    )


def _problem(error: Exception) -> JSONResponse:
    if isinstance(error, IngestionValidationError):
        code, status_code, retryable = "AM_VALIDATION", 422, False
        fields: list[dict[str, str]] | None = [
            {"field": item.field, "code": item.code} for item in error.violations
        ]
    elif isinstance(error, IngestionAuthorizationError):
        code, status_code, retryable, fields = "AM_FORBIDDEN", 403, False, None
    elif isinstance(error, IngestionConflictError):
        code, status_code, retryable, fields = "AM_CONFLICT", 409, False, None
    elif isinstance(error, IngestionDependencyError):
        code, status_code, retryable, fields = (
            "AM_DEPENDENCY_UNAVAILABLE",
            503,
            True,
            None,
        )
    else:
        code, status_code, retryable, fields = "AM_INTEGRITY", 500, False, None
    document: dict[str, object] = {
        "code": code,
        "retryable": retryable,
        "detail": "Ordered replay request was rejected",
    }
    if fields is not None:
        document["fields"] = fields
    return JSONResponse(document, status_code=status_code)


async def _parse_request(request: Request) -> OrderedReplayRequestModel:
    raw = await request.body()
    if not raw or len(raw) > _MAX_REQUEST_BYTES:
        raise IngestionValidationError.single(_FIELD_BODY, "invalid_size")
    try:
        return OrderedReplayRequestModel.model_validate_json(raw)
    except ValidationError as error:
        violations = tuple(
            FieldViolation(
                ".".join(str(part) for part in item["loc"]) or "$body",
                str(item["type"]),
            )
            for item in error.errors(include_url=False, include_context=False, include_input=False)
        )
        raise IngestionValidationError(violations) from None
