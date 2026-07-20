"""Authenticated content-free ING-004 scheduler and dead-letter HTTP boundary."""

from __future__ import annotations

from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, Header, Query, Request, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentmemory.ingestion.domain.backpressure import (
    DeadLetter,
    ReplayDeadLetterRequest,
    ScheduledJob,
)
from agentmemory.ingestion.domain.errors import (
    FieldViolation,
    IngestionAuthorizationError,
    IngestionCapacityError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_UUID7_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^(?:artifact|cas|local-object)://[^?#]{1,480}$"
_MAX_REQUEST_BYTES = 32 * 1024
_FIELD_IDEMPOTENCY = "Idempotency-Key"
_FIELD_BODY = "$body"
_ERR_CONTRACT_QUERY = "contract-only query cannot execute"
_ERR_CONTRACT_COMMAND = "contract-only command cannot execute"


class Authenticator(Protocol):
    """Authenticate the installation-local API capability."""

    async def authenticate(self, authorization: str | None) -> None:
        """Raise unless the bearer capability remains active."""
        ...


class JobQueryHandler(Protocol):
    """Content-free authorized scheduler query boundary."""

    async def execute(self, job_id: str) -> ScheduledJob:
        """Return one currently authorized scheduler job."""
        ...


class DeadLetterListHandler(Protocol):
    """Authorized bounded dead-letter query boundary."""

    async def execute(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        *,
        maximum: int = 100,
    ) -> tuple[DeadLetter, ...]:
        """Return only safe immutable failure evidence."""
        ...


class DeadLetterReplayHandler(Protocol):
    """Authorized immutable replay command boundary."""

    async def execute(self, request: ReplayDeadLetterRequest) -> ScheduledJob:
        """Return the exact prior replay or a newly linked corrected job."""
        ...


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ReplayDeadLetterModel(_StrictModel):
    """Strict corrected content-addressed replay request."""

    operation_id: str = Field(pattern=_UUID7_PATTERN)
    new_job_id: str = Field(pattern=_UUID7_PATTERN)
    actor_id: str = Field(pattern=_UUID7_PATTERN)
    grant_id: str = Field(pattern=_UUID7_PATTERN)
    corrected_request_sha256: str = Field(pattern=_DIGEST_PATTERN)
    corrected_input_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)

    def to_domain(self, dead_letter_id: str) -> ReplayDeadLetterRequest:
        """Translate strict transport data into domain-validated input."""
        return ReplayDeadLetterRequest(
            self.operation_id,
            dead_letter_id,
            self.new_job_id,
            self.actor_id,
            self.grant_id,
            self.corrected_request_sha256,
            self.corrected_input_ref,
        )


class ScheduledJobResponse(_StrictModel):
    """Content-free scheduler lifecycle and immutable lineage."""

    job_id: str
    brain_id: str
    kind: str
    request_sha256: str
    priority: Literal["interactive", "capture", "standard", "background"]
    state: Literal["queued", "leased", "retry_scheduled", "succeeded", "dead_lettered"]
    attempts: int
    next_attempt_at_microseconds: int
    lease_until_microseconds: int | None
    last_error_code: str | None
    result_sha256: str | None
    completed_at_microseconds: int | None
    parent_job_id: str | None
    source_dead_letter_id: str | None
    created_at_microseconds: int
    updated_at_microseconds: int


class DeadLetterResponse(_StrictModel):
    """Safe immutable failure evidence without input or exception text."""

    dead_letter_id: str
    original_job_id: str
    brain_id: str
    priority: Literal["interactive", "capture", "standard", "background"]
    kind: str
    request_sha256: str
    attempts: int
    error_code: str
    diagnostic_code: str
    failed_at_microseconds: int
    created_at_microseconds: int


class DeadLetterListResponse(_StrictModel):
    """Bounded deterministic dead-letter collection."""

    items: tuple[DeadLetterResponse, ...]


def create_backpressure_router(
    authenticator: Authenticator,
    get_job: JobQueryHandler,
    list_dead_letters: DeadLetterListHandler,
    replay_dead_letter: DeadLetterReplayHandler,
) -> APIRouter:
    """Create strict authenticated scheduler visibility and replay routes."""
    router = APIRouter()

    @router.get("/v1/scheduler/jobs/{job_id}", response_model=ScheduledJobResponse)
    async def get_scheduled_job(
        job_id: str,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ScheduledJobResponse | JSONResponse:
        """Authenticate and reauthorize before exposing content-free job state."""
        try:
            await authenticator.authenticate(authorization)
            result = await get_job.execute(job_id)
        except _BOUNDARY_ERRORS as error:
            return _problem(error)
        return _job_response(result)

    @router.get("/v1/dead-letters", response_model=DeadLetterListResponse)
    async def get_dead_letters(
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        actor_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        grant_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        brain_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        maximum: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> DeadLetterListResponse | JSONResponse:
        """Return a bounded newest-first list after current scope authorization."""
        try:
            await authenticator.authenticate(authorization)
            result = await list_dead_letters.execute(
                actor_id,
                grant_id,
                brain_id,
                maximum=maximum,
            )
        except _BOUNDARY_ERRORS as error:
            return _problem(error)
        return DeadLetterListResponse(items=tuple(_dead_response(item) for item in result))

    @router.post(
        "/v1/dead-letters/{dead_letter_id}:replay",
        response_model=ScheduledJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": ReplayDeadLetterModel.model_json_schema()}
                },
            }
        },
    )
    async def replay_failed_job(
        dead_letter_id: str,
        request: Request,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ScheduledJobResponse | JSONResponse:
        """Authenticate, bind idempotency, authorize, and create a linked new attempt."""
        try:
            await authenticator.authenticate(authorization)
            body = await _parse_request(request)
            if idempotency_key != body.operation_id:
                raise IngestionValidationError.single(_FIELD_IDEMPOTENCY, "mismatch")
            result = await replay_dead_letter.execute(body.to_domain(dead_letter_id))
        except _BOUNDARY_ERRORS as error:
            return _problem(error)
        return _job_response(result)

    registered_routes = (get_scheduled_job, get_dead_letters, replay_failed_job)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractGetJob:
    async def execute(self, job_id: str) -> ScheduledJob:
        del job_id
        raise RuntimeError(_ERR_CONTRACT_QUERY)


class _ContractListDeadLetters:
    async def execute(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        *,
        maximum: int = 100,
    ) -> tuple[DeadLetter, ...]:
        del actor_id, grant_id, brain_id, maximum
        raise RuntimeError(_ERR_CONTRACT_QUERY)


class _ContractReplayDeadLetter:
    async def execute(self, request: ReplayDeadLetterRequest) -> ScheduledJob:
        del request
        raise RuntimeError(_ERR_CONTRACT_COMMAND)


def create_contract_backpressure_router() -> APIRouter:
    """Return side-effect-free routes for deterministic OpenAPI export."""
    return create_backpressure_router(
        _ContractAuthenticator(),
        _ContractGetJob(),
        _ContractListDeadLetters(),
        _ContractReplayDeadLetter(),
    )


_BOUNDARY_ERRORS = (
    IngestionValidationError,
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionCapacityError,
    IngestionDependencyError,
    IngestionIntegrityError,
)


def _job_response(job: ScheduledJob) -> ScheduledJobResponse:
    return ScheduledJobResponse(
        job_id=job.request.job_id,
        brain_id=job.request.brain_id,
        kind=job.request.kind,
        request_sha256=job.request.request_sha256,
        priority=job.request.priority.value,
        state=job.state.value,
        attempts=job.attempts,
        next_attempt_at_microseconds=job.next_attempt_at_microseconds,
        lease_until_microseconds=job.lease_until_microseconds,
        last_error_code=None if job.last_error_code is None else job.last_error_code.value,
        result_sha256=job.result_sha256,
        completed_at_microseconds=job.completed_at_microseconds,
        parent_job_id=job.parent_job_id,
        source_dead_letter_id=job.source_dead_letter_id,
        created_at_microseconds=job.created_at_microseconds,
        updated_at_microseconds=job.updated_at_microseconds,
    )


def _dead_response(dead: DeadLetter) -> DeadLetterResponse:
    return DeadLetterResponse(
        dead_letter_id=dead.dead_letter_id,
        original_job_id=dead.original_job_id,
        brain_id=dead.brain_id,
        priority=dead.priority.value,
        kind=dead.kind,
        request_sha256=dead.request_sha256,
        attempts=dead.attempts,
        error_code=dead.error_code.value,
        diagnostic_code=dead.diagnostic_code,
        failed_at_microseconds=dead.failed_at_microseconds,
        created_at_microseconds=dead.created_at_microseconds,
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
    elif isinstance(error, IngestionCapacityError):
        code, status_code, retryable, fields = "AM_CAPACITY_EXHAUSTED", 507, True, None
    elif isinstance(error, IngestionDependencyError):
        code, status_code, retryable, fields = "AM_DEPENDENCY_UNAVAILABLE", 503, True, None
    else:
        code, status_code, retryable, fields = "AM_INTEGRITY", 500, False, None
    document: dict[str, object] = {
        "code": code,
        "retryable": retryable,
        "detail": "Scheduler request was rejected",
    }
    if fields is not None:
        document["fields"] = fields
    return JSONResponse(document, status_code=status_code)


async def _parse_request(request: Request) -> ReplayDeadLetterModel:
    raw = await request.body()
    if not raw or len(raw) > _MAX_REQUEST_BYTES:
        raise IngestionValidationError.single(_FIELD_BODY, "invalid_size")
    try:
        return ReplayDeadLetterModel.model_validate_json(raw)
    except ValidationError as error:
        violations = tuple(
            FieldViolation(
                ".".join(str(part) for part in item["loc"]) or "$body",
                str(item["type"]),
            )
            for item in error.errors(include_url=False, include_context=False, include_input=False)
        )
        raise IngestionValidationError(violations) from None
