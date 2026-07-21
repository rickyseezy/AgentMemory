"""Authenticated MEM-005 memory lifecycle HTTP command adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Protocol

from fastapi import APIRouter, Body, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.memory.application.memory_lifecycle import (
    ArchiveMemoryCommand,
    ForgetMemoryCommand,
    PinMemoryCommand,
    SetMemoryExpiryCommand,
)
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
    MemoryConflictError,
    MemoryDependencyError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from agentmemory.memory.domain.lifecycle import MemoryLifecycleResult

_UUID7_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_TIME_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class MemoryLifecycleRequest(_StrictModel):
    """Strict shared authority and concurrency coordinates."""

    operation_id: str = Field(pattern=_UUID7_PATTERN)
    actor_id: str = Field(pattern=_UUID7_PATTERN)
    grant_id: str = Field(pattern=_UUID7_PATTERN)
    brain_id: str = Field(pattern=_UUID7_PATTERN)
    correlation_id: str = Field(pattern=_UUID7_PATTERN)
    causation_id: str = Field(pattern=_UUID7_PATTERN)
    expected_version: int = Field(ge=1)
    requested_at: str = Field(pattern=_TIME_PATTERN)
    deadline: str = Field(pattern=_TIME_PATTERN)

    def coordinates(
        self,
        memory_id: str,
    ) -> tuple[str, str, str, str, str, str, str, int, datetime, datetime]:
        """Translate exact common fields only after authentication."""
        return (
            self.operation_id,
            self.actor_id,
            self.grant_id,
            self.brain_id,
            self.correlation_id,
            self.causation_id,
            memory_id,
            self.expected_version,
            _parse_time(self.requested_at),
            _parse_time(self.deadline),
        )


class SetMemoryExpiryRequest(MemoryLifecycleRequest):
    """Strict future expiry boundary request."""

    expires_at: str = Field(pattern=_TIME_PATTERN)


class ForgetMemoryRequest(MemoryLifecycleRequest):
    """Strict destructive confirmation request."""

    confirmation: str = Field(pattern=r"^forget-memory$")


class MemoryLifecycleReceiptResponse(_StrictModel):
    """Content-free authenticated lifecycle receipt."""

    operation_id: str
    memory_id: str
    action: str
    recall_state: str
    pinned: bool
    expires_at: str | None
    version: int
    policy_version: str
    result_sha256: str


class AuthenticatorPort(Protocol):
    """Authenticate local capability credentials before domain translation."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class PinMemoryPort(Protocol):
    """Application boundary for pin commands."""

    async def execute(self, command: PinMemoryCommand) -> MemoryLifecycleResult:
        """Execute a pin transition."""
        ...


class ArchiveMemoryPort(Protocol):
    """Application boundary for archive commands."""

    async def execute(self, command: ArchiveMemoryCommand) -> MemoryLifecycleResult:
        """Execute an archive transition."""
        ...


class SetMemoryExpiryPort(Protocol):
    """Application boundary for expiry commands."""

    async def execute(self, command: SetMemoryExpiryCommand) -> MemoryLifecycleResult:
        """Execute an expiry-boundary transition."""
        ...


class ForgetMemoryPort(Protocol):
    """Application boundary for forget commands."""

    async def execute(self, command: ForgetMemoryCommand) -> MemoryLifecycleResult:
        """Execute a forget transition and deletion handoff."""
        ...


def create_memory_lifecycle_router(  # noqa: C901 -- closed transport error map.
    authenticator: AuthenticatorPort,
    pin_handler: PinMemoryPort,
    archive_handler: ArchiveMemoryPort,
    expiry_handler: SetMemoryExpiryPort,
    forget_handler: ForgetMemoryPort,
) -> APIRouter:
    """Create the four separate authorization-first MEM-005 command routes."""
    router = APIRouter()

    @router.post(
        "/memories/{memory_id}:pin",
        operation_id="PinMemoryCommand",
        response_model=MemoryLifecycleReceiptResponse,
    )
    async def pin_memory(
        memory_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        request: MemoryLifecycleRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> MemoryLifecycleReceiptResponse | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            result = await pin_handler.execute(PinMemoryCommand(*request.coordinates(memory_id)))
        except _NOT_FOUND_ERRORS:
            return _problem("AM_NOT_FOUND", 404, "memory is unavailable")
        except MemoryConflictError:
            return _problem("AM_CONFLICT", 409, "memory lifecycle changed; refresh and retry")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "pin request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory store is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "pin receipt failed verification")
        return _receipt(result)

    @router.post(
        "/memories/{memory_id}:archive",
        operation_id="ArchiveMemoryCommand",
        response_model=MemoryLifecycleReceiptResponse,
    )
    async def archive_memory(
        memory_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        request: MemoryLifecycleRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> MemoryLifecycleReceiptResponse | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            result = await archive_handler.execute(
                ArchiveMemoryCommand(*request.coordinates(memory_id))
            )
        except _NOT_FOUND_ERRORS:
            return _problem("AM_NOT_FOUND", 404, "memory is unavailable")
        except MemoryConflictError:
            return _problem("AM_CONFLICT", 409, "memory lifecycle changed; refresh and retry")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "archive request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory store is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "archive receipt failed verification")
        return _receipt(result)

    @router.post(
        "/memories/{memory_id}:expiry",
        operation_id="SetMemoryExpiryCommand",
        response_model=MemoryLifecycleReceiptResponse,
    )
    async def set_memory_expiry(
        memory_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        request: SetMemoryExpiryRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> MemoryLifecycleReceiptResponse | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            result = await expiry_handler.execute(
                SetMemoryExpiryCommand(
                    *request.coordinates(memory_id),
                    expires_at=_parse_time(request.expires_at),
                )
            )
        except _NOT_FOUND_ERRORS:
            return _problem("AM_NOT_FOUND", 404, "memory is unavailable")
        except MemoryConflictError:
            return _problem("AM_CONFLICT", 409, "memory lifecycle changed; refresh and retry")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "expiry request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory store is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "expiry receipt failed verification")
        return _receipt(result)

    @router.delete(
        "/memories/{memory_id}",
        operation_id="ForgetMemoryCommand",
        response_model=MemoryLifecycleReceiptResponse,
    )
    async def forget_memory(
        memory_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        request: Annotated[ForgetMemoryRequest, Body()],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> MemoryLifecycleReceiptResponse | JSONResponse:
        try:
            await authenticator.authenticate(authorization)
            result = await forget_handler.execute(
                ForgetMemoryCommand(
                    *request.coordinates(memory_id),
                    confirmation=request.confirmation,
                )
            )
        except _NOT_FOUND_ERRORS:
            return _problem("AM_NOT_FOUND", 404, "memory is unavailable")
        except MemoryConflictError:
            return _problem("AM_CONFLICT", 409, "memory lifecycle changed; refresh and retry")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "forget request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory store is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "forget receipt failed verification")
        return _receipt(result)

    registered_routes = (pin_memory, archive_memory, set_memory_expiry, forget_memory)
    del registered_routes
    return router


_NOT_FOUND_ERRORS = (MemoryEvidenceNotFoundError, MemoryAuthorizationError)


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractHandlers:
    async def execute(self, command: object) -> MemoryLifecycleResult:
        del command
        message = "contract-only lifecycle handler cannot execute"
        raise RuntimeError(message)


def create_contract_memory_lifecycle_router() -> APIRouter:
    """Return a side-effect-free lifecycle router for deterministic OpenAPI export."""
    handlers = _ContractHandlers()
    return create_memory_lifecycle_router(
        _ContractAuthenticator(),
        handlers,
        handlers,
        handlers,
        handlers,
    )


def _receipt(result: MemoryLifecycleResult) -> MemoryLifecycleReceiptResponse:
    return MemoryLifecycleReceiptResponse(
        operation_id=result.operation_id,
        memory_id=result.memory_id,
        action=result.action.value,
        recall_state=result.recall_state.value,
        pinned=result.pinned,
        expires_at=None if result.expires_at is None else _format_time(result.expires_at),
        version=result.version,
        policy_version=result.policy_version,
        result_sha256=result.result_sha256,
    )


def _parse_time(value: str) -> datetime:
    field = "time"
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid") from error
    if _format_time(parsed) != value:
        raise MemoryValidationError.single(field, "non_canonical")
    return parsed


def _format_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise MemoryIntegrityError
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _problem(
    code: str,
    status: int,
    detail: str,
    *,
    retryable: bool = False,
) -> JSONResponse:
    return JSONResponse(
        {"code": code, "detail": detail, "retryable": retryable},
        status_code=status,
    )
