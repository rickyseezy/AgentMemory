"""Authenticated MEM-004 correction command and history HTTP adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Protocol

from fastapi import APIRouter, Query, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.memory.application.correct_memory import CorrectMemoryCommand
from agentmemory.memory.application.query_memory_corrections import MemoryCorrectionHistoryQuery
from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
    MemoryConflictError,
    MemoryDependencyError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from agentmemory.memory.application.query_memory_corrections import MemoryCorrectionHistoryView
    from agentmemory.memory.domain.correction import (
        MemoryCorrectionAssertion,
        MemoryCorrectionResult,
    )
    from agentmemory.shared.clock import Clock

_UUID7_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_TIME_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
_REASON_PATTERN = r"^[a-z][a-z0-9._-]{0,127}$"
_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class CorrectionScopeModel(_StrictModel):
    """Exact project/repository/checkout correction boundary."""

    brain_id: str = Field(pattern=_UUID7_PATTERN)
    project_id: str = Field(pattern=_UUID7_PATTERN)
    repository_id: str = Field(pattern=_UUID7_PATTERN)
    checkout_id: str | None = Field(default=None, pattern=_UUID7_PATTERN)

    def to_domain(self) -> MemoryScope:
        """Create the validated domain scope."""
        return MemoryScope(
            self.brain_id,
            self.project_id,
            self.repository_id,
            self.checkout_id,
        )


class CorrectMemoryRequest(_StrictModel):
    """Strict transport coordinates for one explicit user correction."""

    operation_id: str = Field(pattern=_UUID7_PATTERN)
    actor_id: str = Field(pattern=_UUID7_PATTERN)
    grant_id: str = Field(pattern=_UUID7_PATTERN)
    brain_id: str = Field(pattern=_UUID7_PATTERN)
    correlation_id: str = Field(pattern=_UUID7_PATTERN)
    causation_id: str = Field(pattern=_UUID7_PATTERN)
    expected_version: int = Field(ge=1)
    statement: str = Field(min_length=1, max_length=8_192)
    scope: CorrectionScopeModel
    valid_from: str = Field(pattern=_TIME_PATTERN)
    valid_to: str | None = Field(default=None, pattern=_TIME_PATTERN)
    reason: str = Field(pattern=_REASON_PATTERN)
    evidence_ids: list[str] = Field(default_factory=list, max_length=64)
    requested_at: str = Field(pattern=_TIME_PATTERN)
    deadline: str = Field(pattern=_TIME_PATTERN)

    def to_domain(self, assertion_id: str) -> CorrectMemoryCommand:
        """Translate only after transport validation and authentication."""
        return CorrectMemoryCommand(
            self.operation_id,
            self.actor_id,
            self.grant_id,
            self.brain_id,
            self.correlation_id,
            self.causation_id,
            assertion_id,
            self.expected_version,
            self.statement,
            self.scope.to_domain(),
            _parse_time(self.valid_from),
            None if self.valid_to is None else _parse_time(self.valid_to),
            self.reason,
            tuple(self.evidence_ids),
            _parse_time(self.requested_at),
            _parse_time(self.deadline),
        )


class CorrectionReceiptResponse(_StrictModel):
    """Content-free authenticated correction receipt."""

    correction_id: str
    root_memory_id: str
    source_assertion_id: str
    relation: str
    source_status: str
    source_version: int
    policy_version: str
    result_sha256: str


class CorrectionAssertionResponse(_StrictModel):
    """One authorized correction assertion in immutable history order."""

    assertion_id: str
    root_memory_id: str
    source_assertion_id: str
    memory_class: str
    statement: str
    content_sha256: str
    scope: CorrectionScopeModel
    relation: str
    reason: str
    evidence_ids: tuple[str, ...]
    actor_id: str
    grant_id: str
    valid_from: str
    valid_to: str | None
    recorded_from: str
    recorded_to: str | None
    status: str
    aggregate_version: int


class RootAssertionResponse(_StrictModel):
    """Historical root assertion retained after correction."""

    assertion_id: str
    memory_class: str
    statement: str
    content_sha256: str
    scope: CorrectionScopeModel
    status: str
    valid_from: str
    valid_to: str | None
    recorded_from: str
    recorded_to: str | None
    aggregate_version: int


class SelectedAssertionResponse(_StrictModel):
    """Deterministic assertion effective at the requested scope and time."""

    assertion_id: str
    root_memory_id: str
    statement: str
    scope: CorrectionScopeModel
    relation: str | None
    policy_version: str


class CorrectionHistoryResponse(_StrictModel):
    """Complete authorized history plus the currently selected assertion."""

    root: RootAssertionResponse
    corrections: tuple[CorrectionAssertionResponse, ...]
    selected: SelectedAssertionResponse


class AuthenticatorPort(Protocol):
    """Authenticate the local caller before processing memory coordinates."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class CorrectMemoryPort(Protocol):
    """Execute the framework-independent correction command."""

    async def execute(self, command: CorrectMemoryCommand) -> MemoryCorrectionResult:
        """Return the request-bound correction receipt."""
        ...


class CorrectionHistoryPort(Protocol):
    """Execute the framework-independent correction history query."""

    async def execute(self, query: MemoryCorrectionHistoryQuery) -> MemoryCorrectionHistoryView:
        """Return authorized history and precedence selection."""
        ...


def create_memory_correction_router(  # noqa: C901 -- closed error mapping stays at transport boundary.
    authenticator: AuthenticatorPort,
    correction_handler: CorrectMemoryPort,
    history_handler: CorrectionHistoryPort,
    clock: Clock,
) -> APIRouter:
    """Create strict authorization-first MEM-004 HTTP transports."""
    router = APIRouter()

    @router.post(
        "/memories/{assertion_id}/corrections",
        operation_id="CorrectMemoryCommand",
        response_model=CorrectionReceiptResponse,
        status_code=201,
    )
    async def correct_memory(
        assertion_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        request: CorrectMemoryRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> CorrectionReceiptResponse | JSONResponse:
        """Append one explicit immutable correction without overwriting source history."""
        try:
            await authenticator.authenticate(authorization)
            result = await correction_handler.execute(request.to_domain(assertion_id))
        except MemoryEvidenceNotFoundError, MemoryAuthorizationError:
            return _problem("AM_NOT_FOUND", 404, "memory assertion is unavailable")
        except MemoryConflictError:
            return _problem("AM_CONFLICT", 409, "memory assertion changed; refresh and retry")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "memory correction request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory correction dependency is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "memory correction failed verification")
        return _receipt(result)

    @router.get(
        "/memories/{memory_id}/corrections",
        operation_id="GetMemoryCorrectionHistoryQuery",
        response_model=CorrectionHistoryResponse,
    )
    async def correction_history(  # noqa: PLR0913 -- authority and scope stay explicit.
        memory_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        brain_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        actor_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        grant_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        project_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        repository_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        valid_at: Annotated[str, Query(pattern=_TIME_PATTERN)],
        recorded_at: Annotated[str, Query(pattern=_TIME_PATTERN)],
        checkout_id: Annotated[str | None, Query(pattern=_UUID7_PATTERN)] = None,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)] = None,
    ) -> CorrectionHistoryResponse | JSONResponse:
        """Return immutable history and the assertion effective for this query scope."""
        try:
            await authenticator.authenticate(authorization)
            now = clock.now()
            result = await history_handler.execute(
                MemoryCorrectionHistoryQuery(
                    memory_id,
                    brain_id,
                    actor_id,
                    grant_id,
                    MemoryScope(brain_id, project_id, repository_id, checkout_id),
                    _parse_time(valid_at),
                    _parse_time(recorded_at),
                    now,
                )
            )
        except MemoryEvidenceNotFoundError, MemoryAuthorizationError:
            return _problem("AM_NOT_FOUND", 404, "memory correction history is unavailable")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "memory correction history request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory correction dependency is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem("AM_INTEGRITY_VIOLATION", 500, "memory history failed verification")
        return _history_response(result)

    registered_routes = (correct_memory, correction_history)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractCorrectionHandler:
    async def execute(self, command: CorrectMemoryCommand) -> MemoryCorrectionResult:
        del command
        message = "contract-only correction handler cannot execute"
        raise RuntimeError(message)


class _ContractHistoryHandler:
    async def execute(self, query: MemoryCorrectionHistoryQuery) -> MemoryCorrectionHistoryView:
        del query
        message = "contract-only correction history handler cannot execute"
        raise RuntimeError(message)


class _ContractClock:
    def now(self) -> datetime:
        message = "contract-only correction clock cannot read time"
        raise RuntimeError(message)


def create_contract_memory_correction_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_memory_correction_router(
        _ContractAuthenticator(),
        _ContractCorrectionHandler(),
        _ContractHistoryHandler(),
        _ContractClock(),
    )


def _receipt(result: MemoryCorrectionResult) -> CorrectionReceiptResponse:
    return CorrectionReceiptResponse(
        correction_id=result.correction_id,
        root_memory_id=result.root_memory_id,
        source_assertion_id=result.source_assertion_id,
        relation=result.relation.value,
        source_status=result.source_status.value,
        source_version=result.source_version,
        policy_version=result.policy_version,
        result_sha256=result.result_sha256,
    )


def _history_response(view: MemoryCorrectionHistoryView) -> CorrectionHistoryResponse:
    root = view.history.root
    selected = view.selected
    return CorrectionHistoryResponse(
        root=RootAssertionResponse(
            assertion_id=root.assertion_id,
            memory_class=root.memory_class.value,
            statement=root.statement,
            content_sha256=root.content_sha256,
            scope=_scope(root.scope),
            status=root.status.value,
            valid_from=_format_time(root.valid_from),
            valid_to=None if root.valid_to is None else _format_time(root.valid_to),
            recorded_from=_format_time(root.recorded_from),
            recorded_to=None if root.recorded_to is None else _format_time(root.recorded_to),
            aggregate_version=root.aggregate_version,
        ),
        corrections=tuple(_assertion(item) for item in view.history.corrections),
        selected=SelectedAssertionResponse(
            assertion_id=selected.assertion_id,
            root_memory_id=selected.root_memory_id,
            statement=selected.statement,
            scope=_scope(selected.scope),
            relation=None if selected.relation is None else selected.relation.value,
            policy_version=selected.policy_version,
        ),
    )


def _assertion(item: MemoryCorrectionAssertion) -> CorrectionAssertionResponse:
    return CorrectionAssertionResponse(
        assertion_id=item.assertion_id,
        root_memory_id=item.root_memory_id,
        source_assertion_id=item.source_assertion_id,
        memory_class=item.memory_class.value,
        statement=item.statement,
        content_sha256=item.content_sha256,
        scope=_scope(item.scope),
        relation=item.relation.value,
        reason=item.reason,
        evidence_ids=item.evidence_ids,
        actor_id=item.actor_id,
        grant_id=item.grant_id,
        valid_from=_format_time(item.valid_from),
        valid_to=None if item.valid_to is None else _format_time(item.valid_to),
        recorded_from=_format_time(item.recorded_from),
        recorded_to=None if item.recorded_to is None else _format_time(item.recorded_to),
        status=item.status.value,
        aggregate_version=item.aggregate_version,
    )


def _scope(scope: MemoryScope) -> CorrectionScopeModel:
    return CorrectionScopeModel(
        brain_id=scope.brain_id,
        project_id=scope.project_id,
        repository_id=scope.repository_id,
        checkout_id=scope.checkout_id,
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


def _problem(code: str, status: int, detail: str, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        {"code": code, "detail": detail, "retryable": retryable},
        status_code=status,
    )
