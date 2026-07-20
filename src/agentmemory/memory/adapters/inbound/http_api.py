"""Authenticated MEM-002 memory explanation HTTP adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Literal, Protocol

from fastapi import APIRouter, Query, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.memory.application.explain_memory import ExplainMemoryQuery
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
    MemoryDependencyError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from agentmemory.memory.domain.explanation import MemoryExplanation
    from agentmemory.shared.clock import Clock

_UUID7_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_TIME_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, populate_by_name=True)


class MemoryScopeResponse(_StrictModel):
    """Exact hierarchical authority carried by one memory."""

    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None


class TimeRangeResponse(_StrictModel):
    """Half-open UTC microsecond time range."""

    from_: str = Field(serialization_alias="from")
    to: str | None


class ConfidenceResponse(_StrictModel):
    """Deterministic integer basis-point confidence dimensions."""

    evidence_support: int
    source_reliability: int
    extraction_quality: int


class ExtractorResponse(_StrictModel):
    """Immutable extractor and model identity."""

    extractor_id: str
    extractor_version: str
    model_id: str
    model_revision: str
    output_schema: str
    fingerprint: str


class MemoryProvenanceResponse(_StrictModel):
    """Complete immutable provenance safe for an authorized caller."""

    actor_id: str
    agent_id: str
    source_task_id: str
    created_by_event: str
    extractor: ExtractorResponse
    evidence_watermark_sha256: str
    extractor_input_sha256: str
    content_sha256: str
    promotion_policy_version: str
    provenance_sha256: str


class EvidenceResponse(_StrictModel):
    """Hash-bound evidence resolution without unavailable source disclosure."""

    event_id: str
    canonical_event_sha256: str
    availability: Literal["available", "purged", "missing"]
    event_type: str | None
    occurred_at: str | None
    resource_uri: str | None


class ExplainMemoryResponse(_StrictModel):
    """Canonical authorized memory explanation response."""

    memory_id: str
    memory_class: str
    scope: MemoryScopeResponse
    status: str
    statement: str
    content_sha256: str
    confidence: ConfidenceResponse
    valid_time: TimeRangeResponse
    recorded_time: TimeRangeResponse
    provenance: MemoryProvenanceResponse
    classification: str
    retention_policy_id: str
    aggregate_version: int
    evidence: tuple[EvidenceResponse, ...]
    evaluated_valid_at: str
    evaluated_recorded_at: str
    effective: bool


class AuthenticatorPort(Protocol):
    """Authenticate the local caller before any memory coordinate is processed."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject absent, malformed, expired, or revoked credentials."""
        ...


class ExplainMemoryPort(Protocol):
    """Execute the framework-independent memory explanation use case."""

    async def execute(self, query: ExplainMemoryQuery) -> MemoryExplanation:
        """Return one complete authorized explanation."""
        ...


def create_memory_router(
    authenticator: AuthenticatorPort,
    handler: ExplainMemoryPort,
    clock: Clock,
) -> APIRouter:
    """Create the strict authorization-first memory explanation transport."""
    router = APIRouter()

    @router.get(
        "/memories/{memory_id}",
        operation_id="ExplainMemoryQuery",
        response_model=ExplainMemoryResponse,
        response_model_by_alias=True,
    )
    async def explain_memory(  # noqa: PLR0913 -- HTTP contract exposes explicit query fields.
        memory_id: Annotated[str, Field(pattern=_UUID7_PATTERN)],
        brain_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        actor_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        grant_id: Annotated[str, Query(pattern=_UUID7_PATTERN)],
        valid_at: Annotated[str, Query(pattern=_TIME_PATTERN)],
        recorded_at: Annotated[str, Query(pattern=_TIME_PATTERN)],
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ExplainMemoryResponse | JSONResponse:
        """Expose complete metadata and only evidence authorized by the exact grant."""
        try:
            await authenticator.authenticate(authorization)
            requested_at = clock.now()
            explanation = await handler.execute(
                ExplainMemoryQuery(
                    memory_id,
                    brain_id,
                    actor_id,
                    grant_id,
                    _parse_time(valid_at),
                    _parse_time(recorded_at),
                    requested_at,
                )
            )
        except MemoryEvidenceNotFoundError, MemoryAuthorizationError:
            return _problem("AM_NOT_FOUND", 404, "memory is unavailable")
        except MemoryValidationError:
            return _problem("AM_VALIDATION", 422, "memory explanation request is invalid")
        except MemoryDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "memory explanation dependency is unavailable",
                retryable=True,
            )
        except MemoryIntegrityError:
            return _problem(
                "AM_INTEGRITY_VIOLATION",
                500,
                "memory provenance failed verification",
            )
        return _response(explanation)

    registered_routes = (explain_memory,)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractHandler:
    async def execute(self, query: ExplainMemoryQuery) -> MemoryExplanation:
        del query
        msg = "contract-only memory handler cannot execute"
        raise RuntimeError(msg)


class _ContractClock:
    def now(self) -> datetime:
        msg = "contract-only memory clock cannot read time"
        raise RuntimeError(msg)


def create_contract_memory_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_memory_router(
        _ContractAuthenticator(),
        _ContractHandler(),
        _ContractClock(),
    )


def _response(explanation: MemoryExplanation) -> ExplainMemoryResponse:
    memory = explanation.memory
    provenance = memory.provenance
    extractor = provenance.extractor
    return ExplainMemoryResponse(
        memory_id=memory.memory_id,
        memory_class=memory.memory_class.value,
        scope=MemoryScopeResponse(
            brain_id=memory.scope.brain_id,
            project_id=memory.scope.project_id,
            repository_id=memory.scope.repository_id,
            checkout_id=memory.scope.checkout_id,
        ),
        status=memory.status.value,
        statement=memory.statement,
        content_sha256=memory.content_sha256,
        confidence=ConfidenceResponse(
            evidence_support=memory.confidence.evidence_support,
            source_reliability=memory.confidence.source_reliability,
            extraction_quality=memory.confidence.extraction_quality,
        ),
        valid_time=TimeRangeResponse(
            from_=_format_time(memory.valid_from),
            to=None if memory.valid_to is None else _format_time(memory.valid_to),
        ),
        recorded_time=TimeRangeResponse(
            from_=_format_time(memory.recorded_from),
            to=None if memory.recorded_to is None else _format_time(memory.recorded_to),
        ),
        provenance=MemoryProvenanceResponse(
            actor_id=provenance.actor_id,
            agent_id=provenance.agent_id,
            source_task_id=provenance.source_task_id,
            created_by_event=provenance.created_by_event,
            extractor=ExtractorResponse(
                extractor_id=extractor.extractor_id,
                extractor_version=extractor.extractor_version,
                model_id=extractor.model_id,
                model_revision=extractor.model_revision,
                output_schema=extractor.output_schema,
                fingerprint=extractor.fingerprint,
            ),
            evidence_watermark_sha256=provenance.evidence_watermark_sha256,
            extractor_input_sha256=provenance.extractor_input_sha256,
            content_sha256=provenance.content_sha256,
            promotion_policy_version=provenance.promotion_policy_version,
            provenance_sha256=provenance.provenance_sha256,
        ),
        classification=memory.classification,
        retention_policy_id=memory.retention_policy_id,
        aggregate_version=memory.aggregate_version,
        evidence=tuple(
            EvidenceResponse(
                event_id=item.event_id,
                canonical_event_sha256=item.canonical_event_sha256,
                availability=item.availability.value,
                event_type=item.event_type,
                occurred_at=None if item.occurred_at is None else _format_time(item.occurred_at),
                resource_uri=item.resource_uri,
            )
            for item in explanation.evidence
        ),
        evaluated_valid_at=_format_time(explanation.valid_at),
        evaluated_recorded_at=_format_time(explanation.recorded_at),
        effective=explanation.effective,
    )


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        field = "time"
        raise MemoryValidationError.single(field, "invalid") from error
    if _format_time(parsed) != value:
        field = "time"
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
