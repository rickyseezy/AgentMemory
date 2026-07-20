"""Authenticated adapter capability registration and operator display API."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Annotated, Literal, Protocol

from fastapi import APIRouter, Header, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.ingestion.application.adapter_capabilities import (
    CapabilityMatrixView,
    GetAdapterCapabilitiesQuery,
    ListAdapterCapabilitiesQuery,
    ObserveAdapterCapabilitiesCommand,
    RegisterAgentAdapterCommand,
)
from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    EvidenceAvailability,
)
from agentmemory.ingestion.domain.agent_event import (
    CaptureCapability,
    CaptureMethod,
    EventFamily,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionValidationError,
)

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.adapter_capability import CapabilityChangeResult

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CAPABILITY_STATUS = Literal[
    "native",
    "inferred",
    "explicit_tool_only",
    "unsupported",
    "permission_denied",
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class EvidenceAvailabilityModel(_StrictModel):
    """One explicit lifecycle signal and its observation status."""

    capability: str
    status: _CAPABILITY_STATUS

    def to_domain(self) -> EvidenceAvailability:
        """Convert only closed capability/status values to domain evidence."""
        return EvidenceAvailability(
            _capability(self.capability),
            CaptureMethod(self.status),
        )


class AdapterCapabilityManifestModel(_StrictModel):
    """Complete immutable per-version adapter declaration."""

    adapter_id: str
    adapter_version: str
    adapter_digest: str
    schema_major: Literal[1]
    supported_families: list[str]
    evidence_availability: list[EvidenceAvailabilityModel]

    def to_domain(self) -> AdapterCapabilityManifest:
        """Canonicalize the untrusted transport declaration in the domain."""
        return AdapterCapabilityManifest.create(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            adapter_digest=self.adapter_digest,
            schema_major=self.schema_major,
            supported_families=tuple(_family(item) for item in self.supported_families),
            evidence_availability=tuple(
                item.to_domain() for item in self.evidence_availability
            ),
        )


class RegisterAgentAdapterRequest(_StrictModel):
    """Idempotent immutable adapter registration command."""

    operation_id: str = Field(min_length=1, max_length=128)
    manifest: AdapterCapabilityManifestModel
    permission_denied: list[str] = Field(default_factory=list)

    def to_command(self) -> RegisterAgentAdapterCommand:
        """Create the framework-independent registration command."""
        return RegisterAgentAdapterCommand(
            self.operation_id,
            self.manifest.to_domain(),
            tuple(_capability(item) for item in self.permission_denied),
        )


class ObserveAdapterCapabilitiesRequest(_StrictModel):
    """Idempotent complete effective capability observation command."""

    operation_id: str = Field(min_length=1, max_length=128)
    adapter_digest: str
    capability_manifest_digest: str
    evidence_availability: list[EvidenceAvailabilityModel]

    def to_command(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> ObserveAdapterCapabilitiesCommand:
        """Bind route identity and complete matrix into one command."""
        return ObserveAdapterCapabilitiesCommand(
            self.operation_id,
            adapter_id,
            adapter_version,
            self.adapter_digest,
            self.capability_manifest_digest,
            tuple(item.to_domain() for item in self.evidence_availability),
        )


class CompatibilityWarningResponse(_StrictModel):
    """Content-free compatibility impact for one changed signal."""

    capability: str
    previous_status: _CAPABILITY_STATUS
    current_status: _CAPABILITY_STATUS
    impact: Literal["informational", "degraded", "breaking"]
    code: str


class CapabilityMatrixResponse(_StrictModel):
    """Complete operator-visible declaration and latest effective evidence."""

    adapter_id: str
    adapter_version: str
    adapter_digest: str
    capability_manifest_digest: str
    schema_major: int
    supported_families: tuple[str, ...]
    revision: int
    observed_at: str
    evidence_availability: tuple[EvidenceAvailabilityModel, ...]
    warnings: tuple[CompatibilityWarningResponse, ...]


class CapabilityChangeResponse(_StrictModel):
    """Command outcome and resulting operator-visible matrix."""

    disposition: Literal["registered", "observed", "unchanged", "duplicate"]
    capability_matrix: CapabilityMatrixResponse


class RegisterHandler(Protocol):
    """Execute an adapter registration command."""

    async def execute(self, command: RegisterAgentAdapterCommand) -> CapabilityChangeResult:
        """Return the durably committed change."""
        ...


class ObserveHandler(Protocol):
    """Execute an effective status observation command."""

    async def execute(
        self,
        command: ObserveAdapterCapabilitiesCommand,
    ) -> CapabilityChangeResult:
        """Return the durably committed observation."""
        ...


class ListHandler(Protocol):
    """Query active operator-visible matrices."""

    async def execute(
        self,
        query: ListAdapterCapabilitiesQuery,
    ) -> tuple[CapabilityMatrixView, ...]:
        """Return deterministic active views."""
        ...


class GetHandler(Protocol):
    """Query one exact operator-visible matrix."""

    async def execute(
        self,
        query: GetAdapterCapabilitiesQuery,
    ) -> CapabilityMatrixView | None:
        """Return one view or None."""
        ...


class Authenticator(Protocol):
    """Authenticate a local installation/session capability."""

    async def authenticate(self, authorization: str | None) -> None:
        """Raise unless the exact bearer capability is active."""
        ...


def create_adapter_capability_router(  # noqa: C901 -- explicit routes retain local error contracts.
    authenticator: Authenticator,
    register: RegisterHandler,
    observe: ObserveHandler,
    list_handler: ListHandler,
    get_handler: GetHandler,
) -> APIRouter:
    """Create strict command/query routes for capability management and display."""
    router = APIRouter()

    @router.post(
        "/v1/agent-adapters:register",
        response_model=CapabilityChangeResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def register_agent_adapter(
        request: RegisterAgentAdapterRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Authenticate and register one immutable adapter version."""
        try:
            await authenticator.authenticate(authorization)
            _validate_idempotency(idempotency_key, request.operation_id)
            result = await register.execute(request.to_command())
        except IngestionValidationError as error:
            return _validation_problem(error)
        except IngestionAuthorizationError:
            return _problem("AM_FORBIDDEN", 403)
        except IngestionConflictError:
            return _problem("AM_CONFLICT", 409)
        except IngestionDependencyError:
            return _problem("AM_DEPENDENCY_UNAVAILABLE", 503, retryable=True)
        response_status = (
            status.HTTP_201_CREATED
            if result.disposition.value == "registered"
            else status.HTTP_200_OK
        )
        return JSONResponse(_change_document(result), status_code=response_status)

    @router.post(
        "/v1/agent-adapters/{adapter_id}/versions/{adapter_version}:observe",
        response_model=CapabilityChangeResponse,
    )
    async def observe_adapter_capabilities(
        adapter_id: str,
        adapter_version: str,
        request: ObserveAdapterCapabilitiesRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Authenticate and append current permission/capability evidence."""
        try:
            await authenticator.authenticate(authorization)
            _validate_idempotency(idempotency_key, request.operation_id)
            result = await observe.execute(
                request.to_command(adapter_id, adapter_version)
            )
        except IngestionValidationError as error:
            return _validation_problem(error)
        except IngestionAuthorizationError:
            return _problem("AM_FORBIDDEN", 403)
        except IngestionConflictError:
            return _problem("AM_CONFLICT", 409)
        except IngestionDependencyError:
            return _problem("AM_DEPENDENCY_UNAVAILABLE", 503, retryable=True)
        return JSONResponse(_change_document(result), status_code=status.HTTP_200_OK)

    @router.get(
        "/v1/agent-adapters/capabilities",
        response_model=tuple[CapabilityMatrixResponse, ...],
    )
    async def list_adapter_capabilities(
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        warning_limit: int = 20,
    ) -> JSONResponse:
        """Authenticate and display every active adapter capability matrix."""
        try:
            await authenticator.authenticate(authorization)
            views = await list_handler.execute(
                ListAdapterCapabilitiesQuery(warning_limit)
            )
        except IngestionValidationError as error:
            return _validation_problem(error)
        except IngestionAuthorizationError:
            return _problem("AM_FORBIDDEN", 403)
        except IngestionDependencyError:
            return _problem("AM_DEPENDENCY_UNAVAILABLE", 503, retryable=True)
        return JSONResponse([_matrix_document(view) for view in views])

    @router.get(
        "/v1/agent-adapters/{adapter_id}/versions/{adapter_version}/capabilities",
        response_model=CapabilityMatrixResponse,
    )
    async def get_adapter_capabilities(
        adapter_id: str,
        adapter_version: str,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        warning_limit: int = 20,
    ) -> JSONResponse:
        """Authenticate and display one exact registered adapter version."""
        try:
            await authenticator.authenticate(authorization)
            view = await get_handler.execute(
                GetAdapterCapabilitiesQuery(
                    adapter_id,
                    adapter_version,
                    warning_limit,
                )
            )
        except IngestionValidationError as error:
            return _validation_problem(error)
        except IngestionAuthorizationError:
            return _problem("AM_FORBIDDEN", 403)
        except IngestionDependencyError:
            return _problem("AM_DEPENDENCY_UNAVAILABLE", 503, retryable=True)
        if view is None:
            return _problem("AM_NOT_FOUND", 404)
        return JSONResponse(_matrix_document(view))

    registered_routes = (
        register_agent_adapter,
        observe_adapter_capabilities,
        list_adapter_capabilities,
        get_adapter_capabilities,
    )
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractCommandHandler:
    async def execute(
        self,
        command: RegisterAgentAdapterCommand | ObserveAdapterCapabilitiesCommand,
    ) -> CapabilityChangeResult:
        del command
        message = "contract-only handler cannot mutate"
        raise RuntimeError(message)


class _ContractListHandler:
    async def execute(
        self,
        query: ListAdapterCapabilitiesQuery,
    ) -> tuple[CapabilityMatrixView, ...]:
        del query
        return ()


class _ContractGetHandler:
    async def execute(
        self,
        query: GetAdapterCapabilitiesQuery,
    ) -> CapabilityMatrixView | None:
        del query
        return None


def create_contract_adapter_capability_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI export."""
    return create_adapter_capability_router(
        _ContractAuthenticator(),
        _ContractCommandHandler(),
        _ContractCommandHandler(),
        _ContractListHandler(),
        _ContractGetHandler(),
    )


def _validate_idempotency(value: str | None, operation_id: str) -> None:
    if value != operation_id or _IDEMPOTENCY_PATTERN.fullmatch(value or "") is None:
        field = "Idempotency-Key"
        raise IngestionValidationError.single(field, "invalid")


def _capability(value: str) -> CaptureCapability:
    try:
        return CaptureCapability(value)
    except ValueError as error:
        field = "capability"
        raise IngestionValidationError.single(field, "unsupported") from error


def _family(value: str) -> EventFamily:
    try:
        return EventFamily(value)
    except ValueError as error:
        field = "supported_families"
        raise IngestionValidationError.single(field, "unsupported") from error


def _change_document(result: CapabilityChangeResult) -> dict[str, object]:
    view = CapabilityMatrixView(result.registration, result.warnings)
    return {
        "disposition": result.disposition.value,
        "capability_matrix": _matrix_document(view),
    }


def _matrix_document(view: CapabilityMatrixView) -> dict[str, object]:
    registration = view.registration
    manifest = registration.manifest
    observation = registration.observation
    return {
        "adapter_id": manifest.adapter_id,
        "adapter_version": manifest.adapter_version,
        "adapter_digest": manifest.adapter_digest,
        "capability_manifest_digest": manifest.manifest_sha256,
        "schema_major": manifest.schema_major,
        "supported_families": [item.value for item in manifest.supported_families],
        "revision": observation.revision,
        "observed_at": observation.observed_at.isoformat().replace("+00:00", "Z"),
        "evidence_availability": [
            {"capability": item.capability.value, "status": item.status.value}
            for item in observation.evidence_availability
        ],
        "warnings": [
            {
                "capability": item.capability.value,
                "previous_status": item.previous_status.value,
                "current_status": item.current_status.value,
                "impact": item.impact.value,
                "code": item.code,
            }
            for item in view.warnings
        ],
    }


def _validation_problem(error: IngestionValidationError) -> JSONResponse:
    return _problem(
        "AM_VALIDATION",
        422,
        fields=[
            {"field": item.field, "code": item.code} for item in error.violations
        ],
    )


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
        "detail": "Adapter capability operation was rejected",
    }
    if fields is not None:
        document["fields"] = fields
    return JSONResponse(document, status_code=http_status)
