"""Authenticated strict PF-003 external adapter registration API."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Literal, Protocol

from fastapi import APIRouter, Header, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.extensions.application.register_adapter import RegisterAdapterCommand
from agentmemory.extensions.domain.errors import (
    AdapterAuthorizationError,
    AdapterConflictError,
    AdapterExtensionError,
    AdapterProbeError,
    AdapterStorageError,
    AdapterTrustError,
    AdapterValidationError,
)
from agentmemory.extensions.domain.models import (
    AdapterCapability,
    AdapterKind,
    AdapterManifest,
    AdapterPermission,
    ProtocolVersion,
)

if TYPE_CHECKING:
    from agentmemory.extensions.domain.models import AdapterRegistration

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PROTOCOL = re.compile(r"^([1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class AdapterExtensionManifestModel(_StrictModel):
    """Transport DTO matching the public manifest schema exactly."""

    schema_version: Literal[1]
    adapter_id: str = Field(min_length=1, max_length=128)
    adapter_version: str = Field(min_length=5, max_length=128)
    kind: Literal["agent", "provider"]
    package_digest: str
    signature_digest: str
    signer_identity: str = Field(min_length=1, max_length=128)
    protocol_min: str
    protocol_max: str
    capabilities: list[str] = Field(min_length=1, max_length=16)
    requested_permissions: list[str] = Field(min_length=1, max_length=16)

    def to_domain(self) -> AdapterManifest:
        """Canonicalize closed enums and protocol versions in the domain."""
        try:
            return AdapterManifest.create(
                schema_version=self.schema_version,
                adapter_id=self.adapter_id,
                adapter_version=self.adapter_version,
                kind=AdapterKind(self.kind),
                package_digest=self.package_digest,
                signature_digest=self.signature_digest,
                signer_identity=self.signer_identity,
                protocol_min=_protocol(self.protocol_min),
                protocol_max=_protocol(self.protocol_max),
                capabilities=tuple(AdapterCapability(item) for item in self.capabilities),
                requested_permissions=tuple(
                    AdapterPermission(item) for item in self.requested_permissions
                ),
            )
        except ValueError as error:
            message = "adapter manifest contains an unsupported value"
            raise AdapterValidationError(message) from error


class RegisterAdapterRequest(_StrictModel):
    """Complete authority-bound idempotent PF-003 command."""

    operation_id: str = Field(min_length=1, max_length=128)
    brain_id: str
    actor_id: str
    grant_id: str
    manifest: AdapterExtensionManifestModel
    requested_at: str

    def to_command(self) -> RegisterAdapterCommand:
        """Translate untrusted transport input to the application command."""
        return RegisterAdapterCommand(
            operation_id=self.operation_id,
            brain_id=self.brain_id,
            actor_id=self.actor_id,
            grant_id=self.grant_id,
            manifest=self.manifest.to_domain(),
            requested_at=_datetime(self.requested_at),
        )


class AdapterRegistrationResponse(_StrictModel):
    """Content-free governed registration evidence."""

    registration_id: str
    brain_id: str
    adapter_id: str
    adapter_version: str
    kind: Literal["agent", "provider"]
    manifest_digest: str
    package_digest: str
    evidence_digest: str
    negotiated_protocol: str
    capabilities: tuple[str, ...]
    state: Literal["active"]
    registered_at: str
    registration_digest: str


class RegisterHandler(Protocol):
    """Execute one framework-independent adapter registration command."""

    async def execute(self, command: RegisterAdapterCommand) -> AdapterRegistration:
        """Return the committed registration or an exact replay."""
        ...


class Authenticator(Protocol):
    """Authenticate one local installation/session capability."""

    async def authenticate(self, authorization: str | None) -> None:
        """Raise unless the exact bearer capability is active."""
        ...


def create_adapter_extension_router(
    authenticator: Authenticator,
    handler: RegisterHandler,
) -> APIRouter:
    """Create the authenticated PF-003 command route."""
    router = APIRouter()

    @router.post(
        "/v1/adapter-extensions:register",
        response_model=AdapterRegistrationResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def register_adapter(
        request: RegisterAdapterRequest,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Authenticate then verify, probe, and atomically register one package."""
        try:
            await authenticator.authenticate(authorization)
            _validate_idempotency(idempotency_key, request.operation_id)
            registration = await handler.execute(request.to_command())
        except AdapterExtensionError as error:
            return _extension_problem(error)
        return JSONResponse(_registration_document(registration), status_code=201)

    registered_routes = (register_adapter,)
    del registered_routes
    return router


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization


class _ContractHandler:
    async def execute(self, command: RegisterAdapterCommand) -> AdapterRegistration:
        del command
        message = "contract-only adapter handler cannot mutate"
        raise RuntimeError(message)


def create_contract_adapter_extension_router() -> APIRouter:
    """Return a side-effect-free router for deterministic OpenAPI generation."""
    return create_adapter_extension_router(_ContractAuthenticator(), _ContractHandler())


def _validate_idempotency(value: str | None, operation_id: str) -> None:
    if value != operation_id or _IDEMPOTENCY.fullmatch(value or "") is None:
        message = "Idempotency-Key does not match operation_id"
        raise AdapterValidationError(message)


def _protocol(value: str) -> ProtocolVersion:
    match = _PROTOCOL.fullmatch(value)
    if match is None:
        message = "adapter protocol version is invalid"
        raise AdapterValidationError(message)
    return ProtocolVersion(int(match.group(1)), int(match.group(2)))


def _datetime(value: str) -> datetime:
    if not value.endswith("Z"):
        message = "requested_at must be canonical UTC"
        raise AdapterValidationError(message)
    try:
        result = datetime.fromisoformat(value)
    except ValueError as error:
        message = "requested_at must be canonical UTC"
        raise AdapterValidationError(message) from error
    if (
        result.utcoffset() != UTC.utcoffset(None)
        or result.isoformat().replace("+00:00", "Z") != value
    ):
        message = "requested_at must be canonical UTC"
        raise AdapterValidationError(message)
    return result


def _registration_document(registration: AdapterRegistration) -> dict[str, object]:
    return {
        "adapter_id": registration.manifest.adapter_id,
        "adapter_version": registration.manifest.adapter_version,
        "brain_id": registration.brain_id,
        "capabilities": [item.value for item in registration.manifest.capabilities],
        "evidence_digest": registration.evidence.evidence_digest,
        "kind": registration.manifest.kind.value,
        "manifest_digest": registration.manifest_digest,
        "negotiated_protocol": str(registration.evidence.negotiated_protocol),
        "package_digest": registration.package_digest,
        "registered_at": registration.registered_at.isoformat().replace("+00:00", "Z"),
        "registration_digest": registration.registration_digest,
        "registration_id": registration.registration_id,
        "state": registration.state.value,
    }


def _problem(code: str, http_status: int, *, retryable: bool = False) -> JSONResponse:
    return JSONResponse(
        {
            "code": code,
            "detail": "Adapter extension operation was rejected",
            "retryable": retryable,
        },
        status_code=http_status,
    )


def _extension_problem(error: AdapterExtensionError) -> JSONResponse:
    mappings: tuple[tuple[type[AdapterExtensionError], str, int, bool], ...] = (
        (AdapterAuthorizationError, "AM_FORBIDDEN", 403, False),
        (AdapterTrustError, "AM_UNTRUSTED_ADAPTER", 422, False),
        (AdapterConflictError, "AM_CONFLICT", 409, False),
        (AdapterProbeError, "AM_ADAPTER_CONFORMANCE_FAILED", 424, False),
        (AdapterStorageError, "AM_DEPENDENCY_UNAVAILABLE", 503, True),
        (AdapterValidationError, "AM_VALIDATION", 422, False),
    )
    for error_type, code, http_status, retryable in mappings:
        if isinstance(error, error_type):
            return _problem(code, http_status, retryable=retryable)
    return _problem("AM_ADAPTER_REJECTED", 500)
