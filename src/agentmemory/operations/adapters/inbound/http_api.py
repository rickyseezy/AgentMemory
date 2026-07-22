"""Authenticated loopback FastAPI adapter for PF-001 bootstrap/readiness."""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, cast
from uuid import uuid7

from fastapi import APIRouter, Depends, FastAPI, Header, Request, Response, Security, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.operations.domain.active_release import ActiveReleasePointer
from agentmemory.operations.domain.bootstrap import BootstrapDisposition, BootstrapRequest
from agentmemory.operations.domain.errors import (
    DomainValidationError,
    ErrorCode,
    OperationError,
)
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSession,
    McpSessionRegistration,
    McpSessionState,
)
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRebuild,
    ProjectionType,
    RebuildManifest,
    StartProjectionRebuildCommand,
)
from agentmemory.operations.domain.readiness import ReadinessBinding
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
    format_rfc3339_microseconds,
)
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
    WorkspaceIndexCoverage,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from contextlib import AbstractAsyncContextManager

    from agentmemory.operations.application.commands.active_release import (
        ActiveReleaseStageResult,
    )
    from agentmemory.operations.application.commands.bootstrap_local_brain import (
        BootstrapResult,
    )
    from agentmemory.operations.application.commands.verify_readiness import (
        ReadinessVerification,
    )
    from agentmemory.operations.domain.ports import ReadinessStatusPort, RuntimeReadinessPort
    from agentmemory.operations.domain.readiness import ReadinessReceipt

_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_RFC3339_MICROSECONDS_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_CHECKPOINT_REQUEST_BYTES = 24 * 1024 * 1024
_WORKSPACE_CHECKPOINT_PATH = "/v1/launcher/sessions:checkpoint"
_MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH"})
_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by the lowercase hexadecimal 256-bit launcher credential.",
    auto_error=False,
)


class _StrictRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class BootstrapRequestModel(_StrictRequest):
    """Strict boundary DTO for first local-Brain bootstrap."""

    command_id: str = Field(min_length=1, max_length=128)
    installation_id: str
    owner_principal_id: str
    owner_grant_id: str
    owner_subject_digest: str
    brain_id: str
    brain_name: str = Field(min_length=1, max_length=63)
    release_digest: str
    generation_id: str

    def to_domain(self) -> BootstrapRequest:
        """Translate validated boundary data into framework-independent values."""
        return BootstrapRequest(
            command_id=OperationId(self.command_id),
            installation_id=Uuid7Id(self.installation_id),
            owner_principal_id=Uuid7Id(self.owner_principal_id),
            owner_grant_id=Uuid7Id(self.owner_grant_id),
            owner_subject_digest=Sha256Digest(self.owner_subject_digest),
            brain_id=Uuid7Id(self.brain_id),
            brain_name=self.brain_name,
            release_digest=Sha256Digest(self.release_digest),
            generation_id=Uuid7Id(self.generation_id),
        )


class ReadinessRequestModel(_StrictRequest):
    """Strict launcher-compatible readiness binding DTO."""

    operation_id: str = Field(min_length=1, max_length=128)
    plan_digest: str
    release_id: str
    generation_id: str
    manifest_digest: str
    compose_digest: str

    def to_domain(self) -> ReadinessBinding:
        """Translate exact launcher bindings into immutable domain values."""
        return ReadinessBinding(
            operation_id=OperationId(self.operation_id),
            plan_digest=Sha256Digest(self.plan_digest),
            release_id=ReleaseId(self.release_id),
            generation_id=Uuid7Id(self.generation_id),
            manifest_digest=Sha256Digest(self.manifest_digest),
            compose_digest=Sha256Digest(self.compose_digest),
        )


class ActiveReleasePointerModel(_StrictRequest):
    """Strict launcher-compatible active pointer record."""

    schema_version: Literal[1]
    installation_id: str
    release_id: str
    generation_id: str
    manifest_digest: str
    compose_digest: str
    readiness_receipt_digest: str
    runtime_endpoint: str
    release_sequence: int
    resource_inventory_version: int
    resource_inventory_digest: str
    security_epoch: int
    activated_at: str
    pointer_digest: str

    def to_domain(self) -> ActiveReleasePointer:
        """Restore and independently authenticate the complete pointer record."""
        return ActiveReleasePointer.restore(self.model_dump())


class ActiveReleaseStageRequestModel(_StrictRequest):
    """Stage one operation-bound pointer."""

    operation_id: str = Field(min_length=1, max_length=128)
    pointer: ActiveReleasePointerModel


class ActiveReleaseCommitRequestModel(ActiveReleaseStageRequestModel):
    """Commit the exact Core stage approved by the host journal."""

    stage_digest: str


class ActiveReleaseMatchesRequestModel(_StrictRequest):
    """Request exact Core mirror reconciliation."""

    pointer: ActiveReleasePointerModel


class ProbeEvidenceResponseModel(_StrictRequest):
    """Exact non-secret launcher evidence record."""

    probe: str
    status: Literal["passed"]
    operation_id: str
    plan_digest: str
    release_id: str
    generation_id: str
    manifest_digest: str
    compose_digest: str
    evidence_digest: str
    observed_at: str


class ReadinessReceiptResponseModel(_StrictRequest):
    """Exact Go-compatible complete readiness receipt record."""

    schema_version: Literal[1] = 1
    operation_id: str
    plan_digest: str
    release_id: str
    generation_id: str
    manifest_digest: str
    compose_digest: str
    evaluated_at: str
    results: tuple[ProbeEvidenceResponseModel, ...]
    receipt_digest: str


class BootstrapResponseModel(_StrictRequest):
    """Idempotent local bootstrap response."""

    installation_id: str
    brain_id: str
    disposition: Literal["created", "already_initialized"]


class StatusResponseModel(_StrictRequest):
    """Authenticated optimized readiness status response."""

    ready: bool
    receipt: ReadinessReceiptResponseModel | None


class ReadinessFailureResponseModel(_StrictRequest):
    """One privacy-safe negative gate result."""

    probe: str
    code: str


class ReadinessVerificationResponseModel(StatusResponseModel):
    """Complete readiness execution result."""

    failures: tuple[ReadinessFailureResponseModel, ...]


class ActiveReleaseStageResponseModel(_StrictRequest):
    """Durable stage acknowledgement."""

    stage_digest: str


class ActiveReleaseCommitResponseModel(_StrictRequest):
    """Exact committed pointer acknowledgement."""

    pointer_digest: str


class ActiveReleaseMatchesResponseModel(_StrictRequest):
    """Closed exact mirror comparison."""

    matches: bool


class SessionCredentialRegistrationRequestModel(_StrictRequest):
    """Exact hash-only PF-005 credential scope from the trusted launcher."""

    session_id: str
    installation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    agent_id: str
    workspace_fingerprint: str
    device_identity: str
    git_repository_id: str
    git_worktree_id: str
    git_coverage: str
    security_epoch: int = Field(ge=1)
    credential_digest: str
    issued_at: str
    expires_at: str

    def to_domain(self) -> McpSessionRegistration:
        """Translate strict transport values into the session authority aggregate."""
        return McpSessionRegistration(
            session_id=Uuid7Id(self.session_id),
            installation_id=Uuid7Id(self.installation_id),
            brain_id=Uuid7Id(self.brain_id),
            actor_id=Uuid7Id(self.actor_id),
            grant_id=Uuid7Id(self.grant_id),
            agent_id=self.agent_id,
            workspace_fingerprint=Sha256Digest(self.workspace_fingerprint),
            device_identity=self.device_identity,
            git_repository_id=self.git_repository_id or None,
            git_worktree_id=self.git_worktree_id or None,
            git_coverage=McpGitCoverage(self.git_coverage),
            security_epoch=self.security_epoch,
            credential_digest=Sha256Digest(self.credential_digest),
            issued_at=_parse_rfc3339_microseconds(self.issued_at),
            expires_at=_parse_rfc3339_microseconds(self.expires_at),
        )


class SessionCredentialRevokeRequestModel(_StrictRequest):
    """Hash-only credential revocation request."""

    credential_digest: str


class SessionBeginRequestModel(_StrictRequest):
    """Bounded initial session lease request."""

    session_id: str
    started_at: str
    lease_seconds: int = Field(ge=1, le=120)


class SessionHeartbeatRequestModel(_StrictRequest):
    """Monotonic session heartbeat request."""

    session_id: str
    heartbeat_at: str


class SessionFinishRequestModel(_StrictRequest):
    """Exact terminal session outcome request."""

    session_id: str
    status: Literal["completed", "interrupted"]
    finished_at: str


class WorkspaceCheckpointChangeModel(_StrictRequest):
    """One bounded relative file delta encoded without a host path."""

    relative_path: str = Field(min_length=1, max_length=4096)
    sha256: str
    content_base64: str = Field(max_length=2_796_208)
    deleted: bool

    def to_domain(self) -> WorkspaceCheckpointChange:
        """Strictly decode canonical Base64 before domain digest verification."""
        try:
            content = base64.b64decode(self.content_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            message = "workspace checkpoint content is invalid"
            raise DomainValidationError(message) from error
        return WorkspaceCheckpointChange(
            relative_path=self.relative_path,
            sha256=Sha256Digest(self.sha256),
            content=content,
            deleted=self.deleted,
        )


class WorkspaceCheckpointRequestModel(_StrictRequest):
    """Exact digest-bound terminal workspace batch from the launcher."""

    session_id: str
    workspace_fingerprint: str
    batch_digest: str
    partial: bool
    changes: list[WorkspaceCheckpointChangeModel] = Field(max_length=10_000)

    def to_domain(self) -> WorkspaceCheckpointBatch:
        """Construct the bounded canonical batch and independently verify its digest."""
        return WorkspaceCheckpointBatch(
            session_id=Uuid7Id(self.session_id),
            workspace_fingerprint=Sha256Digest(self.workspace_fingerprint),
            batch_digest=Sha256Digest(self.batch_digest),
            partial=self.partial,
            changes=tuple(change.to_domain() for change in self.changes),
        )


class SessionCredentialResponseModel(_StrictRequest):
    """Registration response that never contains raw credential material."""

    session_id: str
    credential_digest: str
    status: Literal["registered", "already_registered"]


class SessionCredentialRevocationResponseModel(_StrictRequest):
    """Idempotent content-free credential revocation response."""

    credential_digest: str
    status: Literal["revoked", "already_revoked"]


class SessionLifecycleResponseModel(_StrictRequest):
    """Content-free durable session state response."""

    session_id: str
    state: Literal["registered", "active", "completed", "interrupted"]
    revision: int = Field(ge=0)


class SessionStatusResponseModel(_StrictRequest):
    """Authenticated bridge-visible scope without host paths or secrets."""

    session_id: str
    brain_id: str
    agent_id: str
    workspace_fingerprint: str
    git_coverage: Literal["none", "partial", "complete"]
    index_coverage: Literal["pending", "indexing", "complete", "partial", "degraded"]
    state: Literal["registered", "active"]


class WorkspaceCheckpointResponseModel(_StrictRequest):
    """Durable content-free acknowledgement for one encrypted batch."""

    session_id: str
    batch_digest: str
    status: Literal["checkpointed", "already_checkpointed"]


class RebuildManifestModel(_StrictRequest):
    """Complete immutable implementation/provider pin set for PF-002 replay."""

    application_build: str = Field(min_length=1, max_length=256)
    relational_schema: str = Field(min_length=1, max_length=256)
    graph_schema: str = Field(min_length=1, max_length=256)
    parser_version: str = Field(min_length=1, max_length=256)
    extractor_version: str = Field(min_length=1, max_length=256)
    provider_versions: list[str] = Field(min_length=1, max_length=32)
    embedding_space: str = Field(min_length=1, max_length=256)
    implementation_fingerprint: str

    def to_domain(self) -> RebuildManifest:
        """Translate strict boundary values into the reproducibility manifest."""
        return RebuildManifest(
            application_build=self.application_build,
            relational_schema=self.relational_schema,
            graph_schema=self.graph_schema,
            parser_version=self.parser_version,
            extractor_version=self.extractor_version,
            provider_versions=tuple(self.provider_versions),
            embedding_space=self.embedding_space,
            implementation_fingerprint=Sha256Digest(self.implementation_fingerprint),
        )


class StartProjectionRebuildRequestModel(_StrictRequest):
    """Start one projection family at an optional committed watermark."""

    operation_id: str = Field(min_length=1, max_length=128)
    brain_id: str
    actor_id: str
    grant_id: str
    projection_type: Literal["graph", "memory", "search", "code", "vector"]
    requested_watermark: int | None = Field(default=None, ge=0)
    manifest: RebuildManifestModel

    def to_domain(self) -> StartProjectionRebuildCommand:
        """Create a framework-independent rebuild command."""
        return StartProjectionRebuildCommand(
            operation_id=self.operation_id,
            brain_id=Uuid7Id(self.brain_id),
            actor_id=Uuid7Id(self.actor_id),
            grant_id=Uuid7Id(self.grant_id),
            projection_type=ProjectionType(self.projection_type),
            manifest=self.manifest.to_domain(),
            requested_watermark=self.requested_watermark,
        )


class ProjectionRebuildResponseModel(_StrictRequest):
    """Content-free operation state with deterministic replay evidence."""

    operation_id: str
    brain_id: str
    projection_type: str
    source_watermark: int
    cursor: int
    generation_id: str
    manifest_digest: str
    state: str
    record_count: int
    skipped_tombstones: int
    generation_digest: str | None
    partial_reason: str | None
    created_at: str
    updated_at: str


class AuthenticatorPort(Protocol):
    """Authenticate one launcher request."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject any non-exact protected credential."""
        ...


class BootstrapHandlerPort(Protocol):
    """Execute the local Brain bootstrap use case."""

    async def execute(self, request: BootstrapRequest) -> BootstrapResult:
        """Return one atomic idempotent bootstrap result."""
        ...


class ReadinessHandlerPort(Protocol):
    """Execute the all-dependency readiness use case."""

    async def execute(self, binding: ReadinessBinding) -> ReadinessVerification:
        """Return either a complete receipt or exact negative gates."""
        ...


class ActiveReleaseHandlerPort(Protocol):
    """Execute the governed Core half of host/Core activation."""

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> ActiveReleaseStageResult:
        """Durably stage one readiness-authorized pointer."""
        ...

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        """Commit only the exact staged pointer."""
        ...

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        """Reconcile the exact durable pointer mirror."""
        ...


class ProjectionRebuildHandlerPort(Protocol):
    """Start one durable shadow-generation rebuild."""

    async def execute(self, command: StartProjectionRebuildCommand) -> ProjectionRebuild:
        """Persist and return the exact queued or idempotent operation."""
        ...


class ProjectionRebuildQueryPort(Protocol):
    """Read durable projection operation metadata."""

    async def get(self, operation_id: str) -> ProjectionRebuild | None:
        """Return the operation without projected content."""
        ...


class RegisterMcpSessionPort(Protocol):
    """Register hash-only launcher session authority."""

    async def execute(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        """Return the exact aggregate and whether it was created."""
        ...


class WorkspaceCheckpointPort(Protocol):
    """Authorize and durably encrypt one PF-005 workspace batch."""

    async def execute(self, batch: WorkspaceCheckpointBatch) -> bool:
        """Return whether this exact batch was newly staged."""
        ...


class McpSessionLifecyclePort(Protocol):
    """Apply durable PF-005 lifecycle transitions."""

    async def begin(
        self,
        session_id: Uuid7Id,
        now: datetime,
        lease: timedelta,
    ) -> McpSession:
        """Activate a registered session."""
        ...

    async def heartbeat(self, session_id: Uuid7Id, now: datetime) -> McpSession:
        """Renew an active lease."""
        ...

    async def finish(
        self,
        session_id: Uuid7Id,
        state: McpSessionState,
        now: datetime,
    ) -> McpSession:
        """Persist one terminal outcome."""
        ...

    async def revoke(
        self,
        digest: Sha256Digest,
        now: datetime,
    ) -> tuple[McpSession | None, bool]:
        """Revoke hash-only authority idempotently."""
        ...


class ClockPort(Protocol):
    """Supply trusted UTC time to transport-owned commands."""

    def now(self) -> datetime:
        """Return the current time."""
        ...


class SessionAuthenticatorPort(Protocol):
    """Authenticate only short-lived session scope."""

    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        """Return the current exact session scope."""
        ...


class WorkspaceCoveragePort(Protocol):
    """Read content-free indexing coverage for an authenticated session."""

    async def coverage(self, session_id: Uuid7Id) -> WorkspaceIndexCoverage:
        """Return current checkpoint/index progress."""
        ...


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization
        msg = "contract-only dependency cannot authenticate requests"
        raise RuntimeError(msg)


class _ContractBootstrapHandler:
    async def execute(self, request: BootstrapRequest) -> BootstrapResult:
        del request
        msg = "contract-only dependency cannot execute bootstrap"
        raise RuntimeError(msg)


class _ContractReadinessHandler:
    async def execute(self, binding: ReadinessBinding) -> ReadinessVerification:
        del binding
        msg = "contract-only dependency cannot execute readiness"
        raise RuntimeError(msg)


class _ContractActiveReleaseHandler:
    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> ActiveReleaseStageResult:
        del operation_id, pointer
        msg = "contract-only dependency cannot stage an active release"
        raise RuntimeError(msg)

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        del operation_id, stage_digest, pointer
        msg = "contract-only dependency cannot commit an active release"
        raise RuntimeError(msg)

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        del pointer
        msg = "contract-only dependency cannot reconcile an active release"
        raise RuntimeError(msg)


class _ContractProjectionRebuildHandler:
    async def execute(self, command: StartProjectionRebuildCommand) -> ProjectionRebuild:
        del command
        msg = "contract-only dependency cannot start a projection rebuild"
        raise RuntimeError(msg)


class _ContractProjectionRebuildQuery:
    async def get(self, operation_id: str) -> ProjectionRebuild | None:
        del operation_id
        msg = "contract-only dependency cannot query a projection rebuild"
        raise RuntimeError(msg)


class _ContractMcpSessions:
    async def execute(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        del registration
        msg = "contract-only dependency cannot register an MCP session"
        raise RuntimeError(msg)

    async def begin(self, session_id: Uuid7Id, now: datetime, lease: timedelta) -> McpSession:
        del session_id, now, lease
        msg = "contract-only dependency cannot begin an MCP session"
        raise RuntimeError(msg)

    async def heartbeat(self, session_id: Uuid7Id, now: datetime) -> McpSession:
        del session_id, now
        msg = "contract-only dependency cannot heartbeat an MCP session"
        raise RuntimeError(msg)

    async def finish(
        self, session_id: Uuid7Id, state: McpSessionState, now: datetime
    ) -> McpSession:
        del session_id, state, now
        msg = "contract-only dependency cannot finish an MCP session"
        raise RuntimeError(msg)

    async def revoke(self, digest: Sha256Digest, now: datetime) -> tuple[McpSession | None, bool]:
        del digest, now
        msg = "contract-only dependency cannot revoke an MCP session"
        raise RuntimeError(msg)


class _ContractClock:
    def now(self) -> datetime:
        msg = "contract-only dependency cannot provide time"
        raise RuntimeError(msg)


class _ContractSessionAuthenticator:
    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        del authorization, session_id
        msg = "contract-only dependency cannot authenticate an MCP session"
        raise RuntimeError(msg)


class _ContractWorkspaceCheckpoint:
    async def execute(self, batch: WorkspaceCheckpointBatch) -> bool:
        del batch
        msg = "contract-only dependency cannot checkpoint a workspace"
        raise RuntimeError(msg)

    async def coverage(self, session_id: Uuid7Id) -> WorkspaceIndexCoverage:
        del session_id
        msg = "contract-only dependency cannot query workspace coverage"
        raise RuntimeError(msg)


class _ContractStatusQuery:
    async def latest(self) -> ReadinessReceipt | None:
        msg = "contract-only dependency cannot query status"
        raise RuntimeError(msg)


class _ContractRuntimeReadiness:
    async def verify(self, anchor: ReadinessReceipt) -> ReadinessReceipt | None:
        del anchor
        msg = "contract-only dependency cannot execute runtime readiness"
        raise RuntimeError(msg)


@dataclass(frozen=True, slots=True)
class ApiDependencies:
    """Constructor-injected inbound capabilities."""

    authenticator: AuthenticatorPort
    bootstrap: BootstrapHandlerPort
    readiness: ReadinessHandlerPort
    active_release: ActiveReleaseHandlerPort
    runtime_readiness: RuntimeReadinessPort
    status_query: ReadinessStatusPort
    projection_rebuild: ProjectionRebuildHandlerPort
    projection_rebuild_query: ProjectionRebuildQueryPort
    register_mcp_session: RegisterMcpSessionPort
    mcp_session_lifecycle: McpSessionLifecyclePort
    session_authenticator: SessionAuthenticatorPort
    workspace_checkpoint: WorkspaceCheckpointPort
    workspace_coverage: WorkspaceCoveragePort
    clock: ClockPort
    allowed_hosts: frozenset[str]


class _LoopbackProtection:
    """Apply bounded loopback-only request policy before route dispatch."""

    def __init__(self, dependencies: ApiDependencies) -> None:
        self._dependencies = dependencies
        self._concurrency = asyncio.Semaphore(16)

    async def __call__(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Reject untrusted browser/network identities and bound resource use."""
        rejected = self._validate_boundary(request)
        if rejected is not None:
            _set_security_headers(rejected)
            return rejected
        try:
            async with self._concurrency, asyncio.timeout(30):
                response = await call_next(request)
        except TimeoutError:
            response = _problem(
                ErrorCode.DEADLINE_EXCEEDED,
                504,
                "request deadline was exceeded",
                request,
                retryable=True,
            )
        _set_security_headers(response)
        return response

    def _validate_boundary(self, request: Request) -> JSONResponse | None:
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        if host not in self._dependencies.allowed_hosts:
            return _problem(ErrorCode.FORBIDDEN, 403, "loopback Host is not allowed", request)
        if origin is not None or request.headers.get("sec-fetch-site") not in {
            None,
            "none",
            "same-origin",
        }:
            return _problem(
                ErrorCode.FORBIDDEN,
                403,
                "browser origin is not allowed on this endpoint",
                request,
            )
        return _request_size_rejection(request)


def create_app(
    dependencies: ApiDependencies,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[None]] | None = None,
) -> FastAPI:
    """Create the authenticated loopback application without ambient dependencies."""
    application = FastAPI(
        title="AgentMemory Core",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.middleware("http")(_LoopbackProtection(dependencies))
    authenticate = _authentication_dependency(dependencies)
    _register_exception_handlers(application)
    _register_health_routes(application, dependencies, authenticate)
    _register_session_routes(application, dependencies, authenticate)
    _register_command_routes(application, dependencies, authenticate)
    return application


def export_openapi_schema(
    additional_routers: tuple[APIRouter, ...] = (),
) -> dict[str, object]:
    """Build the deterministic launcher-client contract without runtime secrets."""
    application = create_app(
        ApiDependencies(
            authenticator=_ContractAuthenticator(),
            bootstrap=_ContractBootstrapHandler(),
            readiness=_ContractReadinessHandler(),
            active_release=_ContractActiveReleaseHandler(),
            runtime_readiness=_ContractRuntimeReadiness(),
            status_query=_ContractStatusQuery(),
            projection_rebuild=_ContractProjectionRebuildHandler(),
            projection_rebuild_query=_ContractProjectionRebuildQuery(),
            register_mcp_session=_ContractMcpSessions(),
            mcp_session_lifecycle=_ContractMcpSessions(),
            session_authenticator=_ContractSessionAuthenticator(),
            workspace_checkpoint=_ContractWorkspaceCheckpoint(),
            workspace_coverage=_ContractWorkspaceCheckpoint(),
            clock=_ContractClock(),
            allowed_hosts=frozenset({"127.0.0.1:9411"}),
        )
    )
    for router in additional_routers:
        application.include_router(router)
    return cast("dict[str, object]", application.openapi())


def _authentication_dependency(
    dependencies: ApiDependencies,
) -> Callable[[str | None], Awaitable[None]]:
    async def authenticate(
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> None:
        await dependencies.authenticator.authenticate(authorization)

    return authenticate


def _register_exception_handlers(application: FastAPI) -> None:

    @application.exception_handler(OperationError)
    async def handle_operation_error(request: Request, error: OperationError) -> JSONResponse:
        return _problem(
            error.code,
            _http_status(error.code),
            error.safe_detail,
            request,
            retryable=error.retryable,
        )

    @application.exception_handler(DomainValidationError)
    async def handle_domain_validation(
        request: Request, error: DomainValidationError
    ) -> JSONResponse:
        del error
        return _problem(ErrorCode.VALIDATION, 422, "request validation failed", request)

    @application.exception_handler(RequestValidationError)
    async def handle_request_validation(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        del error
        return _problem(ErrorCode.VALIDATION, 422, "request validation failed", request)

    _registered_handlers = (
        handle_operation_error,
        handle_domain_validation,
        handle_request_validation,
    )
    del _registered_handlers


def _register_health_routes(
    application: FastAPI,
    dependencies: ApiDependencies,
    authenticate: Callable[[str | None], Awaitable[None]],
) -> None:

    @application.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, bool]:
        """Expose alive/not-alive only, with no version or dependency data."""
        return {"alive": True}

    @application.get("/ready", dependencies=[Depends(authenticate)], include_in_schema=False)
    async def readiness_health() -> JSONResponse:
        """Return 200 only after a complete authenticated receipt exists."""
        receipt = await dependencies.status_query.latest()
        if receipt is None:
            return JSONResponse({"ready": False}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        certificate = await dependencies.runtime_readiness.verify(receipt)
        if certificate is None:
            return JSONResponse({"ready": False}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        return JSONResponse({"ready": True}, status_code=status.HTTP_200_OK)

    @application.get(
        "/v1/status",
        dependencies=[Depends(authenticate)],
        response_model=StatusResponseModel,
    )
    async def status_query() -> StatusResponseModel:
        """Return the complete integrity-checked readiness record to the launcher."""
        receipt = await dependencies.status_query.latest()
        if receipt is None:
            return StatusResponseModel(ready=False, receipt=None)
        certificate = await dependencies.runtime_readiness.verify(receipt)
        if certificate is None:
            return StatusResponseModel(ready=False, receipt=None)
        return StatusResponseModel(ready=True, receipt=_receipt_response(certificate))

    _registered_routes = (liveness, readiness_health, status_query)
    del _registered_routes


def _register_session_routes(
    application: FastAPI,
    dependencies: ApiDependencies,
    authenticate: Callable[[str | None], Awaitable[None]],
) -> None:
    @application.get(
        "/v1/session/status",
        response_model=SessionStatusResponseModel,
    )
    async def session_status(
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        session_id: Annotated[str | None, Header(alias="X-AgentMemory-Session-ID")] = None,
    ) -> SessionStatusResponseModel:
        """Prove current bridge scope without accepting the root credential implicitly."""
        session = await dependencies.session_authenticator.authenticate(
            authorization,
            session_id or "",
        )
        return SessionStatusResponseModel(
            session_id=session.registration.session_id.value,
            brain_id=session.registration.brain_id.value,
            agent_id=session.registration.agent_id,
            workspace_fingerprint=session.registration.workspace_fingerprint.value,
            git_coverage=session.registration.git_coverage.value,
            index_coverage=(
                await dependencies.workspace_coverage.coverage(session.registration.session_id)
            ).value,
            state=cast("Literal['registered', 'active']", session.state.value),
        )

    @application.post(
        "/v1/launcher/sessions/credentials",
        dependencies=[Depends(authenticate)],
        response_model=SessionCredentialResponseModel,
    )
    async def register_session_credential(
        request: SessionCredentialRegistrationRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Persist only the digest of one short-lived scoped credential."""
        _validate_idempotency(idempotency_key, request.session_id)
        session, created = await dependencies.register_mcp_session.execute(request.to_domain())
        return JSONResponse(
            {
                "session_id": session.registration.session_id.value,
                "credential_digest": session.registration.credential_digest.value,
                "status": "registered" if created else "already_registered",
            },
            status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    @application.post(
        "/v1/launcher/sessions/credentials:revoke",
        dependencies=[Depends(authenticate)],
        response_model=SessionCredentialRevocationResponseModel,
    )
    async def revoke_session_credential(
        request: SessionCredentialRevokeRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> SessionCredentialRevocationResponseModel:
        """Revoke a hash-only session credential without disclosing its scope."""
        _validate_idempotency(idempotency_key, request.credential_digest)
        _, changed = await dependencies.mcp_session_lifecycle.revoke(
            Sha256Digest(request.credential_digest),
            dependencies.clock.now(),
        )
        return SessionCredentialRevocationResponseModel(
            credential_digest=request.credential_digest,
            status="revoked" if changed else "already_revoked",
        )

    @application.post(
        "/v1/launcher/sessions:begin",
        dependencies=[Depends(authenticate)],
        response_model=SessionLifecycleResponseModel,
    )
    async def begin_session(
        request: SessionBeginRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> SessionLifecycleResponseModel:
        """Begin the bounded lease for one registered launcher session."""
        _validate_idempotency(idempotency_key, request.session_id)
        session = await dependencies.mcp_session_lifecycle.begin(
            Uuid7Id(request.session_id),
            _parse_rfc3339_microseconds(request.started_at),
            timedelta(seconds=request.lease_seconds),
        )
        return _session_lifecycle_response(session)

    @application.post(
        "/v1/launcher/sessions:heartbeat",
        dependencies=[Depends(authenticate)],
        response_model=SessionLifecycleResponseModel,
    )
    async def heartbeat_session(
        request: SessionHeartbeatRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> SessionLifecycleResponseModel:
        """Renew one active session lease at a monotonic timestamp."""
        _validate_idempotency(idempotency_key, request.session_id)
        session = await dependencies.mcp_session_lifecycle.heartbeat(
            Uuid7Id(request.session_id),
            _parse_rfc3339_microseconds(request.heartbeat_at),
        )
        return _session_lifecycle_response(session)

    @application.post(
        "/v1/launcher/sessions:finish",
        dependencies=[Depends(authenticate)],
        response_model=SessionLifecycleResponseModel,
    )
    async def finish_session(
        request: SessionFinishRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> SessionLifecycleResponseModel:
        """Persist one exact completed or interrupted terminal state."""
        _validate_idempotency(idempotency_key, request.session_id)
        session = await dependencies.mcp_session_lifecycle.finish(
            Uuid7Id(request.session_id),
            McpSessionState(request.status),
            _parse_rfc3339_microseconds(request.finished_at),
        )
        return _session_lifecycle_response(session)

    @application.post(
        _WORKSPACE_CHECKPOINT_PATH,
        dependencies=[Depends(authenticate)],
        response_model=WorkspaceCheckpointResponseModel,
    )
    async def checkpoint_workspace(
        request: WorkspaceCheckpointRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Acknowledge only after the exact encrypted staging transaction commits."""
        _validate_idempotency(idempotency_key, request.batch_digest)
        batch = request.to_domain()
        created = await dependencies.workspace_checkpoint.execute(batch)
        return JSONResponse(
            {
                "session_id": batch.session_id.value,
                "batch_digest": batch.batch_digest.value,
                "status": "checkpointed" if created else "already_checkpointed",
            },
            status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    _registered_routes = (
        session_status,
        register_session_credential,
        revoke_session_credential,
        begin_session,
        heartbeat_session,
        finish_session,
        checkpoint_workspace,
    )
    del _registered_routes


def _register_command_routes(
    application: FastAPI,
    dependencies: ApiDependencies,
    authenticate: Callable[[str | None], Awaitable[None]],
) -> None:

    @application.post(
        "/v1/bootstrap",
        dependencies=[Depends(authenticate)],
        response_model=BootstrapResponseModel,
    )
    async def bootstrap_local_brain(
        request: BootstrapRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Create the first installation/owner/Brain aggregate idempotently."""
        _validate_idempotency(idempotency_key, request.command_id)
        result = await dependencies.bootstrap.execute(request.to_domain())
        status_code = _bootstrap_status(result.disposition)
        return JSONResponse(
            {
                "installation_id": result.installation_id,
                "brain_id": result.brain_id,
                "disposition": result.disposition.value,
            },
            status_code=status_code,
        )

    @application.post(
        "/v1/readiness:verify",
        dependencies=[Depends(authenticate)],
        response_model=ReadinessVerificationResponseModel,
    )
    async def verify_readiness(
        request: ReadinessRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ReadinessVerificationResponseModel:
        """Run every live gate and return a Go-compatible complete receipt."""
        _validate_idempotency(idempotency_key, request.operation_id)
        verification = await dependencies.readiness.execute(request.to_domain())
        if verification.receipt is None:
            return ReadinessVerificationResponseModel(
                ready=False,
                receipt=None,
                failures=tuple(
                    ReadinessFailureResponseModel(
                        probe=failure.probe.evidence_key,
                        code=failure.code,
                    )
                    for failure in verification.failures
                ),
            )
        return ReadinessVerificationResponseModel(
            ready=verification.ready,
            receipt=_receipt_response(verification.receipt),
            failures=(),
        )

    @application.post(
        "/v1/active-release:stage",
        dependencies=[Depends(authenticate)],
        response_model=ActiveReleaseStageResponseModel,
    )
    async def stage_active_release(
        request: ActiveReleaseStageRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> JSONResponse:
        """Durably stage only an exact locally certified active pointer."""
        _validate_idempotency(idempotency_key, request.operation_id)
        result = await dependencies.active_release.stage(
            OperationId(request.operation_id),
            request.pointer.to_domain(),
        )
        return JSONResponse(
            {"stage_digest": result.stage_digest.value},
            status_code=status.HTTP_200_OK if result.already_staged else status.HTTP_201_CREATED,
        )

    @application.post(
        "/v1/active-release:commit",
        dependencies=[Depends(authenticate)],
        response_model=ActiveReleaseCommitResponseModel,
    )
    async def commit_active_release(
        request: ActiveReleaseCommitRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ActiveReleaseCommitResponseModel:
        """Mirror only the host-approved exact Core stage."""
        _validate_idempotency(idempotency_key, request.operation_id)
        digest = await dependencies.active_release.commit(
            OperationId(request.operation_id),
            Sha256Digest(request.stage_digest),
            request.pointer.to_domain(),
        )
        return ActiveReleaseCommitResponseModel(pointer_digest=digest.value)

    @application.post(
        "/v1/active-release:matches",
        dependencies=[Depends(authenticate)],
        response_model=ActiveReleaseMatchesResponseModel,
    )
    async def active_release_matches(
        request: ActiveReleaseMatchesRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ActiveReleaseMatchesResponseModel:
        """Return true only when every Core pointer field and mirror agrees."""
        pointer = request.pointer.to_domain()
        _validate_idempotency(idempotency_key, pointer.pointer_digest.value)
        return ActiveReleaseMatchesResponseModel(
            matches=await dependencies.active_release.matches(pointer)
        )

    @application.post(
        "/operations/rebuilds",
        dependencies=[Depends(authenticate)],
        response_model=ProjectionRebuildResponseModel,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def start_projection_rebuild(
        request: StartProjectionRebuildRequestModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ProjectionRebuildResponseModel:
        """Queue a generation-isolated rebuild at one immutable source watermark."""
        _validate_idempotency(idempotency_key, request.operation_id)
        result = await dependencies.projection_rebuild.execute(request.to_domain())
        return _projection_rebuild_response(result)

    @application.get(
        "/operations/rebuilds/{operation_id}",
        dependencies=[Depends(authenticate)],
        response_model=ProjectionRebuildResponseModel,
    )
    async def projection_rebuild_status(operation_id: str) -> ProjectionRebuildResponseModel:
        """Return progress, partial reason, and validation digest without memory content."""
        result = await dependencies.projection_rebuild_query.get(operation_id)
        if result is None:
            raise OperationError(ErrorCode.VALIDATION, "projection rebuild was not found")
        return _projection_rebuild_response(result)

    _registered_routes = (
        bootstrap_local_brain,
        verify_readiness,
        stage_active_release,
        commit_active_release,
        active_release_matches,
        start_projection_rebuild,
        projection_rebuild_status,
    )
    del _registered_routes


def _validate_idempotency(supplied: str | None, expected: str) -> None:
    if supplied != expected or _IDEMPOTENCY_PATTERN.fullmatch(supplied or "") is None:
        raise OperationError(ErrorCode.VALIDATION, "Idempotency-Key is invalid")


def _parse_rfc3339_microseconds(value: str) -> datetime:
    message = "timestamp is invalid"
    if _RFC3339_MICROSECONDS_PATTERN.fullmatch(value) is None:
        raise DomainValidationError(message)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise DomainValidationError(message) from error
    if parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
        raise DomainValidationError(message)
    return parsed


def _session_lifecycle_response(session: McpSession) -> SessionLifecycleResponseModel:
    return SessionLifecycleResponseModel(
        session_id=session.registration.session_id.value,
        state=session.state.value,
        revision=session.revision,
    )


def _request_size_rejection(request: Request) -> JSONResponse | None:
    content_lengths = request.headers.getlist("content-length")
    transfer_encodings = request.headers.getlist("transfer-encoding")
    if transfer_encodings or len(content_lengths) > 1:
        return _problem(
            ErrorCode.VALIDATION,
            400,
            "request framing is ambiguous",
            request,
        )
    if request.method in _MUTATION_METHODS and not content_lengths:
        return _problem(
            ErrorCode.VALIDATION,
            411,
            "Content-Length is required",
            request,
        )
    if content_lengths and not content_lengths[0].isdigit():
        return _problem(ErrorCode.VALIDATION, 400, "Content-Length is invalid", request)
    maximum = (
        _MAX_CHECKPOINT_REQUEST_BYTES
        if request.url.path == _WORKSPACE_CHECKPOINT_PATH
        else _MAX_REQUEST_BYTES
    )
    if content_lengths and int(content_lengths[0]) > maximum:
        return _problem(ErrorCode.VALIDATION, 413, "request body is too large", request)
    return None


def _bootstrap_status(disposition: BootstrapDisposition) -> int:
    if disposition is BootstrapDisposition.CREATED:
        return status.HTTP_201_CREATED
    return status.HTTP_200_OK


def _receipt_response(receipt: ReadinessReceipt) -> ReadinessReceiptResponseModel:
    binding = receipt.binding
    return ReadinessReceiptResponseModel(
        operation_id=binding.operation_id.value,
        plan_digest=binding.plan_digest.value,
        release_id=binding.release_id.value,
        generation_id=binding.generation_id.value,
        manifest_digest=binding.manifest_digest.value,
        compose_digest=binding.compose_digest.value,
        evaluated_at=format_rfc3339_microseconds(receipt.evaluated_at),
        results=tuple(
            ProbeEvidenceResponseModel(
                probe=result.probe.evidence_key,
                status=cast("Literal['passed']", result.status.value),
                operation_id=binding.operation_id.value,
                plan_digest=binding.plan_digest.value,
                release_id=binding.release_id.value,
                generation_id=binding.generation_id.value,
                manifest_digest=binding.manifest_digest.value,
                compose_digest=binding.compose_digest.value,
                evidence_digest=result.evidence_digest.value,
                observed_at=format_rfc3339_microseconds(result.observed_at),
            )
            for result in receipt.results
        ),
        receipt_digest=receipt.digest.value,
    )


def _projection_rebuild_response(value: ProjectionRebuild) -> ProjectionRebuildResponseModel:
    return ProjectionRebuildResponseModel(
        operation_id=value.operation_id,
        brain_id=value.brain_id.value,
        projection_type=value.projection_type.value,
        source_watermark=value.source_watermark,
        cursor=value.cursor,
        generation_id=value.generation_id.value,
        manifest_digest=value.manifest.digest.value,
        state=value.state.value,
        record_count=value.record_count,
        skipped_tombstones=value.skipped_tombstones,
        generation_digest=(
            None if value.generation_digest is None else value.generation_digest.value
        ),
        partial_reason=value.partial_reason,
        created_at=format_rfc3339_microseconds(value.created_at),
        updated_at=format_rfc3339_microseconds(value.updated_at),
    )


def _problem(
    code: ErrorCode,
    http_status: int,
    detail: str,
    request: Request,
    *,
    retryable: bool = False,
) -> JSONResponse:
    correlation_id = request.headers.get("x-correlation-id")
    if correlation_id is None or _IDEMPOTENCY_PATTERN.fullmatch(correlation_id) is None:
        correlation_id = str(uuid7())
    return JSONResponse(
        {
            "type": f"urn:agentmemory:error:{code.value.lower()}",
            "title": "AgentMemory request failed",
            "status": http_status,
            "detail": detail,
            "instance": str(request.url.path),
            "code": code.value,
            "correlation_id": correlation_id,
            "retryable": retryable,
        },
        status_code=http_status,
        media_type="application/problem+json",
    )


def _http_status(code: ErrorCode) -> int:
    return {
        ErrorCode.VALIDATION: 422,
        ErrorCode.UNAUTHENTICATED: 401,
        ErrorCode.FORBIDDEN: 403,
        ErrorCode.CONFLICT: 409,
        ErrorCode.DEPENDENCY_UNAVAILABLE: 503,
        ErrorCode.INTEGRITY_VIOLATION: 500,
        ErrorCode.DEADLINE_EXCEEDED: 504,
        ErrorCode.CAPACITY_EXHAUSTED: 507,
        ErrorCode.INTERNAL: 500,
    }[code]


def _set_security_headers(response: Response) -> None:
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
