"""Strict authenticated HTTP contract for ID-001 workspace resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Protocol

from fastapi import APIRouter, Security
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.identity.application.commands.observe_checkout import ObserveCheckoutCommand
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    IdentityCandidate,
    ObservedWorkspaceQuery,
    ProjectManifest,
    StableId,
    VcsIdentity,
    VcsType,
    WorkspaceResolution,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.checkout import CheckoutAggregate

_AUTHORIZATION = APIKeyHeader(
    name="Authorization",
    scheme_name="AgentMemoryBearer",
    description="Bearer followed by a local AgentMemory capability credential.",
    auto_error=False,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class DeviceObservationModel(_StrictModel):
    """Installation-keyed device and location evidence without raw machine/path values."""

    device_id: str
    device_fingerprint: str
    volume_fingerprint: str
    path_fingerprint: str
    verified: bool
    logical_path_fingerprint: str | None = None
    file_fingerprint: str | None = None

    def to_domain(self) -> DeviceIdentity:
        """Translate a strict boundary observation into immutable domain evidence."""
        return DeviceIdentity(
            StableId(self.device_id),
            Fingerprint(self.device_fingerprint),
            Fingerprint(self.volume_fingerprint),
            Fingerprint(self.path_fingerprint),
            self.verified,
            _optional_fingerprint(self.logical_path_fingerprint),
            _optional_fingerprint(self.file_fingerprint),
        )


class VcsObservationModel(_StrictModel):
    """Privacy-safe VCS fingerprints produced by the local session bridge."""

    vcs_type: Literal["git", "none"]
    repository_fingerprint: str | None
    checkout_fingerprint: str | None
    worktree_fingerprint: str | None
    repository_lookup_approved: bool
    common_directory_fingerprint: str | None = None
    branch: str | None = None
    head_commit: str | None = None
    remote_fingerprints: list[str] = Field(default_factory=list)
    dirty_digest: str | None = None

    def to_domain(self) -> VcsIdentity:
        """Translate only closed VCS values and versioned digest evidence."""
        return VcsIdentity(
            VcsType(self.vcs_type),
            _optional_fingerprint(self.repository_fingerprint),
            _optional_fingerprint(self.checkout_fingerprint),
            _optional_fingerprint(self.worktree_fingerprint),
            repository_lookup_approved=self.repository_lookup_approved,
            common_directory_fingerprint=_optional_fingerprint(self.common_directory_fingerprint),
            branch=self.branch,
            head_commit=self.head_commit,
            remote_fingerprints=tuple(Fingerprint(value) for value in self.remote_fingerprints),
            dirty_digest=_optional_fingerprint(self.dirty_digest),
        )


class ProjectManifestObservationModel(_StrictModel):
    """Validated non-authoritative manifest declaration observed at the host boundary."""

    schema_version: Literal[1]
    project_id: str
    repository_id: str | None = None

    def to_domain(self) -> ProjectManifest:
        """Translate strict manifest identity fields without accepting authority fields."""
        return ProjectManifest(
            self.schema_version,
            StableId(self.project_id),
            None if self.repository_id is None else StableId(self.repository_id),
        )


class ResolveWorkspaceRequestModel(_StrictModel):
    """Authenticated bridge observation for ResolveWorkspaceQuery."""

    operation_id: str = Field(min_length=1, max_length=128)
    brain_id: str
    actor_id: str
    grant_id: str
    device: DeviceObservationModel
    vcs: VcsObservationModel | None = None
    manifest: ProjectManifestObservationModel | None = None

    def query(self) -> ObservedWorkspaceQuery:
        """Create the path-free application query."""
        return ObservedWorkspaceQuery(
            self.operation_id,
            StableId(self.brain_id),
            StableId(self.actor_id),
            StableId(self.grant_id),
        )


class IdentityCandidateResponseModel(_StrictModel):
    """One authorized identity candidate."""

    project_id: str
    repository_id: str
    checkout_id: str | None


class ResolveWorkspaceResponseModel(_StrictModel):
    """Deterministic selected, ambiguous, or absent workspace resolution."""

    brain_id: str
    status: Literal["resolved", "ambiguous", "not_found"]
    source: (
        Literal[
            "manifest",
            "checkout_registry",
            "repository_fingerprint",
            "approved_heuristic",
        ]
        | None
    )
    selected: IdentityCandidateResponseModel | None
    candidates: tuple[IdentityCandidateResponseModel, ...]
    explanation: tuple[str, ...]


class ObserveCheckoutRequestModel(_StrictModel):
    """Authenticated, path-free Checkout observation command."""

    operation_id: str = Field(min_length=1, max_length=128)
    brain_id: str
    actor_id: str
    grant_id: str
    repository_id: str
    device: DeviceObservationModel
    vcs: VcsObservationModel
    expected_version: int | None = Field(default=None, ge=1)

    def command(self) -> ObserveCheckoutCommand:
        """Translate the strict transport body to an immutable application command."""
        return ObserveCheckoutCommand(
            operation_id=self.operation_id,
            brain_id=StableId(self.brain_id),
            actor_id=StableId(self.actor_id),
            grant_id=StableId(self.grant_id),
            repository_id=StableId(self.repository_id),
            device=self.device.to_domain(),
            vcs=self.vcs.to_domain(),
            expected_version=self.expected_version,
        )


class ObserveCheckoutResponseModel(_StrictModel):
    """Content-free canonical Checkout observation result."""

    brain_id: str
    repository_id: str
    checkout_id: str
    version: int


class AuthenticatorPort(Protocol):
    """Authenticate a local capability before identity authorization."""

    async def authenticate(self, authorization: str | None) -> None:
        """Reject an absent, malformed, expired, or revoked capability."""
        ...


class ResolveObservedWorkspacePort(Protocol):
    """Resolve privacy-safe host observations against canonical identity state."""

    async def execute_observed(
        self,
        query: ObservedWorkspaceQuery,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
        manifest: ProjectManifest | None,
    ) -> WorkspaceResolution:
        """Return a typed resolution without mutating identity state."""
        ...


class ObserveCheckoutPort(Protocol):
    """Commit one authenticated Checkout observation."""

    async def execute(self, command: ObserveCheckoutCommand) -> CheckoutAggregate:
        """Return the created or updated aggregate snapshot."""
        ...


class _ContractAuthenticator:
    async def authenticate(self, authorization: str | None) -> None:
        del authorization
        msg = "contract-only dependency cannot authenticate"
        raise RuntimeError(msg)


class _ContractResolver:
    async def execute_observed(
        self,
        query: ObservedWorkspaceQuery,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
        manifest: ProjectManifest | None,
    ) -> WorkspaceResolution:
        del query, device, vcs, manifest
        msg = "contract-only dependency cannot resolve a workspace"
        raise RuntimeError(msg)


class _ContractObserver:
    async def execute(self, command: ObserveCheckoutCommand) -> CheckoutAggregate:
        del command
        msg = "contract-only dependency cannot observe a Checkout"
        raise RuntimeError(msg)


def create_identity_router(  # noqa: C901 -- Two closed endpoints share one router composition.
    authenticator: AuthenticatorPort,
    resolver: ResolveObservedWorkspacePort,
    observer: ObserveCheckoutPort | None = None,
) -> APIRouter:
    """Create the identity router with only constructor-supplied capabilities."""
    router = APIRouter(prefix="/v1")
    checkout_observer = observer or _ContractObserver()

    @router.post(
        "/projects:resolve",
        operation_id="ResolveWorkspaceQuery",
        response_model=ResolveWorkspaceResponseModel,
    )
    async def resolve_workspace(
        request: ResolveWorkspaceRequestModel,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ResolveWorkspaceResponseModel | JSONResponse:
        """Resolve one keyed checkout observation without accepting a raw filesystem path."""
        try:
            await authenticator.authenticate(authorization)
            result = await resolver.execute_observed(
                request.query(),
                request.device.to_domain(),
                None if request.vcs is None else request.vcs.to_domain(),
                None if request.manifest is None else request.manifest.to_domain(),
            )
        except IdentityAuthorizationError:
            return _problem("AM_FORBIDDEN", 403, "identity scope is not authorized", request)
        except IdentityConflictError:
            return _problem("AM_CONFLICT", 409, "workspace identity conflicts", request)
        except IdentityValidationError:
            return _problem("AM_VALIDATION", 422, "workspace evidence is invalid", request)
        except IdentityDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "identity dependency is unavailable",
                request,
                retryable=True,
            )
        return _resolution_response(result)

    @router.post(
        "/checkouts:observe",
        operation_id="ObserveCheckoutCommand",
        response_model=ObserveCheckoutResponseModel,
    )
    async def observe_checkout(
        request: ObserveCheckoutRequestModel,
        authorization: Annotated[str | None, Security(_AUTHORIZATION)],
    ) -> ObserveCheckoutResponseModel | JSONResponse:
        """Commit keyed host and Git evidence without accepting a filesystem path."""
        try:
            await authenticator.authenticate(authorization)
            result = await checkout_observer.execute(request.command())
        except IdentityAuthorizationError:
            return _problem("AM_FORBIDDEN", 403, "identity scope is not authorized", request)
        except IdentityConflictError:
            return _problem("AM_CONFLICT", 409, "Checkout observation conflicts", request)
        except IdentityValidationError:
            return _problem("AM_VALIDATION", 422, "Checkout evidence is invalid", request)
        except IdentityDependencyError:
            return _problem(
                "AM_DEPENDENCY_UNAVAILABLE",
                503,
                "identity dependency is unavailable",
                request,
                retryable=True,
            )
        return ObserveCheckoutResponseModel(
            brain_id=result.brain_id.value,
            repository_id=result.current.repository_id.value,
            checkout_id=result.checkout_id.value,
            version=result.version,
        )

    _registered_routes = (resolve_workspace, observe_checkout)
    del _registered_routes
    return router


def create_contract_identity_router() -> APIRouter:
    """Create a deterministic schema-only router without runtime capabilities."""
    return create_identity_router(
        _ContractAuthenticator(),
        _ContractResolver(),
        _ContractObserver(),
    )


def _resolution_response(result: WorkspaceResolution) -> ResolveWorkspaceResponseModel:
    selected = None if result.selected is None else _candidate_response(result.selected)
    return ResolveWorkspaceResponseModel(
        brain_id=result.brain_id.value,
        status=result.status.value,
        source=None if result.source is None else result.source.value,
        selected=selected,
        candidates=tuple(_candidate_response(candidate) for candidate in result.candidates),
        explanation=result.explanation,
    )


def _candidate_response(candidate: IdentityCandidate) -> IdentityCandidateResponseModel:
    return IdentityCandidateResponseModel(
        project_id=candidate.project_id.value,
        repository_id=candidate.repository_id.value,
        checkout_id=None if candidate.checkout_id is None else candidate.checkout_id.value,
    )


def _optional_fingerprint(value: str | None) -> Fingerprint | None:
    return None if value is None else Fingerprint(value)


def _problem(
    code: str,
    status_code: int,
    detail: str,
    request: ResolveWorkspaceRequestModel | ObserveCheckoutRequestModel,
    *,
    retryable: bool = False,
) -> JSONResponse:
    return JSONResponse(
        {
            "type": f"urn:agentmemory:error:{code.lower()}",
            "title": code,
            "status": status_code,
            "detail": detail,
            "code": code,
            "retryable": retryable,
            "correlation_id": request.operation_id,
        },
        status_code=status_code,
        media_type="application/problem+json",
    )
