"""Register immutable adapter manifests and append effective capability observations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    AdapterCapabilityObservation,
    CapabilityChangeDisposition,
    CapabilityChangeResult,
    EvidenceAvailability,
    RegisteredAdapterCapabilities,
    compare_capability_availability,
)
from agentmemory.ingestion.domain.agent_event import CaptureCapability, CaptureMethod
from agentmemory.ingestion.domain.errors import IngestionConflictError, IngestionValidationError

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.adapter_capability import CapabilityCompatibilityWarning
    from agentmemory.ingestion.domain.ports import (
        AdapterCapabilityQueryRepository,
        AdapterCapabilityUnitOfWorkFactory,
        IngestionIdentityGenerator,
    )
    from agentmemory.shared.clock import Clock

_OPERATION = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_MAX_QUERY_WARNINGS = 100


@dataclass(frozen=True, slots=True)
class RegisterAgentAdapterCommand:
    """Register one immutable manifest and its current permission losses."""

    operation_id: str
    manifest: AdapterCapabilityManifest
    permission_denied: tuple[CaptureCapability, ...] = ()

    def __post_init__(self) -> None:
        """Require a canonical operation and non-fabricated permission overrides."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            field = "operation_id"
            raise IngestionValidationError.single(field, "invalid")
        canonical = tuple(sorted(set(self.permission_denied), key=str))
        if canonical != self.permission_denied:
            field = "permission_denied"
            raise IngestionValidationError.single(field, "not_canonical")
        for capability in self.permission_denied:
            if not self.manifest.availability_for(capability).observable:
                field = "permission_denied"
                raise IngestionValidationError.single(field, "capability_not_declared")

    @property
    def request_sha256(self) -> str:
        """Bind idempotency to exact manifest and permission evidence."""
        return _digest(
            {
                "command": "register_agent_adapter.v1",
                "manifest_sha256": self.manifest.manifest_sha256,
                "permission_denied": [item.value for item in self.permission_denied],
            }
        )


@dataclass(frozen=True, slots=True)
class ObserveAdapterCapabilitiesCommand:
    """Append one complete effective capability snapshot for a registered version."""

    operation_id: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    capability_manifest_digest: str
    evidence_availability: tuple[EvidenceAvailability, ...]

    def __post_init__(self) -> None:
        """Reject malformed command identity before repository access."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            field = "operation_id"
            raise IngestionValidationError.single(field, "invalid")
        if _TOKEN.fullmatch(self.adapter_id) is None:
            field = "adapter_id"
            raise IngestionValidationError.single(field, "invalid_token")
        if _SEMVER.fullmatch(self.adapter_version) is None:
            field = "adapter_version"
            raise IngestionValidationError.single(field, "invalid_semver")
        for value, field in (
            (self.adapter_digest, "adapter_digest"),
            (self.capability_manifest_digest, "capability_manifest_digest"),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise IngestionValidationError.single(field, "invalid_digest")

    @property
    def request_sha256(self) -> str:
        """Bind idempotency to the complete effective status matrix."""
        return _digest(
            {
                "adapter_digest": self.adapter_digest,
                "adapter_id": self.adapter_id,
                "adapter_version": self.adapter_version,
                "capability_manifest_digest": self.capability_manifest_digest,
                "command": "observe_adapter_capabilities.v1",
                "evidence_availability": _availability_document(self.evidence_availability),
            }
        )


@dataclass(frozen=True, slots=True)
class RegisterAgentAdapterHandler:
    """Enforce per-version immutability and compatibility observations."""

    unit_of_work: AdapterCapabilityUnitOfWorkFactory
    identities: IngestionIdentityGenerator
    clock: Clock

    async def execute(self, command: RegisterAgentAdapterCommand) -> CapabilityChangeResult:
        """Register, observe, or return an exact idempotent result atomically."""
        async with self.unit_of_work() as unit:
            replay = await unit.capabilities.replay(
                command.operation_id,
                command.request_sha256,
            )
            if replay is not None:
                return replay
            existing = await unit.capabilities.get(
                command.manifest.adapter_id,
                command.manifest.adapter_version,
            )
            if (
                existing is not None
                and existing.manifest.manifest_sha256 != command.manifest.manifest_sha256
            ):
                message = "adapter manifest is immutable for its version"
                raise IngestionConflictError(message)
            effective = _apply_permission_denials(command)
            if existing is not None and existing.observation.evidence_availability == effective:
                result = CapabilityChangeResult(
                    existing,
                    CapabilityChangeDisposition.UNCHANGED,
                    (),
                )
            else:
                previous = existing or await unit.capabilities.latest(command.manifest.adapter_id)
                revision = 1 if existing is None else existing.observation.revision + 1
                registration = RegisteredAdapterCapabilities(
                    command.manifest,
                    _observation(
                        self.identities,
                        self.clock,
                        command.operation_id,
                        command.manifest,
                        revision,
                        effective,
                    ),
                )
                warnings = (
                    ()
                    if previous is None
                    else compare_capability_availability(
                        previous.observation.evidence_availability,
                        effective,
                    )
                )
                disposition = (
                    CapabilityChangeDisposition.REGISTERED
                    if existing is None
                    else CapabilityChangeDisposition.OBSERVED
                )
                result = CapabilityChangeResult(registration, disposition, warnings)
            await unit.capabilities.persist(
                result,
                command.operation_id,
                command.request_sha256,
            )
            await unit.commit()
            return result


@dataclass(frozen=True, slots=True)
class ObserveAdapterCapabilitiesHandler:
    """Version permission loss/restoration without mutating the declared manifest."""

    unit_of_work: AdapterCapabilityUnitOfWorkFactory
    identities: IngestionIdentityGenerator
    clock: Clock

    async def execute(
        self,
        command: ObserveAdapterCapabilitiesCommand,
    ) -> CapabilityChangeResult:
        """Append a validated complete effective matrix or an idempotent receipt."""
        async with self.unit_of_work() as unit:
            replay = await unit.capabilities.replay(
                command.operation_id,
                command.request_sha256,
            )
            if replay is not None:
                return replay
            current = await unit.capabilities.get(command.adapter_id, command.adapter_version)
            if current is None:
                message = "adapter manifest is not registered"
                raise IngestionConflictError(message)
            manifest = current.manifest
            exact = (
                manifest.adapter_digest == command.adapter_digest
                and manifest.manifest_sha256 == command.capability_manifest_digest
            )
            if not exact:
                message = "adapter manifest identity conflicted"
                raise IngestionConflictError(message)
            candidate = RegisteredAdapterCapabilities(
                manifest,
                _observation(
                    self.identities,
                    self.clock,
                    command.operation_id,
                    manifest,
                    current.observation.revision + 1,
                    command.evidence_availability,
                ),
            )
            warnings = compare_capability_availability(
                current.observation.evidence_availability,
                candidate.observation.evidence_availability,
            )
            result = (
                CapabilityChangeResult(
                    current,
                    CapabilityChangeDisposition.UNCHANGED,
                    (),
                )
                if not warnings
                else CapabilityChangeResult(
                    candidate,
                    CapabilityChangeDisposition.OBSERVED,
                    warnings,
                )
            )
            await unit.capabilities.persist(
                result,
                command.operation_id,
                command.request_sha256,
            )
            await unit.commit()
            return result


@dataclass(frozen=True, slots=True)
class CapabilityMatrixView:
    """One operator-safe matrix with bounded compatibility warnings."""

    registration: RegisteredAdapterCapabilities
    warnings: tuple[CapabilityCompatibilityWarning, ...]


@dataclass(frozen=True, slots=True)
class ListAdapterCapabilitiesQuery:
    """Request every active adapter capability matrix."""

    warning_limit: int = 20

    def __post_init__(self) -> None:
        """Bound warning work and response size."""
        if not 0 <= self.warning_limit <= _MAX_QUERY_WARNINGS:
            field = "warning_limit"
            raise IngestionValidationError.single(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class GetAdapterCapabilitiesQuery:
    """Request one exact active adapter capability matrix."""

    adapter_id: str
    adapter_version: str
    warning_limit: int = 20

    def __post_init__(self) -> None:
        """Validate boundary tokens without selecting on host identity."""
        if _TOKEN.fullmatch(self.adapter_id) is None:
            field = "adapter_id"
            raise IngestionValidationError.single(field, "invalid_token")
        if _SEMVER.fullmatch(self.adapter_version) is None:
            field = "adapter_version"
            raise IngestionValidationError.single(field, "invalid_semver")
        if not 0 <= self.warning_limit <= _MAX_QUERY_WARNINGS:
            field = "warning_limit"
            raise IngestionValidationError.single(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class ListAdapterCapabilitiesHandler:
    """Build operator views from evidence availability, never host-name switches."""

    repository: AdapterCapabilityQueryRepository

    async def execute(
        self,
        query: ListAdapterCapabilitiesQuery,
    ) -> tuple[CapabilityMatrixView, ...]:
        """Return deterministic active matrices with bounded warnings."""
        registrations = await self.repository.list_active()
        views: list[CapabilityMatrixView] = []
        for registration in registrations:
            warnings = (
                ()
                if query.warning_limit == 0
                else await self.repository.warnings(
                    registration.manifest.adapter_id,
                    registration.manifest.adapter_version,
                    maximum=query.warning_limit,
                )
            )
            views.append(CapabilityMatrixView(registration, warnings))
        return tuple(views)


@dataclass(frozen=True, slots=True)
class GetAdapterCapabilitiesHandler:
    """Resolve one exact matrix for operator display and downstream policy."""

    repository: AdapterCapabilityQueryRepository

    async def execute(
        self,
        query: GetAdapterCapabilitiesQuery,
    ) -> CapabilityMatrixView | None:
        """Return one view or None without fabricating an unregistered matrix."""
        registration = await self.repository.get(query.adapter_id, query.adapter_version)
        if registration is None:
            return None
        warnings = (
            ()
            if query.warning_limit == 0
            else await self.repository.warnings(
                query.adapter_id,
                query.adapter_version,
                maximum=query.warning_limit,
            )
        )
        return CapabilityMatrixView(registration, warnings)


def _apply_permission_denials(
    command: RegisterAgentAdapterCommand,
) -> tuple[EvidenceAvailability, ...]:
    denied = frozenset(command.permission_denied)
    return tuple(
        replace(item, status=CaptureMethod.PERMISSION_DENIED) if item.capability in denied else item
        for item in command.manifest.evidence_availability
    )


def _observation(  # noqa: PLR0913 -- observation identity fields remain explicit.
    identities: IngestionIdentityGenerator,
    clock: Clock,
    operation_id: str,
    manifest: AdapterCapabilityManifest,
    revision: int,
    availability: tuple[EvidenceAvailability, ...],
) -> AdapterCapabilityObservation:
    return AdapterCapabilityObservation.create(
        observation_id=identities.new(),
        operation_id=operation_id,
        adapter_id=manifest.adapter_id,
        adapter_version=manifest.adapter_version,
        adapter_digest=manifest.adapter_digest,
        capability_manifest_digest=manifest.manifest_sha256,
        revision=revision,
        evidence_availability=availability,
        observed_at=clock.now(),
    )


def _availability_document(
    availability: tuple[EvidenceAvailability, ...],
) -> list[dict[str, str]]:
    return [
        {"capability": item.capability.value, "status": item.status.value} for item in availability
    ]


def _digest(document: dict[str, object]) -> str:
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()
