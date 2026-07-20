"""ADP-003 registration and effective-observation application tests."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self

import pytest

from agentmemory.ingestion.application.adapter_capabilities import (
    GetAdapterCapabilitiesHandler,
    GetAdapterCapabilitiesQuery,
    ListAdapterCapabilitiesHandler,
    ListAdapterCapabilitiesQuery,
    ObserveAdapterCapabilitiesCommand,
    ObserveAdapterCapabilitiesHandler,
    RegisterAgentAdapterCommand,
    RegisterAgentAdapterHandler,
)
from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    CapabilityChangeDisposition,
    CapabilityChangeResult,
    CapabilityCompatibilityImpact,
    CapabilityCompatibilityWarning,
    EvidenceAvailability,
    RegisteredAdapterCapabilities,
)
from agentmemory.ingestion.domain.agent_event import (
    CaptureCapability,
    CaptureMethod,
    EventFamily,
)
from agentmemory.ingestion.domain.errors import IngestionConflictError, IngestionValidationError
from tests.ingestion.capability_support import complete_availability

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.ingestion.domain.ports import (
        AdapterCapabilityRepository,
        AdapterCapabilityUnitOfWork,
    )

NOW = datetime(2026, 7, 20, 12, 30, tzinfo=UTC)
DIGEST = "a" * 64


def manifest(
    version: str = "1.0.0",
    *,
    session_method: CaptureMethod = CaptureMethod.NATIVE,
) -> AdapterCapabilityManifest:
    return AdapterCapabilityManifest.create(
        adapter_id="agentmemory.codex",
        adapter_version=version,
        adapter_digest=DIGEST,
        schema_major=1,
        supported_families=(EventFamily.SESSION_STARTED,),
        evidence_availability=complete_availability(
            session_lifecycle=session_method,
        ),
    )


class _Repository:
    def __init__(self) -> None:
        self.results: dict[str, tuple[str, CapabilityChangeResult]] = {}
        self.registrations: dict[tuple[str, str], RegisteredAdapterCapabilities] = {}
        self.persisted: list[CapabilityChangeResult] = []

    async def replay(
        self,
        operation_id: str,
        request_sha256: str,
    ) -> CapabilityChangeResult | None:
        stored = self.results.get(operation_id)
        if stored is None:
            return None
        if stored[0] != request_sha256:
            message = "operation identity conflicted"
            raise IngestionConflictError(message)
        return replace(stored[1], disposition=CapabilityChangeDisposition.DUPLICATE)

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> RegisteredAdapterCapabilities | None:
        return self.registrations.get((adapter_id, adapter_version))

    async def latest(self, adapter_id: str) -> RegisteredAdapterCapabilities | None:
        values = [
            value
            for (candidate, _version), value in self.registrations.items()
            if candidate == adapter_id
        ]
        return values[-1] if values else None

    async def persist(
        self,
        result: CapabilityChangeResult,
        operation_id: str,
        request_sha256: str,
    ) -> None:
        registration = result.registration
        key = (registration.manifest.adapter_id, registration.manifest.adapter_version)
        self.registrations[key] = registration
        self.results[operation_id] = (request_sha256, result)
        self.persisted.append(result)


class _UnitOfWork:
    def __init__(self, repository: _Repository) -> None:
        self.capabilities: AdapterCapabilityRepository = repository
        self.commits = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, exc, traceback
        return None

    async def commit(self) -> None:
        self.commits += 1


@dataclass
class _Factory:
    unit: _UnitOfWork

    def __call__(self) -> AdapterCapabilityUnitOfWork:
        return self.unit


class _Ids:
    def __init__(self) -> None:
        self.value = 0x301

    def new(self) -> str:
        result = f"018f0000-0000-7000-8000-{self.value:012x}"
        self.value += 1
        return result


class _QueryRepository:
    def __init__(
        self,
        registrations: tuple[RegisteredAdapterCapabilities, ...],
        warnings: tuple[CapabilityCompatibilityWarning, ...],
    ) -> None:
        self.registrations = registrations
        self.warning_values = warnings
        self.warning_limits: list[int] = []

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> RegisteredAdapterCapabilities | None:
        return next(
            (
                item
                for item in self.registrations
                if item.manifest.adapter_id == adapter_id
                and item.manifest.adapter_version == adapter_version
            ),
            None,
        )

    async def list_active(self) -> tuple[RegisteredAdapterCapabilities, ...]:
        return self.registrations

    async def warnings(
        self,
        adapter_id: str,
        adapter_version: str,
        *,
        maximum: int = 100,
    ) -> tuple[CapabilityCompatibilityWarning, ...]:
        assert adapter_id == "agentmemory.codex"
        assert adapter_version == "1.0.0"
        self.warning_limits.append(maximum)
        return self.warning_values[:maximum]


@dataclass(frozen=True)
class _Clock:
    def now(self) -> datetime:
        return NOW


def _handlers() -> tuple[
    RegisterAgentAdapterHandler,
    ObserveAdapterCapabilitiesHandler,
    _Repository,
    _UnitOfWork,
]:
    repository = _Repository()
    unit = _UnitOfWork(repository)
    dependencies = (_Factory(unit), _Ids(), _Clock())
    return (
        RegisterAgentAdapterHandler(*dependencies),
        ObserveAdapterCapabilitiesHandler(*dependencies),
        repository,
        unit,
    )


@pytest.mark.asyncio
async def test_register_creates_immutable_manifest_and_initial_observation() -> None:
    register, _observe, repository, unit = _handlers()
    result = await register.execute(RegisterAgentAdapterCommand("register-1", manifest()))
    assert result.disposition is CapabilityChangeDisposition.REGISTERED
    assert result.registration.observation.revision == 1
    assert result.registration.observation.operation_id == "register-1"
    assert result.warnings == ()
    assert len(repository.persisted) == 1
    assert unit.commits == 1


@pytest.mark.asyncio
async def test_registration_permission_override_is_effective_not_manifest_mutation() -> None:
    register, _observe, _repository, _unit = _handlers()
    configured = manifest()
    command = RegisterAgentAdapterCommand(
        "register-1",
        configured,
        (CaptureCapability.SESSION_LIFECYCLE,),
    )
    result = await register.execute(command)
    assert result.registration.manifest.availability_for(
        CaptureCapability.SESSION_LIFECYCLE
    ).status is CaptureMethod.NATIVE
    assert result.registration.availability_for(
        CaptureCapability.SESSION_LIFECYCLE
    ).status is CaptureMethod.PERMISSION_DENIED
    assert command.request_sha256 == (
        "0264555538880081e83f7955a9e3bfb3929905ffbf34e48859da9711c7053b0c"
    )


def test_observation_request_digest_binds_canonical_complete_matrix() -> None:
    configured = manifest()
    command = ObserveAdapterCapabilitiesCommand(
        "observe-1",
        configured.adapter_id,
        configured.adapter_version,
        configured.adapter_digest,
        configured.manifest_sha256,
        configured.evidence_availability,
    )
    assert command.request_sha256 == (
        "b479741a62aa5e115a9f849cb805f882eec2a1a2d7c7585e2a278bec94ad73ac"
    )


@pytest.mark.asyncio
async def test_exact_operation_retry_is_duplicate_and_conflicting_reuse_fails() -> None:
    register, _observe, repository, unit = _handlers()
    command = RegisterAgentAdapterCommand("register-1", manifest())
    await register.execute(command)
    duplicate = await register.execute(command)
    assert duplicate.disposition is CapabilityChangeDisposition.DUPLICATE
    assert len(repository.persisted) == 1
    assert unit.commits == 1
    with pytest.raises(IngestionConflictError):
        await register.execute(
            RegisterAgentAdapterCommand(
                "register-1",
                manifest(session_method=CaptureMethod.INFERRED),
            )
        )


@pytest.mark.asyncio
async def test_same_adapter_version_is_immutable_but_exact_state_can_be_unchanged() -> None:
    register, _observe, _repository, _unit = _handlers()
    configured = manifest()
    await register.execute(RegisterAgentAdapterCommand("register-1", configured))
    unchanged = await register.execute(RegisterAgentAdapterCommand("register-2", configured))
    assert unchanged.disposition is CapabilityChangeDisposition.UNCHANGED
    with pytest.raises(IngestionConflictError, match="immutable"):
        await register.execute(
            RegisterAgentAdapterCommand(
                "register-3",
                manifest(session_method=CaptureMethod.INFERRED),
            )
        )


@pytest.mark.asyncio
async def test_new_version_creates_observation_and_compatibility_warning() -> None:
    register, _observe, _repository, _unit = _handlers()
    await register.execute(RegisterAgentAdapterCommand("register-1", manifest()))
    changed = await register.execute(
        RegisterAgentAdapterCommand(
            "register-2",
            manifest("2.0.0", session_method=CaptureMethod.INFERRED),
        )
    )
    assert changed.disposition is CapabilityChangeDisposition.REGISTERED
    assert [(item.code, item.impact.value) for item in changed.warnings] == [
        ("capture_method_changed", "degraded")
    ]


@pytest.mark.asyncio
async def test_permission_loss_and_restore_are_versioned_without_manifest_mutation() -> None:
    register, observe, _repository, _unit = _handlers()
    configured = manifest()
    created = await register.execute(RegisterAgentAdapterCommand("register-1", configured))
    denied_matrix = tuple(
        EvidenceAvailability(
            item.capability,
            (
                CaptureMethod.PERMISSION_DENIED
                if item.capability is CaptureCapability.SESSION_LIFECYCLE
                else item.status
            ),
        )
        for item in configured.evidence_availability
    )
    denied = await observe.execute(
        ObserveAdapterCapabilitiesCommand(
            "observe-2",
            configured.adapter_id,
            configured.adapter_version,
            configured.adapter_digest,
            configured.manifest_sha256,
            denied_matrix,
        )
    )
    assert denied.registration.observation.revision == 2
    assert denied.warnings[0].code == "permission_lost"
    assert denied.registration.manifest == created.registration.manifest

    restored = await observe.execute(
        ObserveAdapterCapabilitiesCommand(
            "observe-3",
            configured.adapter_id,
            configured.adapter_version,
            configured.adapter_digest,
            configured.manifest_sha256,
            configured.evidence_availability,
        )
    )
    assert restored.registration.observation.revision == 3
    assert restored.warnings[0].code == "permission_restored"


@pytest.mark.asyncio
async def test_observation_rejects_fabricated_signal_and_unknown_manifest() -> None:
    register, observe, _repository, _unit = _handlers()
    configured = manifest()
    with pytest.raises(IngestionConflictError, match="not registered"):
        await observe.execute(
            ObserveAdapterCapabilitiesCommand(
                "observe-1",
                configured.adapter_id,
                configured.adapter_version,
                configured.adapter_digest,
                configured.manifest_sha256,
                configured.evidence_availability,
            )
        )
    await register.execute(RegisterAgentAdapterCommand("register-1", configured))
    fabricated = complete_availability(
        session_lifecycle=CaptureMethod.NATIVE,
        file_observation=CaptureMethod.NATIVE,
    )
    with pytest.raises(IngestionValidationError, match="exceeds"):
        await observe.execute(
            ObserveAdapterCapabilitiesCommand(
                "observe-2",
                configured.adapter_id,
                configured.adapter_version,
                configured.adapter_digest,
                configured.manifest_sha256,
                fabricated,
            )
        )


@pytest.mark.asyncio
async def test_query_handlers_expose_evidence_and_bounded_warnings_without_host_logic() -> None:
    register, _observe, repository, _unit = _handlers()
    await register.execute(RegisterAgentAdapterCommand("register-1", manifest()))
    registration = repository.registrations[("agentmemory.codex", "1.0.0")]
    warning = CapabilityCompatibilityWarning(
        CaptureCapability.SESSION_LIFECYCLE,
        CaptureMethod.NATIVE,
        CaptureMethod.PERMISSION_DENIED,
        CapabilityCompatibilityImpact.BREAKING,
        "permission_lost",
    )
    queries = _QueryRepository((registration,), (warning,))

    listed = await ListAdapterCapabilitiesHandler(queries).execute(
        ListAdapterCapabilitiesQuery(1)
    )
    found = await GetAdapterCapabilitiesHandler(queries).execute(
        GetAdapterCapabilitiesQuery("agentmemory.codex", "1.0.0", 0)
    )
    missing = await GetAdapterCapabilitiesHandler(queries).execute(
        GetAdapterCapabilitiesQuery("agentmemory.codex", "9.0.0", 1)
    )

    assert listed[0].registration.availability_for(
        CaptureCapability.SESSION_LIFECYCLE
    ).status is CaptureMethod.NATIVE
    assert listed[0].warnings == (warning,)
    assert found is not None
    assert found.warnings == ()
    assert missing is None
    assert queries.warning_limits == [1]


def test_capability_queries_reject_unbounded_operator_display() -> None:
    with pytest.raises(IngestionValidationError):
        ListAdapterCapabilitiesQuery(101)
    with pytest.raises(IngestionValidationError):
        GetAdapterCapabilitiesQuery("agentmemory.codex", "1.0.0", -1)
    with pytest.raises(IngestionValidationError):
        GetAdapterCapabilitiesQuery("Codex", "1.0.0")
    with pytest.raises(IngestionValidationError):
        GetAdapterCapabilitiesQuery("agentmemory.codex", "latest")


def test_observation_command_rejects_invalid_adapter_identity_before_storage() -> None:
    configured = manifest()
    values = (
        ("Codex", configured.adapter_version),
        (configured.adapter_id, "latest"),
    )
    for adapter_id, adapter_version in values:
        with pytest.raises(IngestionValidationError):
            ObserveAdapterCapabilitiesCommand(
                "observe-1",
                adapter_id,
                adapter_version,
                configured.adapter_digest,
                configured.manifest_sha256,
                configured.evidence_availability,
            )
