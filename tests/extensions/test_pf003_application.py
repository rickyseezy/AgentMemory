"""PF-003 governed external-adapter registration application tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self

import pytest

from agentmemory.extensions.application.register_adapter import (
    RegisterAdapterCommand,
    RegisterAdapterHandler,
)
from agentmemory.extensions.domain.errors import (
    AdapterAuthorizationError,
    AdapterConflictError,
    AdapterProbeError,
    AdapterTrustError,
)
from agentmemory.extensions.domain.models import (
    AdapterAuthorizationRequest,
    AdapterCapability,
    AdapterKind,
    AdapterManifest,
    AdapterPermission,
    AdapterProbeEvidence,
    AdapterRegistration,
    ProtocolVersion,
)
from agentmemory.extensions.domain.ports import AdapterRegistrationEvent

if TYPE_CHECKING:
    from types import TracebackType

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def _manifest() -> AdapterManifest:
    return AdapterManifest.create(
        schema_version=1,
        adapter_id="external-agent",
        adapter_version="1.0.0",
        kind=AdapterKind.AGENT,
        package_digest=DIGEST_A,
        signature_digest=DIGEST_B,
        signer_identity="approved-publisher",
        protocol_min=ProtocolVersion(1, 0),
        protocol_max=ProtocolVersion(1, 2),
        capabilities=(AdapterCapability.AGENT_EVENT_CAPTURE,),
        requested_permissions=(AdapterPermission.CANONICAL_EVENT_WRITE,),
    )


def _command() -> RegisterAdapterCommand:
    return RegisterAdapterCommand(
        operation_id="register-external-agent-1",
        brain_id="018f0000-0000-7000-8000-000000000311",
        actor_id="018f0000-0000-7000-8000-000000000312",
        grant_id="018f0000-0000-7000-8000-000000000313",
        manifest=_manifest(),
        requested_at=NOW,
    )


@pytest.mark.asyncio
async def test_pf003_registers_only_after_auth_trust_permission_and_live_probe() -> None:
    dependencies = Dependencies()
    handler = dependencies.handler()

    result = await handler.execute(_command())

    assert result.manifest_digest == _manifest().manifest_digest
    assert result.evidence.negotiated_protocol == ProtocolVersion(1, 2)
    assert dependencies.calls == ["authorize", "verify", "permissions", "probe"]
    assert dependencies.repository.saved == result
    assert dependencies.unit.committed is True
    expected_event = AdapterRegistrationEvent(
        event_id="018f0000-0000-7000-8000-000000000314",
        event_type="adapter.registration.activated.v1",
        registration_id="018f0000-0000-7000-8000-000000000314",
        brain_id="018f0000-0000-7000-8000-000000000311",
        actor_id="018f0000-0000-7000-8000-000000000312",
        grant_id="018f0000-0000-7000-8000-000000000313",
        adapter_id="external-agent",
        adapter_kind="agent",
        manifest_digest=result.manifest_digest,
        package_digest=DIGEST_A,
        evidence_digest=result.evidence.evidence_digest,
        registration_digest=result.registration_digest,
        occurred_at=NOW,
    )
    assert dependencies.audit.events == [expected_event]
    assert dependencies.outbox.events == [expected_event]


@pytest.mark.asyncio
async def test_pf003_exact_operation_replay_performs_no_external_work() -> None:
    dependencies = Dependencies()
    expected = await dependencies.handler().execute(_command())
    dependencies.calls.clear()

    replayed = await dependencies.handler().execute(_command())

    assert replayed == expected
    assert dependencies.calls == ["authorize"]


@pytest.mark.asyncio
async def test_pf003_conflicting_operation_or_immutable_version_is_rejected() -> None:
    dependencies = Dependencies()
    command = _command()
    await dependencies.handler().execute(command)

    changed = RegisterAdapterCommand(
        operation_id=command.operation_id,
        brain_id=command.brain_id,
        actor_id=command.actor_id,
        grant_id=command.grant_id,
        manifest=replace(command.manifest, package_digest=DIGEST_C),
        requested_at=command.requested_at,
    )
    with pytest.raises(AdapterConflictError):
        await dependencies.handler().execute(changed)

    second_operation = RegisterAdapterCommand(
        operation_id="register-external-agent-2",
        brain_id=command.brain_id,
        actor_id=command.actor_id,
        grant_id=command.grant_id,
        manifest=changed.manifest,
        requested_at=command.requested_at,
    )
    with pytest.raises(AdapterConflictError, match="immutable"):
        await dependencies.handler().execute(second_operation)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "error_type", "expected_calls"),
    [
        ("authorize", AdapterAuthorizationError, ["authorize"]),
        ("verify", AdapterTrustError, ["authorize", "verify"]),
        ("permissions", AdapterAuthorizationError, ["authorize", "verify", "permissions"]),
        ("probe", AdapterProbeError, ["authorize", "verify", "permissions", "probe"]),
    ],
)
async def test_pf003_fails_closed_before_persistence(
    failure: str, error_type: type[Exception], expected_calls: list[str]
) -> None:
    dependencies = Dependencies(failure=failure)

    with pytest.raises(error_type):
        await dependencies.handler().execute(_command())

    assert dependencies.calls == expected_calls
    assert dependencies.repository.saved is None
    assert dependencies.unit.committed is False
    assert dependencies.audit.events == []
    assert dependencies.outbox.events == []


@pytest.mark.asyncio
async def test_pf003_rejects_probe_identity_or_capability_substitution() -> None:
    dependencies = Dependencies(probe_substitution=True)

    with pytest.raises(AdapterProbeError, match="probe evidence"):
        await dependencies.handler().execute(_command())

    assert dependencies.repository.saved is None


@dataclass
class Repository:
    operations: dict[str, tuple[str, AdapterRegistration]] = field(
        default_factory=dict[str, tuple[str, AdapterRegistration]]
    )
    versions: dict[tuple[str, str, str], AdapterRegistration] = field(
        default_factory=dict[tuple[str, str, str], AdapterRegistration]
    )
    saved: AdapterRegistration | None = None

    async def replay(self, operation_id: str, request_digest: str) -> AdapterRegistration | None:
        existing = self.operations.get(operation_id)
        if existing is None:
            return None
        if existing[0] != request_digest:
            message = "operation identity conflict"
            raise AdapterConflictError(message)
        return existing[1]

    async def get_version(
        self,
        brain_id: str,
        adapter_id: str,
        adapter_version: str,
    ) -> AdapterRegistration | None:
        return self.versions.get((brain_id, adapter_id, adapter_version))

    async def save(
        self, operation_id: str, request_digest: str, registration: AdapterRegistration
    ) -> None:
        self.saved = registration
        self.operations[operation_id] = (request_digest, registration)
        self.versions[
            (
                registration.brain_id,
                registration.manifest.adapter_id,
                registration.manifest.adapter_version,
            )
        ] = registration

    async def link_operation(
        self,
        operation_id: str,
        request_digest: str,
        registration: AdapterRegistration,
    ) -> None:
        self.operations[operation_id] = (request_digest, registration)


@dataclass
class EventSink:
    events: list[AdapterRegistrationEvent] = field(default_factory=list[AdapterRegistrationEvent])

    async def append(self, event: AdapterRegistrationEvent) -> None:
        self.events.append(event)


@dataclass
class Unit:
    repository: Repository
    audit: EventSink
    outbox: EventSink
    committed: bool = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        _ = exc_type, exc_value, traceback

    async def commit(self) -> None:
        self.committed = True


@dataclass
class Dependencies:
    failure: str | None = None
    probe_substitution: bool = False
    calls: list[str] = field(default_factory=list[str])
    repository: Repository = field(default_factory=Repository)
    audit: EventSink = field(default_factory=EventSink)
    outbox: EventSink = field(default_factory=EventSink)
    unit: Unit = field(init=False)

    def __post_init__(self) -> None:
        self.unit = Unit(self.repository, self.audit, self.outbox)

    def handler(self) -> RegisterAdapterHandler:
        return RegisterAdapterHandler(
            unit_of_work=lambda: self.unit,
            authorization=self,
            trust=self,
            permissions=self,
            probe=self,
            identities=self,
            supported_protocol_min=ProtocolVersion(1, 0),
            supported_protocol_max=ProtocolVersion(1, 2),
        )

    async def authorize(self, request: AdapterAuthorizationRequest) -> None:
        _ = request
        self.calls.append("authorize")
        if self.failure == "authorize":
            message = "denied"
            raise AdapterAuthorizationError(message)

    async def verify(self, manifest: AdapterManifest) -> None:
        _ = manifest
        self.calls.append("verify")
        if self.failure == "verify":
            message = "invalid signature"
            raise AdapterTrustError(message)

    async def approve(self, manifest: AdapterManifest) -> None:
        _ = manifest
        self.calls.append("permissions")
        if self.failure == "permissions":
            message = "permissions denied"
            raise AdapterAuthorizationError(message)

    async def probe(
        self, manifest: AdapterManifest, negotiated_protocol: ProtocolVersion
    ) -> AdapterProbeEvidence:
        self.calls.append("probe")
        if self.failure == "probe":
            message = "probe failed"
            raise AdapterProbeError(message)
        evidence = AdapterProbeEvidence.create(
            manifest=manifest,
            negotiated_protocol=negotiated_protocol,
            observed_capabilities=manifest.capabilities,
            runtime_digest=DIGEST_C,
            probed_at=NOW,
        )
        if self.probe_substitution:
            substituted = replace(manifest, package_digest=DIGEST_C)
            return AdapterProbeEvidence.create(
                manifest=substituted,
                negotiated_protocol=negotiated_protocol,
                observed_capabilities=substituted.capabilities,
                runtime_digest=evidence.runtime_digest,
                probed_at=evidence.probed_at,
            )
        return evidence

    def new(self) -> str:
        return "018f0000-0000-7000-8000-000000000314"


def test_pf003_command_digest_binds_authority_manifest_and_operation_payload() -> None:
    command = _command()
    assert len(command.request_digest) == 64
    assert (
        command.request_digest
        != RegisterAdapterCommand(
            operation_id="different-operation",
            brain_id=command.brain_id,
            actor_id=command.actor_id,
            grant_id=command.grant_id,
            manifest=command.manifest,
            requested_at=command.requested_at,
        ).request_digest
    )
