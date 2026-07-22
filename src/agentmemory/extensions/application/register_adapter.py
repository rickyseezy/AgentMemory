"""PF-003 authorize, verify, probe, and atomically register external adapters."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agentmemory.extensions.domain.errors import (
    AdapterConflictError,
    AdapterProbeError,
    AdapterValidationError,
)
from agentmemory.extensions.domain.models import (
    AdapterAuthorizationRequest,
    AdapterRegistration,
    AdapterRegistrationState,
    ProtocolVersion,
    negotiate_protocol,
)
from agentmemory.extensions.domain.ports import AdapterRegistrationEvent

if TYPE_CHECKING:
    from agentmemory.extensions.domain.models import AdapterManifest
    from agentmemory.extensions.domain.ports import (
        AdapterCapabilityProbe,
        AdapterIdentityGenerator,
        AdapterPackageTrust,
        AdapterPermissionPolicy,
        AdapterRegistrationAuthorization,
        AdapterRegistrationUnitOfWorkFactory,
    )

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ERR_OPERATION = "operation_id is invalid"
_ERR_AUTHORITY = "authorization identity is invalid"
_ERR_TIME = "requested_at must be UTC"
_ERR_PROTOCOL = "supported protocol range is invalid"
_ERR_IMMUTABLE = "adapter version is immutable"
_ERR_PROBE = "probe evidence substituted manifest or protocol"


@dataclass(frozen=True, slots=True)
class RegisterAdapterCommand:
    """Request governed activation of one external adapter package."""

    operation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    manifest: AdapterManifest
    requested_at: datetime

    def __post_init__(self) -> None:
        """Reject unstable command coordinates before port access."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            raise AdapterValidationError(_ERR_OPERATION)
        # Registration validates these identities again when durable state is created.
        if any(not value for value in (self.brain_id, self.actor_id, self.grant_id)):
            raise AdapterValidationError(_ERR_AUTHORITY)
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() != UTC.utcoffset(None):
            raise AdapterValidationError(_ERR_TIME)

    @property
    def request_digest(self) -> str:
        """Bind idempotency to operation, authority, manifest, and canonical time."""
        document = {
            "actor_id": self.actor_id,
            "brain_id": self.brain_id,
            "command": "register_adapter.v1",
            "grant_id": self.grant_id,
            "manifest_digest": self.manifest.manifest_digest,
            "operation_id": self.operation_id,
            "requested_at": self.requested_at.isoformat().replace("+00:00", "Z"),
        }
        encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    @property
    def authorization(self) -> AdapterAuthorizationRequest:
        """Return the domain-owned current authority request."""
        return AdapterAuthorizationRequest(
            brain_id=self.brain_id,
            actor_id=self.actor_id,
            grant_id=self.grant_id,
            requested_at=self.requested_at,
        )


@dataclass(frozen=True, slots=True)
class RegisterAdapterHandler:
    """Orchestrate registration without importing a vendor or framework."""

    unit_of_work: AdapterRegistrationUnitOfWorkFactory
    authorization: AdapterRegistrationAuthorization
    trust: AdapterPackageTrust
    permissions: AdapterPermissionPolicy
    probe: AdapterCapabilityProbe
    identities: AdapterIdentityGenerator
    supported_protocol_min: ProtocolVersion
    supported_protocol_max: ProtocolVersion

    def __post_init__(self) -> None:
        """Require one coherent daemon protocol range."""
        if self.supported_protocol_min > self.supported_protocol_max:
            raise AdapterValidationError(_ERR_PROTOCOL)

    async def execute(self, command: RegisterAdapterCommand) -> AdapterRegistration:
        """Authorize before reads and activate only exact live-proven packages."""
        await self.authorization.authorize(command.authorization)
        async with self.unit_of_work() as unit:
            replay = await unit.repository.replay(command.operation_id, command.request_digest)
            if replay is not None:
                return replay
            existing = await unit.repository.get_version(
                command.brain_id,
                command.manifest.adapter_id,
                command.manifest.adapter_version,
            )
            if existing is not None:
                if existing.manifest_digest != command.manifest.manifest_digest:
                    raise AdapterConflictError(_ERR_IMMUTABLE)
                await unit.repository.link_operation(
                    command.operation_id,
                    command.request_digest,
                    existing,
                )
                await unit.commit()
                return existing

            await self.trust.verify(command.manifest)
            await self.permissions.approve(command.manifest)
            negotiated = negotiate_protocol(
                command.manifest,
                self.supported_protocol_min,
                self.supported_protocol_max,
            )
            evidence = await self.probe.probe(command.manifest, negotiated)
            if not evidence.binds(command.manifest) or evidence.negotiated_protocol != negotiated:
                raise AdapterProbeError(_ERR_PROBE)

            registration = AdapterRegistration.create(
                registration_id=self.identities.new(),
                brain_id=command.brain_id,
                actor_id=command.actor_id,
                grant_id=command.grant_id,
                manifest=command.manifest,
                evidence=evidence,
                state=AdapterRegistrationState.ACTIVE,
                registered_at=command.requested_at,
            )
            event = _registration_event(self.identities.new(), registration)
            await unit.repository.save(command.operation_id, command.request_digest, registration)
            await unit.audit.append(event)
            await unit.outbox.append(event)
            await unit.commit()
            return registration


def _registration_event(
    event_id: str,
    registration: AdapterRegistration,
) -> AdapterRegistrationEvent:
    return AdapterRegistrationEvent(
        event_id=event_id,
        event_type="adapter.registration.activated.v1",
        registration_id=registration.registration_id,
        brain_id=registration.brain_id,
        actor_id=registration.actor_id,
        grant_id=registration.grant_id,
        adapter_id=registration.manifest.adapter_id,
        adapter_kind=registration.manifest.kind.value,
        manifest_digest=registration.manifest_digest,
        package_digest=registration.package_digest,
        evidence_digest=registration.evidence.evidence_digest,
        registration_digest=registration.registration_digest,
        occurred_at=registration.registered_at,
    )
