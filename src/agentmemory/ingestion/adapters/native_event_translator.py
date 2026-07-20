"""Reference ADP-001 typed native-observation translator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
    PayloadReference,
    required_capability,
)
from agentmemory.ingestion.domain.errors import IngestionAuthorizationError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.ingestion.domain.adapter_capability import AdapterCapabilityManifest


@dataclass(frozen=True, slots=True)
class NativeEventObservation:
    """Typed observable host data after adapter redaction and ID allocation."""

    event_id: str
    event_type: EventFamily
    subject: str
    occurred_at: datetime
    claimed_identity: AgentEventIdentity
    agent_host: str
    model_id: str
    session_id: str
    task_id: str | None
    turn_id: str | None
    subagent_id: str | None
    correlation_id: str
    causation_id: str | None
    ordering_key: str
    sequence: int | None
    classification: Classification
    retention_policy_id: str
    capture_method: CaptureMethod
    source_sha256: str
    payload: AgentEventData | None
    payload_reference: PayloadReference | None
    capture_capabilities: tuple[CaptureCapability, ...]


@dataclass(frozen=True, slots=True)
class CanonicalNativeEventTranslator:
    """Reference implementation of NativeEventTranslator for typed host adapters."""

    manifest: AdapterCapabilityManifest

    def translate(self, observation: NativeEventObservation) -> AgentEvent:
        """Bind typed native evidence to the adapter manifest and canonical envelope."""
        required = self.manifest.availability_for(required_capability(observation.event_type))
        if (
            observation.event_type not in self.manifest.supported_families
            or not set(observation.capture_capabilities).issubset(
                self.manifest.capture_capabilities
            )
            or required.status is not observation.capture_method
        ):
            msg = "native observation exceeds declared adapter capabilities"
            raise IngestionAuthorizationError(msg)
        provenance = AgentEventProvenance(
            agent_host=observation.agent_host,
            adapter_id=self.manifest.adapter_id,
            adapter_version=self.manifest.adapter_version,
            adapter_digest=self.manifest.adapter_digest,
            model_id=observation.model_id,
            session_id=observation.session_id,
            task_id=observation.task_id,
            turn_id=observation.turn_id,
            subagent_id=observation.subagent_id,
            capability_manifest_digest=self.manifest.manifest_sha256,
            capture_method=observation.capture_method,
            source_sha256=observation.source_sha256,
        )
        return AgentEvent.create(
            specversion="1.0",
            event_id=observation.event_id,
            source=f"urn:agentmemory:adapter:{self.manifest.adapter_id}",
            event_type=observation.event_type,
            subject=observation.subject,
            occurred_at=observation.occurred_at,
            datacontenttype="application/json",
            dataschema=observation.event_type.dataschema,
            identity=observation.claimed_identity,
            provenance=provenance,
            correlation_id=observation.correlation_id,
            causation_id=observation.causation_id,
            ordering_key=observation.ordering_key,
            sequence=observation.sequence,
            classification=observation.classification,
            retention_policy_id=observation.retention_policy_id,
            capture_capabilities=observation.capture_capabilities,
            payload=observation.payload,
            payload_reference=observation.payload_reference,
        )
