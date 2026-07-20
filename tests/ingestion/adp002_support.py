"""Deterministic ADP-002 event builders."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from agentmemory.ingestion.domain.agent_event import (
    AdapterCapabilityDescriptor,
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
)

EVENT_ID = "018f0000-0000-7000-8000-000000000101"
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
SESSION_ID = "018f0000-0000-7000-8000-000000000111"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000121"
ORDERING_KEY = "018f0000-0000-7000-8000-000000000131"
NOW = datetime(2026, 7, 20, 10, 12, 13, 123456, tzinfo=UTC)
DIGEST = "a" * 64
PAYLOAD = b'{"secret":"redacted","status":"observed"}'


def descriptor() -> AdapterCapabilityDescriptor:
    return AdapterCapabilityDescriptor.create(
        adapter_id="agentmemory.codex",
        adapter_version="1.0.0",
        adapter_digest=DIGEST,
        schema_major=1,
        supported_families=(EventFamily.SESSION_STARTED,),
        capture_capabilities=(CaptureCapability.SESSION_LIFECYCLE,),
    )


def event(*, event_id: str = EVENT_ID, sequence: int = 1) -> AgentEvent:
    configured = descriptor()
    return AgentEvent.create(
        specversion="1.0",
        event_id=event_id,
        source="urn:agentmemory:adapter:agentmemory.codex",
        event_type=EventFamily.SESSION_STARTED,
        subject=f"session/{SESSION_ID}",
        occurred_at=NOW,
        datacontenttype="application/json",
        dataschema=EventFamily.SESSION_STARTED.dataschema,
        identity=AgentEventIdentity(
            BRAIN_ID,
            PRINCIPAL_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            None,
            None,
            None,
        ),
        provenance=AgentEventProvenance(
            "codex",
            configured.adapter_id,
            configured.adapter_version,
            configured.adapter_digest,
            "unknown",
            SESSION_ID,
            None,
            None,
            None,
            configured.manifest_sha256,
            CaptureMethod.NATIVE,
            DIGEST,
        ),
        correlation_id=CORRELATION_ID,
        causation_id=None,
        ordering_key=ORDERING_KEY,
        sequence=sequence,
        classification=Classification.INTERNAL,
        retention_policy_id="default",
        capture_capabilities=(CaptureCapability.SESSION_LIFECYCLE,),
        payload=AgentEventData(PAYLOAD, hashlib.sha256(PAYLOAD).hexdigest()),
        payload_reference=None,
    )
