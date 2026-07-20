"""Authenticated daemon boundary combining admission and durable append."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, cast

from agentmemory.ingestion.application.admit_agent_event import AgentEventAdmissionHandler
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventCommand
from agentmemory.ingestion.application.privacy import CapturePolicyCommand, CapturePolicyPipeline
from agentmemory.ingestion.domain.agent_event import AgentEventData, EventFamily
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.privacy import CaptureDisposition

if TYPE_CHECKING:
    from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.ports import (
        AdapterCapabilityRegistry,
        AgentEventScopeResolver,
        CapturePolicyDecisionRepository,
        PayloadContentReader,
    )
    from agentmemory.shared.clock import Clock


@dataclass(frozen=True, slots=True)
class CaptureAgentEventHandler:
    """Resolve adapter authority, admit untrusted content, then durably append."""

    capabilities: AdapterCapabilityRegistry
    scope_resolver: AgentEventScopeResolver
    payload_reader: PayloadContentReader
    policy_pipeline: CapturePolicyPipeline
    policy_decisions: CapturePolicyDecisionRepository
    appender: AppendAgentEventHandler
    clock: Clock

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        """Execute the complete minimal local capture boundary."""
        provenance = event.provenance
        registration = await self.capabilities.get(
            provenance.adapter_id,
            provenance.adapter_version,
            provenance.adapter_digest,
        )
        admitted = await AgentEventAdmissionHandler(
            registration,
            self.scope_resolver,
            self.payload_reader,
            self.clock,
        ).execute(event)
        raw = bytearray(await read_payload_bytes(event, self.payload_reader))
        result = await self.policy_pipeline.execute(
            CapturePolicyCommand(
                brain_id=admitted.identity.brain_id,
                repository_id=admitted.identity.repository_id,
                content=raw,
                media_type=event.datacontenttype,
                source_path=source_path_for_policy(event),
                declared_classification=event.classification,
            )
        )
        if result.disposition is CaptureDisposition.EXCLUDED:
            decided_at = round(admitted.ingested_at.timestamp() * 1_000_000)
            await self.policy_decisions.record(
                event.event_id,
                admitted.identity.brain_id,
                admitted.identity.principal_id,
                result,
                decided_at,
            )
            return AppendAgentEventResult(
                event.event_id,
                AppendDisposition.IGNORED,
                decided_at,
                admitted.clock_skew_microseconds,
            )
        if result.payload is None:  # pragma: no cover - CapturePolicyResult invariant.
            raise AssertionError
        sanitized_data = AgentEventData(result.payload, result.output_sha256 or "")
        sanitized_event = replace(
            event,
            payload=sanitized_data,
            payload_reference=None,
            classification=result.classification,
        )
        sanitized = replace(admitted, event=sanitized_event, privacy=result)
        return await self.appender.execute(AppendAgentEventCommand(sanitized))


async def read_payload_bytes(event: AgentEvent, reader: PayloadContentReader) -> bytes:
    """Read the exact admitted inline or immutable referenced payload."""
    if event.payload is not None:
        return event.payload.value
    if event.payload_reference is not None:
        return await reader.read(event.payload_reference)
    raise AssertionError  # pragma: no cover - AgentEvent invariant.


def source_path_for_policy(event: AgentEvent) -> str | None:
    """Derive the observable file path used only by capture exclusion policy."""
    if event.event_type not in {
        EventFamily.FILE_READ,
        EventFamily.FILE_CHANGED,
        EventFamily.FILE_DELETED,
        EventFamily.FILE_RENAMED,
    }:
        return None
    if event.payload is None:
        return event.subject
    untyped_document = cast("object", json.loads(event.payload.value))
    if not isinstance(untyped_document, dict):
        return event.subject
    document = cast("dict[object, object]", untyped_document)
    for field in ("path", "new_path", "old_path"):
        value = document.get(field)
        if isinstance(value, str):
            return value
    return event.subject
