"""Authenticated daemon boundary combining admission and durable append."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.application.admit_agent_event import AgentEventAdmissionHandler
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventCommand

if TYPE_CHECKING:
    from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.capture import AppendAgentEventResult
    from agentmemory.ingestion.domain.ports import (
        AdapterCapabilityRegistry,
        AgentEventScopeResolver,
        PayloadContentReader,
    )
    from agentmemory.shared.clock import Clock


@dataclass(frozen=True, slots=True)
class CaptureAgentEventHandler:
    """Resolve adapter authority, admit untrusted content, then durably append."""

    capabilities: AdapterCapabilityRegistry
    scope_resolver: AgentEventScopeResolver
    payload_reader: PayloadContentReader
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
        return await self.appender.execute(AppendAgentEventCommand(admitted))
