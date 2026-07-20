"""Canonical generated-schema AgentEvent encoder."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.agent_event import AgentEvent


class CanonicalAgentEventEncoder:
    """Serialize domain events through the shared strict transport contract."""

    def encode(self, event: AgentEvent) -> bytes:
        """Return deterministic canonical JSON bytes."""
        return AgentEventEnvelopeV1.from_domain(event).to_canonical_json()
