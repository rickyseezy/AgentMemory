"""ADP-002 minimal command that durably appends one admitted event."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.capture import AppendDisposition

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.capture import AdmittedAgentEvent, AppendAgentEventResult
    from agentmemory.ingestion.domain.ports import (
        AgentEventEncoder,
        AgentEventEnvelopeEncryptor,
        AgentEventUnitOfWorkFactory,
    )


@dataclass(frozen=True, slots=True)
class AppendAgentEventCommand:
    """Trusted admission evidence required by the durable write boundary."""

    admitted: AdmittedAgentEvent


@dataclass(frozen=True, slots=True)
class AppendAgentEventHandler:
    """Encrypt then atomically commit event, outbox, and audit before ACK."""

    encoder: AgentEventEncoder
    encryptor: AgentEventEnvelopeEncryptor
    unit_of_work: AgentEventUnitOfWorkFactory

    async def execute(self, command: AppendAgentEventCommand) -> AppendAgentEventResult:
        """Return accepted/duplicate only after a successful durable transaction."""
        admitted = command.admitted
        canonical = self.encoder.encode(admitted.event)
        encrypted = await self.encryptor.encrypt(
            event_id=admitted.event.event_id,
            brain_id=admitted.identity.brain_id,
            classification=admitted.event.classification.value,
            plaintext=canonical,
        )
        async with self.unit_of_work() as unit_of_work:
            result = await unit_of_work.events.append(admitted, encrypted)
            if result.disposition is AppendDisposition.ACCEPTED:
                await unit_of_work.commit()
            return result
