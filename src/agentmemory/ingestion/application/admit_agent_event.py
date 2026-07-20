"""ADP-001 daemon trust-boundary admission service."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, timedelta
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.capture import AdmittedAgentEvent
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionValidationError,
)

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.adapter_capability import RegisteredAdapterCapabilities
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.ports import AgentEventScopeResolver, PayloadContentReader
    from agentmemory.shared.clock import Clock

_MAX_FUTURE_SKEW = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class AgentEventAdmissionHandler:
    """Verify adapter evidence, content, time, and scope before persistence exists."""

    capabilities: RegisteredAdapterCapabilities
    scope_resolver: AgentEventScopeResolver
    payload_reader: PayloadContentReader
    clock: Clock

    async def execute(self, event: AgentEvent) -> AdmittedAgentEvent:
        """Return a trusted admission object without performing persistence."""
        self._verify_capabilities(event)
        await self._verify_payload(event)
        ingested_at = self.clock.now()
        if ingested_at.tzinfo is None or ingested_at.utcoffset() != UTC.utcoffset(None):
            msg = "ingested_at"
            raise IngestionValidationError.single(msg, "clock_not_utc")
        future_skew = event.occurred_at - ingested_at
        if future_skew > _MAX_FUTURE_SKEW:
            msg = "time"
            raise IngestionValidationError.single(msg, "future_clock_skew")
        identity = await self.scope_resolver.resolve(event.identity, event.provenance)
        skew = round((ingested_at - event.occurred_at).total_seconds() * 1_000_000)
        return AdmittedAgentEvent(event, identity, ingested_at, skew)

    def _verify_capabilities(self, event: AgentEvent) -> None:
        provenance = event.provenance
        manifest = self.capabilities.manifest
        identity_matches = (
            provenance.adapter_id == manifest.adapter_id
            and provenance.adapter_version == manifest.adapter_version
            and provenance.adapter_digest == manifest.adapter_digest
            and provenance.capability_manifest_digest == manifest.manifest_sha256
        )
        exact_method = self.capabilities.authorizes(
            event.event_type,
            provenance.capture_method,
        )
        supported = exact_method and set(event.capture_capabilities).issubset(
            manifest.capture_capabilities
        )
        if not identity_matches or not supported:
            msg = "adapter capabilities do not authorize the canonical event"
            raise IngestionAuthorizationError(msg)

    async def _verify_payload(self, event: AgentEvent) -> None:
        if event.payload is not None:
            value = event.payload.value
        elif event.payload_reference is not None:
            value = await self.payload_reader.read(event.payload_reference)
        else:  # pragma: no cover - AgentEvent constructor invariant.
            raise AssertionError
        if hashlib.sha256(value).hexdigest() != event.content_sha256:
            msg = "content_sha256"
            raise IngestionValidationError.single(msg, "hash_mismatch")
        if event.payload_reference is not None and len(value) != event.payload_reference.size_bytes:
            msg = "dataref"
            raise IngestionValidationError.single(msg, "size_mismatch")
