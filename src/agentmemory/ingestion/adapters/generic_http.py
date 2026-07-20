"""Authenticated loopback AgentAdapterPort for the generic host integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit

import httpx

from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.ingestion.domain.spool_reconciliation import ClockSkew

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.adapter_capability import AdapterCapabilityManifest
    from agentmemory.ingestion.domain.agent_event import AgentEvent

_SUCCESS = frozenset({200, 201})
_CREDENTIAL_BYTES = 32


@dataclass(frozen=True, slots=True)
class HttpGenericAgentAdapter:
    """Register and capture through fixed authenticated Core loopback routes."""

    client: httpx.AsyncClient
    endpoint: str
    credential: bytes

    def __post_init__(self) -> None:
        """Refuse remote, credential-bearing, or path-bearing endpoints."""
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or len(self.credential) != _CREDENTIAL_BYTES
        ):
            msg = "generic adapter endpoint or credential is invalid"
            raise ValueError(msg)

    async def ensure_registered(self, manifest: AdapterCapabilityManifest) -> None:
        """Idempotently register the exact immutable generic-adapter release."""
        operation_id = f"generic-{manifest.manifest_sha256[:32]}"
        try:
            response = await self.client.post(
                f"{self.endpoint.rstrip('/')}/v1/agent-adapters:register",
                headers=self._headers(operation_id),
                json={
                    "manifest": {
                        "adapter_digest": manifest.adapter_digest,
                        "adapter_id": manifest.adapter_id,
                        "adapter_version": manifest.adapter_version,
                        "evidence_availability": [
                            {
                                "capability": item.capability.value,
                                "status": item.status.value,
                            }
                            for item in manifest.evidence_availability
                        ],
                        "schema_major": manifest.schema_major,
                        "supported_families": [
                            family.value for family in manifest.supported_families
                        ],
                    },
                    "operation_id": operation_id,
                    "permission_denied": [],
                },
            )
        except httpx.RequestError as error:
            msg = "generic adapter registration is unavailable"
            raise IngestionDependencyError(msg) from error
        if response.status_code not in _SUCCESS:
            msg = "generic adapter registration was rejected"
            raise IngestionDependencyError(msg)

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        """Durably append one canonical event and strictly parse its safe receipt."""
        canonical = AgentEventEnvelopeV1.from_domain(event).to_canonical_json()
        try:
            response = await self.client.post(
                f"{self.endpoint.rstrip('/')}/v1/agent-events:append",
                content=canonical,
                headers={
                    "Authorization": self._authorization(),
                    "Content-Type": "application/json",
                },
            )
        except httpx.RequestError as error:
            msg = "generic adapter event capture is unavailable"
            raise IngestionDependencyError(msg) from error
        if response.status_code not in _SUCCESS:
            msg = "generic adapter event capture was rejected"
            raise IngestionDependencyError(msg)
        try:
            value = cast("object", response.json())
        except ValueError as error:
            msg = "generic adapter received an invalid capture receipt"
            raise IngestionDependencyError(msg) from error
        if not isinstance(value, dict):
            msg = "generic adapter received an invalid capture receipt"
            raise IngestionDependencyError(msg)
        document = cast("dict[object, object]", value)
        event_id = document.get("event_id")
        status = document.get("status")
        ingested = document.get("ingested_at_microseconds")
        clock_skew = document.get("clock_skew_microseconds")
        if (
            set(document)
            != {
                "event_id",
                "status",
                "ingested_at_microseconds",
                "clock_skew_microseconds",
            }
            or not isinstance(event_id, str)
            or not isinstance(status, str)
            or not isinstance(ingested, int)
            or isinstance(ingested, bool)
            or not isinstance(clock_skew, int)
            or isinstance(clock_skew, bool)
            or not 0 <= ingested < 2**63
        ):
            msg = "generic adapter received an invalid capture receipt"
            raise IngestionDependencyError(msg)
        try:
            disposition = AppendDisposition(status)
        except ValueError as error:
            msg = "generic adapter received an invalid capture receipt"
            raise IngestionDependencyError(msg) from error
        if event_id != event.event_id or disposition not in {
            AppendDisposition.ACCEPTED,
            AppendDisposition.DUPLICATE,
            AppendDisposition.IGNORED,
        }:
            msg = "generic adapter received a conflicting capture receipt"
            raise IngestionDependencyError(msg)
        try:
            ClockSkew(clock_skew, ingested)
        except ValueError as error:
            msg = "generic adapter received an invalid capture receipt"
            raise IngestionDependencyError(msg) from error
        return AppendAgentEventResult(event_id, disposition, ingested, clock_skew)

    def _headers(self, idempotency_key: str) -> dict[str, str]:
        return {
            "Authorization": self._authorization(),
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
        }

    def _authorization(self) -> str:
        return f"Bearer {self.credential.hex()}"
