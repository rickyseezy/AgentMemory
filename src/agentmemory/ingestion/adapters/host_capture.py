"""Fast host hook with reused local IPC and encrypted fallback capture."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast
from urllib.parse import urlsplit

import httpx

from agentmemory.ingestion.adapters.inbound.agent_event_schema import (
    AgentEventEnvelopeV1,
    parse_agent_event_json,
)
from agentmemory.ingestion.adapters.outbound.offline_spool import SpoolCapacityError
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionDependencyError, IngestionValidationError

_MAXIMUM_HOOK_DEADLINE_SECONDS = 1.0


class CaptureStatus(StrEnum):
    """Safe hook status that never contains captured content."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    IGNORED = "ignored"
    DEFERRED = "deferred"
    SPOOL_FULL = "spool_full"
    SPOOL_UNAVAILABLE = "spool_unavailable"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class HookCaptureResult:
    """Bounded content-free result returned to the coding host."""

    event_id: str | None
    status: CaptureStatus


class EventRedactor(Protocol):
    """Apply adapter policy before any persistence boundary."""

    def redact(self, canonical_event: bytes) -> bytes:
        """Return strict redacted AgentEvent JSON bytes."""
        ...


class LocalIpcClient(Protocol):
    """Append via a reused authenticated local connection pool."""

    async def append(self, canonical_event: bytes) -> AppendDisposition:
        """Return one terminal durable policy status or raise a transport failure."""
        ...


class FallbackSpool(Protocol):
    """Persist one canonical event through the bounded host-side fallback."""

    def enqueue(
        self,
        event_id: str,
        ordering_key: str,
        sequence: int | None,
        canonical_event: bytes,
    ) -> bool:
        """Return only after the exact event is durably committed."""
        ...


class HttpAgentEventIpcClient:
    """Bounded loopback-only HTTP client that reuses one AsyncClient pool."""

    def __init__(self, client: httpx.AsyncClient, endpoint: str, credential: str) -> None:
        """Bind one reusable client to the closed loopback append endpoint."""
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/v1/agent-events:append"
            or parsed.query
            or parsed.fragment
        ):
            msg = "AgentEvent IPC endpoint must be the fixed loopback append route"
            raise ValueError(msg)
        self._client = client
        self._endpoint = endpoint
        self._authorization = f"Bearer {credential}"

    async def append(self, canonical_event: bytes) -> AppendDisposition:
        """Send one canonical item over the existing keep-alive pool."""
        response = await self._client.post(
            self._endpoint,
            content=canonical_event,
            headers={
                "Authorization": self._authorization,
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        untyped_document = cast("object", response.json())
        document = (
            cast("dict[str, object]", untyped_document)
            if isinstance(untyped_document, dict)
            else {}
        )
        value = document.get("status")
        if not isinstance(value, str):
            msg = "AgentEvent IPC returned an invalid status"
            raise TypeError(msg)
        try:
            disposition = AppendDisposition(value)
        except ValueError as error:
            msg = "AgentEvent IPC returned an invalid status"
            raise TypeError(msg) from error
        if disposition not in {
            AppendDisposition.ACCEPTED,
            AppendDisposition.DUPLICATE,
            AppendDisposition.IGNORED,
        }:
            msg = "AgentEvent IPC returned a non-durable status"
            raise TypeError(msg)
        return disposition


@dataclass(frozen=True, slots=True)
class AgentEventCaptureHook:
    """Validate/redact then append or durably defer without enrichment work."""

    redactor: EventRedactor
    ipc: LocalIpcClient
    spool: FallbackSpool
    ipc_timeout_seconds: float = 0.035
    hook_deadline_seconds: float = 0.05

    def __post_init__(self) -> None:
        """Require enough bounded time for IPC followed by local fallback."""
        if not (
            0
            < self.ipc_timeout_seconds
            < self.hook_deadline_seconds
            <= _MAXIMUM_HOOK_DEADLINE_SECONDS
        ):
            msg = "capture hook deadlines are invalid"
            raise ValueError(msg)

    async def capture(self, native_event: bytes) -> HookCaptureResult:
        """Return promptly with a content-free status on every expected failure."""
        try:
            async with asyncio.timeout(self.hook_deadline_seconds):
                return await self._capture(native_event)
        except TimeoutError:
            return HookCaptureResult(None, CaptureStatus.DEADLINE_EXCEEDED)

    async def _capture(self, native_event: bytes) -> HookCaptureResult:
        """Perform bounded canonicalization, direct append, and encrypted fallback."""
        try:
            redacted = self.redactor.redact(native_event)
            event = parse_agent_event_json(redacted)
            canonical = AgentEventEnvelopeV1.from_domain(event).to_canonical_json()
        except IngestionValidationError, ValueError:
            return HookCaptureResult(None, CaptureStatus.INVALID)
        except IngestionDependencyError, OSError:
            return HookCaptureResult(None, CaptureStatus.SPOOL_UNAVAILABLE)
        try:
            async with asyncio.timeout(self.ipc_timeout_seconds):
                disposition = await self.ipc.append(canonical)
            return HookCaptureResult(event.event_id, CaptureStatus(disposition.value))
        except TimeoutError, TypeError, httpx.HTTPError, OSError, ValueError:
            try:
                await asyncio.to_thread(
                    self.spool.enqueue,
                    event.event_id,
                    event.ordering_key,
                    event.sequence,
                    canonical,
                )
            except SpoolCapacityError:
                return HookCaptureResult(event.event_id, CaptureStatus.SPOOL_FULL)
            except IngestionDependencyError, OSError:
                return HookCaptureResult(event.event_id, CaptureStatus.SPOOL_UNAVAILABLE)
            return HookCaptureResult(event.event_id, CaptureStatus.DEFERRED)
