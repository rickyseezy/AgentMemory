"""ING-001 bounded worker orchestration for acknowledged canonical events."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.durable_processing import (
    DurableProcessingResult,
    InboxClaimDisposition,
    ProcessingDisposition,
)
from agentmemory.ingestion.domain.errors import IngestionDependencyError, IngestionIntegrityError

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.ports import (
        CanonicalEventProjectionVerifier,
        DurableEventProcessingRepository,
    )
    from agentmemory.shared.clock import Clock

_LEASE_MICROSECONDS = 60 * 1_000_000
_RETRY_MICROSECONDS = 1 * 1_000_000
_DEFAULT_POLL_SECONDS = 0.5
_MAX_POLL_SECONDS = 10.0
_MAX_OWNER_LENGTH = 128
_CONSUMER = "canonical-event-projection-v1"


@dataclass(frozen=True, slots=True)
class DurableEventProcessingHandler:
    """Claim, verify, and atomically finish one durable outbox message."""

    repository: DurableEventProcessingRepository
    verifier: CanonicalEventProjectionVerifier
    clock: Clock
    owner: str

    def __post_init__(self) -> None:
        """Require one stable bounded worker identity."""
        if not self.owner or len(self.owner) > _MAX_OWNER_LENGTH:
            msg = "durable ingestion worker owner is invalid"
            raise ValueError(msg)

    async def execute_once(self) -> DurableProcessingResult:
        """Return only after the terminal/retry transaction has committed."""
        now = _microseconds(self.clock)
        message = await self.repository.claim_next(
            self.owner,
            now,
            now + _LEASE_MICROSECONDS,
        )
        if message is None:
            return DurableProcessingResult.idle()
        inbox = await self.repository.claim_inbox(
            message,
            _CONSUMER,
            self.owner,
            now,
            now + _LEASE_MICROSECONDS,
        )
        if inbox.disposition is InboxClaimDisposition.REPLAY:
            await self.repository.complete_replay(message, inbox, now)
            return DurableProcessingResult(
                message.message_id,
                message.event_id,
                ProcessingDisposition.COMPLETED,
            )
        if inbox.disposition is InboxClaimDisposition.WAIT:
            await self.repository.release_retry(
                message,
                inbox,
                "consumer_claim_busy",
                now + _RETRY_MICROSECONDS,
            )
            return DurableProcessingResult(
                message.message_id,
                message.event_id,
                ProcessingDisposition.RETRY_SCHEDULED,
            )
        try:
            projection = await self.verifier.verify(message)
        except IngestionIntegrityError:
            await self.repository.require_repair(
                message,
                inbox,
                "canonical_integrity_violation",
                now,
            )
            disposition = ProcessingDisposition.REPAIR_REQUIRED
        except IngestionDependencyError:
            await self.repository.release_retry(
                message,
                inbox,
                "dependency_unavailable",
                now + _RETRY_MICROSECONDS,
            )
            disposition = ProcessingDisposition.RETRY_SCHEDULED
        else:
            await self.repository.complete(message, inbox, projection, now)
            disposition = ProcessingDisposition.COMPLETED
        return DurableProcessingResult(message.message_id, message.event_id, disposition)


@dataclass(frozen=True, slots=True)
class DurableIngestionWorker:
    """Recover expired leases at startup and continuously drain durable work."""

    repository: DurableEventProcessingRepository
    handler: DurableEventProcessingHandler
    clock: Clock
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        """Bound idle wakeups and graceful shutdown latency."""
        if not 0 < self.poll_seconds <= _MAX_POLL_SECONDS:
            msg = "durable ingestion worker poll interval is invalid"
            raise ValueError(msg)

    async def run(self, stop: asyncio.Event) -> None:
        """Recover once before processing and isolate transient queue failures."""
        await self._recover_until_available(stop)
        while not stop.is_set():
            result = await self._execute_or_idle()
            if result.disposition is not ProcessingDisposition.IDLE:
                continue
            await _wait_or_stop(stop, self.poll_seconds)

    async def _recover_until_available(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.repository.recover_expired_leases(_microseconds(self.clock))
                while await self.repository.alert_unprocessed_events(_microseconds(self.clock)):
                    continue
            except IngestionDependencyError:
                await _wait_or_stop(stop, self.poll_seconds)
            else:
                return

    async def _execute_or_idle(self) -> DurableProcessingResult:
        try:
            return await self.handler.execute_once()
        except IngestionDependencyError:
            return DurableProcessingResult.idle()


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return


def _microseconds(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)
