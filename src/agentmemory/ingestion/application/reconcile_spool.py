"""ADP-005 bounded, lease-serialized interruption reconciliation use case."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.spool_reconciliation import select_acknowledgements

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.ports import OfflineSpoolRepository, SpoolBatchUploader
    from agentmemory.ingestion.domain.spool_reconciliation import ClockSkew
    from agentmemory.shared.clock import Clock

_MAXIMUM_BATCH_ITEMS = 100
_MAXIMUM_BATCH_BYTES = 1024 * 1024
_MINIMUM_BATCH_BYTES = 96 * 1024
_MAXIMUM_WORKER_ID_BYTES = 128
_MAXIMUM_LEASE_SECONDS = 300


class ReconcileSpoolStatus(StrEnum):
    """Content-free command outcome for scheduling and diagnostics."""

    IDLE = "idle"
    BUSY = "busy"
    RECONCILED = "reconciled"


@dataclass(frozen=True, slots=True)
class ReconcileSpoolCommand:
    """One bounded recovery attempt under a renewable owner identity."""

    worker_id: str
    maximum_items: int = _MAXIMUM_BATCH_ITEMS
    maximum_bytes: int = _MAXIMUM_BATCH_BYTES
    lease_seconds: float = 30.0
    upload_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        """Reject ambiguous owners and unbounded batch/lease policy."""
        if (
            not self.worker_id
            or len(self.worker_id.encode()) > _MAXIMUM_WORKER_ID_BYTES
            or "\x00" in self.worker_id
        ):
            field = "worker_id"
            raise IngestionValidationError.single(field, "invalid")
        if not 1 <= self.maximum_items <= _MAXIMUM_BATCH_ITEMS:
            field = "maximum_items"
            raise IngestionValidationError.single(field, "out_of_range")
        if not _MINIMUM_BATCH_BYTES <= self.maximum_bytes <= _MAXIMUM_BATCH_BYTES:
            field = "maximum_bytes"
            raise IngestionValidationError.single(field, "out_of_range")
        if not 1 <= self.lease_seconds <= _MAXIMUM_LEASE_SECONDS:
            field = "lease_seconds"
            raise IngestionValidationError.single(field, "out_of_range")
        if not 0 < self.upload_timeout_seconds < self.lease_seconds:
            field = "upload_timeout_seconds"
            raise IngestionValidationError.single(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class ReconcileSpoolResult:
    """Bounded reconciliation evidence without captured content."""

    status: ReconcileSpoolStatus
    attempted: int
    acknowledged: int
    remaining: int
    clock_skews: tuple[ClockSkew, ...]


@dataclass(frozen=True, slots=True)
class ReconcileSpoolHandler:
    """Upload one ordered batch and erase only Core-proven durable prefixes."""

    repository: OfflineSpoolRepository
    uploader: SpoolBatchUploader
    clock: Clock

    async def execute(self, command: ReconcileSpoolCommand) -> ReconcileSpoolResult:
        """Serialize recovery, preserve ordering, and release the lease on every exit."""
        acquired_at = _utc_microseconds(self.clock.now())
        expires_at = acquired_at + round(command.lease_seconds * 1_000_000)
        acquired = await self.repository.try_acquire_lease(
            command.worker_id,
            acquired_at,
            expires_at,
        )
        if not acquired:
            return ReconcileSpoolResult(
                ReconcileSpoolStatus.BUSY,
                0,
                0,
                await self.repository.count_pending(),
                (),
            )
        try:
            records = await self.repository.pending(
                maximum_items=command.maximum_items,
                maximum_bytes=command.maximum_bytes,
            )
            if not records:
                return ReconcileSpoolResult(ReconcileSpoolStatus.IDLE, 0, 0, 0, ())
            async with asyncio.timeout(command.upload_timeout_seconds):
                upload_results = await self.uploader.upload(records)
            acknowledgements = select_acknowledgements(records, upload_results)
            acknowledged = await self.repository.acknowledge(
                command.worker_id,
                acknowledgements,
                _utc_microseconds(self.clock.now()),
            )
            if acknowledged != len(acknowledgements):
                msg = "spool repository acknowledged an inconsistent durable prefix"
                raise RuntimeError(msg)
            return ReconcileSpoolResult(
                ReconcileSpoolStatus.RECONCILED,
                len(records),
                acknowledged,
                await self.repository.count_pending(),
                tuple(item.clock_skew for item in acknowledgements),
            )
        finally:
            await self.repository.release_lease(command.worker_id)


def _utc_microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        field = "clock"
        raise IngestionValidationError.single(field, "not_utc")
    return round(value.timestamp() * 1_000_000)
