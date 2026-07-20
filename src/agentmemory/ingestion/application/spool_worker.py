"""Continuous bounded spool recovery policy independent of process supervision."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.errors import IngestionDependencyError, IngestionValidationError

if TYPE_CHECKING:
    from agentmemory.ingestion.application.reconcile_spool import (
        ReconcileSpoolCommand,
        ReconcileSpoolHandler,
    )
    from agentmemory.ingestion.domain.ports import RecoveryScheduler

_MAXIMUM_INTERVAL_SECONDS = 60.0
_MINIMUM_INTERVAL_SECONDS = 0.05
_MAXIMUM_IMMEDIATE_BATCHES = 100


@dataclass(frozen=True, slots=True)
class SpoolRecoveryPolicy:
    """Bound retries and consecutive drain work for a supervised launcher worker."""

    retry_interval_seconds: float = 1.0
    idle_interval_seconds: float = 2.0
    maximum_immediate_batches: int = 10

    def __post_init__(self) -> None:
        """Reject busy loops, excessive recovery latency, and monopolizing drains."""
        for field, value in (
            ("retry_interval_seconds", self.retry_interval_seconds),
            ("idle_interval_seconds", self.idle_interval_seconds),
        ):
            if not _MINIMUM_INTERVAL_SECONDS <= value <= _MAXIMUM_INTERVAL_SECONDS:
                raise IngestionValidationError.single(field, "out_of_range")
        if not 1 <= self.maximum_immediate_batches <= _MAXIMUM_IMMEDIATE_BATCHES:
            field = "maximum_immediate_batches"
            raise IngestionValidationError.single(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class SpoolRecoveryWorker:
    """Retry unavailable Core and rapidly drain acknowledged bounded batches."""

    handler: ReconcileSpoolHandler
    scheduler: RecoveryScheduler
    policy: SpoolRecoveryPolicy

    async def run(self, command: ReconcileSpoolCommand) -> None:
        """Run until supervised shutdown while retaining every unproven record."""
        immediate_batches = 0
        while True:
            try:
                result = await self.handler.execute(command)
            except IngestionDependencyError, TimeoutError:
                immediate_batches = 0
                if await self.scheduler.wait(self.policy.retry_interval_seconds):
                    return
                continue
            can_continue_immediately = (
                result.acknowledged > 0
                and result.remaining > 0
                and immediate_batches < self.policy.maximum_immediate_batches
            )
            if can_continue_immediately:
                immediate_batches += 1
                continue
            immediate_batches = 0
            blocked_batch = (
                result.attempted > 0 and result.acknowledged == 0 and result.remaining > 0
            )
            interval = (
                self.policy.retry_interval_seconds
                if blocked_batch
                else self.policy.idle_interval_seconds
            )
            if await self.scheduler.wait(interval):
                return
