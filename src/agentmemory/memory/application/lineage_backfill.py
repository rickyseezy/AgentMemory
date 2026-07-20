"""Resumable bounded historical task-lineage backfill orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.memory.domain.errors import MemoryDependencyError, MemoryIntegrityError
from agentmemory.memory.domain.lineage_backfill import TaskLineageBackfillState

if TYPE_CHECKING:
    from agentmemory.memory.domain.ports import TaskLineageBackfillRepository

_PAGE_SIZE = 64
_MAX_PAGE_SIZE = 256
_RETRY_SECONDS = 1.0
_INVALID_PAGE_SIZE = "task-lineage backfill page size is invalid"


@dataclass(frozen=True, slots=True)
class TaskLineageBackfillWorker:
    """Resume one fixed historical source watermark until fully indexed."""

    repository: TaskLineageBackfillRepository
    page_size: int = _PAGE_SIZE

    def __post_init__(self) -> None:
        """Bound decryption and transaction work per page."""
        if not 1 <= self.page_size <= _MAX_PAGE_SIZE:
            raise ValueError(_INVALID_PAGE_SIZE)

    async def run(self, stop: asyncio.Event) -> None:
        """Resume after dependency interruption while retaining the exact cursor."""
        while not stop.is_set():
            try:
                completed = await self.run_page()
            except MemoryDependencyError:
                await _wait_or_stop(stop, _RETRY_SECONDS)
                continue
            except MemoryIntegrityError:
                return
            if completed:
                return

    async def run_page(self) -> bool:
        """Process one bounded page and report durable completion."""
        progress = await self.repository.start_or_resume()
        if progress.state is TaskLineageBackfillState.COMPLETED:
            return True
        if (
            progress.state is TaskLineageBackfillState.INTERRUPTED
            and progress.last_error_code == "integrity_violation"
        ):
            raise MemoryIntegrityError
        try:
            outcomes = await self.repository.load_after(progress, self.page_size)
            if not outcomes:
                completed = await self.repository.complete(progress)
                return completed.state is TaskLineageBackfillState.COMPLETED
            for outcome in outcomes:
                progress = await self.repository.checkpoint(progress, outcome)
        except MemoryDependencyError:
            await self.repository.interrupt(progress, "dependency_unavailable")
            raise
        except MemoryIntegrityError:
            await self.repository.interrupt(progress, "integrity_violation")
            raise
        else:
            return False


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return
