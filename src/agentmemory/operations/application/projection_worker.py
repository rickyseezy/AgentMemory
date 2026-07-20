"""Bounded durable PF-002 projection worker lifecycle."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.application.commands.projection_rebuild import ProjectionRebuilder
    from agentmemory.operations.domain.ports import ProjectionRebuildRepository

_DEFAULT_POLL_SECONDS = 0.5
_MAX_POLL_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class ProjectionRebuildWorker:
    """Drain durable rebuild jobs without allowing one failure to stop later work."""

    repository: ProjectionRebuildRepository
    rebuilder: ProjectionRebuilder
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        """Bound idle wakeups and shutdown latency."""
        if self.poll_seconds <= 0 or self.poll_seconds > _MAX_POLL_SECONDS:
            msg = "projection worker poll interval is invalid"
            raise ValueError(msg)

    async def run(self, stop: asyncio.Event) -> None:
        """Poll durable state until graceful shutdown is requested."""
        while not stop.is_set():
            operation_id = await self.repository.next_runnable()
            if operation_id is None:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.poll_seconds)
                except TimeoutError:
                    continue
                continue
            await self._execute(operation_id)

    async def _execute(self, operation_id: str) -> None:
        try:
            await self.rebuilder.execute(operation_id)
        except OperationError as error:
            if error.code in {ErrorCode.DEPENDENCY_UNAVAILABLE, ErrorCode.DEADLINE_EXCEEDED}:
                await self.repository.mark_partial(operation_id, error.code.value.lower())
                return
            await self.repository.fail(operation_id, _failure_reason(error.code))
        except Exception:  # noqa: BLE001 -- Worker isolates unknown job failures and continues.
            await self.repository.fail(operation_id, "internal_error")


def _failure_reason(code: ErrorCode) -> str:
    if code is ErrorCode.FORBIDDEN:
        return "authorization_revoked"
    if code is ErrorCode.INTEGRITY_VIOLATION:
        return "integrity_violation"
    if code is ErrorCode.CONFLICT:
        return "concurrent_conflict"
    return "operation_failed"
