"""PF-002 durable worker isolation, retry, and shutdown tests."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.operations.application.projection_worker import ProjectionRebuildWorker
from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.application.commands.projection_rebuild import ProjectionRebuilder
    from agentmemory.operations.domain.ports import ProjectionRebuildRepository


@dataclass(slots=True)
class _Repository:
    next_value: str | None = None
    partial: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    failed: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])

    async def next_runnable(self) -> str | None:
        value = self.next_value
        self.next_value = None
        return value

    async def mark_partial(self, operation_id: str, reason: str) -> object:
        self.partial.append((operation_id, reason))
        return object()

    async def fail(self, operation_id: str, reason: str) -> object:
        self.failed.append((operation_id, reason))
        return object()


@dataclass(slots=True)
class _Rebuilder:
    error: BaseException | None = None
    calls: list[str] = field(default_factory=list[str])

    async def execute(self, operation_id: str) -> object:
        self.calls.append(operation_id)
        if self.error is not None:
            raise self.error
        return object()


def _worker(repository: _Repository, rebuilder: _Rebuilder) -> ProjectionRebuildWorker:
    # The worker only consumes the protocol methods exercised by this focused test double.
    return ProjectionRebuildWorker(
        cast("ProjectionRebuildRepository", repository),
        cast("ProjectionRebuilder", rebuilder),
    )


@pytest.mark.asyncio
async def test_worker_executes_one_job_and_stops_cleanly() -> None:
    repository = _Repository(next_value="rebuild-1")
    rebuilder = _Rebuilder()
    worker = _worker(repository, rebuilder)
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop))
    for _ in range(20):
        if rebuilder.calls:
            break
        await asyncio.sleep(0)
    stop.set()
    await task
    assert rebuilder.calls == ["rebuild-1"]


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [ErrorCode.DEPENDENCY_UNAVAILABLE, ErrorCode.DEADLINE_EXCEEDED])
async def test_worker_pauses_retryable_dependency_failures(code: ErrorCode) -> None:
    repository = _Repository()
    worker = _worker(repository, _Rebuilder(OperationError(code, "safe", retryable=True)))
    await worker._execute("rebuild-2")
    assert repository.partial == [("rebuild-2", code.value.lower())]
    assert repository.failed == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "reason"),
    [
        (ErrorCode.FORBIDDEN, "authorization_revoked"),
        (ErrorCode.INTEGRITY_VIOLATION, "integrity_violation"),
        (ErrorCode.CONFLICT, "concurrent_conflict"),
        (ErrorCode.VALIDATION, "operation_failed"),
    ],
)
async def test_worker_quarantines_nonretryable_typed_failures(
    code: ErrorCode,
    reason: str,
) -> None:
    repository = _Repository()
    worker = _worker(repository, _Rebuilder(OperationError(code, "safe")))
    await worker._execute("rebuild-3")
    assert repository.failed == [("rebuild-3", reason)]


@pytest.mark.asyncio
async def test_worker_contains_unknown_failure_and_rejects_unsafe_poll_interval() -> None:
    repository = _Repository()
    message = "unknown"
    worker = _worker(repository, _Rebuilder(RuntimeError(message)))
    await worker._execute("rebuild-4")
    assert repository.failed == [("rebuild-4", "internal_error")]
    with pytest.raises(ValueError, match="poll interval"):
        ProjectionRebuildWorker(
            cast("ProjectionRebuildRepository", repository),
            cast("ProjectionRebuilder", _Rebuilder()),
            poll_seconds=0,
        )
