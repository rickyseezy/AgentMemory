# pyright: reportPrivateUsage=false
"""MEM-001 lineage-backfill domain and bounded-worker mutation tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, cast

import pytest

import agentmemory.memory.application.lineage_backfill as backfill_module
from agentmemory.memory.application.lineage_backfill import TaskLineageBackfillWorker
from agentmemory.memory.domain.errors import (
    MemoryDependencyError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from agentmemory.memory.domain.lineage_backfill import (
    TaskLineageBackfillOutcome,
    TaskLineageBackfillProgress,
    TaskLineageBackfillState,
    TaskLineageRecord,
)
from tests.ingestion.adp002_support import CORRELATION_ID, PRINCIPAL_ID, SESSION_ID
from tests.memory.test_mem001_consolidation_application import CAUSATION_ID
from tests.memory.test_mem001_consolidation_domain import EVENT_ONE, EVENT_TWO, TASK_ID, scope

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.domain.ports import TaskLineageBackfillRepository

_AT_ONE = 1_721_476_800_000_000
_AT_TWO = _AT_ONE + 1
_TRUE = bool(1)


def _progress(  # noqa: PLR0913 -- Orthogonal state axes.
    *,
    state: TaskLineageBackfillState = TaskLineageBackfillState.RUNNING,
    scanned: int = 0,
    indexed: int = 0,
    ignored: int = 0,
    total: int = 2,
    error: str | None = None,
) -> TaskLineageBackfillProgress:
    return TaskLineageBackfillProgress(
        "mem001-task-lineage-v1",
        state,
        _AT_ONE if scanned else None,
        EVENT_ONE if scanned else None,
        _AT_TWO if total else None,
        EVENT_TWO if total else None,
        scanned,
        indexed,
        ignored,
        total,
        error,
    )


def _record() -> TaskLineageRecord:
    return TaskLineageRecord(
        EVENT_ONE,
        PRINCIPAL_ID,
        scope(),
        SESSION_ID,
        TASK_ID,
        CORRELATION_ID,
        CAUSATION_ID,
        "agentmemory.task.completed.v1",
        "internal",
        "default",
        _AT_ONE,
        "a" * 64,
        _AT_ONE,
    )


_PROGRESS_MUTATIONS: tuple[
    tuple[Callable[[TaskLineageBackfillProgress], TaskLineageBackfillProgress], str], ...
] = (
    (lambda value: replace(value, operation_id="other"), "operation_id"),
    (
        lambda value: replace(value, state=cast("TaskLineageBackfillState", "running")),
        "state",
    ),
    (lambda value: replace(value, cursor_created_at=_AT_ONE), "cursor"),
    (lambda value: replace(value, watermark_event_id=None), "watermark"),
    (lambda value: replace(value, scanned=cast("int", _TRUE)), "counts"),
    (lambda value: replace(value, indexed=1), "counts"),
    (
        lambda value: replace(
            value,
            total=0,
            watermark_created_at=_AT_TWO,
            watermark_event_id=EVENT_TWO,
        ),
        "watermark",
    ),
    (
        lambda value: replace(
            value,
            scanned=1,
            indexed=1,
            cursor_created_at=None,
            cursor_event_id=None,
        ),
        "cursor",
    ),
    (
        lambda value: replace(
            value,
            scanned=1,
            indexed=1,
            cursor_created_at=_AT_TWO + 1,
            cursor_event_id=EVENT_TWO,
        ),
        "cursor",
    ),
    (
        lambda value: replace(value, state=TaskLineageBackfillState.COMPLETED),
        "state",
    ),
    (lambda value: replace(value, last_error_code="unknown"), "last_error_code"),
    (
        lambda value: replace(value, state=TaskLineageBackfillState.INTERRUPTED),
        "last_error_code",
    ),
    (lambda value: replace(value, last_error_code="interrupted"), "last_error_code"),
    (
        lambda value: replace(value, state=TaskLineageBackfillState.PENDING, total=2),
        "state",
    ),
    (lambda value: replace(value, watermark_created_at=0), "watermark.created_at"),
    (lambda value: replace(value, watermark_event_id="invalid"), "watermark.event_id"),
)


@pytest.mark.parametrize(("mutation", "field"), _PROGRESS_MUTATIONS)
def test_progress_rejects_every_invalid_cursor_count_and_state_shape(
    mutation: Callable[[TaskLineageBackfillProgress], TaskLineageBackfillProgress],
    field: str,
) -> None:
    with pytest.raises(MemoryValidationError) as failure:
        mutation(_progress())
    assert failure.value.code_for(field) is not None


def test_progress_accepts_running_interrupted_completed_and_empty_states() -> None:
    assert _progress().state is TaskLineageBackfillState.RUNNING
    assert (
        _progress(
            state=TaskLineageBackfillState.INTERRUPTED,
            error="dependency_unavailable",
        ).last_error_code
        == "dependency_unavailable"
    )
    completed = _progress(
        state=TaskLineageBackfillState.COMPLETED,
        scanned=2,
        indexed=1,
        ignored=1,
    )
    assert completed.scanned == completed.total
    empty = _progress(state=TaskLineageBackfillState.COMPLETED, total=0)
    assert empty.watermark_event_id is None


_RECORD_MUTATIONS: tuple[tuple[Callable[[TaskLineageRecord], TaskLineageRecord], str], ...] = (
    (lambda value: replace(value, event_id="invalid"), "lineage.event_id"),
    (lambda value: replace(value, principal_id="invalid"), "lineage.principal_id"),
    (lambda value: replace(value, session_id="invalid"), "lineage.session_id"),
    (lambda value: replace(value, task_id="invalid"), "lineage.task_id"),
    (lambda value: replace(value, correlation_id="invalid"), "lineage.correlation_id"),
    (lambda value: replace(value, causation_id="invalid"), "lineage.causation_id"),
    (lambda value: replace(value, event_type="invalid"), "lineage.event_type"),
    (lambda value: replace(value, classification="secret"), "lineage.classification"),
    (lambda value: replace(value, retention_policy_id="INVALID"), "lineage.retention_policy_id"),
    (lambda value: replace(value, occurred_at_microseconds=0), "lineage.occurred_at"),
    (
        lambda value: replace(value, occurred_at_microseconds=cast("int", _TRUE)),
        "lineage.occurred_at",
    ),
    (
        lambda value: replace(value, canonical_event_sha256="0" * 64),
        "lineage.canonical_event_sha256",
    ),
    (
        lambda value: replace(value, canonical_event_sha256="a" * 63),
        "lineage.canonical_event_sha256",
    ),
    (lambda value: replace(value, source_created_at=0), "lineage.source_created_at"),
    (
        lambda value: replace(value, source_created_at=cast("int", _TRUE)),
        "lineage.source_created_at",
    ),
)


@pytest.mark.parametrize(("mutation", "field"), _RECORD_MUTATIONS)
def test_lineage_record_rejects_malformed_or_mutable_source_metadata(
    mutation: Callable[[TaskLineageRecord], TaskLineageRecord],
    field: str,
) -> None:
    with pytest.raises(MemoryValidationError) as failure:
        mutation(_record())
    assert failure.value.code_for(field) is not None


def test_outcome_binds_record_to_exact_source_position() -> None:
    record = _record()
    assert TaskLineageBackfillOutcome(EVENT_ONE, _AT_ONE, record).record == record
    assert TaskLineageBackfillOutcome(EVENT_TWO, _AT_TWO, None).record is None
    mutations: tuple[tuple[Callable[[], TaskLineageBackfillOutcome], str], ...] = (
        (lambda: TaskLineageBackfillOutcome("invalid", _AT_ONE, None), "outcome.event_id"),
        (lambda: TaskLineageBackfillOutcome(EVENT_ONE, 0, None), "outcome.source_created_at"),
        (
            lambda: TaskLineageBackfillOutcome(EVENT_ONE, cast("int", _TRUE), None),
            "outcome.source_created_at",
        ),
        (lambda: TaskLineageBackfillOutcome(EVENT_TWO, _AT_ONE, record), "outcome.record"),
        (lambda: TaskLineageBackfillOutcome(EVENT_ONE, _AT_TWO, record), "outcome.record"),
        (
            lambda: TaskLineageBackfillOutcome(
                EVENT_ONE,
                _AT_ONE,
                cast("TaskLineageRecord", object()),
            ),
            "outcome.record",
        ),
    )
    for mutation, expected_field in mutations:
        with pytest.raises(MemoryValidationError) as failure:
            mutation()
        assert failure.value.code_for(expected_field) is not None


def _outcomes() -> tuple[TaskLineageBackfillOutcome, ...]:
    return (
        TaskLineageBackfillOutcome(EVENT_ONE, _AT_ONE, _record()),
        TaskLineageBackfillOutcome(EVENT_TWO, _AT_TWO, None),
    )


def _integers() -> list[int]:
    return []


def _outcome_list() -> list[TaskLineageBackfillOutcome]:
    return []


def _strings() -> list[str]:
    return []


@dataclass
class _Repository:
    progress: TaskLineageBackfillProgress
    outcomes: tuple[TaskLineageBackfillOutcome, ...] = ()
    load_error: Exception | None = None
    starts: int = 0
    loads: list[int] = field(default_factory=_integers)
    checkpoints: list[TaskLineageBackfillOutcome] = field(default_factory=_outcome_list)
    interrupts: list[str] = field(default_factory=_strings)
    completes: int = 0

    async def start_or_resume(self) -> TaskLineageBackfillProgress:
        self.starts += 1
        if (
            self.progress.state is TaskLineageBackfillState.INTERRUPTED
            and self.progress.last_error_code != "integrity_violation"
        ):
            self.progress = replace(
                self.progress,
                state=TaskLineageBackfillState.RUNNING,
                last_error_code=None,
            )
        return self.progress

    async def load_after(
        self,
        progress: TaskLineageBackfillProgress,
        limit: int,
    ) -> tuple[TaskLineageBackfillOutcome, ...]:
        assert progress == self.progress
        self.loads.append(limit)
        if self.load_error is not None:
            error, self.load_error = self.load_error, None
            raise error
        return self.outcomes

    async def checkpoint(
        self,
        progress: TaskLineageBackfillProgress,
        outcome: TaskLineageBackfillOutcome,
    ) -> TaskLineageBackfillProgress:
        assert progress == self.progress
        self.checkpoints.append(outcome)
        indexed = self.progress.indexed + int(outcome.record is not None)
        ignored = self.progress.ignored + int(outcome.record is None)
        self.progress = TaskLineageBackfillProgress(
            self.progress.operation_id,
            TaskLineageBackfillState.RUNNING,
            outcome.source_created_at,
            outcome.event_id,
            self.progress.watermark_created_at,
            self.progress.watermark_event_id,
            self.progress.scanned + 1,
            indexed,
            ignored,
            self.progress.total,
            None,
        )
        return self.progress

    async def complete(
        self,
        progress: TaskLineageBackfillProgress,
    ) -> TaskLineageBackfillProgress:
        assert progress == self.progress
        self.completes += 1
        self.progress = replace(
            progress,
            state=TaskLineageBackfillState.COMPLETED,
            last_error_code=None,
        )
        return self.progress

    async def interrupt(
        self,
        progress: TaskLineageBackfillProgress,
        reason_code: str,
    ) -> TaskLineageBackfillProgress:
        assert progress == self.progress
        self.interrupts.append(reason_code)
        self.progress = replace(
            progress,
            state=TaskLineageBackfillState.INTERRUPTED,
            last_error_code=reason_code,
        )
        return self.progress


def _worker(repository: _Repository, page_size: int = 2) -> TaskLineageBackfillWorker:
    return TaskLineageBackfillWorker(
        cast("TaskLineageBackfillRepository", repository),
        page_size,
    )


@pytest.mark.parametrize("page_size", [0, -1, 257])
def test_worker_rejects_unbounded_page_sizes(page_size: int) -> None:
    with pytest.raises(ValueError, match="page size is invalid"):
        _worker(_Repository(_progress()), page_size)


@pytest.mark.asyncio
async def test_worker_short_circuits_completed_and_completes_empty_page() -> None:
    completed = _Repository(
        _progress(
            state=TaskLineageBackfillState.COMPLETED,
            scanned=2,
            indexed=1,
            ignored=1,
        )
    )
    assert await _worker(completed).run_page()
    assert not completed.loads

    empty = _Repository(_progress(total=0))
    assert await _worker(empty).run_page()
    assert empty.loads == [2]
    assert empty.completes == 1


@pytest.mark.asyncio
async def test_worker_checkpoints_every_ordered_outcome_without_early_completion() -> None:
    repository = _Repository(_progress(), _outcomes())
    assert not await _worker(repository).run_page()
    assert repository.loads == [2]
    assert repository.checkpoints == list(_outcomes())
    assert (
        repository.progress.scanned,
        repository.progress.indexed,
        repository.progress.ignored,
    ) == (
        2,
        1,
        1,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (MemoryDependencyError(), "dependency_unavailable"),
        (MemoryIntegrityError(), "integrity_violation"),
    ],
)
async def test_worker_checkpoints_typed_interruption_before_propagating(
    error: Exception,
    reason: str,
) -> None:
    repository = _Repository(_progress(), load_error=error)
    with pytest.raises(type(error)):
        await _worker(repository).run_page()
    assert repository.interrupts == [reason]
    assert repository.progress.last_error_code == reason


@pytest.mark.asyncio
async def test_worker_never_automatically_resumes_integrity_interruption() -> None:
    repository = _Repository(
        _progress(
            state=TaskLineageBackfillState.INTERRUPTED,
            error="integrity_violation",
        )
    )
    with pytest.raises(MemoryIntegrityError):
        await _worker(repository).run_page()
    assert not repository.loads
    assert not repository.interrupts

    await _worker(repository).run(asyncio.Event())
    assert repository.starts == 2
    assert not repository.loads


@pytest.mark.asyncio
async def test_worker_run_honors_stop_and_retries_only_dependency_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped = asyncio.Event()
    stopped.set()
    untouched = _Repository(_progress())
    await _worker(untouched).run(stopped)
    assert untouched.starts == 0

    monkeypatch.setattr(backfill_module, "_RETRY_SECONDS", 0)
    retrying = _Repository(
        _progress(total=0),
        load_error=MemoryDependencyError(),
    )
    await _worker(retrying).run(asyncio.Event())
    assert retrying.interrupts == ["dependency_unavailable"]
    assert retrying.completes == 1


@pytest.mark.asyncio
async def test_wait_returns_on_timeout_and_stop_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[float | None] = []

    async def inspect_timeout(
        awaitable: object,
        *,
        timeout: float | None,  # noqa: ASYNC109 -- Mirrors asyncio.wait_for for mutation proof.
    ) -> None:
        observed.append(timeout)
        awaitable.close()  # type: ignore[attr-defined]
        assert timeout is not None
        raise TimeoutError

    stop = asyncio.Event()
    with monkeypatch.context() as context:
        context.setattr(asyncio, "wait_for", inspect_timeout)
        await backfill_module._wait_or_stop(stop, 0)
    assert observed == [0]

    stop.set()
    await backfill_module._wait_or_stop(stop, 1)
