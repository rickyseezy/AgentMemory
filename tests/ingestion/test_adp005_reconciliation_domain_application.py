"""ADP-005 ordered reconciliation policy and application TDD suite."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

from agentmemory.ingestion.application.reconcile_spool import (
    ReconcileSpoolCommand,
    ReconcileSpoolHandler,
    ReconcileSpoolStatus,
)
from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.spool_reconciliation import (
    ClockSkew,
    SpoolAcknowledgement,
    SpoolRecord,
    SpoolUploadDisposition,
    SpoolUploadResult,
    select_acknowledgements,
)

NOW = datetime(2026, 7, 20, 18, 0, tzinfo=UTC)


def record(event_id: str, ordering_key: str, spool_sequence: int) -> SpoolRecord:
    return SpoolRecord(event_id, ordering_key, spool_sequence, spool_sequence, b'{"safe":true}')


def durable(
    event_id: str,
    disposition: SpoolUploadDisposition = SpoolUploadDisposition.ACCEPTED,
    *,
    skew: int = 10,
) -> SpoolUploadResult:
    return SpoolUploadResult(event_id, disposition, 1_000_000, skew)


def retryable(event_id: str) -> SpoolUploadResult:
    return SpoolUploadResult(event_id, SpoolUploadDisposition.RETRYABLE)


def test_clock_skew_accepts_signed_server_delta_without_changing_an_occurrence() -> None:
    behind = ClockSkew(-5_000_000, 1_000_000)
    ahead = ClockSkew(5_000_000, 11_000_000)

    assert behind.microseconds == -5_000_000
    assert ahead.microseconds == 5_000_000


@pytest.mark.parametrize(
    "value",
    [
        lambda: ClockSkew(microseconds=True, server_ingested_at_microseconds=1),
        lambda: ClockSkew(microseconds=0, server_ingested_at_microseconds=True),
        lambda: ClockSkew(0, -1),
        lambda: ClockSkew(0, 2**63),
        lambda: ClockSkew(2**63, 1),
    ],
)
def test_clock_skew_rejects_unsafe_values(value: Callable[[], object]) -> None:
    with pytest.raises(IngestionValidationError):
        value()


def test_partial_failure_acknowledges_only_each_keys_contiguous_durable_prefix() -> None:
    records = (
        record("a-1", "a", 1),
        record("a-2", "a", 2),
        record("b-1", "b", 1),
    )
    results = (
        durable("a-1"),
        retryable("a-2"),
        durable("b-1", SpoolUploadDisposition.DUPLICATE, skew=-20),
    )

    selected = select_acknowledgements(records, results)

    assert [item.event_id for item in selected] == ["a-1", "b-1"]
    assert selected[1].clock_skew.microseconds == -20


def test_later_durable_item_is_retained_when_an_earlier_same_key_item_failed() -> None:
    records = (record("a-1", "a", 1), record("a-2", "a", 2))

    selected = select_acknowledgements(records, (retryable("a-1"), durable("a-2")))

    assert selected == ()


@pytest.mark.parametrize(
    "results",
    [
        (durable("a-1"),),
        (durable("a-1"), durable("a-1")),
        (durable("a-1"), durable("unknown")),
    ],
)
def test_upload_response_rejects_missing_duplicate_or_unknown_identities(
    results: tuple[SpoolUploadResult, ...],
) -> None:
    records = (record("a-1", "a", 1), record("a-2", "a", 2))

    with pytest.raises(IngestionValidationError, match="upload_results"):
        select_acknowledgements(records, results)


@pytest.mark.parametrize(
    "result",
    [
        lambda: SpoolUploadResult("", SpoolUploadDisposition.RETRYABLE),
        lambda: SpoolUploadResult("a", SpoolUploadDisposition.ACCEPTED),
        lambda: SpoolUploadResult("a", SpoolUploadDisposition.RETRYABLE, 1, 0),
        lambda: SpoolAcknowledgement(
            "a",
            "key",
            1,
            SpoolUploadDisposition.REJECTED,
            ClockSkew(0, 1),
        ),
    ],
)
def test_delivery_values_reject_incomplete_or_non_durable_evidence(
    result: Callable[[], object],
) -> None:
    with pytest.raises(IngestionValidationError):
        result()


@dataclass
class FixedClock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


@dataclass
class SequenceClock:
    values: list[datetime]

    def now(self) -> datetime:
        return self.values.pop(0)


@dataclass
class MemoryRepository:
    records: list[SpoolRecord]
    owner: str | None = None
    acknowledgements: list[SpoolAcknowledgement] = field(default_factory=list[SpoolAcknowledgement])
    requested_limits: tuple[int, int] | None = None
    release_count: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def try_acquire_lease(
        self,
        owner: str,
        acquired_at_microseconds: int,
        expires_at_microseconds: int,
    ) -> bool:
        assert expires_at_microseconds > acquired_at_microseconds
        async with self.lock:
            if self.owner is not None:
                return False
            self.owner = owner
            return True

    async def pending(
        self,
        *,
        maximum_items: int,
        maximum_bytes: int,
    ) -> tuple[SpoolRecord, ...]:
        self.requested_limits = (maximum_items, maximum_bytes)
        selected: list[SpoolRecord] = []
        used = 0
        for item in self.records:
            if len(selected) >= maximum_items or used + len(item.canonical_event) > maximum_bytes:
                break
            selected.append(item)
            used += len(item.canonical_event)
        return tuple(selected)

    async def acknowledge(
        self,
        owner: str,
        acknowledgements: tuple[SpoolAcknowledgement, ...],
        acknowledged_at_microseconds: int,
    ) -> int:
        assert owner == self.owner
        assert acknowledged_at_microseconds >= 0
        self.acknowledgements.extend(acknowledgements)
        ids = {item.event_id for item in acknowledgements}
        self.records = [item for item in self.records if item.event_id not in ids]
        return len(acknowledgements)

    async def count_pending(self) -> int:
        return len(self.records)

    async def release_lease(self, owner: str) -> None:
        if self.owner == owner:
            self.owner = None
        self.release_count += 1


@dataclass
class FixedUploader:
    results: tuple[SpoolUploadResult, ...]
    calls: list[tuple[SpoolRecord, ...]] = field(default_factory=list[tuple[SpoolRecord, ...]])

    async def upload(self, records: tuple[SpoolRecord, ...]) -> tuple[SpoolUploadResult, ...]:
        self.calls.append(records)
        return self.results


@pytest.mark.asyncio
async def test_reconcile_uploads_bounded_batch_advances_prefix_and_releases_lease() -> None:
    repository = MemoryRepository(
        [record("a-1", "a", 1), record("a-2", "a", 2), record("b-1", "b", 1)]
    )
    uploader = FixedUploader((durable("a-1"), retryable("a-2"), durable("b-1")))
    handler = ReconcileSpoolHandler(repository, uploader, FixedClock())

    result = await handler.execute(
        ReconcileSpoolCommand("worker-1", maximum_items=3, maximum_bytes=96 * 1024)
    )

    assert result.status is ReconcileSpoolStatus.RECONCILED
    assert result.attempted == 3
    assert result.acknowledged == 2
    assert result.remaining == 1
    assert repository.requested_limits == (3, 96 * 1024)
    assert repository.owner is None
    assert repository.release_count == 1


@pytest.mark.asyncio
async def test_reconcile_rejects_clock_becoming_non_utc_before_ack() -> None:
    repository = MemoryRepository([record("a-1", "a", 1)])
    handler = ReconcileSpoolHandler(
        repository,
        FixedUploader((durable("a-1"),)),
        SequenceClock([NOW, NOW.replace(tzinfo=None)]),
    )

    with pytest.raises(IngestionValidationError, match="clock"):
        await handler.execute(ReconcileSpoolCommand("worker"))

    assert repository.records
    assert repository.release_count == 1


@pytest.mark.asyncio
async def test_stopped_core_keeps_records_and_restart_reconciles_exact_bytes() -> None:
    repository = MemoryRepository([record("a-1", "a", 1)])

    class InterruptedUploader:
        async def upload(
            self,
            records: tuple[SpoolRecord, ...],
        ) -> tuple[SpoolUploadResult, ...]:
            assert records[0].canonical_event == b'{"safe":true}'
            message = "core stopped"
            raise OSError(message)

    with pytest.raises(OSError, match="stopped"):
        await ReconcileSpoolHandler(repository, InterruptedUploader(), FixedClock()).execute(
            ReconcileSpoolCommand("worker-1")
        )
    assert [item.event_id for item in repository.records] == ["a-1"]
    assert repository.owner is None

    result = await ReconcileSpoolHandler(
        repository,
        FixedUploader((durable("a-1"),)),
        FixedClock(),
    ).execute(ReconcileSpoolCommand("worker-2"))

    assert result.acknowledged == 1
    assert result.remaining == 0


@pytest.mark.asyncio
async def test_empty_and_busy_recovery_are_content_free_and_side_effect_free() -> None:
    empty = MemoryRepository([])
    idle = await ReconcileSpoolHandler(empty, FixedUploader(()), FixedClock()).execute(
        ReconcileSpoolCommand("worker-1")
    )
    busy = MemoryRepository([record("a-1", "a", 1)], owner="other")
    blocked = await ReconcileSpoolHandler(
        busy,
        FixedUploader((durable("a-1"),)),
        FixedClock(),
    ).execute(ReconcileSpoolCommand("worker-1"))

    assert idle.status is ReconcileSpoolStatus.IDLE
    assert blocked.status is ReconcileSpoolStatus.BUSY
    assert blocked.remaining == 1


@pytest.mark.asyncio
async def test_concurrent_recovery_allows_only_one_uploader() -> None:
    repository = MemoryRepository([record("a-1", "a", 1)])
    entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingUploader:
        async def upload(
            self,
            records: tuple[SpoolRecord, ...],
        ) -> tuple[SpoolUploadResult, ...]:
            entered.set()
            await release.wait()
            return (durable(records[0].event_id),)

    handler = ReconcileSpoolHandler(repository, BlockingUploader(), FixedClock())
    first = asyncio.create_task(handler.execute(ReconcileSpoolCommand("worker-1")))
    await entered.wait()
    second = await handler.execute(ReconcileSpoolCommand("worker-2"))
    release.set()
    first_result = await first

    assert second.status is ReconcileSpoolStatus.BUSY
    assert first_result.acknowledged == 1


@pytest.mark.parametrize(
    "command",
    [
        lambda: ReconcileSpoolCommand(""),
        lambda: ReconcileSpoolCommand("worker", maximum_items=0),
        lambda: ReconcileSpoolCommand("worker", maximum_items=101),
        lambda: ReconcileSpoolCommand("worker", maximum_bytes=0),
        lambda: ReconcileSpoolCommand("worker", maximum_bytes=1024 * 1024 + 1),
        lambda: ReconcileSpoolCommand("worker", lease_seconds=0),
        lambda: ReconcileSpoolCommand("worker", upload_timeout_seconds=30),
    ],
)
def test_reconcile_command_rejects_unbounded_policy(command: Callable[[], object]) -> None:
    with pytest.raises(IngestionValidationError):
        command()
