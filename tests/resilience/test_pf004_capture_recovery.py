"""PF-004 host-continuation and idempotent catch-up acceptance tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter, sleep
from typing import TYPE_CHECKING

import pytest

from agentmemory.ingestion.adapters.host_capture import AgentEventCaptureHook, CaptureStatus
from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.adapters.outbound.offline_spool import (
    EncryptedSqliteSpool,
    SqliteOfflineSpoolRepository,
)
from agentmemory.ingestion.application.reconcile_spool import (
    ReconcileSpoolCommand,
    ReconcileSpoolHandler,
)
from agentmemory.ingestion.domain.spool_reconciliation import (
    SpoolRecord,
    SpoolUploadDisposition,
    SpoolUploadResult,
)
from tests.core.support import write_secret
from tests.ingestion.adp002_support import EVENT_ID, event

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.ingestion.domain.capture import AppendDisposition

NOW = datetime(2026, 7, 22, 17, 0, tzinfo=UTC)


class PassRedactor:
    """Keep the already canonical fixture unchanged."""

    def redact(self, canonical_event: bytes) -> bytes:
        return canonical_event


class OfflineLedger:
    """Represent an unavailable canonical ledger endpoint."""

    async def append(self, canonical_event: bytes) -> AppendDisposition:
        assert canonical_event
        raise OSError


class SlowSpool:
    """Represent local disk latency beyond the complete host-hook budget."""

    def enqueue(
        self,
        event_id: str,
        ordering_key: str,
        sequence: int | None,
        canonical_event: bytes,
    ) -> bool:
        assert event_id
        assert ordering_key
        assert sequence is not None
        assert canonical_event
        sleep(0.1)
        return True


@dataclass
class FixedClock:
    """Supply deterministic UTC reconciliation time."""

    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


@dataclass
class DuplicateUploader:
    """Model Core proving the exact event was already durably applied."""

    calls: list[tuple[SpoolRecord, ...]] = field(default_factory=list[tuple[SpoolRecord, ...]])

    async def upload(self, records: tuple[SpoolRecord, ...]) -> tuple[SpoolUploadResult, ...]:
        self.calls.append(records)
        return tuple(
            SpoolUploadResult(
                record.event_id,
                SpoolUploadDisposition.DUPLICATE,
                ingested_at_microseconds=1_000_000,
                clock_skew_microseconds=0,
            )
            for record in records
        )


def spool(tmp_path: Path) -> EncryptedSqliteSpool:
    """Create one owner-private bounded encrypted spool."""
    tmp_path.chmod(0o700)
    key = tmp_path / "spool-key"
    write_secret(key, b"k" * 32)
    value = EncryptedSqliteSpool(
        tmp_path / "spool.sqlite3",
        key,
        maximum_records=10,
        maximum_bytes=128 * 1024,
    )
    value.initialize()
    return value


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.resilience
async def test_pf004_host_returns_with_typed_degradation_before_slow_disk_finishes() -> None:
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    hook = AgentEventCaptureHook(
        PassRedactor(),
        OfflineLedger(),
        SlowSpool(),
        ipc_timeout_seconds=0.005,
        hook_deadline_seconds=0.02,
    )

    started = perf_counter()
    result = await hook.capture(raw)
    elapsed = perf_counter() - started

    assert result.status is CaptureStatus.DEADLINE_EXCEEDED
    assert elapsed < 0.075


@pytest.mark.asyncio
@pytest.mark.e2e
@pytest.mark.resilience
async def test_pf004_offline_capture_and_duplicate_recovery_produce_one_effective_event(
    tmp_path: Path,
) -> None:
    value = spool(tmp_path)
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    hook = AgentEventCaptureHook(PassRedactor(), OfflineLedger(), value)

    first, retry = await asyncio.gather(hook.capture(raw), hook.capture(raw))

    assert first.status is CaptureStatus.DEFERRED
    assert retry.status is CaptureStatus.DEFERRED
    assert value.count_pending() == 1
    uploader = DuplicateUploader()
    result = await ReconcileSpoolHandler(
        SqliteOfflineSpoolRepository(value),
        uploader,
        FixedClock(),
    ).execute(ReconcileSpoolCommand("pf004-worker", maximum_bytes=96 * 1024))
    assert result.acknowledged == 1
    assert result.remaining == 0
    assert len(uploader.calls) == 1
    assert [record.event_id for record in uploader.calls[0]] == [EVENT_ID]
