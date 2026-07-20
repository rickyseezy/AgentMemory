"""ING-001 durable processing domain and application acceptance tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Any, cast

import pytest

from agentmemory.ingestion.application.durable_processing import (
    DurableEventProcessingHandler,
    DurableIngestionWorker,
)
from agentmemory.ingestion.domain.durable_processing import (
    ClaimedOutboxMessage,
    DurableProcessingResult,
    InboxClaimDisposition,
    InboxReceiptClaim,
    ProcessingDisposition,
    VerifiedEventProjection,
)
from agentmemory.ingestion.domain.errors import (
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)
from tests.core.support import FixedClock
from tests.ingestion.adp002_support import BRAIN_ID, EVENT_ID, NOW

MESSAGE_ID = "018f0000-0000-7000-8000-000000000901"
PAYLOAD_SHA256 = "a" * 64
CANONICAL_SHA256 = "b" * 64
PROJECTION_SHA256 = "c" * 64


def claimed(**changes: object) -> ClaimedOutboxMessage:
    value = ClaimedOutboxMessage(
        message_id=MESSAGE_ID,
        event_id=EVENT_ID,
        brain_id=BRAIN_ID,
        topic=f"am.local.{BRAIN_ID}.ingestion.agent-event-appended.v1",
        payload=b'{"schema_version":1}',
        payload_sha256=PAYLOAD_SHA256,
        attempt=1,
        lease_owner="core-018f0000-0000-7000-8000-000000000902",
        lease_until_microseconds=42,
    )
    return replace(value, **cast("Any", changes))


def inbox_claim(
    message: ClaimedOutboxMessage | None = None,
    disposition: InboxClaimDisposition = InboxClaimDisposition.CLAIMED,
) -> InboxReceiptClaim:
    resolved = message or claimed()
    return InboxReceiptClaim(
        consumer="canonical-event-projection-v1",
        message_id=resolved.message_id,
        event_id=resolved.event_id,
        request_sha256=resolved.payload_sha256,
        disposition=disposition,
        owner="worker-1" if disposition is InboxClaimDisposition.CLAIMED else None,
        lease_until_microseconds=(42 if disposition is InboxClaimDisposition.CLAIMED else None),
        attempt=1,
        result_sha256=(PROJECTION_SHA256 if disposition is InboxClaimDisposition.REPLAY else None),
    )


def receipt(**changes: object) -> InboxReceiptClaim:
    return replace(inbox_claim(), **cast("Any", changes))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("message_id", "bad"),
        ("event_id", "bad"),
        ("brain_id", "bad"),
        ("topic", "wrong"),
        ("payload", b""),
        ("payload_sha256", "bad"),
        ("attempt", 0),
        ("lease_owner", ""),
        ("lease_until_microseconds", -1),
    ],
)
def test_claimed_outbox_message_rejects_malformed_state(field_name: str, value: object) -> None:
    with pytest.raises(IngestionValidationError):
        claimed(**{field_name: value})


def test_verified_projection_and_result_are_closed_and_hash_bound() -> None:
    projection = VerifiedEventProjection(
        EVENT_ID,
        CANONICAL_SHA256,
        PROJECTION_SHA256,
    )
    completed = DurableProcessingResult(
        MESSAGE_ID,
        EVENT_ID,
        ProcessingDisposition.COMPLETED,
    )
    assert projection.event_id == completed.event_id
    with pytest.raises(IngestionValidationError):
        VerifiedEventProjection(EVENT_ID, "bad", PROJECTION_SHA256)
    with pytest.raises(IngestionValidationError):
        VerifiedEventProjection("bad", CANONICAL_SHA256, PROJECTION_SHA256)
    with pytest.raises(IngestionValidationError):
        DurableProcessingResult(MESSAGE_ID, EVENT_ID, ProcessingDisposition.IDLE)
    with pytest.raises(IngestionValidationError):
        DurableProcessingResult("bad", EVENT_ID, ProcessingDisposition.COMPLETED)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("consumer", "bad consumer"),
        ("message_id", "bad"),
        ("request_sha256", "bad"),
        ("owner", None),
        ("disposition", InboxClaimDisposition.WAIT),
        ("result_sha256", "bad"),
        ("attempt", 0),
    ],
)
def test_inbox_receipt_rejects_ambiguous_claim_and_replay_evidence(
    field_name: str,
    value: object,
) -> None:
    changes = {field_name: value}
    if field_name == "disposition":
        changes |= {"owner": None, "lease_until_microseconds": None, "result_sha256": "c" * 64}
    if field_name == "result_sha256":
        changes |= {
            "disposition": InboxClaimDisposition.REPLAY,
            "owner": None,
            "lease_until_microseconds": None,
        }
    with pytest.raises(IngestionValidationError):
        receipt(**changes)


@pytest.mark.parametrize("owner", ["", "x" * 129])
def test_handler_rejects_invalid_worker_owner(owner: str) -> None:
    with pytest.raises(ValueError, match="worker owner"):
        DurableEventProcessingHandler(_Queue(), _Verifier(), FixedClock(NOW), owner)


@dataclass
class _Queue:
    candidates: list[ClaimedOutboxMessage] = field(default_factory=list[ClaimedOutboxMessage])
    completed: list[
        tuple[ClaimedOutboxMessage, InboxReceiptClaim, VerifiedEventProjection, int]
    ] = field(
        default_factory=list[
            tuple[ClaimedOutboxMessage, InboxReceiptClaim, VerifiedEventProjection, int]
        ]
    )
    repairs: list[tuple[ClaimedOutboxMessage, InboxReceiptClaim, str, int]] = field(
        default_factory=list[tuple[ClaimedOutboxMessage, InboxReceiptClaim, str, int]]
    )
    retries: list[tuple[ClaimedOutboxMessage, InboxReceiptClaim, str, int]] = field(
        default_factory=list[tuple[ClaimedOutboxMessage, InboxReceiptClaim, str, int]]
    )
    inbox_disposition: InboxClaimDisposition = InboxClaimDisposition.CLAIMED
    replays: list[tuple[ClaimedOutboxMessage, InboxReceiptClaim, int]] = field(
        default_factory=list[tuple[ClaimedOutboxMessage, InboxReceiptClaim, int]]
    )
    recovered: list[int] = field(default_factory=list[int])
    startup_scans: list[int] = field(default_factory=list[int])
    startup_remaining: int = 0

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ClaimedOutboxMessage | None:
        del owner, now_microseconds, lease_until_microseconds
        return self.candidates.pop(0) if self.candidates else None

    async def complete(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        projection: VerifiedEventProjection,
        completed_at_microseconds: int,
    ) -> None:
        self.completed.append((message, inbox, projection, completed_at_microseconds))

    async def claim_inbox(
        self,
        message: ClaimedOutboxMessage,
        consumer: str,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> InboxReceiptClaim:
        del consumer, owner, now_microseconds, lease_until_microseconds
        return inbox_claim(message, self.inbox_disposition)

    async def complete_replay(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        completed_at_microseconds: int,
    ) -> None:
        self.replays.append((message, inbox, completed_at_microseconds))

    async def require_repair(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        reason_code: str,
        detected_at_microseconds: int,
    ) -> None:
        self.repairs.append((message, inbox, reason_code, detected_at_microseconds))

    async def release_retry(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        self.retries.append((message, inbox, reason_code, retry_at_microseconds))

    async def recover_expired_leases(self, now_microseconds: int) -> int:
        self.recovered.append(now_microseconds)
        return 1

    async def alert_unprocessed_events(self, detected_at_microseconds: int) -> int:
        self.startup_scans.append(detected_at_microseconds)
        if self.startup_remaining:
            self.startup_remaining -= 1
            return 1
        return 0


@dataclass
class _Verifier:
    projection: VerifiedEventProjection | None = None
    error: Exception | None = None

    async def verify(self, message: ClaimedOutboxMessage) -> VerifiedEventProjection:
        del message
        if self.error is not None:
            raise self.error
        assert self.projection is not None
        return self.projection


@pytest.mark.asyncio
async def test_handler_commits_terminal_projection_for_verified_event() -> None:
    queue = _Queue([claimed()])
    projection = VerifiedEventProjection(EVENT_ID, CANONICAL_SHA256, PROJECTION_SHA256)
    handler = DurableEventProcessingHandler(
        queue, _Verifier(projection), FixedClock(NOW), "worker-1"
    )
    result = await handler.execute_once()
    assert result.disposition is ProcessingDisposition.COMPLETED
    assert queue.completed == [
        (
            claimed(),
            inbox_claim(),
            projection,
            round(NOW.timestamp() * 1_000_000),
        )
    ]
    assert queue.repairs == []
    assert queue.retries == []


@pytest.mark.asyncio
async def test_integrity_failure_becomes_terminal_repair_alert_without_retry() -> None:
    queue = _Queue([claimed()])
    handler = DurableEventProcessingHandler(
        queue,
        _Verifier(error=IngestionIntegrityError("unsafe detail")),
        FixedClock(NOW),
        "worker-1",
    )
    result = await handler.execute_once()
    assert result.disposition is ProcessingDisposition.REPAIR_REQUIRED
    assert queue.repairs[0][2] == "canonical_integrity_violation"
    assert "unsafe" not in queue.repairs[0][2]
    assert queue.retries == []


@pytest.mark.asyncio
async def test_dependency_failure_releases_lease_without_terminal_acknowledgement() -> None:
    queue = _Queue([claimed()])
    handler = DurableEventProcessingHandler(
        queue,
        _Verifier(error=IngestionDependencyError("disk unavailable")),
        FixedClock(NOW),
        "worker-1",
    )
    result = await handler.execute_once()
    assert result.disposition is ProcessingDisposition.RETRY_SCHEDULED
    assert queue.retries[0][2] == "dependency_unavailable"
    assert queue.completed == []
    assert queue.repairs == []


@pytest.mark.asyncio
async def test_idle_result_contains_no_fabricated_identifiers() -> None:
    result = await DurableEventProcessingHandler(
        _Queue(),
        _Verifier(),
        FixedClock(NOW),
        "worker-1",
    ).execute_once()
    assert result == DurableProcessingResult.idle()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("disposition", "expected"),
    [
        (InboxClaimDisposition.REPLAY, ProcessingDisposition.COMPLETED),
        (InboxClaimDisposition.WAIT, ProcessingDisposition.RETRY_SCHEDULED),
    ],
)
async def test_handler_replays_or_defers_before_executing_side_effect(
    disposition: InboxClaimDisposition,
    expected: ProcessingDisposition,
) -> None:
    queue = _Queue([claimed()], inbox_disposition=disposition)
    result = await DurableEventProcessingHandler(
        queue,
        _Verifier(),
        FixedClock(NOW),
        "worker-1",
    ).execute_once()
    assert result.disposition is expected
    assert bool(queue.replays) is (disposition is InboxClaimDisposition.REPLAY)
    assert bool(queue.retries) is (disposition is InboxClaimDisposition.WAIT)


@pytest.mark.asyncio
async def test_worker_recovers_expired_leases_before_processing_and_stops() -> None:
    queue = _Queue([claimed()], startup_remaining=1)
    projection = VerifiedEventProjection(EVENT_ID, CANONICAL_SHA256, PROJECTION_SHA256)
    handler = DurableEventProcessingHandler(
        queue, _Verifier(projection), FixedClock(NOW), "worker-1"
    )
    worker = DurableIngestionWorker(queue, handler, FixedClock(NOW), poll_seconds=0.001)
    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop))
    for _ in range(100):
        if queue.completed:
            break
        await asyncio.sleep(0.001)
    stop.set()
    await task
    assert queue.recovered == [round(NOW.timestamp() * 1_000_000)]
    assert queue.startup_scans == [
        round(NOW.timestamp() * 1_000_000),
        round(NOW.timestamp() * 1_000_000),
    ]
    assert len(queue.completed) == 1


@pytest.mark.parametrize("poll_seconds", [0, -1, 11])
def test_worker_rejects_unbounded_poll_interval(poll_seconds: float) -> None:
    queue = _Queue()
    handler = DurableEventProcessingHandler(queue, _Verifier(), FixedClock(NOW), "worker-1")
    with pytest.raises(ValueError, match="poll interval"):
        DurableIngestionWorker(queue, handler, FixedClock(NOW), poll_seconds=poll_seconds)
