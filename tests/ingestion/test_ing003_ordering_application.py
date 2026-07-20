"""ING-003 live consumer causal-order orchestration tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.ingestion.application.durable_processing import DurableEventProcessingHandler
from agentmemory.ingestion.domain.durable_processing import (
    ClaimedOutboxMessage,
    InboxClaimDisposition,
    InboxReceiptClaim,
    ProcessingDisposition,
    VerifiedEventProjection,
)
from agentmemory.ingestion.domain.ordered_replay import (
    OrderClaimDisposition,
    OrderedEventClaim,
)
from tests.core.support import FixedClock
from tests.ingestion.adp002_support import BRAIN_ID, EVENT_ID, NOW, ORDERING_KEY

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.ports import (
        CanonicalEventProjectionVerifier,
        DurableEventProcessingRepository,
    )

MESSAGE_ID = "018f0000-0000-7000-8000-000000000901"
ZERO_DIGEST = "0" * 64
PAYLOAD_DIGEST = "a" * 64
PROJECTION_DIGEST = "b" * 64


def message() -> ClaimedOutboxMessage:
    return ClaimedOutboxMessage(
        message_id=MESSAGE_ID,
        event_id=EVENT_ID,
        brain_id=BRAIN_ID,
        topic=f"am.local.{BRAIN_ID}.ingestion.agent-event-appended.v1",
        payload=b'{"schema_version":1}',
        payload_sha256=PAYLOAD_DIGEST,
        attempt=1,
        lease_owner="worker-1",
        lease_until_microseconds=42,
    )


def inbox() -> InboxReceiptClaim:
    return InboxReceiptClaim(
        "canonical-event-projection-v1",
        MESSAGE_ID,
        EVENT_ID,
        PAYLOAD_DIGEST,
        InboxClaimDisposition.CLAIMED,
        "worker-1",
        42,
        1,
        None,
    )


def order(disposition: OrderClaimDisposition) -> OrderedEventClaim:
    if disposition is OrderClaimDisposition.UNORDERED:
        return OrderedEventClaim(
            ORDERING_KEY,
            None,
            None,
            ZERO_DIGEST,
            disposition,
            None,
            None,
            None,
            None,
        )
    if disposition is OrderClaimDisposition.READY:
        return OrderedEventClaim(
            ORDERING_KEY,
            1,
            0,
            ZERO_DIGEST,
            disposition,
            "worker-1",
            42,
            None,
            None,
        )
    if disposition is OrderClaimDisposition.BUSY:
        return OrderedEventClaim(
            ORDERING_KEY,
            1,
            0,
            ZERO_DIGEST,
            disposition,
            None,
            None,
            None,
            None,
        )
    if disposition is OrderClaimDisposition.WAIT:
        return OrderedEventClaim(
            ORDERING_KEY,
            3,
            0,
            ZERO_DIGEST,
            disposition,
            None,
            None,
            1,
            2,
        )
    if disposition is OrderClaimDisposition.LATE_REPLAY_REQUIRED:
        return OrderedEventClaim(
            ORDERING_KEY,
            1,
            2,
            "c" * 64,
            disposition,
            None,
            None,
            None,
            None,
        )
    return OrderedEventClaim(
        ORDERING_KEY,
        3,
        0,
        ZERO_DIGEST,
        disposition,
        "worker-1",
        42,
        1,
        2,
    )


@dataclass
class _Verifier:
    calls: int = 0

    async def verify(self, message: ClaimedOutboxMessage) -> VerifiedEventProjection:
        self.calls += 1
        return VerifiedEventProjection(message.event_id, "d" * 64, PROJECTION_DIGEST)


@dataclass
class _Queue:
    order_claim: OrderedEventClaim
    completions: list[tuple[OrderedEventClaim, VerifiedEventProjection]] = field(
        default_factory=list[tuple[OrderedEventClaim, VerifiedEventProjection]]
    )
    retries: list[tuple[OrderedEventClaim | None, str]] = field(
        default_factory=list[tuple[OrderedEventClaim | None, str]]
    )
    deferred: list[OrderedEventClaim] = field(default_factory=list[OrderedEventClaim])

    async def claim_next(self, owner: str, now: int, lease: int) -> ClaimedOutboxMessage:
        del owner, now, lease
        return message()

    async def claim_inbox(
        self,
        claimed: ClaimedOutboxMessage,
        consumer: str,
        owner: str,
        now: int,
        lease: int,
    ) -> InboxReceiptClaim:
        del claimed, consumer, owner, now, lease
        return inbox()

    async def claim_order(  # noqa: PLR0913 -- Mirrors the production port exactly.
        self,
        claimed: ClaimedOutboxMessage,
        receipt: InboxReceiptClaim,
        owner: str,
        now: int,
        lease: int,
        gap_timeout: int,
    ) -> OrderedEventClaim:
        del claimed, receipt, owner, now, lease, gap_timeout
        return self.order_claim

    async def complete(
        self,
        claimed: ClaimedOutboxMessage,
        receipt: InboxReceiptClaim,
        order_claim: OrderedEventClaim,
        projection: VerifiedEventProjection,
        now: int,
    ) -> None:
        del claimed, receipt, now
        self.completions.append((order_claim, projection))

    async def complete_replay(
        self,
        claimed: ClaimedOutboxMessage,
        receipt: InboxReceiptClaim,
        now: int,
    ) -> None:
        del claimed, receipt, now

    async def release_retry(
        self,
        claimed: ClaimedOutboxMessage,
        receipt: InboxReceiptClaim,
        order_claim: OrderedEventClaim | None,
        reason: str,
        retry_at: int,
    ) -> None:
        del claimed, receipt, retry_at
        self.retries.append((order_claim, reason))

    async def defer_replay(
        self,
        claimed: ClaimedOutboxMessage,
        receipt: InboxReceiptClaim,
        order_claim: OrderedEventClaim,
        detected_at: int,
    ) -> None:
        del claimed, receipt, detected_at
        self.deferred.append(order_claim)


def _handler(queue: _Queue, verifier: _Verifier) -> DurableEventProcessingHandler:
    return DurableEventProcessingHandler(
        cast("DurableEventProcessingRepository", queue),
        cast("CanonicalEventProjectionVerifier", verifier),
        FixedClock(NOW),
        "worker-1",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "disposition",
    [
        OrderClaimDisposition.READY,
        OrderClaimDisposition.READY_AFTER_GAP,
        OrderClaimDisposition.UNORDERED,
    ],
)
async def test_ready_order_claim_is_passed_to_atomic_projection_completion(
    disposition: OrderClaimDisposition,
) -> None:
    queue = _Queue(order(disposition))
    verifier = _Verifier()
    result = await _handler(queue, verifier).execute_once()
    assert result.disposition is ProcessingDisposition.COMPLETED
    assert verifier.calls == 1
    assert queue.completions[0][0] == order(disposition)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("disposition", "reason"),
    [
        (OrderClaimDisposition.BUSY, "causal_order_busy"),
        (OrderClaimDisposition.WAIT, "causal_gap_wait"),
    ],
)
async def test_busy_or_missing_predecessor_retries_before_projection_side_effect(
    disposition: OrderClaimDisposition,
    reason: str,
) -> None:
    queue = _Queue(order(disposition))
    verifier = _Verifier()
    result = await _handler(queue, verifier).execute_once()
    assert result.disposition is ProcessingDisposition.RETRY_SCHEDULED
    assert verifier.calls == 0
    assert queue.retries == [(order(disposition), reason)]


@pytest.mark.asyncio
async def test_late_event_is_deferred_for_shadow_replay_without_live_projection() -> None:
    queue = _Queue(order(OrderClaimDisposition.LATE_REPLAY_REQUIRED))
    verifier = _Verifier()
    result = await _handler(queue, verifier).execute_once()
    assert result.disposition is ProcessingDisposition.REPLAY_REQUIRED
    assert verifier.calls == 0
    assert queue.deferred == [order(OrderClaimDisposition.LATE_REPLAY_REQUIRED)]
