"""SQLite ING-001 outbox leasing, canonical verification, and repair alerts."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Self, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.ingestion.adapters.inbound.agent_event_schema import parse_agent_event_json
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    BrainEncryptionKey,
    decrypt_agent_event,
)
from agentmemory.ingestion.domain.capture import EncryptedAgentEvent
from agentmemory.ingestion.domain.durable_processing import (
    ClaimedOutboxMessage,
    InboxClaimDisposition,
    InboxReceiptClaim,
    VerifiedEventProjection,
)
from agentmemory.ingestion.domain.errors import (
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.ordered_replay import (
    CANONICAL_EVENT_PROJECTION_FINGERPRINT,
    OrderClaimDisposition,
    OrderedEventClaim,
    OrderedReductionInput,
    RecordedOperationEvidence,
    reduce_projection,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from agentmemory.ingestion.adapters.outbound.envelope_crypto import BrainKeyProvider
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_STORAGE = "Durable event processing storage is unavailable"
_ERR_INTEGRITY = "Canonical event integrity verification failed"
_ERR_LEASE = "Durable event processing lease diverged"
_ERR_INBOX_CONFLICT = "Inbox message identity conflicts with committed input"
_REPAIR_DETAILS = "Canonical event integrity verification failed"
_OUTBOX_KEYS = frozenset({"brain_id", "event_id", "event_type", "schema_version"})
_STARTUP_SCAN_LIMIT = 100
_PROJECTION_GENERATION = "canonical-event-projection-v1"
_ZERO_DIGEST = "0" * 64

_VERIFY_QUERY = """
SELECT o.id AS message_id, o.source_event_id, o.topic, o.payload, o.payload_sha256,
       e.event_id, e.brain_id, e.type, e.payload_hash, e.classification,
       e.occurred_at, e.ingested_at, e.payload_ref,
       a.sha256 AS artifact_sha256, a.media_type AS artifact_media_type,
       a.byte_length AS artifact_byte_length, a.blob_uri AS artifact_blob_uri,
       a.classification AS artifact_classification,
       x.project_id, x.repository_id, x.checkout_id, x.canonical_sha256,
       x.envelope_version, x.algorithm, x.brain_key_id, x.data_key_id,
       x.payload_nonce, x.ciphertext, x.wrapped_data_key_nonce,
       x.wrapped_data_key, x.aad_sha256
FROM outbox_messages AS o
JOIN agent_events AS e ON e.event_id = o.source_event_id
JOIN agent_event_envelopes AS x ON x.event_id = e.event_id
LEFT JOIN artifacts AS a ON a.id = e.payload_ref
WHERE o.id=:message_id AND o.source_event_id=:event_id
"""


class SqliteDurableEventProcessingRepository:
    """Own short FULL-synchronous lease and terminal-state transactions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical single-writer store."""
        self._store = store

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ClaimedOutboxMessage | None:
        """Claim the oldest available message by priority, due time, then UUIDv7."""
        async with _WriteTransaction(self._store) as transaction:
            row = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT o.id,o.source_event_id,e.brain_id,o.topic,o.payload,"
                            "o.payload_sha256,o.attempts FROM outbox_messages AS o "
                            "JOIN agent_events AS e ON e.event_id=o.source_event_id "
                            "WHERE o.status='ready' AND o.not_before<=:now "
                            "AND o.topic LIKE 'am.local.%.ingestion.agent-event-appended.v1' "
                            "ORDER BY o.priority,o.not_before,o.id LIMIT 1"
                        ),
                        {"now": now_microseconds},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                await transaction.commit()
                return None
            updated = await transaction.connection.execute(
                text(
                    "UPDATE outbox_messages SET status='leased',lease_owner=:owner,"
                    "lease_until=:lease_until,attempts=attempts+1,last_error_code=NULL "
                    "WHERE id=:id AND status='ready'"
                ),
                {
                    "id": str(row["id"]),
                    "lease_until": lease_until_microseconds,
                    "owner": owner,
                },
            )
            if updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_LEASE)
            await transaction.commit()
        try:
            return _claimed(row, owner, lease_until_microseconds)
        except IngestionValidationError:
            await self._repair_malformed_row(row, now_microseconds)
            return None

    async def complete(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim,
        projection: VerifiedEventProjection,
        completed_at_microseconds: int,
    ) -> None:
        """Commit exactly one terminal receipt together with lease completion."""
        if (
            projection.event_id != message.event_id
            or inbox.disposition is not InboxClaimDisposition.CLAIMED
            or inbox.owner is None
        ):
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            reduction, state_sha256 = await _ordered_reduction(
                transaction.connection,
                message,
                inbox,
                order,
                projection,
            )
            await transaction.connection.execute(
                text(
                    "INSERT INTO event_projection_receipts "
                    "(event_id,outbox_message_id,brain_id,canonical_sha256,projection_sha256,"
                    "status,completed_at,created_at,schema_version) VALUES "
                    "(:event_id,:message_id,:brain_id,:canonical,:projection,'completed',"
                    ":completed_at,:completed_at,1)"
                ),
                {
                    "brain_id": message.brain_id,
                    "canonical": bytes.fromhex(projection.canonical_sha256),
                    "completed_at": completed_at_microseconds,
                    "event_id": message.event_id,
                    "message_id": message.message_id,
                    "projection": bytes.fromhex(projection.projection_sha256),
                },
            )
            await _finish_lease(
                transaction.connection,
                message,
                "completed",
                completed_at_microseconds,
                None,
            )
            await transaction.connection.execute(
                text(
                    "INSERT INTO projection_idempotency_receipts "
                    "(projection_name,idempotency_key,brain_id,source_message_id,"
                    "projection_generation,request_sha256,result_sha256,completed_at,"
                    "created_at,schema_version) VALUES "
                    "(:projection,:key,:brain,:message,:generation,:request,:result,:now,:now,1)"
                ),
                {
                    "brain": message.brain_id,
                    "generation": _PROJECTION_GENERATION,
                    "key": message.event_id,
                    "message": message.message_id,
                    "now": completed_at_microseconds,
                    "projection": inbox.consumer,
                    "request": bytes.fromhex(inbox.request_sha256),
                    "result": bytes.fromhex(projection.projection_sha256),
                },
            )
            inbox_updated = await transaction.connection.execute(
                text(
                    "UPDATE inbox_receipts SET state='completed',lease_owner=NULL,"
                    "lease_until=NULL,result_sha256=:result,processed_at=:now,updated_at=:now "
                    "WHERE consumer=:consumer AND idempotency_key=:key AND state='processing' "
                    "AND lease_owner=:owner"
                ),
                {
                    "consumer": inbox.consumer,
                    "key": message.event_id,
                    "now": completed_at_microseconds,
                    "owner": inbox.owner,
                    "result": bytes.fromhex(projection.projection_sha256),
                },
            )
            if inbox_updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_LEASE)
            await _finish_ordered_projection(
                transaction.connection,
                message,
                inbox,
                order,
                reduction,
                state_sha256,
                completed_at_microseconds,
            )
            await _append_projection_audit(
                transaction.connection,
                message,
                projection,
                completed_at_microseconds,
            )
            await transaction.commit()

    async def claim_order(  # noqa: PLR0913 -- Port carries exact lease/gap evidence.
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
        gap_timeout_microseconds: int,
    ) -> OrderedEventClaim:
        """Arbitrate one event against its per-key causal watermark."""
        if (
            inbox.disposition is not InboxClaimDisposition.CLAIMED
            or inbox.owner != owner
            or lease_until_microseconds <= now_microseconds
            or gap_timeout_microseconds < 0
        ):
            raise IngestionIntegrityError(_ERR_LEASE)
        async with _WriteTransaction(self._store) as transaction:
            event_row = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT x.ordering_key,x.sequence FROM agent_event_envelopes x "
                            "JOIN agent_events e ON e.event_id=x.event_id "
                            "WHERE x.event_id=:event AND e.brain_id=:brain"
                        ),
                        {"brain": message.brain_id, "event": message.event_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if event_row is None:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            ordering_key = str(event_row["ordering_key"])
            raw_sequence = event_row["sequence"]
            if raw_sequence is None:
                claim = OrderedEventClaim(
                    ordering_key,
                    None,
                    None,
                    _ZERO_DIGEST,
                    OrderClaimDisposition.UNORDERED,
                    None,
                    None,
                    None,
                    None,
                )
                await transaction.commit()
                return claim
            event_sequence = int(str(raw_sequence))
            await transaction.connection.execute(
                text(
                    "INSERT OR IGNORE INTO projection_order_watermarks "
                    "(projection_name,brain_id,ordering_key,applied_sequence,state_sha256,"
                    "created_at,updated_at,schema_version) VALUES "
                    "(:projection,:brain,:ordering,0,:state,:now,:now,1)"
                ),
                {
                    "brain": message.brain_id,
                    "now": now_microseconds,
                    "ordering": ordering_key,
                    "projection": inbox.consumer,
                    "state": bytes(32),
                },
            )
            watermark = await _watermark(
                transaction.connection,
                inbox.consumer,
                message.brain_id,
                ordering_key,
            )
            prior_sequence = int(str(watermark["applied_sequence"]))
            prior_state = _bytes(watermark["state_sha256"]).hex()
            if event_sequence <= prior_sequence:
                await _mark_late_gap(
                    transaction.connection,
                    message,
                    inbox.consumer,
                    ordering_key,
                    event_sequence,
                    now_microseconds,
                )
                claim = OrderedEventClaim(
                    ordering_key,
                    event_sequence,
                    prior_sequence,
                    prior_state,
                    OrderClaimDisposition.LATE_REPLAY_REQUIRED,
                    None,
                    None,
                    None,
                    None,
                )
                await transaction.commit()
                return claim
            current_lease = watermark["lease_until"]
            if current_lease is not None and int(str(current_lease)) > now_microseconds:
                claim = OrderedEventClaim(
                    ordering_key,
                    event_sequence,
                    prior_sequence,
                    prior_state,
                    OrderClaimDisposition.BUSY,
                    None,
                    None,
                    None,
                    None,
                )
                await transaction.commit()
                return claim
            if current_lease is not None:
                await _clear_expired_order_lease(
                    transaction.connection,
                    inbox.consumer,
                    message.brain_id,
                    ordering_key,
                    now_microseconds,
                )
            if event_sequence == prior_sequence + 1:
                disposition = OrderClaimDisposition.READY
                gap_from = None
                gap_to = None
            else:
                gap_from = prior_sequence + 1
                gap_to = event_sequence - 1
                timeout_at = now_microseconds + gap_timeout_microseconds
                gap = (
                    (
                        await transaction.connection.execute(
                            text(
                                "SELECT state,timeout_at FROM projection_order_gaps "
                                "WHERE projection_name=:projection AND brain_id=:brain "
                                "AND ordering_key=:ordering AND blocking_event_id=:event"
                            ),
                            {
                                "brain": message.brain_id,
                                "event": message.event_id,
                                "ordering": ordering_key,
                                "projection": inbox.consumer,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if gap is None:
                    await transaction.connection.execute(
                        text(
                            "INSERT INTO projection_order_gaps "
                            "(projection_name,brain_id,ordering_key,blocking_event_id,"
                            "from_sequence,to_sequence,state,first_detected_at,timeout_at,"
                            "created_at,updated_at,schema_version) VALUES "
                            "(:projection,:brain,:ordering,:event,:gap_from,:gap_to,'waiting',"
                            ":now,:timeout,:now,:now,1)"
                        ),
                        {
                            "brain": message.brain_id,
                            "event": message.event_id,
                            "gap_from": gap_from,
                            "gap_to": gap_to,
                            "now": now_microseconds,
                            "ordering": ordering_key,
                            "projection": inbox.consumer,
                            "timeout": timeout_at,
                        },
                    )
                else:
                    timeout_at = int(str(gap["timeout_at"]))
                    await transaction.connection.execute(
                        text(
                            "UPDATE projection_order_gaps SET from_sequence=:gap_from,"
                            "to_sequence=:gap_to,updated_at=:now WHERE "
                            "projection_name=:projection AND brain_id=:brain "
                            "AND ordering_key=:ordering AND blocking_event_id=:event "
                            "AND state='waiting'"
                        ),
                        {
                            "brain": message.brain_id,
                            "event": message.event_id,
                            "gap_from": gap_from,
                            "gap_to": gap_to,
                            "now": now_microseconds,
                            "ordering": ordering_key,
                            "projection": inbox.consumer,
                        },
                    )
                if timeout_at > now_microseconds:
                    claim = OrderedEventClaim(
                        ordering_key,
                        event_sequence,
                        prior_sequence,
                        prior_state,
                        OrderClaimDisposition.WAIT,
                        None,
                        None,
                        gap_from,
                        gap_to,
                    )
                    await transaction.commit()
                    return claim
                await transaction.connection.execute(
                    text(
                        "UPDATE projection_order_gaps SET state='declared',declared_at=:now,"
                        "updated_at=:now WHERE projection_name=:projection AND brain_id=:brain "
                        "AND ordering_key=:ordering AND blocking_event_id=:event "
                        "AND state='waiting' AND timeout_at<=:now"
                    ),
                    {
                        "brain": message.brain_id,
                        "event": message.event_id,
                        "now": now_microseconds,
                        "ordering": ordering_key,
                        "projection": inbox.consumer,
                    },
                )
                disposition = OrderClaimDisposition.READY_AFTER_GAP
            await _lease_order_watermark(
                transaction.connection,
                message,
                inbox.consumer,
                ordering_key,
                event_sequence,
                prior_sequence,
                owner,
                lease_until_microseconds,
            )
            claim = OrderedEventClaim(
                ordering_key,
                event_sequence,
                prior_sequence,
                prior_state,
                disposition,
                owner,
                lease_until_microseconds,
                gap_from,
                gap_to,
            )
            await transaction.commit()
            return claim

    async def claim_inbox(
        self,
        message: ClaimedOutboxMessage,
        consumer: str,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> InboxReceiptClaim:
        """Claim one consumer identity or replay its exact committed result."""
        conflict = False
        repair_required = False
        async with _WriteTransaction(self._store) as transaction:
            row = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT * FROM inbox_receipts WHERE consumer=:consumer "
                            "AND (message_id=:message OR idempotency_key=:key) "
                            "ORDER BY CASE WHEN message_id=:message THEN 0 ELSE 1 END LIMIT 1"
                        ),
                        {
                            "consumer": consumer,
                            "key": message.event_id,
                            "message": message.message_id,
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                await transaction.connection.execute(
                    text(
                        "INSERT INTO inbox_receipts "
                        "(consumer,message_id,idempotency_key,brain_id,request_sha256,state,"
                        "attempts,lease_owner,lease_until,created_at,updated_at,schema_version) "
                        "VALUES (:consumer,:message,:key,:brain,:request,'processing',1,:owner,"
                        ":lease,:now,:now,1)"
                    ),
                    {
                        "brain": message.brain_id,
                        "consumer": consumer,
                        "key": message.event_id,
                        "lease": lease_until_microseconds,
                        "message": message.message_id,
                        "now": now_microseconds,
                        "owner": owner,
                        "request": bytes.fromhex(message.payload_sha256),
                    },
                )
                claim = InboxReceiptClaim(
                    consumer,
                    message.message_id,
                    message.event_id,
                    message.payload_sha256,
                    InboxClaimDisposition.CLAIMED,
                    owner,
                    lease_until_microseconds,
                    1,
                    None,
                )
            elif _bytes(row["request_sha256"]).hex() != message.payload_sha256:
                await _append_inbox_conflict(
                    transaction.connection,
                    message,
                    consumer,
                    _bytes(row["request_sha256"]),
                    now_microseconds,
                )
                if str(row["state"]) != "repair_required":
                    await _upsert_repair_alert(
                        transaction.connection,
                        message,
                        "idempotency_conflict",
                        now_microseconds,
                    )
                    await _finish_lease(
                        transaction.connection,
                        message,
                        "repair_required",
                        None,
                        "idempotency_conflict",
                    )
                    await transaction.connection.execute(
                        text(
                            "UPDATE inbox_receipts SET state='repair_required',lease_owner=NULL,"
                            "lease_until=NULL,processed_at=:now,updated_at=:now "
                            "WHERE consumer=:consumer AND idempotency_key=:key "
                            "AND state='processing'"
                        ),
                        {
                            "consumer": consumer,
                            "key": message.event_id,
                            "now": now_microseconds,
                        },
                    )
                conflict = True
                claim = _inbox_wait_claim(message, consumer, int(str(row["attempts"])))
            elif str(row["state"]) == "completed":
                claim = InboxReceiptClaim(
                    consumer,
                    message.message_id,
                    message.event_id,
                    message.payload_sha256,
                    InboxClaimDisposition.REPLAY,
                    None,
                    None,
                    int(str(row["attempts"])),
                    _bytes(row["result_sha256"]).hex(),
                )
            elif str(row["state"]) == "repair_required":
                repair_required = True
                claim = _inbox_wait_claim(message, consumer, int(str(row["attempts"])))
            elif int(str(row["lease_until"])) > now_microseconds:
                claim = _inbox_wait_claim(message, consumer, int(str(row["attempts"])))
            else:
                updated = await transaction.connection.execute(
                    text(
                        "UPDATE inbox_receipts SET lease_owner=:owner,lease_until=:lease,"
                        "attempts=attempts+1,updated_at=:now WHERE consumer=:consumer "
                        "AND idempotency_key=:key AND state='processing' AND lease_until<=:now"
                    ),
                    {
                        "consumer": consumer,
                        "key": message.event_id,
                        "lease": lease_until_microseconds,
                        "now": now_microseconds,
                        "owner": owner,
                    },
                )
                if updated.rowcount != 1:
                    claim = _inbox_wait_claim(message, consumer, int(str(row["attempts"])))
                else:
                    claim = InboxReceiptClaim(
                        consumer,
                        message.message_id,
                        message.event_id,
                        message.payload_sha256,
                        InboxClaimDisposition.CLAIMED,
                        owner,
                        lease_until_microseconds,
                        int(str(row["attempts"])) + 1,
                        None,
                    )
            await transaction.commit()
        if conflict:
            raise IngestionConflictError(_ERR_INBOX_CONFLICT)
        if repair_required:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        return claim

    async def complete_replay(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        completed_at_microseconds: int,
    ) -> None:
        """Validate exact terminal evidence before ACKing a repeated delivery."""
        if inbox.disposition is not InboxClaimDisposition.REPLAY or inbox.result_sha256 is None:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            row = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT i.result_sha256,p.result_sha256 AS projection_sha256,"
                            "p.request_sha256 "
                            "FROM inbox_receipts i JOIN projection_idempotency_receipts p "
                            "ON p.projection_name=i.consumer AND "
                            "p.idempotency_key=i.idempotency_key "
                            "WHERE i.consumer=:consumer AND i.idempotency_key=:key "
                            "AND i.state='completed'"
                        ),
                        {"consumer": inbox.consumer, "key": message.event_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                row is None
                or _bytes(row["result_sha256"]).hex() != inbox.result_sha256
                or _bytes(row["projection_sha256"]).hex() != inbox.result_sha256
                or _bytes(row["request_sha256"]).hex() != message.payload_sha256
            ):
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            await _finish_lease(
                transaction.connection,
                message,
                "completed",
                completed_at_microseconds,
                None,
            )
            await transaction.commit()

    async def require_repair(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim,
        reason_code: str,
        detected_at_microseconds: int,
    ) -> None:
        """Atomically stop corrupt work, create a local alert, and append safe audit."""
        async with _WriteTransaction(self._store) as transaction:
            await _upsert_repair_alert(
                transaction.connection,
                message,
                reason_code,
                detected_at_microseconds,
            )
            await _finish_lease(
                transaction.connection,
                message,
                "repair_required",
                None,
                reason_code,
            )
            await _append_repair_audit(transaction.connection, message, detected_at_microseconds)
            await _finish_inbox_repair(
                transaction.connection,
                inbox,
                detected_at_microseconds,
            )
            await _release_order_lease(transaction.connection, message, inbox, order)
            await transaction.commit()

    async def release_retry(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim | None,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        """Release the exact active lease without claiming terminal success."""
        async with _WriteTransaction(self._store) as transaction:
            updated = await transaction.connection.execute(
                text(
                    "UPDATE outbox_messages SET status='ready',lease_owner=NULL,lease_until=NULL,"
                    "not_before=:retry_at,last_error_code=:reason WHERE id=:id "
                    "AND status='leased' AND lease_owner=:owner"
                ),
                {
                    "id": message.message_id,
                    "owner": message.lease_owner,
                    "reason": reason_code,
                    "retry_at": retry_at_microseconds,
                },
            )
            if updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_LEASE)
            if inbox.disposition is InboxClaimDisposition.CLAIMED:
                inbox_updated = await transaction.connection.execute(
                    text(
                        "UPDATE inbox_receipts SET lease_until=:retry,updated_at=:retry "
                        "WHERE consumer=:consumer AND idempotency_key=:key "
                        "AND state='processing' AND lease_owner=:owner"
                    ),
                    {
                        "consumer": inbox.consumer,
                        "key": message.event_id,
                        "owner": inbox.owner,
                        "retry": retry_at_microseconds,
                    },
                )
                if inbox_updated.rowcount != 1:
                    raise IngestionIntegrityError(_ERR_LEASE)
            if order is not None:
                await _release_order_lease(transaction.connection, message, inbox, order)
            await transaction.commit()

    async def defer_replay(
        self,
        message: ClaimedOutboxMessage,
        inbox: InboxReceiptClaim,
        order: OrderedEventClaim,
        detected_at_microseconds: int,
    ) -> None:
        """Hold a late event outside live state until an explicit shadow replay succeeds."""
        if (
            order.disposition is not OrderClaimDisposition.LATE_REPLAY_REQUIRED
            or order.event_sequence is None
            or inbox.disposition is not InboxClaimDisposition.CLAIMED
            or inbox.owner is None
        ):
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            await _assert_order_event(
                transaction.connection,
                message,
                order.ordering_key,
                order.event_sequence,
            )
            await transaction.connection.execute(
                text(
                    "INSERT OR IGNORE INTO ordered_replay_required_events "
                    "(projection_name,event_id,brain_id,outbox_message_id,ordering_key,"
                    "event_sequence,state,detected_at,schema_version) VALUES "
                    "(:projection,:event,:brain,:message,:ordering,:sequence,'pending',:now,1)"
                ),
                {
                    "brain": message.brain_id,
                    "event": message.event_id,
                    "message": message.message_id,
                    "now": detected_at_microseconds,
                    "ordering": order.ordering_key,
                    "projection": inbox.consumer,
                    "sequence": order.event_sequence,
                },
            )
            await _finish_lease(
                transaction.connection,
                message,
                "replay_required",
                None,
                "causal_late_event",
            )
            inbox_updated = await transaction.connection.execute(
                text(
                    "UPDATE inbox_receipts SET state='replay_required',lease_owner=NULL,"
                    "lease_until=NULL,processed_at=:now,updated_at=:now WHERE "
                    "consumer=:consumer AND message_id=:message AND state='processing' "
                    "AND lease_owner=:owner"
                ),
                {
                    "consumer": inbox.consumer,
                    "message": inbox.message_id,
                    "now": detected_at_microseconds,
                    "owner": inbox.owner,
                },
            )
            if inbox_updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_LEASE)
            await _append_replay_required_audit(
                transaction.connection,
                message,
                detected_at_microseconds,
            )
            await transaction.commit()

    async def recover_expired_leases(self, now_microseconds: int) -> int:
        """Return every expired lease to ready before normal startup processing."""
        async with _WriteTransaction(self._store) as transaction:
            result = await transaction.connection.execute(
                text(
                    "UPDATE outbox_messages SET status='ready',lease_owner=NULL,lease_until=NULL,"
                    "not_before=:now,last_error_code='lease_expired' "
                    "WHERE status='leased' AND lease_until<=:now"
                ),
                {"now": now_microseconds},
            )
            await transaction.connection.execute(
                text(
                    "UPDATE projection_order_watermarks SET lease_owner=NULL,"
                    "lease_event_id=NULL,lease_sequence=NULL,lease_until=NULL,updated_at=:now "
                    "WHERE lease_until IS NOT NULL AND lease_until<=:now"
                ),
                {"now": now_microseconds},
            )
            await transaction.commit()
            return max(result.rowcount, 0)

    async def alert_unprocessed_events(self, detected_at_microseconds: int) -> int:
        """Create bounded alerts for canonical events missing atomic dispatch intent."""
        async with _WriteTransaction(self._store) as transaction:
            rows = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT e.event_id,e.brain_id FROM agent_events AS e "
                            "JOIN agent_event_envelopes AS x ON x.event_id=e.event_id "
                            "LEFT JOIN outbox_messages AS o ON o.source_event_id=e.event_id "
                            "LEFT JOIN event_projection_receipts AS r ON r.event_id=e.event_id "
                            "LEFT JOIN ingestion_repair_alerts AS a "
                            "ON a.source_event_id=e.event_id "
                            "WHERE o.id IS NULL AND r.event_id IS NULL AND a.id IS NULL "
                            "ORDER BY e.ingested_at,e.event_id LIMIT :limit"
                        ),
                        {"limit": _STARTUP_SCAN_LIMIT},
                    )
                )
                .mappings()
                .all()
            )
            for row in rows:
                await transaction.connection.execute(
                    text(
                        "INSERT INTO ingestion_repair_alerts "
                        "(id,brain_id,source_event_id,outbox_message_id,component,error_code,"
                        "safe_details,state,first_detected_at,last_detected_at,created_at,"
                        "updated_at,schema_version) VALUES "
                        "(:id,:brain,:event,NULL,'canonical_ingestion','outbox_missing',"
                        "'Canonical event dispatch intent is missing','open',"
                        ":now,:now,:now,:now,1)"
                    ),
                    {
                        "brain": str(row["brain_id"]),
                        "event": str(row["event_id"]),
                        "id": str(uuid7()),
                        "now": detected_at_microseconds,
                    },
                )
            await transaction.commit()
            return len(rows)

    async def _repair_malformed_row(self, row: RowMapping, detected_at: int) -> None:
        message_id = str(row["id"])
        event_id = str(row["source_event_id"])
        brain_id = str(row["brain_id"])
        async with _WriteTransaction(self._store) as transaction:
            await transaction.connection.execute(
                text(
                    "UPDATE outbox_messages SET status='repair_required',lease_owner=NULL,"
                    "lease_until=NULL,last_error_code='canonical_integrity_violation' "
                    "WHERE id=:id"
                ),
                {"id": message_id},
            )
            await transaction.connection.execute(
                text(
                    "INSERT INTO ingestion_repair_alerts "
                    "(id,brain_id,source_event_id,outbox_message_id,component,error_code,"
                    "safe_details,state,first_detected_at,last_detected_at,created_at,updated_at,"
                    "schema_version) VALUES (:id,:brain,:event,:message,'canonical_ingestion',"
                    "'canonical_integrity_violation',:details,'open',:now,:now,:now,:now,1)"
                ),
                {
                    "brain": brain_id,
                    "details": _REPAIR_DETAILS,
                    "event": event_id,
                    "id": str(uuid7()),
                    "message": message_id,
                    "now": detected_at,
                },
            )
            await transaction.commit()


class SqliteCanonicalEventProjectionVerifier:
    """Authenticate canonical event/outbox bindings and derive a terminal digest."""

    def __init__(self, engine: AsyncEngine, keys: BrainKeyProvider) -> None:
        """Bind read-only canonical storage and Brain key access."""
        self._engine = engine
        self._keys = keys

    async def verify(self, message: ClaimedOutboxMessage) -> VerifiedEventProjection:
        """Fail closed on missing, malformed, divergent, or unauthenticated records."""
        try:
            async with self._engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(_VERIFY_QUERY),
                            {"event_id": message.event_id, "message_id": message.message_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        if row is None:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        brain_key = await self._keys.current(message.brain_id)
        return _verify_row(message, row, brain_key)


class _WriteTransaction:
    """Small transaction helper that owns the shared writer lock and commit boundary."""

    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self.connection: AsyncConnection
        self._committed = False

    async def __aenter__(self) -> Self:
        await self._store.write_lock.acquire()
        try:
            self.connection = await self._store.engine.connect()
            await self.connection.exec_driver_sql("BEGIN IMMEDIATE")
        except SQLAlchemyError as error:
            if hasattr(self, "connection"):
                await self.connection.close()
            self._store.write_lock.release()
            raise IngestionDependencyError(_ERR_STORAGE) from error
        except BaseException:
            if hasattr(self, "connection"):
                await self.connection.close()
            self._store.write_lock.release()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, traceback
        storage_error = exc if isinstance(exc, SQLAlchemyError) else None
        try:
            if not self._committed:
                try:
                    await self.connection.rollback()
                except SQLAlchemyError as error:
                    storage_error = error
        finally:
            try:
                await self.connection.close()
            finally:
                self._store.write_lock.release()
        if storage_error is not None:
            raise IngestionDependencyError(_ERR_STORAGE) from storage_error
        return None

    async def commit(self) -> None:
        try:
            await self.connection.commit()
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        self._committed = True


async def _watermark(
    connection: AsyncConnection,
    projection_name: str,
    brain_id: str,
    ordering_key: str,
) -> RowMapping:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM projection_order_watermarks WHERE "
                    "projection_name=:projection AND brain_id=:brain AND ordering_key=:ordering"
                ),
                {
                    "brain": brain_id,
                    "ordering": ordering_key,
                    "projection": projection_name,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    return row


async def _clear_expired_order_lease(
    connection: AsyncConnection,
    projection_name: str,
    brain_id: str,
    ordering_key: str,
    now_microseconds: int,
) -> None:
    await connection.execute(
        text(
            "UPDATE projection_order_watermarks SET lease_owner=NULL,lease_event_id=NULL,"
            "lease_sequence=NULL,lease_until=NULL,updated_at=:now WHERE "
            "projection_name=:projection AND brain_id=:brain AND ordering_key=:ordering "
            "AND lease_until IS NOT NULL AND lease_until<=:now"
        ),
        {
            "brain": brain_id,
            "now": now_microseconds,
            "ordering": ordering_key,
            "projection": projection_name,
        },
    )


async def _lease_order_watermark(  # noqa: PLR0913 -- CAS inputs are intentionally explicit.
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    projection_name: str,
    ordering_key: str,
    event_sequence: int,
    prior_sequence: int,
    owner: str,
    lease_until_microseconds: int,
) -> None:
    result = await connection.execute(
        text(
            "UPDATE projection_order_watermarks SET lease_owner=:owner,lease_event_id=:event,"
            "lease_sequence=:sequence,lease_until=:lease,updated_at=:lease WHERE "
            "projection_name=:projection AND brain_id=:brain AND ordering_key=:ordering "
            "AND applied_sequence=:prior AND lease_owner IS NULL"
        ),
        {
            "brain": message.brain_id,
            "event": message.event_id,
            "lease": lease_until_microseconds,
            "ordering": ordering_key,
            "owner": owner,
            "prior": prior_sequence,
            "projection": projection_name,
            "sequence": event_sequence,
        },
    )
    if result.rowcount != 1:
        raise IngestionIntegrityError(_ERR_LEASE)


async def _mark_late_gap(  # noqa: PLR0913 -- Durable gap identity is composite.
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    projection_name: str,
    ordering_key: str,
    event_sequence: int,
    detected_at_microseconds: int,
) -> None:
    await connection.execute(
        text(
            "UPDATE projection_order_gaps SET state='late_arrived',late_event_id=:event,"
            "late_arrived_at=:now,updated_at=:now WHERE rowid=(SELECT rowid FROM "
            "projection_order_gaps WHERE projection_name=:projection AND brain_id=:brain "
            "AND ordering_key=:ordering AND state='declared' AND "
            ":sequence BETWEEN from_sequence AND to_sequence ORDER BY declared_at,rowid LIMIT 1)"
        ),
        {
            "brain": message.brain_id,
            "event": message.event_id,
            "now": detected_at_microseconds,
            "ordering": ordering_key,
            "projection": projection_name,
            "sequence": event_sequence,
        },
    )


async def _assert_order_event(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    ordering_key: str,
    event_sequence: int | None,
) -> None:
    value = (
        await connection.execute(
            text(
                "SELECT COUNT(*) FROM agent_event_envelopes x JOIN agent_events e "
                "ON e.event_id=x.event_id WHERE x.event_id=:event AND e.brain_id=:brain "
                "AND x.ordering_key=:ordering AND "
                "((:sequence IS NULL AND x.sequence IS NULL) OR x.sequence=:sequence)"
            ),
            {
                "brain": message.brain_id,
                "event": message.event_id,
                "ordering": ordering_key,
                "sequence": event_sequence,
            },
        )
    ).scalar_one()
    if value != 1:
        raise IngestionIntegrityError(_ERR_INTEGRITY)


async def _ordered_reduction(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    inbox: InboxReceiptClaim,
    order: OrderedEventClaim,
    projection: VerifiedEventProjection,
) -> tuple[OrderedReductionInput, str]:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT e.brain_id,e.schema_version AS event_schema_version,"
                    "x.ordering_key,x.sequence,x.canonical_sha256,"
                    "r.operation_id,r.profile_id,r.model_revision,r.purpose,"
                    "r.result_sha256 AS recorded_result_sha256,r.result_ref AS recorded_result_ref,"
                    "p.profile_id AS provider_profile_id,p.brain_id AS provider_brain_id,"
                    "p.state AS provider_state,p.result_sha256 AS provider_result_sha256,"
                    "p.result_ref AS provider_result_ref FROM agent_events e "
                    "JOIN agent_event_envelopes x ON x.event_id=e.event_id "
                    "LEFT JOIN recorded_reduction_inputs r ON "
                    "r.event_id=e.event_id AND r.projection_name=:projection "
                    "LEFT JOIN provider_operation_results p ON p.operation_id=r.operation_id "
                    "WHERE e.event_id=:event AND e.brain_id=:brain"
                ),
                {
                    "brain": message.brain_id,
                    "event": message.event_id,
                    "projection": inbox.consumer,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    raw_sequence = row["sequence"]
    event_sequence = None if raw_sequence is None else int(str(raw_sequence))
    canonical_sha256 = _bytes(row["canonical_sha256"]).hex()
    if (
        str(row["ordering_key"]) != order.ordering_key
        or event_sequence != order.event_sequence
        or canonical_sha256 != projection.canonical_sha256
    ):
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    operation_id = row["operation_id"]
    recorded: RecordedOperationEvidence | None = None
    if operation_id is not None:
        recorded_result = _bytes(row["recorded_result_sha256"])
        provider_result = _bytes(row["provider_result_sha256"])
        if (
            str(row["provider_state"]) != "completed"
            or str(row["profile_id"]) != str(row["provider_profile_id"])
            or str(row["provider_brain_id"]) != message.brain_id
            or recorded_result != provider_result
            or str(row["recorded_result_ref"]) != str(row["provider_result_ref"])
        ):
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        recorded = RecordedOperationEvidence(
            str(operation_id),
            str(row["profile_id"]),
            str(row["model_revision"]),
            str(row["purpose"]),
            recorded_result.hex(),
        )
    reduction = OrderedReductionInput(
        message.event_id,
        order.ordering_key,
        order.event_sequence,
        int(str(row["event_schema_version"])),
        canonical_sha256,
        projection.projection_sha256,
        recorded is not None,
        recorded,
    )
    prior_state = order.prior_state_sha256
    if order.disposition is OrderClaimDisposition.UNORDERED:
        if order.prior_sequence is not None:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        prior_state = _ZERO_DIGEST
    elif order.disposition not in {
        OrderClaimDisposition.READY,
        OrderClaimDisposition.READY_AFTER_GAP,
    }:
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    return reduction, reduce_projection(
        prior_state,
        reduction,
        CANONICAL_EVENT_PROJECTION_FINGERPRINT,
    )


async def _finish_ordered_projection(  # noqa: PLR0913 -- Atomic boundary needs all evidence.
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    inbox: InboxReceiptClaim,
    order: OrderedEventClaim,
    reduction: OrderedReductionInput,
    state_sha256: str,
    completed_at_microseconds: int,
) -> None:
    if order.disposition in {
        OrderClaimDisposition.READY,
        OrderClaimDisposition.READY_AFTER_GAP,
    }:
        if (
            order.owner is None
            or order.event_sequence is None
            or order.prior_sequence is None
            or order.owner != inbox.owner
        ):
            raise IngestionIntegrityError(_ERR_LEASE)
        updated = await connection.execute(
            text(
                "UPDATE projection_order_watermarks SET applied_sequence=:sequence,"
                "state_sha256=:state,last_event_id=:event,lease_owner=NULL,lease_event_id=NULL,"
                "lease_sequence=NULL,lease_until=NULL,updated_at=:now WHERE "
                "projection_name=:projection AND brain_id=:brain AND ordering_key=:ordering "
                "AND applied_sequence=:prior AND state_sha256=:prior_state "
                "AND lease_owner=:owner AND lease_event_id=:event AND lease_sequence=:sequence"
            ),
            {
                "brain": message.brain_id,
                "event": message.event_id,
                "now": completed_at_microseconds,
                "ordering": order.ordering_key,
                "owner": order.owner,
                "prior": order.prior_sequence,
                "prior_state": bytes.fromhex(order.prior_state_sha256),
                "projection": inbox.consumer,
                "sequence": order.event_sequence,
                "state": bytes.fromhex(state_sha256),
            },
        )
        if updated.rowcount != 1:
            raise IngestionIntegrityError(_ERR_LEASE)
    elif order.disposition is not OrderClaimDisposition.UNORDERED:
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    await connection.execute(
        text(
            "INSERT INTO ordered_projection_history "
            "(projection_name,event_id,brain_id,ordering_key,event_sequence,"
            "event_schema_version,canonical_sha256,projection_sha256,prior_state_sha256,"
            "state_sha256,code_fingerprint,recorded_operation_id,applied_at,schema_version) "
            "VALUES (:projection,:event,:brain,:ordering,:sequence,:event_schema,:canonical,"
            ":result,:prior,:state,:fingerprint,:operation,:now,1)"
        ),
        {
            "brain": message.brain_id,
            "canonical": bytes.fromhex(reduction.canonical_sha256),
            "event": message.event_id,
            "event_schema": reduction.event_schema_version,
            "fingerprint": CANONICAL_EVENT_PROJECTION_FINGERPRINT,
            "now": completed_at_microseconds,
            "operation": (
                None
                if reduction.recorded_operation is None
                else reduction.recorded_operation.operation_id
            ),
            "ordering": order.ordering_key,
            "prior": bytes.fromhex(order.prior_state_sha256),
            "projection": inbox.consumer,
            "result": bytes.fromhex(reduction.projection_sha256),
            "sequence": order.event_sequence,
            "state": bytes.fromhex(state_sha256),
        },
    )


async def _release_order_lease(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    inbox: InboxReceiptClaim,
    order: OrderedEventClaim,
) -> None:
    if order.disposition not in {
        OrderClaimDisposition.READY,
        OrderClaimDisposition.READY_AFTER_GAP,
    }:
        return
    if order.owner is None or order.event_sequence is None or order.owner != inbox.owner:
        raise IngestionIntegrityError(_ERR_LEASE)
    result = await connection.execute(
        text(
            "UPDATE projection_order_watermarks SET lease_owner=NULL,lease_event_id=NULL,"
            "lease_sequence=NULL,lease_until=NULL WHERE projection_name=:projection "
            "AND brain_id=:brain AND ordering_key=:ordering AND lease_owner=:owner "
            "AND lease_event_id=:event AND lease_sequence=:sequence"
        ),
        {
            "brain": message.brain_id,
            "event": message.event_id,
            "ordering": order.ordering_key,
            "owner": order.owner,
            "projection": inbox.consumer,
            "sequence": order.event_sequence,
        },
    )
    if result.rowcount != 1:
        raise IngestionIntegrityError(_ERR_LEASE)


def _claimed(row: RowMapping, owner: str, lease_until: int) -> ClaimedOutboxMessage:
    return ClaimedOutboxMessage(
        message_id=str(row["id"]),
        event_id=str(row["source_event_id"]),
        brain_id=str(row["brain_id"]),
        topic=str(row["topic"]),
        payload=str(row["payload"]).encode("utf-8"),
        payload_sha256=_bytes(row["payload_sha256"]).hex(),
        attempt=int(str(row["attempts"])) + 1,
        lease_owner=owner,
        lease_until_microseconds=lease_until,
    )


def _verify_row(
    message: ClaimedOutboxMessage,
    row: RowMapping,
    brain_key: BrainEncryptionKey,
) -> VerifiedEventProjection:
    try:
        _verify_outbox(message, row)
        encrypted = _encrypted(row)
        raw = decrypt_agent_event(
            encrypted,
            brain_key,
            event_id=message.event_id,
            brain_id=message.brain_id,
            classification=str(row["classification"]),
        )
        if hashlib.sha256(raw).hexdigest() != encrypted.canonical_sha256:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        event = parse_agent_event_json(raw)
        _verify_event_index(event, row, message)
    except (IngestionDependencyError, IngestionValidationError, ValueError) as error:
        raise IngestionIntegrityError(_ERR_INTEGRITY) from error
    projection = json.dumps(
        {
            "canonical_sha256": encrypted.canonical_sha256,
            "event_id": message.event_id,
            "schema_version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return VerifiedEventProjection(
        message.event_id,
        encrypted.canonical_sha256,
        hashlib.sha256(projection).hexdigest(),
    )


def _verify_outbox(message: ClaimedOutboxMessage, row: RowMapping) -> None:
    if hashlib.sha256(message.payload).hexdigest() != message.payload_sha256:
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    try:
        document = cast("object", json.loads(message.payload))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise IngestionIntegrityError(_ERR_INTEGRITY) from error
    expected = {
        "brain_id": message.brain_id,
        "event_id": message.event_id,
        "event_type": str(row["type"]),
        "schema_version": 1,
    }
    canonical = json.dumps(expected, separators=(",", ":"), sort_keys=True).encode()
    if not isinstance(document, dict):
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    typed_document = cast("dict[str, object]", document)
    if frozenset(typed_document) != _OUTBOX_KEYS or canonical != message.payload:
        raise IngestionIntegrityError(_ERR_INTEGRITY)


def _encrypted(row: RowMapping) -> EncryptedAgentEvent:
    return EncryptedAgentEvent(
        int(str(row["envelope_version"])),
        str(row["algorithm"]),
        str(row["brain_key_id"]),
        str(row["data_key_id"]),
        _bytes(row["payload_nonce"]),
        _bytes(row["ciphertext"]),
        _bytes(row["wrapped_data_key_nonce"]),
        _bytes(row["wrapped_data_key"]),
        _bytes(row["aad_sha256"]).hex(),
        _bytes(row["canonical_sha256"]).hex(),
    )


def _verify_event_index(event: object, row: RowMapping, message: ClaimedOutboxMessage) -> None:
    from agentmemory.ingestion.domain.agent_event import AgentEvent  # noqa: PLC0415

    if not isinstance(event, AgentEvent):
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    reference = event.payload_reference
    stored_payload_ref = None if row["payload_ref"] is None else str(row["payload_ref"])
    if (
        event.event_id != message.event_id
        or event.identity.brain_id != message.brain_id
        or event.identity.project_id != str(row["project_id"])
        or event.identity.repository_id != str(row["repository_id"])
        or event.identity.checkout_id
        != (None if row["checkout_id"] is None else str(row["checkout_id"]))
        or event.event_type.value != str(row["type"])
        or event.classification.value != str(row["classification"])
        or round(event.occurred_at.timestamp() * 1_000_000) != int(str(row["occurred_at"]))
        or bytes.fromhex(event.content_sha256) != _bytes(row["payload_hash"])
        or (reference is None) != (stored_payload_ref is None)
    ):
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    if reference is not None and (
        _bytes(row["artifact_sha256"]) != bytes.fromhex(reference.content_sha256)
        or str(row["artifact_media_type"]) != event.datacontenttype
        or int(str(row["artifact_byte_length"])) != reference.size_bytes
        or str(row["artifact_blob_uri"]) != reference.uri
        or str(row["artifact_classification"]) != event.classification.value
    ):
        raise IngestionIntegrityError(_ERR_INTEGRITY)


def _inbox_wait_claim(
    message: ClaimedOutboxMessage,
    consumer: str,
    attempt: int,
) -> InboxReceiptClaim:
    return InboxReceiptClaim(
        consumer,
        message.message_id,
        message.event_id,
        message.payload_sha256,
        InboxClaimDisposition.WAIT,
        None,
        None,
        attempt,
        None,
    )


async def _finish_inbox_repair(
    connection: AsyncConnection,
    inbox: InboxReceiptClaim,
    detected_at: int,
) -> None:
    if inbox.disposition is not InboxClaimDisposition.CLAIMED or inbox.owner is None:
        raise IngestionIntegrityError(_ERR_LEASE)
    result = await connection.execute(
        text(
            "UPDATE inbox_receipts SET state='repair_required',lease_owner=NULL,"
            "lease_until=NULL,processed_at=:now,updated_at=:now WHERE consumer=:consumer "
            "AND message_id=:message AND state='processing' AND lease_owner=:owner"
        ),
        {
            "consumer": inbox.consumer,
            "message": inbox.message_id,
            "now": detected_at,
            "owner": inbox.owner,
        },
    )
    if result.rowcount != 1:
        raise IngestionIntegrityError(_ERR_LEASE)


async def _append_inbox_conflict(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    consumer: str,
    expected_sha256: bytes,
    detected_at: int,
) -> None:
    identity_hash = hashlib.sha256(f"{consumer}\x00{message.message_id}".encode()).hexdigest()
    actual = bytes.fromhex(message.payload_sha256)
    inserted = await connection.execute(
        text(
            "INSERT INTO idempotency_conflicts "
            "(id,brain_id,namespace,identity_key,expected_sha256,actual_sha256,"
            "source_message_id,detected_at,schema_version) VALUES "
            "(:id,:brain,'inbox',:identity,:expected,:actual,:message,:now,1) "
            "ON CONFLICT(namespace,identity_key,actual_sha256) DO NOTHING"
        ),
        {
            "actual": actual,
            "brain": message.brain_id,
            "expected": expected_sha256,
            "id": str(uuid7()),
            "identity": identity_hash,
            "message": message.message_id,
            "now": detected_at,
        },
    )
    if inserted.rowcount != 1:
        return
    previous_hash = await _previous_audit_hash(connection)
    fact = _audit_fact(
        "ingestion.idempotency_conflict",
        message.brain_id,
        identity_hash,
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,'system:ingestion-idempotency','ingestion.idempotency_conflict',:target,"
            ":key,:before,:after,:previous,:event_hash,:now,1)"
        ),
        {
            "after": actual,
            "before": expected_sha256,
            "brain": message.brain_id,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"inbox-conflict:{identity_hash}:{message.payload_sha256}",
            "now": detected_at,
            "previous": previous_hash,
            "target": f"inbox:{identity_hash}",
        },
    )


async def _append_projection_audit(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    projection: VerifiedEventProjection,
    completed_at: int,
) -> None:
    previous_hash = await _previous_audit_hash(connection)
    fact = _audit_fact("ingestion.event_projected", message.brain_id, message.event_id)
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,'system:ingestion-projection','ingestion.event_projected',:event,:key,"
            ":before,:after,:previous,:event_hash,:now,1)"
        ),
        {
            "after": bytes.fromhex(projection.projection_sha256),
            "before": bytes.fromhex(projection.canonical_sha256),
            "brain": message.brain_id,
            "event": message.event_id,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"ingestion-projected:{message.event_id}",
            "now": completed_at,
            "previous": previous_hash,
        },
    )


async def _append_replay_required_audit(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    detected_at: int,
) -> None:
    previous_hash = await _previous_audit_hash(connection)
    fact = _audit_fact("ingestion.replay_required", message.brain_id, message.event_id)
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,'system:ingestion-projection','ingestion.replay_required',:event,:key,"
            ":before,:after,:previous,:event_hash,:now,1)"
        ),
        {
            "after": hashlib.sha256(b"replay_required").digest(),
            "before": bytes(32),
            "brain": message.brain_id,
            "event": message.event_id,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"ingestion-replay-required:{message.event_id}",
            "now": detected_at,
            "previous": previous_hash,
        },
    )


async def _previous_audit_hash(connection: AsyncConnection) -> bytes:
    value = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    return value if isinstance(value, bytes) else bytes(32)


def _audit_fact(action: str, brain_id: str, target: str) -> bytes:
    return json.dumps(
        {"action": action, "brain_id": brain_id, "target": target},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


async def _finish_lease(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    status: str,
    completed_at: int | None,
    error_code: str | None,
) -> None:
    result = await connection.execute(
        text(
            "UPDATE outbox_messages SET status=:status,lease_owner=NULL,lease_until=NULL,"
            "completed_at=:completed,last_error_code=:error WHERE id=:id "
            "AND status='leased' AND lease_owner=:owner"
        ),
        {
            "completed": completed_at,
            "error": error_code,
            "id": message.message_id,
            "owner": message.lease_owner,
            "status": status,
        },
    )
    if result.rowcount != 1:
        raise IngestionIntegrityError(_ERR_LEASE)


async def _upsert_repair_alert(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    reason_code: str,
    detected_at: int,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO ingestion_repair_alerts "
            "(id,brain_id,source_event_id,outbox_message_id,component,error_code,safe_details,"
            "state,first_detected_at,last_detected_at,created_at,updated_at,schema_version) VALUES "
            "(:id,:brain,:event,:message,'canonical_ingestion',:code,:details,'open',"
            ":now,:now,:now,:now,1) ON CONFLICT(source_event_id) DO UPDATE SET "
            "last_detected_at=excluded.last_detected_at,updated_at=excluded.updated_at"
        ),
        {
            "brain": message.brain_id,
            "code": reason_code,
            "details": _REPAIR_DETAILS,
            "event": message.event_id,
            "id": str(uuid7()),
            "message": message.message_id,
            "now": detected_at,
        },
    )


async def _append_repair_audit(
    connection: AsyncConnection,
    message: ClaimedOutboxMessage,
    detected_at: int,
) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = previous if isinstance(previous, bytes) else bytes(32)
    fact = json.dumps(
        {
            "action": "ingestion.repair_required",
            "brain_id": message.brain_id,
            "occurred_at": detected_at,
            "target_ref": message.event_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,'system:ingestion','ingestion.repair_required',:event,:key,:before,:after,"
            ":previous,:event_hash,:now,1)"
        ),
        {
            "after": hashlib.sha256(b"repair_required").digest(),
            "before": bytes(32),
            "brain": message.brain_id,
            "event": message.event_id,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"ingestion-repair:{message.event_id}",
            "now": detected_at,
            "previous": previous_hash,
        },
    )


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    return value
