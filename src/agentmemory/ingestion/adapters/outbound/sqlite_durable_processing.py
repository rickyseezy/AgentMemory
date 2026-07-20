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
    VerifiedEventProjection,
)
from agentmemory.ingestion.domain.errors import (
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
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
_REPAIR_DETAILS = "Canonical event integrity verification failed"
_OUTBOX_KEYS = frozenset({"brain_id", "event_id", "event_type", "schema_version"})
_STARTUP_SCAN_LIMIT = 100

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
        projection: VerifiedEventProjection,
        completed_at_microseconds: int,
    ) -> None:
        """Commit exactly one terminal receipt together with lease completion."""
        if projection.event_id != message.event_id:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
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
            await transaction.commit()

    async def require_repair(
        self,
        message: ClaimedOutboxMessage,
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
            await transaction.commit()

    async def release_retry(
        self,
        message: ClaimedOutboxMessage,
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
