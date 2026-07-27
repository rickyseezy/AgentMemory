"""Bounded encrypted host-side AgentEvent fallback spool."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.ingestion.domain.spool_reconciliation import (
    SpoolAcknowledgement,
    SpoolRecord,
)
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_file,
    require_private_directory,
    zero_secret,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.ports import AgentAdapterPort

_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAXIMUM_BATCH = 100
_MAXIMUM_BATCH_BYTES = 1024 * 1024
_MAXIMUM_EVENT_BYTES = 96 * 1024
_MAXIMUM_OWNER_BYTES = 128
_ERR_PATH = "AgentEvent spool path is unsafe"
_ERR_IDENTITY = "AgentEvent spool identity conflicted"
_ERR_WRITE = "AgentEvent spool write failed"
_ERR_READ = "AgentEvent spool read failed"
_ERR_INTEGRITY = "AgentEvent spool integrity failed"
_ERR_ACK = "AgentEvent spool acknowledgement failed"
_ERR_LEASE = "AgentEvent spool recovery lease failed"
_ERR_WATERMARK = "AgentEvent spool watermark conflicted"


class SpoolCapacityError(RuntimeError):
    """Signal that bounded spool capacity cannot accept another item."""


@dataclass(frozen=True, slots=True)
class SpoolingAgentAdapter:
    """Decorate any host adapter with the same encrypted dependency-failure fallback."""

    primary: AgentAdapterPort
    spool: EncryptedSqliteSpool

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        """Return deferred only after exact canonical bytes commit to the local spool."""
        try:
            return await self.primary.execute(event)
        except IngestionDependencyError:
            canonical = AgentEventEnvelopeV1.from_domain(event).to_canonical_json()
            try:
                await asyncio.to_thread(
                    self.spool.enqueue,
                    event.event_id,
                    event.ordering_key,
                    event.sequence,
                    canonical,
                )
            except (SpoolCapacityError, OSError) as error:
                raise IngestionDependencyError(_ERR_WRITE) from error
            return AppendAgentEventResult(event.event_id, AppendDisposition.DEFERRED, 0, 0)


class EncryptedSqliteSpool:
    """Use a dedicated owner-only AES-GCM key and FULL-durability SQLite file."""

    def __init__(
        self,
        path: Path,
        key_file: Path,
        *,
        maximum_records: int = 10_000,
        maximum_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        """Bind private storage/key paths and immutable capacity limits."""
        if maximum_records < 1 or maximum_bytes < 1:
            msg = "Spool bounds must be positive"
            raise ValueError(msg)
        self._path = path
        self._key_file = key_file
        self._maximum_records = maximum_records
        self._maximum_bytes = maximum_bytes
        self._enqueue_lock = Lock()

    def initialize(self) -> None:
        """Create the private durable spool schema without following unsafe paths."""
        require_private_directory(self._path.parent)
        _ensure_private_database(self._path)
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS spool_events (
                    created_order INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    ordering_key TEXT NOT NULL,
                    sequence INTEGER,
                    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                    ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16),
                    plaintext_bytes INTEGER NOT NULL CHECK(plaintext_bytes > 0),
                    canonical_sha256 BLOB NOT NULL CHECK(length(canonical_sha256) = 32),
                    aad_sha256 BLOB NOT NULL CHECK(length(aad_sha256) = 32),
                    UNIQUE(ordering_key, sequence)
                );
                CREATE INDEX IF NOT EXISTS ix_spool_delivery
                  ON spool_events(ordering_key, sequence, created_order);
                CREATE TABLE IF NOT EXISTS spool_recovery_lease (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    owner TEXT,
                    acquired_at_microseconds INTEGER,
                    expires_at_microseconds INTEGER
                );
                INSERT OR IGNORE INTO spool_recovery_lease(singleton) VALUES (1);
                CREATE TABLE IF NOT EXISTS spool_watermarks (
                    ordering_key TEXT PRIMARY KEY,
                    acknowledged_spool_sequence INTEGER NOT NULL,
                    acknowledged_event_sequence INTEGER,
                    last_event_id TEXT NOT NULL,
                    last_disposition TEXT NOT NULL
                      CHECK(last_disposition IN ('accepted', 'duplicate')),
                    server_ingested_at_microseconds INTEGER NOT NULL,
                    clock_skew_microseconds INTEGER NOT NULL,
                    acknowledged_at_microseconds INTEGER NOT NULL
                );
                """
            )
        self._path.chmod(0o600)

    def enqueue(
        self,
        event_id: str,
        ordering_key: str,
        sequence: int | None,
        canonical_event: bytes,
    ) -> bool:
        """Commit one encrypted record, returning False for an exact retry."""
        if not canonical_event:
            msg = "Canonical event must not be empty"
            raise ValueError(msg)
        if len(canonical_event) > _MAXIMUM_EVENT_BYTES:
            msg = "Canonical event exceeds the maximum size"
            raise ValueError(msg)
        key = read_protected_file(self._key_file, frozenset({32}))
        nonce = os.urandom(_NONCE_BYTES)
        aad = _aad(event_id, ordering_key, sequence)
        try:
            ciphertext = AESGCM(bytes(key)).encrypt(nonce, canonical_event, aad)
        finally:
            zero_secret(key)
        try:
            with self._enqueue_lock, closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT aad_sha256, canonical_sha256 FROM spool_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing is not None:
                    identity = (
                        hashlib.sha256(aad).digest(),
                        hashlib.sha256(canonical_event).digest(),
                    )
                    if existing != identity:
                        raise IngestionDependencyError(_ERR_IDENTITY)
                    connection.rollback()
                    return False
                count, used = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(plaintext_bytes), 0) FROM spool_events"
                ).fetchone()
                exceeds_records = count >= self._maximum_records
                exceeds_bytes = used + len(canonical_event) > self._maximum_bytes
                if exceeds_records or exceeds_bytes:
                    connection.rollback()
                    raise SpoolCapacityError
                connection.execute(
                    "INSERT INTO spool_events "
                    "(event_id, ordering_key, sequence, nonce, ciphertext, plaintext_bytes, "
                    "canonical_sha256, aad_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        ordering_key,
                        sequence,
                        nonce,
                        ciphertext,
                        len(canonical_event),
                        hashlib.sha256(canonical_event).digest(),
                        hashlib.sha256(aad).digest(),
                    ),
                )
                connection.commit()
                return True
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_WRITE) from error

    def pending(
        self,
        maximum: int = 100,
        maximum_bytes: int = _MAXIMUM_BATCH_BYTES,
    ) -> tuple[SpoolRecord, ...]:
        """Return a bounded batch preserving each ordering key's sequence."""
        if not 1 <= maximum <= _MAXIMUM_BATCH:
            msg = "Spool batch size must be between 1 and 100"
            raise ValueError(msg)
        if not 1 <= maximum_bytes <= _MAXIMUM_BATCH_BYTES:
            msg = "Spool batch bytes must be between 1 and 1048576"
            raise ValueError(msg)
        try:
            with closing(self._connect()) as connection:
                rows: Sequence[
                    tuple[int, str, str, int | None, bytes, bytes, bytes, bytes, int]
                ] = connection.execute(
                    "SELECT COALESCE(w.acknowledged_spool_sequence, 0) + "
                    "ROW_NUMBER() OVER (PARTITION BY e.ordering_key ORDER BY "
                    "CASE WHEN e.sequence IS NULL THEN 1 ELSE 0 END, e.sequence, "
                    "e.created_order), e.event_id, e.ordering_key, e.sequence, e.nonce, "
                    "e.ciphertext, e.canonical_sha256, e.aad_sha256, e.plaintext_bytes "
                    "FROM spool_events AS e LEFT JOIN spool_watermarks AS w "
                    "ON w.ordering_key = e.ordering_key ORDER BY e.ordering_key, "
                    "CASE WHEN e.sequence IS NULL THEN 1 ELSE 0 END, e.sequence, e.created_order "
                    "LIMIT ?",
                    (maximum,),
                ).fetchall()
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_READ) from error
        key = read_protected_file(self._key_file, frozenset({32}))
        try:
            records: list[SpoolRecord] = []
            selected_bytes = 0
            for (
                spool_sequence,
                event_id,
                ordering_key,
                sequence,
                nonce,
                ciphertext,
                canonical_digest,
                aad_digest,
                plaintext_bytes,
            ) in rows:
                if selected_bytes + plaintext_bytes > maximum_bytes:
                    break
                aad = _aad(event_id, ordering_key, sequence)
                if hashlib.sha256(aad).digest() != aad_digest:
                    raise IngestionDependencyError(_ERR_INTEGRITY)
                try:
                    plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
                except InvalidTag as error:
                    raise IngestionDependencyError(_ERR_INTEGRITY) from error
                if hashlib.sha256(plaintext).digest() != canonical_digest:
                    raise IngestionDependencyError(_ERR_INTEGRITY)
                records.append(
                    SpoolRecord(event_id, ordering_key, spool_sequence, sequence, plaintext)
                )
                selected_bytes += plaintext_bytes
            return tuple(records)
        finally:
            zero_secret(key)

    def acknowledge(self, event_ids: tuple[str, ...]) -> int:
        """Durably erase only explicitly accepted or duplicate item IDs."""
        if not event_ids:
            return 0
        if len(event_ids) > _MAXIMUM_BATCH:
            msg = "Spool acknowledgement batch must contain at most 100 IDs"
            raise ValueError(msg)
        placeholders = ",".join("?" for _ in event_ids)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    # The interpolated fragment contains one literal placeholder per
                    # tuple item; every event ID remains a bound parameter.
                    f"DELETE FROM spool_events WHERE event_id IN ({placeholders})",  # noqa: S608  # nosec B608
                    event_ids,
                )
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                return cursor.rowcount
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_ACK) from error

    def try_acquire_recovery_lease(
        self,
        owner: str,
        acquired_at_microseconds: int,
        expires_at_microseconds: int,
    ) -> bool:
        """Atomically acquire or recover the singleton reconciliation lease."""
        if (
            not _valid_owner(owner)
            or isinstance(acquired_at_microseconds, bool)
            or isinstance(expires_at_microseconds, bool)
            or expires_at_microseconds <= acquired_at_microseconds
            or acquired_at_microseconds < 0
            or expires_at_microseconds >= 2**63
        ):
            msg = "Spool recovery lease arguments are invalid"
            raise ValueError(msg)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "UPDATE spool_recovery_lease SET owner = ?, acquired_at_microseconds = ?, "
                    "expires_at_microseconds = ? WHERE singleton = 1 AND "
                    "(owner IS NULL OR expires_at_microseconds <= ?)",
                    (
                        owner,
                        acquired_at_microseconds,
                        expires_at_microseconds,
                        acquired_at_microseconds,
                    ),
                )
                connection.commit()
                return cursor.rowcount == 1
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_LEASE) from error

    def release_recovery_lease(self, owner: str) -> None:
        """Release the singleton lease only for its exact current owner."""
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    "UPDATE spool_recovery_lease SET owner = NULL, "
                    "acquired_at_microseconds = NULL, expires_at_microseconds = NULL "
                    "WHERE singleton = 1 AND owner = ?",
                    (owner,),
                )
                connection.commit()
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_LEASE) from error

    def count_pending(self) -> int:
        """Return the exact content-free number of encrypted pending records."""
        try:
            with closing(self._connect()) as connection:
                row = connection.execute("SELECT COUNT(*) FROM spool_events").fetchone()
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_READ) from error
        if row is None:
            raise IngestionDependencyError(_ERR_READ)
        return int(row[0])

    def acknowledge_reconciled(
        self,
        owner: str,
        acknowledgements: tuple[SpoolAcknowledgement, ...],
        acknowledged_at_microseconds: int,
    ) -> int:
        """Erase verified prefixes and persist content-free watermarks in one transaction."""
        _validate_acknowledgement_arguments(owner, acknowledged_at_microseconds)
        if not acknowledgements:
            return 0
        if len(acknowledgements) > _MAXIMUM_BATCH:
            msg = "Spool acknowledgement batch must contain at most 100 items"
            raise ValueError(msg)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                lease = connection.execute(
                    "SELECT owner, expires_at_microseconds FROM spool_recovery_lease "
                    "WHERE singleton = 1"
                ).fetchone()
                if (
                    lease is None
                    or lease[0] != owner
                    or not isinstance(lease[1], int)
                    or lease[1] <= acknowledged_at_microseconds
                ):
                    raise IngestionDependencyError(_ERR_LEASE)
                grouped: dict[str, list[SpoolAcknowledgement]] = {}
                for acknowledgement in acknowledgements:
                    grouped.setdefault(acknowledgement.ordering_key, []).append(acknowledgement)
                for ordering_key, items in grouped.items():
                    watermark = connection.execute(
                        "SELECT acknowledged_spool_sequence FROM spool_watermarks "
                        "WHERE ordering_key = ?",
                        (ordering_key,),
                    ).fetchone()
                    acknowledged_sequence = 0 if watermark is None else int(watermark[0])
                    rows = connection.execute(
                        "SELECT created_order, event_id, sequence FROM spool_events "
                        "WHERE ordering_key = ? ORDER BY "
                        "CASE WHEN sequence IS NULL THEN 1 ELSE 0 END, sequence, created_order "
                        "LIMIT ?",
                        (ordering_key, len(items)),
                    ).fetchall()
                    expected = [
                        (
                            int(row[0]),
                            str(row[1]),
                            None if row[2] is None else int(row[2]),
                            acknowledged_sequence + index,
                        )
                        for index, row in enumerate(rows, start=1)
                    ]
                    supplied = [(item.spool_sequence, item.event_id, item) for item in items]
                    if [(item[0], item[1]) for item in supplied] != [
                        (item[3], item[1]) for item in expected
                    ]:
                        raise IngestionDependencyError(_ERR_WATERMARK)
                    for (created_order, event_id, event_sequence, spool_sequence), (
                        _,
                        _,
                        item,
                    ) in zip(
                        expected,
                        supplied,
                        strict=True,
                    ):
                        deleted = connection.execute(
                            "DELETE FROM spool_events WHERE created_order = ? AND event_id = ?",
                            (created_order, event_id),
                        )
                        if deleted.rowcount != 1:
                            raise IngestionDependencyError(_ERR_WATERMARK)
                        connection.execute(
                            "INSERT INTO spool_watermarks "
                            "(ordering_key, acknowledged_spool_sequence, "
                            "acknowledged_event_sequence, last_event_id, last_disposition, "
                            "server_ingested_at_microseconds, clock_skew_microseconds, "
                            "acknowledged_at_microseconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                            "ON CONFLICT(ordering_key) DO UPDATE SET "
                            "acknowledged_spool_sequence = excluded.acknowledged_spool_sequence, "
                            "acknowledged_event_sequence = excluded.acknowledged_event_sequence, "
                            "last_event_id = excluded.last_event_id, "
                            "last_disposition = excluded.last_disposition, "
                            "server_ingested_at_microseconds = "
                            "excluded.server_ingested_at_microseconds, "
                            "clock_skew_microseconds = excluded.clock_skew_microseconds, "
                            "acknowledged_at_microseconds = excluded.acknowledged_at_microseconds "
                            "WHERE excluded.acknowledged_spool_sequence > "
                            "spool_watermarks.acknowledged_spool_sequence",
                            (
                                ordering_key,
                                spool_sequence,
                                event_sequence,
                                event_id,
                                item.disposition.value,
                                item.clock_skew.server_ingested_at_microseconds,
                                item.clock_skew.microseconds,
                                acknowledged_at_microseconds,
                            ),
                        )
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                return len(acknowledgements)
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_ACK) from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=0.01)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA busy_timeout=10")
        return connection


def _aad(event_id: str, ordering_key: str, sequence: int | None) -> bytes:
    return f"agentmemory-spool-v1\x00{event_id}\x00{ordering_key}\x00{sequence}".encode()


@dataclass(frozen=True, slots=True)
class SqliteOfflineSpoolRepository:
    """Async repository adapter over the synchronous FULL-durability spool primitive."""

    spool: EncryptedSqliteSpool

    async def try_acquire_lease(
        self,
        owner: str,
        acquired_at_microseconds: int,
        expires_at_microseconds: int,
    ) -> bool:
        """Acquire the durable lease without blocking the event loop."""
        return await asyncio.to_thread(
            self.spool.try_acquire_recovery_lease,
            owner,
            acquired_at_microseconds,
            expires_at_microseconds,
        )

    async def pending(
        self,
        *,
        maximum_items: int,
        maximum_bytes: int,
    ) -> tuple[SpoolRecord, ...]:
        """Read and decrypt one bounded ordered batch off the event loop."""
        return await asyncio.to_thread(self.spool.pending, maximum_items, maximum_bytes)

    async def acknowledge(
        self,
        owner: str,
        acknowledgements: tuple[SpoolAcknowledgement, ...],
        acknowledged_at_microseconds: int,
    ) -> int:
        """Atomically erase durable prefixes and advance their watermarks."""
        return await asyncio.to_thread(
            self.spool.acknowledge_reconciled,
            owner,
            acknowledgements,
            acknowledged_at_microseconds,
        )

    async def count_pending(self) -> int:
        """Return the current encrypted pending count."""
        return await asyncio.to_thread(self.spool.count_pending)

    async def release_lease(self, owner: str) -> None:
        """Release only the exact owner's durable lease."""
        await asyncio.to_thread(self.spool.release_recovery_lease, owner)


def _require_private_database(path: Path) -> None:
    if not path.exists():
        return
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise IngestionDependencyError(_ERR_PATH)


def _ensure_private_database(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        pass
    except OSError as error:
        raise IngestionDependencyError(_ERR_PATH) from error
    else:
        os.close(descriptor)
    _require_private_database(path)


def _valid_owner(owner: str) -> bool:
    return bool(owner) and len(owner.encode()) <= _MAXIMUM_OWNER_BYTES and "\x00" not in owner


def _validate_acknowledgement_arguments(owner: str, acknowledged_at: int) -> None:
    if (
        not _valid_owner(owner)
        or isinstance(acknowledged_at, bool)
        or not 0 <= acknowledged_at < 2**63
    ):
        msg = "Spool acknowledgement arguments are invalid"
        raise ValueError(msg)
