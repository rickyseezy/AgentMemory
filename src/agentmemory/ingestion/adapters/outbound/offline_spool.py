"""Bounded encrypted host-side AgentEvent fallback spool."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_file,
    require_private_directory,
    zero_secret,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAXIMUM_BATCH = 100
_ERR_PATH = "AgentEvent spool path is unsafe"
_ERR_IDENTITY = "AgentEvent spool identity conflicted"
_ERR_WRITE = "AgentEvent spool write failed"
_ERR_READ = "AgentEvent spool read failed"
_ERR_INTEGRITY = "AgentEvent spool integrity failed"
_ERR_ACK = "AgentEvent spool acknowledgement failed"


class SpoolCapacityError(RuntimeError):
    """Signal that bounded spool capacity cannot accept another item."""


@dataclass(frozen=True, slots=True)
class SpoolRecord:
    """One decrypted pending event selected in stable ordering-key order."""

    event_id: str
    ordering_key: str
    sequence: int | None
    canonical_event: bytes


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

    def initialize(self) -> None:
        """Create the private durable spool schema without following unsafe paths."""
        require_private_directory(self._path.parent)
        if self._path.exists() and self._path.is_symlink():
            raise IngestionDependencyError(_ERR_PATH)
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
        key = read_protected_file(self._key_file, frozenset({32}))
        nonce = os.urandom(_NONCE_BYTES)
        aad = _aad(event_id, ordering_key, sequence)
        try:
            ciphertext = AESGCM(bytes(key)).encrypt(nonce, canonical_event, aad)
        finally:
            zero_secret(key)
        try:
            with closing(self._connect()) as connection:
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

    def pending(self, maximum: int = 100) -> tuple[SpoolRecord, ...]:
        """Return a bounded batch preserving each ordering key's sequence."""
        if not 1 <= maximum <= _MAXIMUM_BATCH:
            msg = "Spool batch size must be between 1 and 100"
            raise ValueError(msg)
        try:
            with closing(self._connect()) as connection:
                rows: Sequence[tuple[str, str, int | None, bytes, bytes, bytes, bytes]] = (
                    connection.execute(
                        "SELECT event_id, ordering_key, sequence, nonce, ciphertext, "
                        "canonical_sha256, aad_sha256 "
                        "FROM spool_events ORDER BY ordering_key, "
                        "CASE WHEN sequence IS NULL THEN 1 ELSE 0 END, sequence, created_order "
                        "LIMIT ?",
                        (maximum,),
                    ).fetchall()
                )
        except sqlite3.Error as error:
            raise IngestionDependencyError(_ERR_READ) from error
        key = read_protected_file(self._key_file, frozenset({32}))
        try:
            records: list[SpoolRecord] = []
            for (
                event_id,
                ordering_key,
                sequence,
                nonce,
                ciphertext,
                canonical_digest,
                aad_digest,
            ) in rows:
                aad = _aad(event_id, ordering_key, sequence)
                if hashlib.sha256(aad).digest() != aad_digest:
                    raise IngestionDependencyError(_ERR_INTEGRITY)
                try:
                    plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
                except InvalidTag as error:
                    raise IngestionDependencyError(_ERR_INTEGRITY) from error
                if hashlib.sha256(plaintext).digest() != canonical_digest:
                    raise IngestionDependencyError(_ERR_INTEGRITY)
                records.append(SpoolRecord(event_id, ordering_key, sequence, plaintext))
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
                return cursor.rowcount
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
