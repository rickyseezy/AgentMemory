"""Encrypted durable PF-005 workspace-checkpoint staging repository."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Final, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.operations.adapters.outbound.protected_file import read_protected_file, zero_secret
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
    WorkspaceCheckpointIngestionResult,
    WorkspaceIndexCoverage,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_KEY_BYTES: Final = 32
_NONCE_BYTES: Final = 12
_ALGORITHM: Final = "AES-256-GCM"
_MAX_PENDING: Final = 256


@dataclass(slots=True)
class SqliteWorkspaceCheckpointRepository:
    """Encrypt each bounded batch before its immutable SQLite transaction commits."""

    store: SqliteCoreStore
    installation_key_file: Path
    clock: Clock

    async def stage(self, batch: WorkspaceCheckpointBatch) -> bool:
        """Acknowledge only committed ciphertext; exact retries return False."""
        canonical = batch.canonical_bytes()
        try:
            key = await _read_key(self.installation_key_file)
            nonce = os.urandom(_NONCE_BYTES)
            aad = _aad(batch)
            try:
                ciphertext = AESGCM(bytes(key)).encrypt(nonce, canonical, aad)
            finally:
                zero_secret(key)
            async with self.store.write_lock, self.store.engine.begin() as connection:
                existing = (
                    (
                        await connection.execute(
                            text(
                                "SELECT session_id,workspace_fingerprint FROM "
                                "mcp_workspace_checkpoint_batches WHERE batch_digest=:digest"
                            ),
                            {"digest": bytes.fromhex(batch.batch_digest.value)},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    if existing["session_id"] != batch.session_id.value or bytes(
                        existing["workspace_fingerprint"]
                    ) != bytes.fromhex(batch.workspace_fingerprint.value):
                        _raise_checkpoint_conflict()
                    return False
                batch_sequence = int(
                    (
                        await connection.execute(
                            text(
                                "SELECT COALESCE(MAX(batch_sequence),0)+1 FROM "
                                "mcp_workspace_checkpoint_batches"
                            )
                        )
                    ).scalar_one()
                )
                await connection.execute(
                    text(
                        "INSERT INTO mcp_workspace_checkpoint_batches "
                        "(batch_digest,batch_sequence,session_id,workspace_fingerprint,partial,"
                        "change_count,"
                        "algorithm,nonce,ciphertext,aad_sha256,canonical_sha256,state,created_at,"
                        "schema_version) VALUES (:digest,:sequence,:session,:workspace,:partial,"
                        ":count,"
                        ":algorithm,:nonce,:ciphertext,:aad,:canonical,'pending',:created,1)"
                    ),
                    {
                        "digest": bytes.fromhex(batch.batch_digest.value),
                        "sequence": batch_sequence,
                        "session": batch.session_id.value,
                        "workspace": bytes.fromhex(batch.workspace_fingerprint.value),
                        "partial": int(batch.partial),
                        "count": len(batch.changes),
                        "algorithm": _ALGORITHM,
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                        "aad": hashlib.sha256(aad).digest(),
                        "canonical": hashlib.sha256(canonical).digest(),
                        "created": int(self.clock.now().timestamp() * 1_000_000),
                    },
                )
        except OperationError:
            raise
        except (OSError, SQLAlchemyError, ValueError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace checkpoint storage is unavailable",
                retryable=True,
            ) from error
        return True

    async def pending(self, limit: int) -> tuple[WorkspaceCheckpointBatch, ...]:
        """Decrypt and authenticate deterministic unacknowledged batches."""
        if limit < 1 or limit > _MAX_PENDING:
            raise OperationError(ErrorCode.VALIDATION, "checkpoint recovery limit is invalid")
        try:
            key = await _read_key(self.installation_key_file)
            try:
                async with self.store.engine.connect() as connection:
                    rows = (
                        (
                            await connection.execute(
                                text(
                                    "SELECT b.* FROM mcp_workspace_checkpoint_batches b "
                                    "LEFT JOIN mcp_workspace_checkpoint_receipts r "
                                    "ON r.batch_digest=b.batch_digest "
                                    "WHERE r.batch_digest IS NULL "
                                    "ORDER BY b.batch_sequence "
                                    "LIMIT :limit"
                                ),
                                {"limit": limit},
                            )
                        )
                        .mappings()
                        .all()
                    )
                return tuple(_decrypt_row(dict(row), key) for row in rows)
            finally:
                zero_secret(key)
        except OperationError:
            raise
        except (OSError, SQLAlchemyError, TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "workspace checkpoint recovery failed",
            ) from error

    async def acknowledge(
        self,
        batch_digest: Sha256Digest,
        result: WorkspaceCheckpointIngestionResult,
    ) -> bool:
        """Append an immutable exact reconciliation receipt."""
        try:
            async with self.store.write_lock, self.store.engine.begin() as connection:
                existing = (
                    (
                        await connection.execute(
                            text(
                                "SELECT result_sha256,event_count FROM "
                                "mcp_workspace_checkpoint_receipts WHERE batch_digest=:digest"
                            ),
                            {"digest": bytes.fromhex(batch_digest.value)},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    if (
                        bytes(existing["result_sha256"])
                        != bytes.fromhex(result.result_sha256.value)
                        or int(existing["event_count"]) != result.event_count
                    ):
                        _raise_checkpoint_conflict()
                    return False
                known = (
                    await connection.execute(
                        text(
                            "SELECT 1 FROM mcp_workspace_checkpoint_batches "
                            "WHERE batch_digest=:digest"
                        ),
                        {"digest": bytes.fromhex(batch_digest.value)},
                    )
                ).scalar_one_or_none()
                if known is None:
                    _raise_missing_checkpoint()
                await connection.execute(
                    text(
                        "INSERT INTO mcp_workspace_checkpoint_receipts "
                        "(batch_digest,result_sha256,event_count,completed_at,schema_version) "
                        "VALUES (:digest,:result,:count,:completed,1)"
                    ),
                    {
                        "digest": bytes.fromhex(batch_digest.value),
                        "result": bytes.fromhex(result.result_sha256.value),
                        "count": result.event_count,
                        "completed": _microseconds(self.clock.now()),
                    },
                )
        except OperationError:
            raise
        except (OSError, SQLAlchemyError, ValueError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace checkpoint receipt is unavailable",
                retryable=True,
            ) from error
        return True

    async def coverage(self, session_id: Uuid7Id) -> WorkspaceIndexCoverage:
        """Report whether every staged batch has a completed durable index run."""
        try:
            async with self.store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "WITH latest AS (SELECT s.run_id,s.state FROM "
                                "incremental_index_run_snapshots s WHERE s.snapshot_version="
                                "(SELECT MAX(x.snapshot_version) FROM "
                                "incremental_index_run_snapshots x WHERE x.run_id=s.run_id)) "
                                "SELECT COUNT(*) AS batches,COALESCE(MAX(b.partial),0) AS partial,"
                                "COUNT(r.batch_digest) AS receipts,"
                                "COALESCE(SUM(CASE WHEN latest.state='completed' THEN 1 ELSE 0 "
                                "END),0) AS completed,COALESCE(SUM(CASE WHEN "
                                "latest.state='failed' THEN 1 ELSE 0 END),0) AS failed FROM "
                                "mcp_workspace_checkpoint_batches b LEFT JOIN "
                                "mcp_workspace_checkpoint_receipts r ON r.batch_digest="
                                "b.batch_digest LEFT JOIN incremental_index_runs runs ON "
                                "runs.operation_id='pf005-index-' || lower(hex(b.batch_digest)) "
                                "LEFT JOIN latest ON latest.run_id=runs.run_id "
                                "WHERE b.session_id=:session"
                            ),
                            {"session": session_id.value},
                        )
                    )
                    .mappings()
                    .one()
                )
            values = dict(row)
            batches = _integer(values, "batches")
            partial = bool(_integer(values, "partial"))
            receipts = _integer(values, "receipts")
            completed = _integer(values, "completed")
            failed = _integer(values, "failed")
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace index coverage is unavailable",
                retryable=True,
            ) from error
        if batches == 0:
            return WorkspaceIndexCoverage.PENDING
        if partial:
            return WorkspaceIndexCoverage.PARTIAL
        if failed:
            return WorkspaceIndexCoverage.DEGRADED
        if receipts == batches and completed == batches:
            return WorkspaceIndexCoverage.COMPLETE
        return WorkspaceIndexCoverage.INDEXING


def _aad(batch: WorkspaceCheckpointBatch) -> bytes:
    return _aad_values(
        batch.session_id.value,
        batch.workspace_fingerprint.value,
        batch.batch_digest.value,
    )


def _aad_values(session_id: str, workspace_fingerprint: str, batch_digest: str) -> bytes:
    return json.dumps(
        {
            "algorithm": _ALGORITHM,
            "batch_digest": batch_digest,
            "purpose": "mcp-workspace-checkpoint-v1",
            "session_id": session_id,
            "workspace_fingerprint": workspace_fingerprint,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


async def _read_key(path: Path) -> bytearray:
    return await asyncio.to_thread(read_protected_file, path, frozenset({_KEY_BYTES}))


def _decrypt_row(row: dict[str, object], key: bytearray) -> WorkspaceCheckpointBatch:
    digest = _blob(row, "batch_digest", 32).hex()
    session = _text(row, "session_id")
    workspace = _blob(row, "workspace_fingerprint", 32).hex()
    aad = _aad_values(session, workspace, digest)
    if hashlib.sha256(aad).digest() != _blob(row, "aad_sha256", 32):
        raise ValueError
    if _text(row, "algorithm") != _ALGORITHM:
        raise ValueError
    plaintext = bytearray(
        AESGCM(bytes(key)).decrypt(
            _blob(row, "nonce", _NONCE_BYTES),
            _blob(row, "ciphertext"),
            aad,
        )
    )
    try:
        if hashlib.sha256(plaintext).digest() != _blob(row, "canonical_sha256", 32):
            raise ValueError
        batch = _decode_batch(bytes(plaintext), digest)
    finally:
        zero_secret(plaintext)
    if (
        batch.session_id.value != session
        or batch.workspace_fingerprint.value != workspace
        or int(bool(batch.partial)) != _integer(row, "partial")
        or len(batch.changes) != _integer(row, "change_count")
    ):
        raise ValueError
    return batch


def _decode_batch(payload: bytes, digest: str) -> WorkspaceCheckpointBatch:
    parsed = cast("object", json.loads(payload, object_pairs_hook=_unique_object))
    if not isinstance(parsed, dict):
        raise TypeError
    raw = cast("dict[str, object]", parsed)
    if set(raw) != {
        "session_id",
        "workspace_fingerprint",
        "batch_digest",
        "partial",
        "changes",
    }:
        raise ValueError
    if raw["batch_digest"] != "" or not isinstance(raw["partial"], bool):
        raise ValueError
    changes_raw = raw["changes"]
    if not isinstance(changes_raw, list):
        raise TypeError
    changes = tuple(_decode_change(value) for value in cast("list[object]", changes_raw))
    return WorkspaceCheckpointBatch(
        Uuid7Id(_required_string(raw["session_id"])),
        Sha256Digest(_required_string(raw["workspace_fingerprint"])),
        Sha256Digest(digest),
        raw["partial"],
        changes,
    )


def _decode_change(raw: object) -> WorkspaceCheckpointChange:
    if not isinstance(raw, dict):
        raise TypeError
    document = cast("dict[str, object]", raw)
    if set(document) != {
        "relative_path",
        "sha256",
        "content_base64",
        "deleted",
    }:
        raise ValueError
    if not isinstance(document["deleted"], bool):
        raise TypeError
    content = base64.b64decode(_required_string(document["content_base64"]), validate=True)
    return WorkspaceCheckpointChange(
        _required_string(document["relative_path"]),
        Sha256Digest(_required_string(document["sha256"])),
        content,
        document["deleted"],
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _required_string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _text(row: dict[str, object], key: str) -> str:
    return _required_string(row[key])


def _blob(row: dict[str, object], key: str, length: int | None = None) -> bytes:
    value = row[key]
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise ValueError
    return value


def _integer(row: dict[str, object], key: str) -> int:
    value = row[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value


def _microseconds(value: object) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError
    return int(value.timestamp()) * 1_000_000 + value.microsecond


def _raise_checkpoint_conflict() -> None:
    raise OperationError(ErrorCode.CONFLICT, "workspace checkpoint digest conflicted")


def _raise_missing_checkpoint() -> None:
    raise OperationError(
        ErrorCode.INTEGRITY_VIOLATION,
        "workspace checkpoint batch is missing",
    )
