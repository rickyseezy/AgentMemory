"""Aggregate-specific SQLite repositories and explicit Core Unit of Work."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import TYPE_CHECKING, Self

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.operations.adapters.outbound.receipt_codec import decode_receipt, encode_receipt
from agentmemory.operations.adapters.outbound.sqlite_active_release import (
    SqliteActiveReleaseRepository,
)
from agentmemory.operations.domain.bootstrap import BootstrapDisposition, BootstrapRequest
from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.readiness import ReadinessReceipt
    from agentmemory.shared.clock import Clock


class SqliteCoreUnitOfWork:
    """Own one serialized BEGIN IMMEDIATE transaction and its repositories."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the transaction to the one active Core store."""
        self._store = store
        self._clock = clock
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.receipts: SqliteReadinessReceiptRepository
        self.bootstrap: SqliteBootstrapRepository
        self.audit: SqliteAuditRepository
        self.active_releases: SqliteActiveReleaseRepository

    async def __aenter__(self) -> Self:
        """Acquire the sole writer and expose transaction-scoped repositories."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        self.receipts = SqliteReadinessReceiptRepository(self._require_connection(), self._clock)
        self.bootstrap = SqliteBootstrapRepository(self._require_connection(), self._clock)
        self.audit = SqliteAuditRepository(self._require_connection(), self._clock)
        self.active_releases = SqliteActiveReleaseRepository(
            self._require_connection(),
            self._clock,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unfinished work, close the connection, and release writer ownership."""
        connection = self._require_connection()
        try:
            if not self._committed:
                await connection.rollback()
        finally:
            await connection.close()
            self._connection = None
            self._store.write_lock.release()
        return None

    async def commit(self) -> None:
        """Commit once; the context manager never implicitly commits."""
        if self._committed:
            raise OperationError(ErrorCode.CONFLICT, "Core transaction was already committed")
        try:
            await self._require_connection().commit()
        except IntegrityError as error:
            raise OperationError(ErrorCode.CONFLICT, "canonical Core state conflicted") from error
        self._committed = True

    def _require_connection(self) -> AsyncConnection:
        if self._connection is None:
            msg = "Core Unit of Work is not active"
            raise RuntimeError(msg)
        return self._connection


class SqliteUnitOfWorkFactory:
    """Create one fresh Core UoW per application command."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Keep only stable infrastructure dependencies."""
        self._store = store
        self._clock = clock

    def __call__(self) -> SqliteCoreUnitOfWork:
        """Return an unopened transaction scope."""
        return SqliteCoreUnitOfWork(self._store, self._clock)


class SqliteBootstrapRepository:
    """Persist the exact installation/owner/Brain bootstrap aggregate."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind repository operations to the caller's transaction."""
        self._connection = connection
        self._clock = clock

    async def ensure(self, request: BootstrapRequest) -> BootstrapDisposition:
        """Create bootstrap records once or verify an exact existing aggregate."""
        row = (
            (
                await self._connection.execute(
                    text(
                        "SELECT installation_id, owner_principal_id, active_release_digest, "
                        "active_data_generation FROM installation_state "
                        "WHERE singleton_key = 'local'"
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is not None:
            await self._verify_existing(request, dict(row))
            return BootstrapDisposition.ALREADY_INITIALIZED
        now = _unix_microseconds(self._clock)
        await self._connection.execute(
            text(
                "INSERT INTO installation_state "
                "(singleton_key, installation_id, owner_principal_id, active_release_digest, "
                "active_data_generation, security_epoch, created_at, updated_at, schema_version) "
                "VALUES ('local', :installation_id, :owner_id, :release_digest, :generation_id, "
                "1, :now, :now, 1)"
            ),
            {
                "installation_id": request.installation_id.value,
                "owner_id": request.owner_principal_id.value,
                "release_digest": bytes.fromhex(request.release_digest.value),
                "generation_id": request.generation_id.value,
                "now": now,
            },
        )
        await self._connection.execute(
            text(
                "INSERT INTO brains "
                "(id, normalized_name, display_name, trust_class, status, version, created_at, "
                "updated_at, schema_version) VALUES "
                "(:id, :name, :name, 'personal', 'active', 1, :now, :now, 1)"
            ),
            {"id": request.brain_id.value, "name": request.brain_name, "now": now},
        )
        await self._connection.execute(
            text(
                "INSERT INTO principals "
                "(id, local_subject_digest, type, status, created_at, updated_at, schema_version) "
                "VALUES (:id, :subject, 'owner', 'active', :now, :now, 1)"
            ),
            {
                "id": request.owner_principal_id.value,
                "subject": bytes.fromhex(request.owner_subject_digest.value),
                "now": now,
            },
        )
        await self._connection.execute(
            text(
                "INSERT INTO scope_grants "
                "(id, principal_id, role, brain_id, valid_from, valid_to, created_at, updated_at, "
                "schema_version) VALUES "
                "(:id, :principal_id, 'owner', :brain_id, :now, NULL, :now, :now, 1)"
            ),
            {
                "id": request.owner_grant_id.value,
                "principal_id": request.owner_principal_id.value,
                "brain_id": request.brain_id.value,
                "now": now,
            },
        )
        return BootstrapDisposition.CREATED

    async def _verify_existing(self, request: BootstrapRequest, row: Mapping[str, object]) -> None:
        existing_release = row["active_release_digest"]
        if not isinstance(existing_release, bytes):
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "bootstrap state was malformed")
        expected = (
            request.installation_id.value,
            request.owner_principal_id.value,
            request.release_digest.value,
            request.generation_id.value,
        )
        actual = (
            row["installation_id"],
            row["owner_principal_id"],
            existing_release.hex(),
            row["active_data_generation"],
        )
        if actual != expected:
            raise OperationError(ErrorCode.CONFLICT, "existing bootstrap state has another binding")
        checks = (
            (
                "SELECT COUNT(*) FROM brains WHERE id = :id AND normalized_name = :value "
                "AND status = 'active'",
                {"id": request.brain_id.value, "value": request.brain_name},
            ),
            (
                "SELECT COUNT(*) FROM principals WHERE id = :id AND local_subject_digest = :value "
                "AND type = 'owner' AND status = 'active'",
                {
                    "id": request.owner_principal_id.value,
                    "value": bytes.fromhex(request.owner_subject_digest.value),
                },
            ),
            (
                "SELECT COUNT(*) FROM scope_grants WHERE id = :id AND principal_id = :principal "
                "AND brain_id = :brain AND role = 'owner'",
                {
                    "id": request.owner_grant_id.value,
                    "principal": request.owner_principal_id.value,
                    "brain": request.brain_id.value,
                },
            ),
        )
        for statement, parameters in checks:
            count = (await self._connection.execute(text(statement), parameters)).scalar_one()
            if count != 1:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "bootstrap aggregate is incomplete"
                )


class SqliteAuditRepository:
    """Append and verify one hash-chained non-content audit fact."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind audit writes to the owning canonical transaction."""
        self._connection = connection
        self._clock = clock

    async def append_bootstrap(
        self,
        request: BootstrapRequest,
        disposition: BootstrapDisposition,
    ) -> None:
        """Append one idempotent bootstrap fact without duplicating retry history."""
        idempotency_key = f"bootstrap:{request.installation_id.value}"
        after_hash = hashlib.sha256(_bootstrap_bytes(request)).digest()
        existing = (
            await self._connection.execute(
                text("SELECT after_hash FROM audit_events WHERE idempotency_key = :key"),
                {"key": idempotency_key},
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing != after_hash:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "bootstrap audit fact conflicted"
                )
            return
        previous = (
            await self._connection.execute(
                text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
            )
        ).scalar_one_or_none()
        previous_hash = previous if isinstance(previous, bytes) else bytes(32)
        occurred_at = _unix_microseconds(self._clock)
        event_payload = {
            "action": "installation.bootstrap",
            "actor_id": request.owner_principal_id.value,
            "brain_id": request.brain_id.value,
            "disposition": disposition.value,
            "occurred_at": occurred_at,
            "target_ref": request.installation_id.value,
        }
        canonical = json.dumps(event_payload, separators=(",", ":"), sort_keys=True).encode()
        event_hash = hashlib.sha256(previous_hash + canonical).digest()
        await self._connection.execute(
            text(
                "INSERT INTO audit_events "
                "(brain_id, actor_id, action, target_ref, idempotency_key, before_hash, "
                "after_hash, previous_hash, event_hash, occurred_at, schema_version) VALUES "
                "(:brain_id, :actor_id, 'installation.bootstrap', :target_ref, :key, :before_hash, "
                ":after_hash, :previous_hash, :event_hash, :occurred_at, 1)"
            ),
            {
                "brain_id": request.brain_id.value,
                "actor_id": request.owner_principal_id.value,
                "target_ref": request.installation_id.value,
                "key": idempotency_key,
                "before_hash": bytes(32),
                "after_hash": after_hash,
                "previous_hash": previous_hash,
                "event_hash": event_hash,
                "occurred_at": occurred_at,
            },
        )


class SqliteReadinessReceiptRepository:
    """Store exact deterministic readiness receipt records."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind receipt operations to the caller's transaction."""
        self._connection = connection
        self._clock = clock

    async def add(self, receipt: ReadinessReceipt) -> None:
        """Insert once or verify byte-identical idempotent state."""
        payload = encode_receipt(receipt)
        existing = (
            (
                await self._connection.execute(
                    text(
                        "SELECT receipt_digest, record_json FROM readiness_receipts "
                        "WHERE operation_id = :operation_id"
                    ),
                    {"operation_id": receipt.binding.operation_id.value},
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing is not None:
            digest = existing["receipt_digest"]
            if (
                not isinstance(digest, bytes)
                or digest.hex() != receipt.digest.value
                or existing["record_json"] != payload
            ):
                raise OperationError(ErrorCode.CONFLICT, "readiness receipt binding already exists")
            return
        await self._connection.execute(
            text(
                "INSERT INTO readiness_receipts "
                "(operation_id, release_id, generation_id, receipt_digest, record_json, "
                "evaluated_at, created_at, schema_version) VALUES "
                "(:operation_id, :release_id, :generation_id, :digest, :record_json, "
                ":evaluated_at, :created_at, 1)"
            ),
            {
                "operation_id": receipt.binding.operation_id.value,
                "release_id": receipt.binding.release_id.value,
                "generation_id": receipt.binding.generation_id.value,
                "digest": bytes.fromhex(receipt.digest.value),
                "record_json": payload,
                "evaluated_at": _datetime_microseconds(receipt.evaluated_at),
                "created_at": _unix_microseconds(self._clock),
            },
        )

    async def latest(self) -> ReadinessReceipt | None:
        """Return and revalidate the most recent receipt."""
        payload = (
            await self._connection.execute(
                text(
                    "SELECT record_json FROM readiness_receipts ORDER BY evaluated_at DESC LIMIT 1"
                )
            )
        ).scalar_one_or_none()
        if payload is None:
            return None
        if not isinstance(payload, str):
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "readiness receipt was malformed")
        try:
            return decode_receipt(payload)
        except ValueError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "readiness receipt failed integrity validation",
            ) from error


def _bootstrap_bytes(request: BootstrapRequest) -> bytes:
    values = (
        request.installation_id.value,
        request.owner_principal_id.value,
        request.owner_grant_id.value,
        request.owner_subject_digest.value,
        request.brain_id.value,
        request.brain_name,
        request.release_digest.value,
        request.generation_id.value,
    )
    return "\x00".join(values).encode()


def _unix_microseconds(clock: Clock) -> int:
    return _datetime_microseconds(clock.now())


def _datetime_microseconds(value: object) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "timestamp was invalid")
    return int(value.timestamp()) * 1_000_000 + value.microsecond
