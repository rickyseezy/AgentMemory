"""Concrete SQLite, volume, audit, deletion, lease, and smoke readiness checks."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from typing import TYPE_CHECKING

from sqlalchemy import text

from agentmemory.operations.adapters.outbound.probes import ProbeCheckFailedError
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Uuid7Id

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.readiness import ReadinessBinding
    from agentmemory.shared.clock import Clock

EXPECTED_MIGRATION_HEAD = "0035_pf005_mcp_sessions"


class SqliteActiveBrainResolver:
    """Resolve the sole active bootstrap Brain from canonical state."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind identity reads to the active canonical database."""
        self._store = store

    async def get(self) -> Uuid7Id:
        """Return one active Brain and reject missing or ambiguous state."""
        async with self._store.engine.connect() as connection:
            identifiers = (
                (await connection.execute(text("SELECT id FROM brains WHERE status = 'active'")))
                .scalars()
                .all()
            )
        if len(identifiers) != 1 or not isinstance(identifiers[0], str):
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "active local Brain is ambiguous")
        return Uuid7Id(identifiers[0])


class SqliteReadinessChecks:
    """Own the independent canonical-store readiness capabilities."""

    def __init__(
        self,
        store: SqliteCoreStore,
        clock: Clock,
        state_directory: Path,
        artifact_directory: Path,
    ) -> None:
        """Bind checks to the active store, owned volumes, and policy clock."""
        self._store = store
        self._clock = clock
        self._state_directory = state_directory
        self._artifact_directory = artifact_directory

    async def sqlite_integrity(self, binding: ReadinessBinding) -> str:
        """Verify engine policy, integrity, and foreign-key consistency."""
        del binding
        observation = await self._store.observe_and_enforce_policy()
        async with self._store.engine.connect() as connection:
            integrity = (await connection.exec_driver_sql("PRAGMA integrity_check")).scalars().all()
            foreign_key_failures = (
                await connection.exec_driver_sql("PRAGMA foreign_key_check")
            ).all()
        if integrity != ["ok"] or foreign_key_failures:
            msg = "sqlite_integrity_failed"
            raise ProbeCheckFailedError(msg)
        version = ".".join(str(part) for part in observation.version)
        return f"sqlite:{version}:wal:full:foreign_keys"

    async def migration_head(self, binding: ReadinessBinding) -> str:
        """Require the exact relational migration head selected by this release."""
        del binding
        async with self._store.engine.connect() as connection:
            try:
                head = (
                    await connection.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar_one()
            except Exception as error:
                msg = "migration_head_unavailable"
                raise ProbeCheckFailedError(msg) from error
        if head != EXPECTED_MIGRATION_HEAD:
            msg = "migration_head_mismatch"
            raise ProbeCheckFailedError(msg)
        return f"alembic:{EXPECTED_MIGRATION_HEAD}"

    async def writable_volumes(self, binding: ReadinessBinding) -> str:
        """Prove owner-only durable writes in both required persistent volumes."""
        token = hashlib.sha256(binding.operation_id.value.encode()).hexdigest()[:16]
        await asyncio.gather(
            asyncio.to_thread(_durable_directory_probe, self._state_directory, token),
            asyncio.to_thread(_durable_directory_probe, self._artifact_directory, token),
        )
        return "state:durable;artifacts:durable"

    async def audit_append(self, binding: ReadinessBinding) -> str:
        """Append and read back one idempotent hash-chained governed audit fact."""
        idempotency_key = f"readiness.audit:{binding.operation_id.value}"
        after_hash = hashlib.sha256(binding.plan_digest.value.encode()).digest()
        async with self._write_connection() as connection:
            existing = (
                (
                    await connection.execute(
                        text(
                            "SELECT after_hash, event_hash FROM audit_events "
                            "WHERE idempotency_key = :key"
                        ),
                        {"key": idempotency_key},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is None:
                owner, brain = await _owner_and_brain(connection)
                previous = (
                    await connection.execute(
                        text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
                    )
                ).scalar_one_or_none()
                previous_hash = previous if isinstance(previous, bytes) else bytes(32)
                occurred_at = _unix_microseconds(self._clock)
                canonical = json.dumps(
                    {
                        "action": "installation.readiness.audit",
                        "actor_id": owner,
                        "brain_id": brain,
                        "occurred_at": occurred_at,
                        "target_ref": binding.operation_id.value,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
                event_hash = hashlib.sha256(previous_hash + canonical).digest()
                await connection.execute(
                    text(
                        "INSERT INTO audit_events "
                        "(brain_id, actor_id, action, target_ref, idempotency_key, before_hash, "
                        "after_hash, previous_hash, event_hash, occurred_at, schema_version) "
                        "VALUES "
                        "(:brain, :owner, 'installation.readiness.audit', :target, :key, :before, "
                        ":after, :previous, :event, :occurred_at, 1)"
                    ),
                    {
                        "brain": brain,
                        "owner": owner,
                        "target": binding.operation_id.value,
                        "key": idempotency_key,
                        "before": bytes(32),
                        "after": after_hash,
                        "previous": previous_hash,
                        "event": event_hash,
                        "occurred_at": occurred_at,
                    },
                )
            elif existing["after_hash"] != after_hash:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "readiness audit fact conflicted"
                )
        return f"audit:{hashlib.sha256(idempotency_key.encode()).hexdigest()}"

    async def deletion_guard(self, binding: ReadinessBinding) -> str:
        """Tombstone a canary, prove immediate query denial, then remove its content."""
        canary_id = f"readiness-deletion-{_short_binding(binding)}"
        target_hash = hashlib.sha256(canary_id.encode()).digest()
        content = "AgentMemory PF-001 deletion guard canary"
        content_hash = hashlib.sha256(content.encode()).digest()
        async with self._write_connection() as connection:
            _, brain = await _owner_and_brain(connection)
            now = _unix_microseconds(self._clock)
            await connection.execute(
                text(
                    "INSERT INTO smoke_memories "
                    "(id, brain_id, generation_id, content_hash, content, deleted, created_at, "
                    "updated_at, schema_version) VALUES "
                    "(:id, :brain, :generation, :hash, :content, 0, :now, :now, 1) "
                    "ON CONFLICT(id) DO UPDATE SET content = excluded.content, deleted = 0, "
                    "updated_at = excluded.updated_at"
                ),
                {
                    "id": canary_id,
                    "brain": brain,
                    "generation": binding.generation_id.value,
                    "hash": content_hash,
                    "content": content,
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO deletion_tombstones "
                    "(id, brain_id, target_type, target_id_hash, effective_at, purge_state, "
                    "restore_guard_version, created_at, schema_version) VALUES "
                    "(:id, :brain, 'readiness_canary', :target, :now, 'tombstoned', 1, :now, 1) "
                    "ON CONFLICT(brain_id, target_type, target_id_hash) DO NOTHING"
                ),
                {
                    "id": f"tombstone-{_short_binding(binding)}",
                    "brain": brain,
                    "target": target_hash,
                    "now": now,
                },
            )
            visible = (
                await connection.execute(
                    text(
                        "SELECT id FROM smoke_memories WHERE id = :id AND deleted = 0 "
                        "AND NOT EXISTS (SELECT 1 FROM deletion_tombstones WHERE brain_id = :brain "
                        "AND target_type = 'readiness_canary' AND target_id_hash = :target)"
                    ),
                    {"id": canary_id, "brain": brain, "target": target_hash},
                )
            ).scalar_one_or_none()
            if visible is not None:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "deletion guard returned content"
                )
            await connection.execute(
                text("DELETE FROM smoke_memories WHERE id = :id"), {"id": canary_id}
            )
            await connection.execute(
                text(
                    "UPDATE deletion_tombstones SET purge_state = 'completed' "
                    "WHERE brain_id = :brain AND target_type = 'readiness_canary' "
                    "AND target_id_hash = :target"
                ),
                {"brain": brain, "target": target_hash},
            )
        return f"tombstone:{target_hash.hex()}:excluded"

    async def expired_lease_recovery(self, binding: ReadinessBinding) -> str:
        """Recover one expired lease exactly once and remove the synthetic job."""
        job_id = f"readiness-lease-{_short_binding(binding)}"
        now = _unix_microseconds(self._clock)
        async with self._write_connection() as connection:
            _, brain = await _owner_and_brain(connection)
            await connection.execute(
                text(
                    "INSERT INTO jobs "
                    "(id, brain_id, kind, idempotency_key, state, attempts, lease_owner, "
                    "lease_until, next_attempt_at, request_sha256, created_at, updated_at, "
                    "schema_version) VALUES "
                    "(:id, :brain, 'readiness', :id, 'leased', 1, 'interrupted-worker', :expired, "
                    ":now, :request_hash, :now, :now, 1) "
                    "ON CONFLICT(kind, idempotency_key) DO UPDATE SET "
                    "state = 'leased', attempts = 1, lease_owner = 'interrupted-worker', "
                    "lease_until = excluded.lease_until, updated_at = excluded.updated_at"
                ),
                {
                    "id": job_id,
                    "brain": brain,
                    "expired": now - 1,
                    "now": now,
                    "request_hash": hashlib.sha256(job_id.encode()).digest(),
                },
            )
            recovered = await connection.execute(
                text(
                    "UPDATE jobs SET state = 'queued', attempts = attempts + 1, "
                    "lease_owner = NULL, lease_until = NULL, updated_at = :now "
                    "WHERE id = :id AND state = 'leased' AND lease_until < :now"
                ),
                {"id": job_id, "now": now},
            )
            if recovered.rowcount != 1:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "expired lease was not recovered"
                )
            state = (
                await connection.execute(
                    text(
                        "SELECT state, attempts, lease_owner, lease_until FROM jobs WHERE id = :id"
                    ),
                    {"id": job_id},
                )
            ).one()
            if tuple(state) != ("queued", 2, None, None):
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "expired lease recovery was invalid"
                )
            await connection.execute(text("DELETE FROM jobs WHERE id = :id"), {"id": job_id})
        return "expired_lease:queued:attempt_2"

    def _write_connection(self) -> _WriteConnection:
        return _WriteConnection(self._store)


class SqliteSemanticSmokeStore:
    """Persist the canonical half of the write/index/recall readiness canary."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind canary persistence to the sole writer."""
        self._store = store
        self._clock = clock

    async def write(self, binding: ReadinessBinding, canary_id: str, content: str) -> str:
        """Commit canonical event, memory source, and outbox projection intent."""
        content_digest = hashlib.sha256(content.encode()).digest()
        async with _WriteConnection(self._store) as connection:
            _, brain = await _owner_and_brain(connection)
            await _assert_generation(connection, binding)
            now = _unix_microseconds(self._clock)
            existing = (
                await connection.execute(
                    text("SELECT content_hash FROM smoke_memories WHERE id = :id"),
                    {"id": canary_id},
                )
            ).scalar_one_or_none()
            if existing is not None and existing != content_digest:
                raise OperationError(ErrorCode.CONFLICT, "semantic readiness canary conflicted")
            await connection.execute(
                text(
                    "INSERT INTO agent_events "
                    "(event_id, brain_id, type, payload_hash, classification, occurred_at, "
                    "ingested_at, schema_version) VALUES "
                    "(:id, :brain, 'readiness.semantic_canary', :hash, 'internal', :now, :now, 1) "
                    "ON CONFLICT(event_id) DO NOTHING"
                ),
                {"id": canary_id, "brain": brain, "hash": content_digest, "now": now},
            )
            await connection.execute(
                text(
                    "INSERT INTO smoke_memories "
                    "(id, brain_id, generation_id, content_hash, content, deleted, created_at, "
                    "updated_at, schema_version) VALUES "
                    "(:id, :brain, :generation, :hash, :content, 0, :now, :now, 1) "
                    "ON CONFLICT(id) DO NOTHING"
                ),
                {
                    "id": canary_id,
                    "brain": brain,
                    "generation": binding.generation_id.value,
                    "hash": content_digest,
                    "content": content,
                    "now": now,
                },
            )
            outbox_payload = json.dumps(
                {"canary_id": canary_id, "content_sha256": content_digest.hex()},
                separators=(",", ":"),
                sort_keys=True,
            )
            await connection.execute(
                text(
                    "INSERT INTO outbox_messages "
                    "(id, source_event_id, topic, message_key, payload, status, priority, "
                    "not_before, attempts, payload_sha256, created_at, schema_version) VALUES "
                    "(:id, :source, :topic, :key, :payload, 'ready', 100, :now, 0, "
                    ":payload_sha256, :now, 1) "
                    "ON CONFLICT(source_event_id, topic, message_key) DO NOTHING"
                ),
                {
                    "id": f"outbox-{canary_id}",
                    "source": canary_id,
                    "topic": f"am.local.{brain}.indexing.readiness-canary.v1",
                    "key": canary_id,
                    "payload": outbox_payload,
                    "payload_sha256": hashlib.sha256(outbox_payload.encode()).digest(),
                    "now": now,
                },
            )
        return content_digest.hex()

    async def delete(self, binding: ReadinessBinding, canary_id: str) -> None:
        """Remove every synthetic canonical record after graph cleanup succeeds."""
        async with _WriteConnection(self._store) as connection:
            await _assert_generation(connection, binding)
            await connection.execute(
                text("DELETE FROM outbox_messages WHERE source_event_id = :id"), {"id": canary_id}
            )
            await connection.execute(
                text("DELETE FROM smoke_memories WHERE id = :id"), {"id": canary_id}
            )
            await connection.execute(
                text("DELETE FROM agent_events WHERE event_id = :id"), {"id": canary_id}
            )


class _WriteConnection:
    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self._connection: AsyncConnection | None = None

    async def __aenter__(self) -> AsyncConnection:
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        return self._connection

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        connection = self._require_connection()
        try:
            if exc_type is None:
                await connection.commit()
            else:
                await connection.rollback()
        finally:
            await connection.close()
            self._connection = None
            self._store.write_lock.release()

    def _require_connection(self) -> AsyncConnection:
        if self._connection is None:
            msg = "write connection is not active"
            raise RuntimeError(msg)
        return self._connection


async def _owner_and_brain(connection: AsyncConnection) -> tuple[str, str]:
    result = (
        await connection.execute(
            text(
                "SELECT i.owner_principal_id, b.id FROM installation_state i "
                "JOIN brains b ON b.status = 'active' WHERE i.singleton_key = 'local'"
            )
        )
    ).all()
    if len(result) != 1 or not isinstance(result[0][0], str) or not isinstance(result[0][1], str):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "local Brain bootstrap is incomplete")
    return result[0][0], result[0][1]


async def _assert_generation(connection: AsyncConnection, binding: ReadinessBinding) -> None:
    generation = (
        await connection.execute(
            text(
                "SELECT active_data_generation FROM installation_state "
                "WHERE singleton_key = 'local'"
            )
        )
    ).scalar_one_or_none()
    if generation != binding.generation_id.value:
        raise OperationError(ErrorCode.CONFLICT, "readiness generation is not active")


def _durable_directory_probe(directory: Path, token: str) -> None:
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or directory.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022 != 0
    ):
        raise OperationError(ErrorCode.FORBIDDEN, "persistent volume ownership is unsafe")
    path = directory / f".agentmemory-readiness-{token}"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, b"agentmemory-volume-readiness-v1")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.unlink()
    directory_descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _short_binding(binding: ReadinessBinding) -> str:
    return hashlib.sha256(
        f"{binding.operation_id.value}\x00{binding.generation_id.value}".encode()
    ).hexdigest()[:24]


def _unix_microseconds(clock: Clock) -> int:
    now = clock.now()
    if now.tzinfo is None:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "policy clock returned naive time")
    return int(now.timestamp()) * 1_000_000 + now.microsecond
