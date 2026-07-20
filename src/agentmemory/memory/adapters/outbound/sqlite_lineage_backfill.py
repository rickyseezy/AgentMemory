"""SQLite resumable historical task-lineage backfill for MEM-001."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, NoReturn

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.adapters.inbound.agent_event_schema import parse_agent_event_json
from agentmemory.ingestion.domain.errors import (
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)
from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.errors import MemoryDependencyError, MemoryIntegrityError
from agentmemory.memory.domain.lineage_backfill import (
    TaskLineageBackfillOutcome,
    TaskLineageBackfillProgress,
    TaskLineageBackfillState,
    TaskLineageRecord,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.memory.domain.ports import CanonicalTaskEventReader
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_OPERATION = "mem001-task-lineage-v1"
_MAX_PAGE_SIZE = 256


class SqliteTaskLineageBackfillRepository:
    """Checkpoint authenticated historical canonical event metadata."""

    def __init__(
        self,
        store: SqliteCoreStore,
        reader: CanonicalTaskEventReader,
        clock: Clock,
    ) -> None:
        """Bind canonical source, local decryption capability, and deterministic clock."""
        self._store = store
        self._reader = reader
        self._clock = clock

    async def start_or_resume(self) -> TaskLineageBackfillProgress:
        """Capture one immutable source watermark or resume the retained cursor."""
        now = self._now()
        async with self._store.write_lock:
            connection = await self._store.engine.connect()
            try:
                await connection.exec_driver_sql("BEGIN IMMEDIATE")
                existing = await _progress_row(connection)
                if existing is not None:
                    if (
                        str(existing["state"]) == "interrupted"
                        and str(existing["last_error_code"]) != "integrity_violation"
                    ):
                        await connection.execute(
                            text(
                                "UPDATE memory_task_lineage_backfills SET state='running',"
                                "last_error_code=NULL,updated_at=:now WHERE "
                                "operation_id=:operation "
                                "AND state='interrupted'"
                            ),
                            {"operation": _OPERATION, "now": now},
                        )
                        existing = await _progress_row(connection)
                    await connection.commit()
                    if existing is None:
                        _raise_integrity()
                    return _progress(existing)
                watermark = (
                    (
                        await connection.execute(
                            text(
                                "SELECT created_at,event_id FROM event_schema_sources "
                                "ORDER BY created_at DESC,event_id DESC LIMIT 1"
                            )
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                total = 0
                if watermark is not None:
                    total = int(
                        (
                            await connection.execute(
                                text(
                                    "SELECT COUNT(*) FROM event_schema_sources WHERE "
                                    "created_at<:at OR (created_at=:at AND event_id<=:event)"
                                ),
                                {"at": watermark["created_at"], "event": watermark["event_id"]},
                            )
                        ).scalar_one()
                    )
                await connection.execute(
                    text(
                        "INSERT INTO memory_task_lineage_backfills "
                        "(operation_id,state,cursor_created_at,cursor_event_id,"
                        "source_watermark_created_at,source_watermark_event_id,scanned,indexed,"
                        "ignored,total,last_error_code,started_at,updated_at,completed_at,"
                        "schema_version) VALUES (:operation,'running',NULL,NULL,:watermark_at,"
                        ":watermark_event,0,0,0,:total,NULL,:now,:now,NULL,1)"
                    ),
                    {
                        "operation": _OPERATION,
                        "watermark_at": None if watermark is None else watermark["created_at"],
                        "watermark_event": None if watermark is None else watermark["event_id"],
                        "total": total,
                        "now": now,
                    },
                )
                row = await _progress_row(connection)
                await connection.commit()
                if row is None:
                    _raise_integrity()
                return _progress(row)
            except MemoryIntegrityError:
                await connection.rollback()
                raise
            except (IntegrityError, SQLAlchemyError) as error:
                await connection.rollback()
                raise MemoryDependencyError from error
            finally:
                await connection.close()

    async def load_after(
        self,
        progress: TaskLineageBackfillProgress,
        limit: int,
    ) -> tuple[TaskLineageBackfillOutcome, ...]:
        """Decrypt and strictly parse one bounded source page outside a write transaction."""
        if (
            not 1 <= limit <= _MAX_PAGE_SIZE
            or progress.state is not TaskLineageBackfillState.RUNNING
        ):
            raise MemoryIntegrityError
        if progress.watermark_created_at is None:
            return ()
        try:
            async with self._store.engine.connect() as connection:
                rows = list(
                    (
                        await connection.execute(
                            text(
                                "SELECT event_id,created_at,original_canonical_sha256 FROM "
                                "event_schema_sources WHERE (:cursor_at IS NULL OR created_at>"
                                ":cursor_at OR (created_at=:cursor_at AND event_id>:cursor_event)) "
                                "AND (created_at<:watermark_at OR (created_at=:watermark_at "
                                "AND event_id<=:watermark_event)) ORDER BY created_at,event_id "
                                "LIMIT :limit"
                            ),
                            {
                                "cursor_at": progress.cursor_created_at,
                                "cursor_event": progress.cursor_event_id,
                                "watermark_at": progress.watermark_created_at,
                                "watermark_event": progress.watermark_event_id,
                                "limit": limit,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        return tuple([await self._derive(row) for row in rows])

    async def checkpoint(
        self,
        progress: TaskLineageBackfillProgress,
        outcome: TaskLineageBackfillOutcome,
    ) -> TaskLineageBackfillProgress:
        """Store optional lineage and advance exactly one cursor atomically."""
        now = self._now()
        async with self._store.write_lock:
            connection = await self._store.engine.connect()
            try:
                await connection.exec_driver_sql("BEGIN IMMEDIATE")
                current_row = await _progress_row(connection)
                if current_row is None or _progress(current_row) != progress:
                    _raise_integrity()
                if progress.state is not TaskLineageBackfillState.RUNNING:
                    _raise_integrity()
                if outcome.record is not None:
                    await _insert_lineage(connection, outcome.record)
                changed = await connection.execute(
                    text(
                        "UPDATE memory_task_lineage_backfills SET cursor_created_at=:cursor_at,"
                        "cursor_event_id=:cursor_event,scanned=scanned+1,indexed=indexed+:indexed,"
                        "ignored=ignored+:ignored,updated_at=:now WHERE operation_id=:operation "
                        "AND state='running' AND scanned=:scanned "
                        "AND cursor_created_at IS :prior_at AND cursor_event_id IS :prior_event"
                    ),
                    {
                        "cursor_at": outcome.source_created_at,
                        "cursor_event": outcome.event_id,
                        "indexed": int(outcome.record is not None),
                        "ignored": int(outcome.record is None),
                        "now": now,
                        "operation": _OPERATION,
                        "scanned": progress.scanned,
                        "prior_at": progress.cursor_created_at,
                        "prior_event": progress.cursor_event_id,
                    },
                )
                if changed.rowcount != 1:
                    _raise_integrity()
                row = await _progress_row(connection)
                await connection.commit()
                if row is None:
                    _raise_integrity()
                return _progress(row)
            except MemoryIntegrityError:
                await connection.rollback()
                raise
            except (IntegrityError, SQLAlchemyError) as error:
                await connection.rollback()
                raise MemoryDependencyError from error
            finally:
                await connection.close()

    async def complete(
        self,
        progress: TaskLineageBackfillProgress,
    ) -> TaskLineageBackfillProgress:
        """Complete only the fully scanned immutable watermark."""
        now = self._now()
        if progress.scanned != progress.total:
            raise MemoryIntegrityError
        async with self._store.write_lock:
            try:
                async with self._store.engine.begin() as connection:
                    changed = await connection.execute(
                        text(
                            "UPDATE memory_task_lineage_backfills SET state='completed',"
                            "completed_at=:now,updated_at=:now,last_error_code=NULL "
                            "WHERE operation_id=:operation AND state='running' AND scanned=total "
                            "AND scanned=:scanned"
                        ),
                        {"operation": _OPERATION, "now": now, "scanned": progress.scanned},
                    )
                    if changed.rowcount != 1:
                        _raise_integrity()
                    row = await _progress_row(connection)
                    if row is None:
                        _raise_integrity()
                    return _progress(row)
            except MemoryIntegrityError:
                raise
            except SQLAlchemyError as error:
                raise MemoryDependencyError from error

    async def interrupt(
        self,
        progress: TaskLineageBackfillProgress,
        reason_code: str,
    ) -> TaskLineageBackfillProgress:
        """Retain exact progress and one closed failure reason."""
        if reason_code not in {"dependency_unavailable", "integrity_violation", "interrupted"}:
            raise MemoryIntegrityError
        now = self._now()
        async with self._store.write_lock:
            try:
                async with self._store.engine.begin() as connection:
                    changed = await connection.execute(
                        text(
                            "UPDATE memory_task_lineage_backfills SET state='interrupted',"
                            "last_error_code=:reason,updated_at=:now WHERE operation_id=:operation "
                            "AND state='running' AND scanned=:scanned"
                        ),
                        {
                            "reason": reason_code,
                            "now": now,
                            "operation": _OPERATION,
                            "scanned": progress.scanned,
                        },
                    )
                    if changed.rowcount != 1:
                        _raise_integrity()
                    row = await _progress_row(connection)
                    if row is None:
                        _raise_integrity()
                    return _progress(row)
            except MemoryIntegrityError:
                raise
            except SQLAlchemyError as error:
                raise MemoryDependencyError from error

    async def _derive(self, row: RowMapping) -> TaskLineageBackfillOutcome:
        event_id = str(row["event_id"])
        created_at = int(row["created_at"])
        try:
            raw = await self._reader.read(event_id)
            source_digest = _bytes(row["original_canonical_sha256"])
            if hashlib.sha256(raw).digest() != source_digest:
                raise MemoryIntegrityError
            event = parse_agent_event_json(raw)
        except IngestionDependencyError as error:
            raise MemoryDependencyError from error
        except (IngestionIntegrityError, IngestionValidationError) as error:
            raise MemoryIntegrityError from error
        task_id = event.provenance.task_id
        if task_id is None:
            return TaskLineageBackfillOutcome(event_id, created_at, None)
        identity = event.identity
        record = TaskLineageRecord(
            event.event_id,
            identity.principal_id,
            MemoryScope(
                identity.brain_id,
                identity.project_id,
                identity.repository_id,
                identity.checkout_id,
            ),
            event.provenance.session_id,
            task_id,
            event.correlation_id,
            event.causation_id or event.event_id,
            event.event_type.value,
            event.classification.value,
            event.retention_policy_id,
            round(event.occurred_at.timestamp() * 1_000_000),
            source_digest.hex(),
            created_at,
        )
        return TaskLineageBackfillOutcome(event_id, created_at, record)

    def _now(self) -> int:
        return round(self._clock.now().timestamp() * 1_000_000)


async def _progress_row(connection: AsyncConnection) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM memory_task_lineage_backfills WHERE operation_id=:operation"),
                {"operation": _OPERATION},
            )
        )
        .mappings()
        .one_or_none()
    )


def _progress(row: RowMapping) -> TaskLineageBackfillProgress:
    return TaskLineageBackfillProgress(
        str(row["operation_id"]),
        TaskLineageBackfillState(str(row["state"])),
        None if row["cursor_created_at"] is None else int(row["cursor_created_at"]),
        None if row["cursor_event_id"] is None else str(row["cursor_event_id"]),
        None
        if row["source_watermark_created_at"] is None
        else int(row["source_watermark_created_at"]),
        None if row["source_watermark_event_id"] is None else str(row["source_watermark_event_id"]),
        int(row["scanned"]),
        int(row["indexed"]),
        int(row["ignored"]),
        int(row["total"]),
        None if row["last_error_code"] is None else str(row["last_error_code"]),
    )


async def _insert_lineage(
    connection: AsyncConnection,
    record: TaskLineageRecord,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO event_task_lineage "
            "(event_id,brain_id,principal_id,project_id,repository_id,checkout_id,session_id,"
            "task_id,correlation_id,causation_id,event_type,classification,retention_policy_id,"
            "occurred_at,canonical_event_sha256,created_at,schema_version) VALUES "
            "(:event,:brain,:principal,:project,:repository,:checkout,:session,:task,"
            ":correlation,:causation,:event_type,:classification,:retention,:occurred_at,"
            ":digest,:created_at,1) ON CONFLICT(event_id) DO NOTHING"
        ),
        {
            "event": record.event_id,
            "brain": record.scope.brain_id,
            "principal": record.principal_id,
            "project": record.scope.project_id,
            "repository": record.scope.repository_id,
            "checkout": record.scope.checkout_id,
            "session": record.session_id,
            "task": record.task_id,
            "correlation": record.correlation_id,
            "causation": record.causation_id,
            "event_type": record.event_type,
            "classification": record.classification,
            "retention": record.retention_policy_id,
            "occurred_at": record.occurred_at_microseconds,
            "digest": bytes.fromhex(record.canonical_event_sha256),
            "created_at": record.source_created_at,
        },
    )
    row = (
        (
            await connection.execute(
                text("SELECT * FROM event_task_lineage WHERE event_id=:event"),
                {"event": record.event_id},
            )
        )
        .mappings()
        .one()
    )
    expected: dict[str, object] = {
        "brain_id": record.scope.brain_id,
        "principal_id": record.principal_id,
        "project_id": record.scope.project_id,
        "repository_id": record.scope.repository_id,
        "checkout_id": record.scope.checkout_id,
        "session_id": record.session_id,
        "task_id": record.task_id,
        "correlation_id": record.correlation_id,
        "causation_id": record.causation_id,
        "event_type": record.event_type,
        "classification": record.classification,
        "retention_policy_id": record.retention_policy_id,
        "occurred_at": record.occurred_at_microseconds,
        "canonical_event_sha256": bytes.fromhex(record.canonical_event_sha256),
    }
    if any(row[key] != value for key, value in expected.items()):
        raise MemoryIntegrityError


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise MemoryIntegrityError


def _raise_integrity() -> NoReturn:
    raise MemoryIntegrityError
