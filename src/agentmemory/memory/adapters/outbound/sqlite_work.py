"""SQLite durable discovery and leasing for automatic MEM-001 consolidation."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.memory.domain.consolidation import (
    MemoryScope,
    consolidation_idempotency_key,
    derive_evidence_watermark,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryDependencyError,
    MemoryIntegrityError,
)
from agentmemory.memory.domain.work import MemoryConsolidationWork, MemoryWorkState

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.memory.domain.consolidation import ExtractorIdentity
    from agentmemory.memory.domain.work import MemoryWorkErrorCode, MemoryWorkRetryDecision
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_TERMINALS = ("agentmemory.task.checkpointed.v1", "agentmemory.task.completed.v1")
_DISCOVERY_LIMIT = 32
_DIGEST_BYTES = 32


class SqliteMemoryConsolidationWorkRepository:
    """Discover exact lineage snapshots and own compare-and-swap work leases."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical single-writer store."""
        self._store = store

    async def claim_next(
        self,
        extractor: ExtractorIdentity,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> MemoryConsolidationWork | None:
        """Claim due work first, then discover a never-processed exact snapshot."""
        if not owner or lease_until_microseconds <= now_microseconds:
            raise MemoryIntegrityError
        async with self._store.write_lock:
            connection = await self._store.engine.connect()
            try:
                await connection.exec_driver_sql("BEGIN IMMEDIATE")
                if not await _lineage_ready(connection):
                    await connection.commit()
                    return None
                existing = await _claim_due(
                    connection,
                    extractor,
                    owner,
                    now_microseconds,
                    lease_until_microseconds,
                )
                if existing is not None:
                    await connection.commit()
                    return existing
                for _ in range(_DISCOVERY_LIMIT):
                    discovered = await _discover(
                        connection,
                        extractor,
                        owner,
                        now_microseconds,
                        lease_until_microseconds,
                    )
                    if discovered is None or isinstance(discovered, MemoryConsolidationWork):
                        await connection.commit()
                        return discovered
                await connection.commit()
                return None  # noqa: TRY300 -- Commit is required before the bounded empty result.
            except MemoryConflictError, MemoryIntegrityError:
                await connection.rollback()
                raise
            except IntegrityError as error:
                await connection.rollback()
                raise MemoryConflictError from error
            except SQLAlchemyError as error:
                await connection.rollback()
                raise MemoryDependencyError from error
            finally:
                await connection.close()

    async def succeed(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        result_sha256: str,
        completed_at_microseconds: int,
    ) -> None:
        """Complete only the matching owner, attempt, and lease."""
        await self._transition(
            work,
            owner,
            "UPDATE memory_consolidation_work SET state='succeeded',lease_owner=NULL,"
            "lease_until=NULL,result_sha256=:result,completed_at=:now,updated_at=:now "
            "WHERE idempotency_key=:key AND state='leased' AND lease_owner=:owner "
            "AND lease_until=:lease AND attempts=:attempts",
            {
                "result": _digest_bytes(result_sha256),
                "now": completed_at_microseconds,
            },
        )

    async def fail(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        error_code: MemoryWorkErrorCode,
        decision: MemoryWorkRetryDecision,
        failed_at_microseconds: int,
    ) -> None:
        """Release for bounded retry or retain immutable terminal failure evidence."""
        if decision.retry:
            if decision.delay_microseconds is None:
                raise MemoryIntegrityError
            state = "retry_scheduled"
            next_attempt = failed_at_microseconds + decision.delay_microseconds
            completed: int | None = None
        else:
            state = "dead_lettered"
            next_attempt = failed_at_microseconds
            completed = failed_at_microseconds
        await self._transition(
            work,
            owner,
            "UPDATE memory_consolidation_work SET state=:state,lease_owner=NULL,"
            "lease_until=NULL,next_attempt_at=:next,last_error_code=:error,"
            "completed_at=:completed,updated_at=:now WHERE idempotency_key=:key "
            "AND state='leased' AND lease_owner=:owner AND lease_until=:lease "
            "AND attempts=:attempts",
            {
                "state": state,
                "next": next_attempt,
                "error": error_code.value,
                "completed": completed,
                "now": failed_at_microseconds,
            },
        )

    async def recover_expired(self, now_microseconds: int) -> int:
        """Release every expired lease without resetting completed attempts."""
        async with self._store.write_lock:
            try:
                async with self._store.engine.begin() as connection:
                    changed = await connection.execute(
                        text(
                            "UPDATE memory_consolidation_work SET state='retry_scheduled',"
                            "lease_owner=NULL,lease_until=NULL,next_attempt_at=:now,"
                            "last_error_code='dependency_unavailable',updated_at=:now "
                            "WHERE state='leased' AND lease_until<=:now"
                        ),
                        {"now": now_microseconds},
                    )
                    return changed.rowcount
            except SQLAlchemyError as error:
                raise MemoryDependencyError from error

    async def _transition(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        statement: str,
        extra: dict[str, object],
    ) -> None:
        parameters = {
            "key": bytes.fromhex(work.idempotency_key),
            "owner": owner,
            "lease": work.lease_until_microseconds,
            "attempts": work.attempts,
            **extra,
        }
        async with self._store.write_lock:
            try:
                async with self._store.engine.begin() as connection:
                    changed = await connection.execute(text(statement), parameters)
                    _require_changed(changed.rowcount)
            except MemoryConflictError:
                raise
            except SQLAlchemyError as error:
                raise MemoryDependencyError from error


async def _claim_due(
    connection: AsyncConnection,
    extractor: ExtractorIdentity,
    owner: str,
    now: int,
    lease_until: int,
) -> MemoryConsolidationWork | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM memory_consolidation_work WHERE extractor_fingerprint=:fp "
                    "AND state IN ('queued','retry_scheduled') AND next_attempt_at<=:now "
                    "ORDER BY next_attempt_at,created_at,operation_id LIMIT 1"
                ),
                {"fp": bytes.fromhex(extractor.fingerprint), "now": now},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    grant = await _current_grant(connection, row, now)
    grant_id = str(row["grant_id"]) if grant is None else grant
    changed = await connection.execute(
        text(
            "UPDATE memory_consolidation_work SET state='leased',attempts=attempts+1,"
            "grant_id=:grant,lease_owner=:owner,lease_until=:lease,updated_at=:now "
            "WHERE idempotency_key=:key AND state IN ('queued','retry_scheduled') "
            "AND next_attempt_at<=:now"
        ),
        {
            "key": row["idempotency_key"],
            "grant": grant_id,
            "owner": owner,
            "lease": lease_until,
            "now": now,
        },
    )
    if changed.rowcount != 1:
        raise MemoryConflictError
    claimed = dict(row)
    claimed.update(
        state="leased",
        attempts=int(row["attempts"]) + 1,
        grant_id=grant_id,
        lease_owner=owner,
        lease_until=lease_until,
    )
    return _work(cast("RowMapping", claimed), extractor)


async def _lineage_ready(connection: AsyncConnection) -> bool:
    state = (
        await connection.execute(
            text(
                "SELECT state FROM memory_task_lineage_backfills "
                "WHERE operation_id='mem001-task-lineage-v1'"
            )
        )
    ).scalar_one_or_none()
    return state == "completed"


async def _discover(
    connection: AsyncConnection,
    extractor: ExtractorIdentity,
    owner: str,
    now: int,
    lease_until: int,
) -> MemoryConsolidationWork | bool | None:
    row = await _terminal_candidate(connection, extractor, now)
    if row is None:
        return None
    evidence = list(
        (
            await connection.execute(
                text(
                    "SELECT event_id,event_type,canonical_event_sha256,created_at FROM "
                    "event_task_lineage WHERE brain_id=:brain AND project_id=:project "
                    "AND repository_id=:repository AND checkout_id IS :checkout "
                    "AND task_id=:task AND (occurred_at<:terminal_time OR "
                    "(occurred_at=:terminal_time AND event_id<=:terminal)) "
                    "ORDER BY occurred_at,event_id"
                ),
                {
                    "brain": row["brain_id"],
                    "project": row["project_id"],
                    "repository": row["repository_id"],
                    "checkout": row["checkout_id"],
                    "task": row["task_id"],
                    "terminal_time": row["occurred_at"],
                    "terminal": row["event_id"],
                },
            )
        )
        .mappings()
        .all()
    )
    if not evidence or str(evidence[-1]["event_id"]) != str(row["event_id"]):
        raise MemoryIntegrityError
    watermark = derive_evidence_watermark(
        tuple(
            (
                str(item["event_id"]),
                str(item["event_type"]),
                _bytes(item["canonical_event_sha256"]).hex(),
            )
            for item in evidence
        )
    )
    key = consolidation_idempotency_key(str(row["task_id"]), watermark, extractor.fingerprint)
    observed = max(evidence, key=lambda item: (int(item["created_at"]), str(item["event_id"])))
    receipt = (
        await connection.execute(
            text("SELECT result_sha256 FROM memory_consolidations WHERE idempotency_key=:key"),
            {"key": bytes.fromhex(key)},
        )
    ).scalar_one_or_none()
    grant = await _current_grant(connection, row, now)
    if grant is None:
        raise MemoryIntegrityError
    state = "succeeded" if receipt is not None else "leased"
    operation = f"mem001-{key[:48]}"
    await connection.execute(
        text(
            "INSERT INTO memory_consolidation_work "
            "(idempotency_key,operation_id,terminal_event_id,extractor_fingerprint,"
            "evidence_watermark_sha256,observed_lineage_created_at,observed_lineage_event_id,"
            "brain_id,project_id,repository_id,checkout_id,task_id,actor_id,grant_id,"
            "correlation_id,causation_id,state,attempts,next_attempt_at,lease_owner,lease_until,"
            "last_error_code,result_sha256,created_at,updated_at,completed_at,schema_version) "
            "VALUES (:key,:operation,:terminal,:fp,:watermark,:observed_at,:observed_event,"
            ":brain,:project,:repository,:checkout,:task,:actor,:grant,:correlation,:causation,"
            ":state,:attempts,:now,:owner,:lease,NULL,:result,:now,:now,:completed,1)"
        ),
        {
            "key": bytes.fromhex(key),
            "operation": operation,
            "terminal": row["event_id"],
            "fp": bytes.fromhex(extractor.fingerprint),
            "watermark": bytes.fromhex(watermark),
            "observed_at": int(observed["created_at"]),
            "observed_event": str(observed["event_id"]),
            "brain": row["brain_id"],
            "project": row["project_id"],
            "repository": row["repository_id"],
            "checkout": row["checkout_id"],
            "task": row["task_id"],
            "actor": row["principal_id"],
            "grant": grant,
            "correlation": row["correlation_id"],
            "causation": row["causation_id"],
            "state": state,
            "attempts": 0 if receipt is not None else 1,
            "now": now,
            "owner": None if receipt is not None else owner,
            "lease": None if receipt is not None else lease_until,
            "result": receipt,
            "completed": now if receipt is not None else None,
        },
    )
    if receipt is not None:
        return False
    loaded = {
        **dict(row),
        "idempotency_key": bytes.fromhex(key),
        "operation_id": operation,
        "evidence_watermark_sha256": bytes.fromhex(watermark),
        "state": state,
        "attempts": 1,
        "lease_owner": owner,
        "lease_until": lease_until,
        "grant_id": grant,
    }
    return _work(cast("RowMapping", loaded), extractor)


async def _terminal_candidate(
    connection: AsyncConnection,
    extractor: ExtractorIdentity,
    now: int,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT l.* FROM event_task_lineage l JOIN principals p "
                    "ON p.id=l.principal_id WHERE l.event_type IN (:checkpointed,:completed) "
                    "AND p.status='active' AND EXISTS (SELECT 1 FROM scope_grants g "
                    "WHERE g.principal_id=l.principal_id AND g.brain_id=l.brain_id "
                    "AND g.role IN ('owner','admin','editor','worker') "
                    "AND (g.project_id IS NULL OR g.project_id=l.project_id) "
                    "AND (g.repository_id IS NULL OR g.repository_id=l.repository_id) "
                    "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now)) "
                    "AND NOT EXISTS (SELECT 1 FROM memory_consolidation_work w "
                    "WHERE w.terminal_event_id=l.event_id AND w.extractor_fingerprint=:fp "
                    "AND w.observed_lineage_created_at=(SELECT e.created_at FROM "
                    "event_task_lineage e WHERE e.brain_id=l.brain_id "
                    "AND e.project_id=l.project_id AND e.repository_id=l.repository_id "
                    "AND e.checkout_id IS l.checkout_id AND e.task_id=l.task_id "
                    "AND (e.occurred_at<l.occurred_at OR "
                    "(e.occurred_at=l.occurred_at AND e.event_id<=l.event_id)) "
                    "ORDER BY e.created_at DESC,e.event_id DESC LIMIT 1) "
                    "AND w.observed_lineage_event_id=(SELECT e.event_id FROM "
                    "event_task_lineage e WHERE e.brain_id=l.brain_id "
                    "AND e.project_id=l.project_id AND e.repository_id=l.repository_id "
                    "AND e.checkout_id IS l.checkout_id AND e.task_id=l.task_id "
                    "AND (e.occurred_at<l.occurred_at OR "
                    "(e.occurred_at=l.occurred_at AND e.event_id<=l.event_id)) "
                    "ORDER BY e.created_at DESC,e.event_id DESC LIMIT 1)) "
                    "ORDER BY l.created_at,l.event_id LIMIT 1"
                ),
                {
                    "checkpointed": _TERMINALS[0],
                    "completed": _TERMINALS[1],
                    "now": now,
                    "fp": bytes.fromhex(extractor.fingerprint),
                },
            )
        )
        .mappings()
        .one_or_none()
    )


async def _current_grant(
    connection: AsyncConnection,
    row: RowMapping,
    now: int,
) -> str | None:
    value = (
        await connection.execute(
            text(
                "SELECT g.id FROM scope_grants g JOIN principals p ON p.id=g.principal_id "
                "JOIN brains b ON b.id=g.brain_id WHERE g.principal_id=:actor "
                "AND g.brain_id=:brain AND g.role IN ('owner','admin','editor','worker') "
                "AND (g.project_id IS NULL OR g.project_id=:project) "
                "AND (g.repository_id IS NULL OR g.repository_id=:repository) "
                "AND p.status='active' AND b.status='active' AND g.valid_from<=:now "
                "AND (g.valid_to IS NULL OR g.valid_to>:now) "
                "ORDER BY (g.repository_id IS NOT NULL) DESC,(g.project_id IS NOT NULL) DESC,"
                "CASE g.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'editor' THEN 2 "
                "ELSE 3 END,g.id LIMIT 1"
            ),
            {
                "actor": row["actor_id"] if "actor_id" in row else row["principal_id"],
                "brain": row["brain_id"],
                "project": row["project_id"],
                "repository": row["repository_id"],
                "now": now,
            },
        )
    ).scalar_one_or_none()
    return None if value is None else str(value)


def _work(row: RowMapping, extractor: ExtractorIdentity) -> MemoryConsolidationWork:
    return MemoryConsolidationWork(
        str(row["operation_id"]),
        _bytes(row["idempotency_key"]).hex(),
        str(row["task_id"]),
        str(row.get("terminal_event_id", row.get("event_id"))),
        str(row.get("actor_id", row.get("principal_id"))),
        str(row["grant_id"]),
        str(row["correlation_id"]),
        str(row["causation_id"]),
        MemoryScope(
            str(row["brain_id"]),
            str(row["project_id"]),
            str(row["repository_id"]),
            None if row["checkout_id"] is None else str(row["checkout_id"]),
        ),
        _bytes(row["evidence_watermark_sha256"]).hex(),
        extractor,
        MemoryWorkState(str(row["state"])),
        int(row["attempts"]),
        str(row["lease_owner"]),
        int(row["lease_until"]),
    )


def _digest_bytes(value: str) -> bytes:
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise MemoryIntegrityError from error
    if len(result) != _DIGEST_BYTES or not any(result):
        raise MemoryIntegrityError
    return result


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise MemoryIntegrityError


def _require_changed(rowcount: int) -> None:
    if rowcount != 1:
        raise MemoryConflictError
