"""SQLite ING-004 priority scheduler, capacity guard, and immutable DLQ."""

# ruff: noqa: TRY300, TRY301 -- Transaction methods centralize rollback translation.

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.domain.backpressure import (
    AdmissionDisposition,
    CapacitySnapshot,
    DeadLetter,
    JobErrorCode,
    JobPriority,
    JobRequest,
    JobState,
    QueueLimits,
    ReplayDeadLetterRequest,
    RetryDisposition,
    ScheduledJob,
    select_dispatch_priority,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionCapacityError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.ingestion.domain.backpressure import RetryDecision
    from agentmemory.ingestion.domain.ports import LocalStorageCapacityProbe
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_SOFT_THROTTLE_MICROSECONDS = 1_000_000
_ERR_STORAGE = "Scheduler storage is unavailable"
_ERR_CONFLICT = "Scheduler immutable identity conflicted"
_ERR_LEASE = "Scheduler lease no longer matches"
_ERR_DLQ = "Dead letter history is inconsistent"
_ERR_ACCESS = "Scheduler Brain scope is not authorized"
_MAX_ALERT_VALUE = 2**63 - 1

_JOB_SELECT = """
SELECT j.id,j.brain_id,j.kind,j.idempotency_key,j.state,j.attempts,j.lease_owner,
       j.lease_until,j.next_attempt_at,j.created_at,j.updated_at,j.request_sha256,
       j.result_sha256,j.completed_at,j.priority_class,j.last_error_code,j.parent_job_id,
       a.actor_id,a.grant_id,a.input_ref,r.dead_letter_id AS source_dead_letter_id
FROM jobs AS j
JOIN job_authorizations AS a ON a.job_id=j.id
LEFT JOIN dead_letter_replays AS r ON r.new_job_id=j.id
"""


@dataclass(frozen=True, slots=True)
class LocalDiskSpaceProbe:
    """Read free bytes from the filesystem containing canonical SQLite state."""

    path: Path

    def free_bytes(self) -> int:
        """Return a nonnegative free-byte count or a typed local dependency failure."""
        try:
            value = shutil.disk_usage(self.path).free
        except OSError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        if value < 0 or value > _MAX_ALERT_VALUE:
            raise IngestionIntegrityError(_ERR_STORAGE)
        return value


class SqliteJobSchedulerAccessPolicy:
    """Authorize exact current owner grants against canonical identity state."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind canonical identity state through the shared store."""
        self._store = store

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        now_microseconds: int,
    ) -> None:
        """Reject inactive principal, Brain, grant, role, or validity window."""
        try:
            async with self._store.engine.connect() as connection:
                found = (
                    await connection.execute(
                        text(
                            "SELECT 1 FROM scope_grants AS g "
                            "JOIN principals AS p ON p.id=g.principal_id AND p.status='active' "
                            "JOIN brains AS b ON b.id=g.brain_id AND b.status='active' "
                            "WHERE g.id=:grant AND g.principal_id=:actor AND g.brain_id=:brain "
                            "AND g.role='owner' AND g.valid_from<=:now "
                            "AND (g.valid_to IS NULL OR g.valid_to>:now)"
                        ),
                        {
                            "actor": actor_id,
                            "brain": brain_id,
                            "grant": grant_id,
                            "now": now_microseconds,
                        },
                    )
                ).scalar_one_or_none()
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        if found is None:
            raise IngestionAuthorizationError(_ERR_ACCESS)


class SqliteJobSchedulerRepository:
    """Serialize durable admission, fair leasing, and immutable failure history."""

    def __init__(
        self,
        store: SqliteCoreStore,
        storage: LocalStorageCapacityProbe,
    ) -> None:
        """Bind the single-writer store and local-volume capacity probe."""
        self._store = store
        self._storage = storage

    async def submit(
        self,
        request: JobRequest,
        limits: QueueLimits,
        now_microseconds: int,
    ) -> ScheduledJob:
        """Admit atomically with queue reservations and exact idempotency checks."""
        connection = await self._begin_write()
        try:
            existing = await self._find_identity(connection, request.kind, request.idempotency_key)
            if existing is not None:
                result = _job(existing)
                _require_exact_request(result.request, request)
                await connection.commit()
                return result
            snapshot = await self._snapshot(connection, existing_identity=False)
            decision = limits.admit(request.priority, snapshot)
            if decision.disposition is AdmissionDisposition.REJECT_CAPACITY:
                await connection.rollback()
                raise IngestionCapacityError(
                    decision.reason_code or "capacity_limit",
                    retryable=True,
                )
            next_attempt = now_microseconds
            if decision.disposition is AdmissionDisposition.THROTTLE:
                next_attempt += _SOFT_THROTTLE_MICROSECONDS
            await self._insert_job(connection, request, None, next_attempt, now_microseconds)
            await self._append_alerts(connection, limits, snapshot, now_microseconds)
            await connection.commit()
            loaded = await self.get(request.job_id)
            if loaded is None:
                raise IngestionIntegrityError(_ERR_STORAGE)
            return loaded
        except IngestionCapacityError, IngestionConflictError, IngestionIntegrityError:
            await _rollback(connection)
            raise
        except IntegrityError as error:
            await _rollback(connection)
            raise IngestionConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def get(self, job_id: str) -> ScheduledJob | None:
        """Load only a scheduler-owned authorized job."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(_JOB_SELECT + " WHERE j.id=:id"),
                            {"id": job_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return None if row is None else _job(row)

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
        limits: QueueLimits,
    ) -> ScheduledJob | None:
        """Persist weighted fairness and lease one due job by compare-and-swap."""
        connection = await self._begin_write()
        try:
            available_rows = (
                (
                    await connection.execute(
                        text(
                            "SELECT DISTINCT j.priority_class FROM jobs AS j "
                            "JOIN job_authorizations AS a ON a.job_id=j.id "
                            "WHERE j.state IN ('queued','leased','retry_scheduled') "
                            "AND j.state<>'leased' "
                            "AND j.next_attempt_at<=:now"
                        ),
                        {"now": now_microseconds},
                    )
                )
                .scalars()
                .all()
            )
            available = frozenset(JobPriority(str(value)) for value in available_rows)
            if not available:
                await connection.commit()
                return None
            cursor = int(
                (
                    await connection.execute(
                        text("SELECT dispatch_cursor FROM scheduler_state WHERE singleton_id=1")
                    )
                ).scalar_one()
            )
            snapshot = await self._snapshot(connection, existing_identity=False)
            priority, next_cursor = select_dispatch_priority(
                available,
                cursor,
                soft_limited=(
                    snapshot.total_pending >= limits.soft_pending
                    or snapshot.free_bytes <= limits.soft_free_bytes
                ),
                background_stride=limits.soft_background_stride,
            )
            if priority is None:
                raise IngestionIntegrityError(_ERR_STORAGE)
            job_id = (
                await connection.execute(
                    text(
                        "SELECT j.id FROM jobs AS j JOIN job_authorizations AS a ON a.job_id=j.id "
                        "WHERE j.priority_class=:priority "
                        "AND j.state IN ('queued','leased','retry_scheduled') "
                        "AND j.state<>'leased' AND j.next_attempt_at<=:now "
                        "ORDER BY j.next_attempt_at,j.created_at,j.id LIMIT 1"
                    ),
                    {"now": now_microseconds, "priority": priority.value},
                )
            ).scalar_one()
            changed = await connection.execute(
                text(
                    "UPDATE jobs SET state='leased',attempts=attempts+1,lease_owner=:owner,"
                    "lease_until=:until,updated_at=:now,last_error_code=NULL "
                    "WHERE id=:id AND state IN ('queued','retry_scheduled') "
                    "AND lease_owner IS NULL AND lease_until IS NULL AND next_attempt_at<=:now"
                ),
                {
                    "id": job_id,
                    "now": now_microseconds,
                    "owner": owner,
                    "until": lease_until_microseconds,
                },
            )
            if changed.rowcount != 1:
                raise IngestionConflictError(_ERR_LEASE)
            modulus = len(tuple(JobPriority)) * limits.soft_background_stride
            await connection.execute(
                text(
                    "UPDATE scheduler_state SET dispatch_cursor=:cursor,updated_at=:now "
                    "WHERE singleton_id=1"
                ),
                {"cursor": next_cursor % modulus, "now": now_microseconds},
            )
            row = (
                (await connection.execute(text(_JOB_SELECT + " WHERE j.id=:id"), {"id": job_id}))
                .mappings()
                .one()
            )
            await connection.commit()
            return _job(row)
        except IngestionConflictError, IngestionIntegrityError:
            await _rollback(connection)
            raise
        except SQLAlchemyError as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def succeed(
        self,
        job: ScheduledJob,
        owner: str,
        result_sha256: str,
        completed_at_microseconds: int,
    ) -> ScheduledJob:
        """Complete only the exact owner/attempt/lease and retain immutable digest evidence."""
        connection = await self._begin_write()
        try:
            changed = await connection.execute(
                text(
                    "UPDATE jobs SET state='succeeded',lease_owner=NULL,lease_until=NULL,"
                    "result_sha256=:result,completed_at=:completed,updated_at=:completed "
                    "WHERE id=:id AND state='leased' AND lease_owner=:owner "
                    "AND lease_until=:lease AND attempts=:attempts"
                ),
                {
                    "attempts": job.attempts,
                    "completed": completed_at_microseconds,
                    "id": job.request.job_id,
                    "lease": job.lease_until_microseconds,
                    "owner": owner,
                    "result": bytes.fromhex(result_sha256),
                },
            )
            if changed.rowcount != 1:
                raise IngestionConflictError(_ERR_LEASE)
            row = (
                (
                    await connection.execute(
                        text(_JOB_SELECT + " WHERE j.id=:id"), {"id": job.request.job_id}
                    )
                )
                .mappings()
                .one()
            )
            await connection.commit()
            return _job(row)
        except IngestionConflictError, ValueError:
            await _rollback(connection)
            raise
        except SQLAlchemyError as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def fail(  # noqa: PLR0913 -- Lease CAS requires complete typed failure evidence.
        self,
        job: ScheduledJob,
        owner: str,
        error_code: JobErrorCode,
        decision: RetryDecision,
        diagnostic_code: str,
        failed_at_microseconds: int,
    ) -> ScheduledJob:
        """Schedule the bounded retry or append one immutable terminal dead letter."""
        connection = await self._begin_write()
        try:
            if decision.disposition is RetryDisposition.RETRY:
                if decision.delay_microseconds is None:
                    raise IngestionIntegrityError(_ERR_DLQ)
                changed = await connection.execute(
                    text(
                        "UPDATE jobs SET state='retry_scheduled',lease_owner=NULL,"
                        "lease_until=NULL,next_attempt_at=:next,last_error_code=:error,"
                        "updated_at=:now WHERE id=:id AND state='leased' "
                        "AND lease_owner=:owner AND lease_until=:lease AND attempts=:attempts"
                    ),
                    {
                        "attempts": job.attempts,
                        "error": error_code.value,
                        "id": job.request.job_id,
                        "lease": job.lease_until_microseconds,
                        "next": failed_at_microseconds + decision.delay_microseconds,
                        "now": failed_at_microseconds,
                        "owner": owner,
                    },
                )
            else:
                dead_letter_id = str(uuid7())
                dead = DeadLetter(
                    dead_letter_id,
                    job.request.job_id,
                    job.request.brain_id,
                    job.request.priority,
                    job.request.kind,
                    job.request.request_sha256,
                    job.attempts,
                    error_code,
                    diagnostic_code,
                    failed_at_microseconds,
                    failed_at_microseconds,
                )
                changed = await connection.execute(
                    text(
                        "UPDATE jobs SET state='dead_lettered',lease_owner=NULL,lease_until=NULL,"
                        "last_error_code=:error,updated_at=:now WHERE id=:id AND state='leased' "
                        "AND lease_owner=:owner AND lease_until=:lease AND attempts=:attempts"
                    ),
                    {
                        "attempts": job.attempts,
                        "error": error_code.value,
                        "id": job.request.job_id,
                        "lease": job.lease_until_microseconds,
                        "now": failed_at_microseconds,
                        "owner": owner,
                    },
                )
                if changed.rowcount == 1:
                    await _insert_dead_letter(connection, dead)
            if changed.rowcount != 1:
                raise IngestionConflictError(_ERR_LEASE)
            row = (
                (
                    await connection.execute(
                        text(_JOB_SELECT + " WHERE j.id=:id"), {"id": job.request.job_id}
                    )
                )
                .mappings()
                .one()
            )
            await connection.commit()
            return _job(row)
        except IngestionConflictError, IngestionIntegrityError, ValueError:
            await _rollback(connection)
            raise
        except (IntegrityError, SQLAlchemyError) as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def recover_expired(self, now_microseconds: int) -> int:
        """Release every expired lease while retaining completed attempt count."""
        connection = await self._begin_write()
        try:
            result = await connection.execute(
                text(
                    "UPDATE jobs SET state='retry_scheduled',lease_owner=NULL,lease_until=NULL,"
                    "next_attempt_at=:now,last_error_code='transient_storage',updated_at=:now "
                    "WHERE id IN (SELECT j.id FROM jobs AS j JOIN job_authorizations AS a "
                    "ON a.job_id=j.id WHERE j.state='leased' AND j.lease_until<=:now)"
                ),
                {"now": now_microseconds},
            )
            await connection.commit()
            return result.rowcount
        except SQLAlchemyError as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def capacity_snapshot(
        self,
        *,
        kind: str,
        idempotency_key: str,
    ) -> CapacitySnapshot:
        """Observe capacity with exact identity evidence under the writer lock."""
        connection = await self._begin_write()
        try:
            existing = await self._find_identity(connection, kind, idempotency_key)
            result = await self._snapshot(connection, existing_identity=existing is not None)
            await connection.commit()
            return result
        except SQLAlchemyError as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def list_dead_letters(
        self,
        brain_id: str,
        *,
        maximum: int,
    ) -> tuple[DeadLetter, ...]:
        """Return newest typed failure evidence without job input references."""
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT id,original_job_id,brain_id,priority_class,kind,"
                                "request_sha256,attempts,error_code,diagnostic_code,"
                                "failed_at,created_at "
                                "FROM dead_letters WHERE brain_id=:brain "
                                "ORDER BY created_at DESC,id DESC LIMIT :maximum"
                            ),
                            {"brain": brain_id, "maximum": maximum},
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return tuple(_dead_letter(row) for row in rows)

    async def get_dead_letter(self, dead_letter_id: str) -> DeadLetter | None:
        """Load one immutable failure record."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT id,original_job_id,brain_id,priority_class,kind,"
                                "request_sha256,attempts,error_code,diagnostic_code,"
                                "failed_at,created_at "
                                "FROM dead_letters WHERE id=:id"
                            ),
                            {"id": dead_letter_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return None if row is None else _dead_letter(row)

    async def replay_dead_letter(
        self,
        request: ReplayDeadLetterRequest,
        limits: QueueLimits,
        now_microseconds: int,
    ) -> ScheduledJob:
        """Create one corrected linked job and immutable replay receipt atomically."""
        connection = await self._begin_write()
        try:
            receipt = (
                (
                    await connection.execute(
                        text(
                            "SELECT request_sha256,new_job_id FROM dead_letter_replays "
                            "WHERE operation_id=:operation"
                        ),
                        {"operation": request.operation_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if receipt is not None:
                if _hex(receipt["request_sha256"]) != request.request_sha256:
                    raise IngestionConflictError(_ERR_CONFLICT)
                row = (
                    (
                        await connection.execute(
                            text(_JOB_SELECT + " WHERE j.id=:id"),
                            {"id": str(receipt["new_job_id"])},
                        )
                    )
                    .mappings()
                    .one()
                )
                await connection.commit()
                return _job(row)
            dead_row = (
                (
                    await connection.execute(
                        text(
                            "SELECT id,original_job_id,brain_id,priority_class,kind,request_sha256,"
                            "attempts,error_code,diagnostic_code,failed_at,created_at "
                            "FROM dead_letters WHERE id=:id"
                        ),
                        {"id": request.dead_letter_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if dead_row is None:
                raise IngestionIntegrityError(_ERR_DLQ)
            dead = _dead_letter(dead_row)
            snapshot = await self._snapshot(connection, existing_identity=False)
            decision = limits.admit(dead.priority, snapshot)
            if decision.disposition is AdmissionDisposition.REJECT_CAPACITY:
                raise IngestionCapacityError(
                    decision.reason_code or "capacity_limit",
                    retryable=True,
                )
            next_attempt = now_microseconds
            if decision.disposition is AdmissionDisposition.THROTTLE:
                next_attempt += _SOFT_THROTTLE_MICROSECONDS
            new_request = JobRequest(
                request.new_job_id,
                dead.brain_id,
                request.actor_id,
                request.grant_id,
                dead.kind,
                f"dlq-replay:{request.operation_id}",
                request.corrected_request_sha256,
                dead.priority,
                request.corrected_input_ref,
            )
            await self._insert_job(
                connection,
                new_request,
                dead.original_job_id,
                next_attempt,
                now_microseconds,
            )
            await connection.execute(
                text(
                    "INSERT INTO dead_letter_replays "
                    "(operation_id,dead_letter_id,new_job_id,actor_id,grant_id,request_sha256,"
                    "created_at,schema_version) VALUES "
                    "(:operation,:dead,:job,:actor,:grant,:request,:now,1)"
                ),
                {
                    "actor": request.actor_id,
                    "dead": request.dead_letter_id,
                    "grant": request.grant_id,
                    "job": request.new_job_id,
                    "now": now_microseconds,
                    "operation": request.operation_id,
                    "request": bytes.fromhex(request.request_sha256),
                },
            )
            await self._append_alerts(connection, limits, snapshot, now_microseconds)
            row = (
                (
                    await connection.execute(
                        text(_JOB_SELECT + " WHERE j.id=:id"), {"id": request.new_job_id}
                    )
                )
                .mappings()
                .one()
            )
            await connection.commit()
            return _job(row)
        except IngestionCapacityError, IngestionConflictError, IngestionIntegrityError:
            await _rollback(connection)
            raise
        except IntegrityError as error:
            await _rollback(connection)
            raise IngestionConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            await _rollback(connection)
            raise IngestionDependencyError(_ERR_STORAGE) from error
        finally:
            await connection.close()
            self._store.write_lock.release()

    async def _begin_write(self) -> AsyncConnection:
        await self._store.write_lock.acquire()
        connection: AsyncConnection | None = None
        try:
            connection = await self._store.engine.connect()
            await connection.exec_driver_sql("BEGIN IMMEDIATE")
            return connection
        except BaseException:
            if connection is not None:
                await connection.close()
            self._store.write_lock.release()
            raise

    async def _find_identity(
        self,
        connection: AsyncConnection,
        kind: str,
        idempotency_key: str,
    ) -> RowMapping | None:
        return (
            (
                await connection.execute(
                    text(_JOB_SELECT + " WHERE j.kind=:kind AND j.idempotency_key=:key"),
                    {"key": idempotency_key, "kind": kind},
                )
            )
            .mappings()
            .one_or_none()
        )

    async def _snapshot(
        self,
        connection: AsyncConnection,
        *,
        existing_identity: bool,
    ) -> CapacitySnapshot:
        rows = (
            (
                await connection.execute(
                    text(
                        "SELECT j.priority_class,COUNT(*) AS pending FROM jobs AS j "
                        "JOIN job_authorizations AS a ON a.job_id=j.id "
                        "WHERE j.state IN ('queued','leased','retry_scheduled') "
                        "GROUP BY j.priority_class"
                    )
                )
            )
            .mappings()
            .all()
        )
        counts = dict.fromkeys(JobPriority, 0)
        for row in rows:
            counts[JobPriority(str(row["priority_class"]))] = int(row["pending"])
        capture_outbox = int(
            (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM outbox_messages "
                        "WHERE status IN ('ready','leased','replay_required')"
                    )
                )
            ).scalar_one()
        )
        counts[JobPriority.CAPTURE] += capture_outbox
        total = sum(counts.values())
        return CapacitySnapshot(
            total,
            counts[JobPriority.INTERACTIVE],
            counts[JobPriority.CAPTURE],
            counts[JobPriority.STANDARD],
            counts[JobPriority.BACKGROUND],
            self._storage.free_bytes(),
            existing_identity=existing_identity,
        )

    async def _insert_job(
        self,
        connection: AsyncConnection,
        request: JobRequest,
        parent_job_id: str | None,
        next_attempt_at: int,
        now_microseconds: int,
    ) -> None:
        await connection.execute(
            text(
                "INSERT INTO jobs "
                "(id,brain_id,kind,idempotency_key,state,attempts,lease_owner,lease_until,"
                "next_attempt_at,created_at,updated_at,schema_version,input_ref,request_sha256,"
                "result_sha256,completed_at,priority_class,last_error_code,parent_job_id) VALUES "
                "(:id,:brain,:kind,:key,'queued',0,NULL,NULL,:next,:now,:now,1,NULL,:request,"
                "NULL,NULL,:priority,NULL,:parent)"
            ),
            {
                "brain": request.brain_id,
                "id": request.job_id,
                "key": request.idempotency_key,
                "kind": request.kind,
                "next": next_attempt_at,
                "now": now_microseconds,
                "parent": parent_job_id,
                "priority": request.priority.value,
                "request": bytes.fromhex(request.request_sha256),
            },
        )
        await connection.execute(
            text(
                "INSERT INTO job_authorizations "
                "(job_id,actor_id,grant_id,input_ref,created_at,schema_version) "
                "VALUES (:job,:actor,:grant,:input,:now,1)"
            ),
            {
                "actor": request.actor_id,
                "grant": request.grant_id,
                "input": request.input_ref,
                "job": request.job_id,
                "now": now_microseconds,
            },
        )

    async def _append_alerts(
        self,
        connection: AsyncConnection,
        limits: QueueLimits,
        before: CapacitySnapshot,
        now_microseconds: int,
    ) -> None:
        pending_after = before.total_pending + 1
        for threshold in limits.alert_percentages:
            if pending_after * 100 < limits.hard_pending * threshold:
                continue
            await connection.execute(
                text(
                    "INSERT INTO scheduler_alerts "
                    "(id,metric,threshold_percent,observed_value,observed_limit,created_at,"
                    "schema_version) VALUES (:id,'queue_pending',:threshold,:value,:limit,:now,1) "
                    "ON CONFLICT(metric,threshold_percent) DO NOTHING"
                ),
                {
                    "id": str(uuid7()),
                    "limit": limits.hard_pending,
                    "now": now_microseconds,
                    "threshold": threshold,
                    "value": pending_after,
                },
            )
        disk_threshold = 100 if before.free_bytes <= limits.hard_free_bytes else None
        if disk_threshold is None and before.free_bytes <= limits.soft_free_bytes:
            disk_threshold = limits.alert_percentages[0]
        if disk_threshold is not None:
            await connection.execute(
                text(
                    "INSERT INTO scheduler_alerts "
                    "(id,metric,threshold_percent,observed_value,observed_limit,created_at,"
                    "schema_version) VALUES (:id,'disk_free',:threshold,:value,:limit,:now,1) "
                    "ON CONFLICT(metric,threshold_percent) DO NOTHING"
                ),
                {
                    "id": str(uuid7()),
                    "limit": limits.hard_free_bytes,
                    "now": now_microseconds,
                    "threshold": disk_threshold,
                    "value": before.free_bytes,
                },
            )


class SqliteCaptureCapacityEnforcer:
    """Evaluate new capture inside the exact serialized append transaction."""

    def __init__(
        self,
        storage: LocalStorageCapacityProbe,
        limits: QueueLimits,
    ) -> None:
        """Bind immutable limits and the canonical-volume capacity probe."""
        self._storage = storage
        self._limits = limits

    async def assert_admissible(
        self,
        connection: AsyncConnection,
        event_id: str,
    ) -> None:
        """Fail new capture at hard queue/disk limits while allowing exact retries."""
        existing = (
            await connection.execute(
                text("SELECT 1 FROM agent_events WHERE event_id=:event"), {"event": event_id}
            )
        ).scalar_one_or_none()
        counts = int(
            (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM jobs AS j JOIN job_authorizations AS a "
                        "ON a.job_id=j.id WHERE j.state IN "
                        "('queued','leased','retry_scheduled')) + "
                        "(SELECT COUNT(*) FROM outbox_messages "
                        "WHERE status IN ('ready','leased','replay_required'))"
                    )
                )
            ).scalar_one()
        )
        capture = int(
            (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM jobs AS j JOIN job_authorizations AS a "
                        "ON a.job_id=j.id WHERE j.priority_class='capture' "
                        "AND j.state IN ('queued','leased','retry_scheduled')) + "
                        "(SELECT COUNT(*) FROM outbox_messages "
                        "WHERE status IN ('ready','leased','replay_required'))"
                    )
                )
            ).scalar_one()
        )
        snapshot = CapacitySnapshot(
            counts,
            0,
            capture,
            0,
            0,
            self._storage.free_bytes(),
            existing_identity=existing is not None,
        )
        decision = self._limits.admit(JobPriority.CAPTURE, snapshot)
        if decision.disposition is AdmissionDisposition.REJECT_CAPACITY:
            raise IngestionCapacityError(decision.reason_code or "capacity_limit", retryable=True)


def _job(row: RowMapping) -> ScheduledJob:
    request = JobRequest(
        str(row["id"]),
        str(row["brain_id"]),
        str(row["actor_id"]),
        str(row["grant_id"]),
        str(row["kind"]),
        str(row["idempotency_key"]),
        _hex(row["request_sha256"]),
        JobPriority(str(row["priority_class"])),
        None if row["input_ref"] is None else str(row["input_ref"]),
    )
    return ScheduledJob(
        request,
        JobState(str(row["state"])),
        int(row["attempts"]),
        int(row["next_attempt_at"]),
        None if row["lease_owner"] is None else str(row["lease_owner"]),
        None if row["lease_until"] is None else int(row["lease_until"]),
        None if row["last_error_code"] is None else JobErrorCode(str(row["last_error_code"])),
        None if row["result_sha256"] is None else _hex(row["result_sha256"]),
        None if row["completed_at"] is None else int(row["completed_at"]),
        None if row["parent_job_id"] is None else str(row["parent_job_id"]),
        (None if row["source_dead_letter_id"] is None else str(row["source_dead_letter_id"])),
        int(row["created_at"]),
        int(row["updated_at"]),
    )


def _dead_letter(row: RowMapping) -> DeadLetter:
    return DeadLetter(
        str(row["id"]),
        str(row["original_job_id"]),
        str(row["brain_id"]),
        JobPriority(str(row["priority_class"])),
        str(row["kind"]),
        _hex(row["request_sha256"]),
        int(row["attempts"]),
        JobErrorCode(str(row["error_code"])),
        str(row["diagnostic_code"]),
        int(row["failed_at"]),
        int(row["created_at"]),
    )


async def _insert_dead_letter(connection: AsyncConnection, dead: DeadLetter) -> None:
    await connection.execute(
        text(
            "INSERT INTO dead_letters "
            "(id,original_job_id,brain_id,priority_class,kind,request_sha256,attempts,error_code,"
            "diagnostic_code,failed_at,created_at,schema_version) VALUES "
            "(:id,:job,:brain,:priority,:kind,:request,:attempts,:error,:diagnostic,:failed,:now,1)"
        ),
        {
            "attempts": dead.attempts,
            "brain": dead.brain_id,
            "diagnostic": dead.diagnostic_code,
            "error": dead.error_code.value,
            "failed": dead.failed_at_microseconds,
            "id": dead.dead_letter_id,
            "job": dead.original_job_id,
            "kind": dead.kind,
            "now": dead.created_at_microseconds,
            "priority": dead.priority.value,
            "request": bytes.fromhex(dead.request_sha256),
        },
    )


def _require_exact_request(existing: JobRequest, request: JobRequest) -> None:
    if existing != request:
        raise IngestionConflictError(_ERR_CONFLICT)


def _hex(value: object) -> str:
    if not isinstance(value, bytes):
        raise IngestionIntegrityError(_ERR_STORAGE)
    return value.hex()


async def _rollback(connection: AsyncConnection) -> None:
    try:
        await connection.rollback()
    except SQLAlchemyError:
        return
