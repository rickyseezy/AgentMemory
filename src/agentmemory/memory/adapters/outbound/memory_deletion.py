"""Idempotent MEM-005 local and Neo4j derived-memory deletion executor."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, cast

from neo4j import Query, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.ingestion.domain.backpressure import JobErrorCode
from agentmemory.ingestion.domain.errors import ScheduledJobExecutionError
from agentmemory.memory.domain.errors import MemoryIntegrityError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from neo4j import AsyncDriver
    from sqlalchemy.engine import RowMapping

    from agentmemory.ingestion.domain.backpressure import ScheduledJob
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_JOB_KIND = "governance.memory_deletion"
_MAX_DATABASE_NAME_LENGTH = 63
_DELETE_GRAPH = """CYPHER 25
UNWIND $targets AS target
MATCH (record:ProjectionRecord {brain_id: $brain_id})
WHERE record.target_type = target.target_type
  AND record.target_id_hash = target.target_id_hash
DETACH DELETE record
"""
_COUNT_GRAPH = """CYPHER 25
UNWIND $targets AS target
MATCH (record:ProjectionRecord {brain_id: $brain_id})
WHERE record.target_type = target.target_type
  AND record.target_id_hash = target.target_id_hash
RETURN count(record) AS remaining
"""


class MemoryDeletionExecutor:
    """Advance one durable forget manifest through purge and verification."""

    def __init__(
        self,
        store: SqliteCoreStore,
        driver: AsyncDriver,
        database: str,
        clock: Clock,
    ) -> None:
        """Bind both local derived storage and the configured Neo4j database."""
        if (
            not database
            or len(database) > _MAX_DATABASE_NAME_LENGTH
            or not database.replace("_", "").isalnum()
        ):
            message = "Neo4j database identity is invalid"
            raise ValueError(message)
        self._store = store
        self._driver = driver
        self._database = database
        self._clock = clock

    async def execute(self, job: ScheduledJob) -> str:
        """Purge, verify, and seal one exact scheduler-owned deletion manifest."""
        if job.request.kind != _JOB_KIND:
            raise ScheduledJobExecutionError(JobErrorCode.POISON_JOB, "unexpected_job_kind")
        manifest = await self._load_manifest(job)
        if str(manifest["state"]) == "completed":
            return _result_digest(manifest)
        await self._mark_purging(job, manifest)
        targets = await self._targets(job, manifest)
        await self._purge_local(job)
        await self._purge_graph(job.request.brain_id, targets)
        await self._verify_local(job)
        await self._verify_graph(job.request.brain_id, targets)
        await self._complete(job)
        return _result_digest(manifest)

    async def _load_manifest(self, job: ScheduledJob) -> RowMapping:
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT d.* FROM memory_deletion_manifests d "
                                "JOIN job_authorizations a ON a.job_id=d.job_id "
                                "WHERE d.job_id=:job AND d.brain_id=:brain "
                                "AND a.actor_id=:actor AND a.grant_id=:grant"
                            ),
                            _job_parameters(job),
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise _storage_unavailable(error) from error
        if row is None:
            raise ScheduledJobExecutionError(
                JobErrorCode.INTEGRITY_VIOLATION,
                "deletion_manifest_missing",
            )
        return row

    async def _mark_purging(self, job: ScheduledJob, manifest: RowMapping) -> None:
        state = str(manifest["state"])
        if state not in {"tombstoned", "purging", "verification"}:
            raise ScheduledJobExecutionError(
                JobErrorCode.INTEGRITY_VIOLATION,
                "deletion_manifest_state_invalid",
            )
        if state != "tombstoned":
            return
        await self._update(
            "UPDATE memory_deletion_manifests SET state='purging',updated_at=:now "
            "WHERE job_id=:job AND state='tombstoned'",
            job,
        )

    async def _targets(
        self,
        job: ScheduledJob,
        manifest: RowMapping,
    ) -> tuple[dict[str, str], ...]:
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT target_type,target_id_hash FROM deletion_tombstones "
                                "WHERE id IN (SELECT tombstone_id FROM memory_deletion_targets "
                                "WHERE operation_id=:operation) AND brain_id=:brain "
                                "AND purge_state IN ('tombstoned','completed') "
                                "ORDER BY target_type,target_id_hash"
                            ),
                            {
                                "brain": job.request.brain_id,
                                "operation": str(manifest["operation_id"]),
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise _storage_unavailable(error) from error
        targets = tuple(
            {
                "target_id_hash": _bytes(row["target_id_hash"]).hex(),
                "target_type": str(row["target_type"]),
            }
            for row in rows
        )
        if not targets:
            raise ScheduledJobExecutionError(
                JobErrorCode.INTEGRITY_VIOLATION,
                "deletion_tombstones_missing",
            )
        return targets

    async def _purge_local(self, job: ScheduledJob) -> None:
        try:
            async with self._store.write_lock, self._store.engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM projection_records WHERE brain_id=:brain AND EXISTS "
                        "(SELECT 1 FROM deletion_tombstones d WHERE d.brain_id=:brain "
                        "AND d.target_type=projection_records.target_type "
                        "AND d.target_id_hash=projection_records.target_id_hash "
                        "AND d.purge_state IN ('tombstoned','completed'))"
                    ),
                    {"brain": job.request.brain_id},
                )
        except SQLAlchemyError as error:
            raise _storage_unavailable(error) from error

    async def _verify_local(self, job: ScheduledJob) -> None:
        try:
            async with self._store.engine.connect() as connection:
                remaining = (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM projection_records p "
                            "JOIN deletion_tombstones d ON d.brain_id=p.brain_id "
                            "AND d.target_type=p.target_type AND d.target_id_hash=p.target_id_hash "
                            "WHERE p.brain_id=:brain "
                            "AND d.purge_state IN ('tombstoned','completed')"
                        ),
                        {"brain": job.request.brain_id},
                    )
                ).scalar_one()
        except SQLAlchemyError as error:
            raise _storage_unavailable(error) from error
        if remaining != 0:
            raise ScheduledJobExecutionError(
                JobErrorCode.INTEGRITY_VIOLATION,
                "local_projection_purge_incomplete",
            )

    async def _purge_graph(self, brain_id: str, targets: tuple[dict[str, str], ...]) -> None:
        await self._graph_query(_DELETE_GRAPH, brain_id, targets)

    async def _verify_graph(self, brain_id: str, targets: tuple[dict[str, str], ...]) -> None:
        records = await self._graph_query(
            _COUNT_GRAPH,
            brain_id,
            targets,
            routing=RoutingControl.READ,
        )
        if len(records) != 1 or records[0].get("remaining") != 0:
            raise ScheduledJobExecutionError(
                JobErrorCode.INTEGRITY_VIOLATION,
                "graph_projection_purge_incomplete",
            )

    async def _graph_query(
        self,
        query: str,
        brain_id: str,
        targets: tuple[dict[str, str], ...],
        *,
        routing: RoutingControl = RoutingControl.WRITE,
    ) -> list[dict[str, object]]:
        try:
            result = await self._driver.execute_query(
                Query(query),  # pyright: ignore[reportArgumentType]
                parameters_={"brain_id": brain_id, "targets": list(targets)},
                database_=self._database,
                routing_=routing,
            )
        except (DriverError, Neo4jError) as error:
            raise ScheduledJobExecutionError(
                JobErrorCode.DEPENDENCY_UNAVAILABLE,
                "graph_deletion_unavailable",
            ) from error
        records = cast("Sequence[Mapping[str, object]]", result[0])
        return [dict(record) for record in records]

    async def _complete(self, job: ScheduledJob) -> None:
        try:
            async with self._store.write_lock, self._store.engine.begin() as connection:
                state = (
                    await connection.execute(
                        text("SELECT state FROM memory_deletion_manifests WHERE job_id=:job"),
                        {"job": job.request.job_id},
                    )
                ).scalar_one_or_none()
                if state == "purging":
                    await connection.execute(
                        text(
                            "UPDATE memory_deletion_manifests SET state='verification',"
                            "updated_at=:now WHERE job_id=:job AND state='purging'"
                        ),
                        {"job": job.request.job_id, "now": _micros(self._clock)},
                    )
                    state = "verification"
                if state == "verification":
                    await connection.execute(
                        text(
                            "UPDATE memory_deletion_manifests SET state='completed',"
                            "updated_at=:now WHERE job_id=:job AND state='verification'"
                        ),
                        {"job": job.request.job_id, "now": _micros(self._clock)},
                    )
                    state = "completed"
                if state != "completed":
                    raise ScheduledJobExecutionError(
                        JobErrorCode.INTEGRITY_VIOLATION,
                        "deletion_manifest_transition_conflict",
                    )
                await connection.execute(
                    text(
                        "UPDATE deletion_tombstones SET purge_state='completed' "
                        "WHERE id IN (SELECT tombstone_id FROM memory_deletion_targets "
                        "WHERE operation_id=(SELECT operation_id FROM memory_deletion_manifests "
                        "WHERE job_id=:job)) AND brain_id=:brain AND purge_state='tombstoned'"
                    ),
                    {"brain": job.request.brain_id, "job": job.request.job_id},
                )
        except SQLAlchemyError as error:
            raise _storage_unavailable(error) from error

    async def _update(self, statement: str, job: ScheduledJob) -> None:
        try:
            async with self._store.write_lock, self._store.engine.begin() as connection:
                changed = await connection.execute(
                    text(statement),
                    {"job": job.request.job_id, "now": _micros(self._clock)},
                )
        except SQLAlchemyError as error:
            raise _storage_unavailable(error) from error
        if changed.rowcount != 1:
            raise ScheduledJobExecutionError(
                JobErrorCode.INTEGRITY_VIOLATION,
                "deletion_manifest_transition_conflict",
            )


def _job_parameters(job: ScheduledJob) -> dict[str, str]:
    return {
        "actor": job.request.actor_id,
        "brain": job.request.brain_id,
        "grant": job.request.grant_id,
        "job": job.request.job_id,
    }


def _result_digest(manifest: RowMapping) -> str:
    document = {
        "brain_id": str(manifest["brain_id"]),
        "dependency_types": json.loads(str(manifest["dependency_types_json"])),
        "job_id": str(manifest["job_id"]),
        "memory_id": str(manifest["memory_id"]),
        "operation_id": str(manifest["operation_id"]),
        "policy_version": "memory-deletion.v1",
    }
    return hashlib.sha256(
        json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _storage_unavailable(error: SQLAlchemyError) -> ScheduledJobExecutionError:
    del error
    return ScheduledJobExecutionError(
        JobErrorCode.TRANSIENT_STORAGE,
        "deletion_storage_unavailable",
    )


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise MemoryIntegrityError


def _micros(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)
