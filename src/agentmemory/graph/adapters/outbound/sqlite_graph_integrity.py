"""GRA-006 append-only SQLite migration, finding, and repair journal."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityFinding,
    GraphMigrationRun,
    GraphMigrationState,
    GraphProjectionKind,
    GraphRepairPlan,
    IntegrityFindingKind,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.graph.domain.graph_integrity import GraphMigrationBatch
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_ACTION = "graph integrity repository action is not authorized"
_ERR_AUTHORIZATION = "graph integrity repository scope is not authorized"
_ERR_CONFLICT = "graph integrity operation conflicts with durable history"
_ERR_INTEGRITY = "graph integrity journal failed verification"
_ERR_STORAGE = "graph integrity storage is unavailable"


class SqliteGraphMigrationRepository:
    """Persist immutable migration snapshots after every committed graph batch."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical SQLite store and authorization clock."""
        self._store = store
        self._clock = clock

    async def start(self, scope: AuthorizedScope, run: GraphMigrationRun) -> GraphMigrationRun:
        """Insert snapshot zero or replay the exact existing operation."""
        _require_action(scope, "graph.integrity.migrate")
        try:
            async with _write_transaction(self._store) as connection:
                await _require_brain_authority(connection, scope, self._clock.now())
                row = await _latest_migration(connection, run.operation_id)
                if row is not None:
                    stored = _decode_migration(row)
                    _require_conflict_free(
                        valid=(
                            stored == run
                            and bytes(cast("bytes", row["scope_fingerprint"])).hex()
                            == scope.scope_fingerprint
                        )
                    )
                    return stored
                await _insert_migration(connection, scope, run, 0)
                return run
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def get(self, scope: AuthorizedScope, operation_id: str) -> GraphMigrationRun | None:
        """Load one run only after current Brain authorization."""
        _require_action(scope, "graph.integrity.migrate")
        try:
            async with self._store.engine.connect() as connection:
                await _require_brain_authority(connection, scope, self._clock.now())
                row = await _latest_migration(connection, operation_id)
                if row is None or str(row["brain_id"]) != scope.brain_id.value:
                    return None
                return _decode_migration(row)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def checkpoint(
        self,
        scope: AuthorizedScope,
        run: GraphMigrationRun,
        batch: GraphMigrationBatch,
        at: datetime,
    ) -> GraphMigrationRun:
        """Append exactly one monotonic cursor snapshot."""
        _require_action(scope, "graph.integrity.migrate")
        next_run = run.checkpoint(
            batch.next_cursor, batch.scanned, batch.changed, batch.quarantined, at
        )
        return await self._append(scope, run, next_run)

    async def save(self, scope: AuthorizedScope, run: GraphMigrationRun) -> GraphMigrationRun:
        """Append validation/completion state or replay its exact snapshot."""
        _require_action(scope, "graph.integrity.migrate")
        try:
            async with _write_transaction(self._store) as connection:
                await _require_brain_authority(connection, scope, self._clock.now())
                row = _require_row(await _latest_migration(connection, run.operation_id))
                stored = _decode_migration(row)
                if stored == run:
                    return stored
                _require_conflict_free(valid=_same_migration_progress(stored, run))
                _require_state_transition(stored.state, run.state)
                await _insert_migration(connection, scope, run, int(row["snapshot_version"]) + 1)
                return run
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def _append(
        self, scope: AuthorizedScope, previous: GraphMigrationRun, current: GraphMigrationRun
    ) -> GraphMigrationRun:
        try:
            async with _write_transaction(self._store) as connection:
                await _require_brain_authority(connection, scope, self._clock.now())
                row = _require_row(await _latest_migration(connection, current.operation_id))
                stored = _decode_migration(row)
                if stored == current:
                    return stored
                _require_conflict_free(valid=stored == previous)
                await _insert_migration(
                    connection, scope, current, int(row["snapshot_version"]) + 1
                )
                return current
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


class SqliteGraphIntegrityJournal:
    """Append deterministic findings and one effective repair receipt per finding."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical SQLite store and authorization clock."""
        self._store = store
        self._clock = clock

    async def record(
        self, scope: AuthorizedScope, findings: tuple[GraphIntegrityFinding, ...]
    ) -> tuple[GraphIntegrityFinding, ...]:
        """Authorize all repositories before appending any finding."""
        _require_action(scope, "graph.integrity.validate")
        try:
            async with _write_transaction(self._store) as connection:
                for repository_id in sorted({item.repository_id for item in findings}):
                    await _require_repository_authority(
                        connection, scope, repository_id, self._clock.now()
                    )
                for finding in findings:
                    row = await _finding_row(connection, finding.id)
                    if row is None:
                        await _insert_finding(connection, scope, finding)
                    else:
                        _require_conflict_free(valid=_decode_finding(row) == finding)
                return findings
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def get(self, scope: AuthorizedScope, finding_id: str) -> GraphIntegrityFinding | None:
        """Return one finding only after current Repository authorization."""
        _require_action(scope, "graph.integrity.repair")
        try:
            async with self._store.engine.connect() as connection:
                row = await _finding_row(connection, finding_id)
                if row is None or str(row["brain_id"]) != scope.brain_id.value:
                    return None
                await _require_repository_authority(
                    connection, scope, str(row["repository_id"]), self._clock.now()
                )
                return _decode_finding(row)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def repaired(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        finding: GraphIntegrityFinding,
        plan: GraphRepairPlan,
        repaired_at: datetime,
    ) -> None:
        """Append exact actor, scope, approval, action, and time authority."""
        _require_action(scope, "graph.integrity.repair")
        digest = _repair_digest(operation_id, finding, plan, scope, repaired_at)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_repository_authority(
                    connection, scope, finding.repository_id, self._clock.now()
                )
                row = (
                    (
                        await connection.execute(
                            text("SELECT * FROM graph_integrity_repairs WHERE operation_id=:id"),
                            {"id": operation_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    _require_conflict_free(valid=bytes(row["repair_digest"]) == digest)
                else:
                    await connection.execute(
                        text(
                            "INSERT INTO graph_integrity_repairs(operation_id,finding_id,brain_id,"
                            "principal_id,scope_fingerprint,action,approval_id,repaired_at,"
                            "repair_digest) VALUES(:operation,:finding,:brain,:principal,:scope,"
                            ":action,:approval,:at,:digest)"
                        ),
                        {
                            "operation": operation_id,
                            "finding": finding.id,
                            "brain": scope.brain_id.value,
                            "principal": scope.principal_id.value,
                            "scope": bytes.fromhex(scope.scope_fingerprint),
                            "action": plan.action.value,
                            "approval": plan.approval_id,
                            "at": _micros(repaired_at),
                            "digest": digest,
                        },
                    )
                await _append_repair_audit(
                    connection, operation_id, finding, scope, repaired_at, digest
                )
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


async def _insert_migration(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    run: GraphMigrationRun,
    version: int,
) -> None:
    document = _migration_document(run)
    await connection.execute(
        text(
            "INSERT INTO graph_migration_snapshots(operation_id,snapshot_version,brain_id,"
            "principal_id,scope_fingerprint,migration_id,migration_checksum,source_watermark,"
            "batch_size,cursor,scanned_count,changed_count,quarantined_count,state,started_at,"
            "updated_at,snapshot_digest) VALUES(:operation,:version,:brain,:principal,:scope,"
            ":migration,:checksum,:watermark,:batch,:cursor,:scanned,:changed,:quarantined,"
            ":state,:started,:updated,:digest)"
        ),
        {
            **document,
            "operation": run.operation_id,
            "version": version,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "digest": _digest(document),
        },
    )


def _migration_document(run: GraphMigrationRun) -> dict[str, object]:
    return {
        "brain": run.brain_id,
        "migration": run.migration_id,
        "checksum": bytes.fromhex(run.migration_checksum),
        "watermark": run.source_watermark,
        "batch": run.batch_size,
        "cursor": run.cursor,
        "scanned": run.scanned_count,
        "changed": run.changed_count,
        "quarantined": run.quarantined_count,
        "state": run.state.value,
        "started": _micros(run.started_at),
        "updated": _micros(run.updated_at),
    }


async def _latest_migration(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM graph_migration_snapshots WHERE operation_id=:id "
                    "ORDER BY snapshot_version DESC LIMIT 1"
                ),
                {"id": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _decode_migration(row: RowMapping) -> GraphMigrationRun:
    try:
        return GraphMigrationRun(
            str(row["operation_id"]),
            str(row["brain_id"]),
            str(row["migration_id"]),
            bytes(cast("bytes", row["migration_checksum"])).hex(),
            int(str(row["source_watermark"])),
            int(str(row["batch_size"])),
            int(str(row["cursor"])),
            int(str(row["scanned_count"])),
            int(str(row["changed_count"])),
            int(str(row["quarantined_count"])),
            GraphMigrationState(str(row["state"])),
            _time(row["started_at"]),
            _time(row["updated_at"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


def _same_migration_progress(left: GraphMigrationRun, right: GraphMigrationRun) -> bool:
    return replace(left, state=right.state, updated_at=right.updated_at) == right


def _require_state_transition(left: GraphMigrationState, right: GraphMigrationState) -> None:
    if (left, right) not in {
        (GraphMigrationState.RUNNING, GraphMigrationState.VALIDATING),
        (GraphMigrationState.VALIDATING, GraphMigrationState.COMPLETED),
    }:
        raise GraphConflictError(_ERR_CONFLICT)


async def _insert_finding(
    connection: AsyncConnection, scope: AuthorizedScope, finding: GraphIntegrityFinding
) -> None:
    await connection.execute(
        text(
            "INSERT INTO graph_integrity_findings(finding_id,brain_id,project_id,repository_id,"
            "principal_id,scope_fingerprint,kind,projection_kind,projection_id,canonical_id,"
            "observed_generation_id,expected_generation_id,projection_digest,checked_at) "
            "VALUES(:id,:brain,:project,:repository,:principal,:scope,:kind,:projection_kind,"
            ":projection,:canonical,:observed,:expected,:digest,:checked)"
        ),
        {
            "id": finding.id,
            "brain": finding.brain_id,
            "project": finding.project_id,
            "repository": finding.repository_id,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "kind": finding.kind.value,
            "projection_kind": finding.projection_kind.value,
            "projection": finding.projection_id,
            "canonical": finding.canonical_id,
            "observed": bytes.fromhex(finding.observed_generation_id),
            "expected": bytes.fromhex(finding.expected_generation_id),
            "digest": bytes.fromhex(finding.projection_digest),
            "checked": _micros(finding.checked_at),
        },
    )


async def _finding_row(connection: AsyncConnection, finding_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM graph_integrity_findings WHERE finding_id=:id LIMIT 1"),
                {"id": finding_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _decode_finding(row: RowMapping) -> GraphIntegrityFinding:
    try:
        canonical = row["canonical_id"]
        return GraphIntegrityFinding(
            str(row["finding_id"]),
            IntegrityFindingKind(str(row["kind"])),
            str(row["projection_id"]),
            GraphProjectionKind(str(row["projection_kind"])),
            str(row["brain_id"]),
            str(row["project_id"]),
            str(row["repository_id"]),
            None if canonical is None else str(canonical),
            bytes(cast("bytes", row["observed_generation_id"])).hex(),
            bytes(cast("bytes", row["expected_generation_id"])).hex(),
            bytes(cast("bytes", row["projection_digest"])).hex(),
            _time(row["checked_at"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


async def _require_brain_authority(
    connection: AsyncConnection, scope: AuthorizedScope, now: datetime
) -> None:
    row = (
        await connection.execute(
            text(
                "SELECT 1 FROM brains AS brain JOIN principals AS principal "
                "ON principal.id=:principal "
                "WHERE brain.id=:brain AND brain.status='active' AND principal.status='active' "
                "AND EXISTS(SELECT 1 FROM scope_grants AS grant_row "
                "WHERE grant_row.principal_id=:principal AND grant_row.brain_id=:brain "
                "AND grant_row.role IN ('owner','admin','editor') AND grant_row.valid_from<=:now "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now))"
            ),
            {
                "principal": scope.principal_id.value,
                "brain": scope.brain_id.value,
                "now": _micros(now),
            },
        )
    ).scalar_one_or_none()
    if row is None:
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)


async def _require_repository_authority(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    repository_id: str,
    now: datetime,
) -> None:
    if repository_id not in {item.value for item in scope.repository_ids}:
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)
    row = (
        await connection.execute(
            text(
                "SELECT project.id FROM repositories AS repository "
                "JOIN project_repositories AS binding ON binding.repository_id=repository.id "
                "JOIN projects AS project ON project.id=binding.project_id "
                "WHERE repository.id=:repository AND project.brain_id=:brain "
                "AND repository.status='active' AND project.status='active' AND EXISTS("
                "SELECT 1 FROM scope_grants AS grant_row WHERE grant_row.principal_id=:principal "
                "AND grant_row.brain_id=:brain AND grant_row.role IN ('owner','admin','editor') "
                "AND grant_row.valid_from<=:now "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) "
                "AND (grant_row.project_id IS NULL OR grant_row.project_id=project.id) "
                "AND (grant_row.repository_id IS NULL OR grant_row.repository_id=repository.id))"
            ),
            {
                "principal": scope.principal_id.value,
                "brain": scope.brain_id.value,
                "repository": repository_id,
                "now": _micros(now),
            },
        )
    ).scalar_one_or_none()
    if row is None or str(row) not in {item.value for item in scope.project_ids}:
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)


def _repair_digest(
    operation_id: str,
    finding: GraphIntegrityFinding,
    plan: GraphRepairPlan,
    scope: AuthorizedScope,
    repaired_at: datetime,
) -> bytes:
    return _digest(
        {
            "action": plan.action.value,
            "approval_id": plan.approval_id,
            "finding_id": finding.id,
            "operation_id": operation_id,
            "principal_id": scope.principal_id.value,
            "repaired_at": _micros(repaired_at),
            "scope_fingerprint": scope.scope_fingerprint,
        }
    )


async def _append_repair_audit(  # noqa: PLR0913 -- Audit binds every authority dimension.
    connection: AsyncConnection,
    operation_id: str,
    finding: GraphIntegrityFinding,
    scope: AuthorizedScope,
    repaired_at: datetime,
    repair_digest: bytes,
) -> None:
    """Append or verify the central hash-chained repair fact transactionally."""
    key = f"graph-integrity-repair:{operation_id}"
    existing = (
        await connection.execute(
            text("SELECT after_hash FROM audit_events WHERE idempotency_key=:key"), {"key": key}
        )
    ).scalar_one_or_none()
    if existing is not None:
        _require_conflict_free(valid=existing == repair_digest)
        return
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = previous if isinstance(previous, bytes) else bytes(32)
    occurred_at = _micros(repaired_at)
    document = json.dumps(
        {
            "action": "graph.integrity.repair",
            "actor_id": scope.principal_id.value,
            "brain_id": scope.brain_id.value,
            "occurred_at": occurred_at,
            "target_ref": finding.id,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    await connection.execute(
        text(
            "INSERT INTO audit_events(brain_id,actor_id,action,target_ref,idempotency_key,"
            "before_hash,after_hash,previous_hash,event_hash,occurred_at,schema_version) "
            "VALUES(:brain,:actor,'graph.integrity.repair',:target,:key,:before,:after,"
            ":previous,:event,:at,1)"
        ),
        {
            "brain": scope.brain_id.value,
            "actor": scope.principal_id.value,
            "target": finding.id,
            "key": key,
            "before": bytes.fromhex(finding.projection_digest),
            "after": repair_digest,
            "previous": previous_hash,
            "event": hashlib.sha256(previous_hash + document).digest(),
            "at": occurred_at,
        },
    )


def _require_conflict_free(*, valid: bool) -> None:
    if not valid:
        raise GraphConflictError(_ERR_CONFLICT)


def _require_row(row: RowMapping | None) -> RowMapping:
    if row is None:
        raise GraphConflictError(_ERR_CONFLICT)
    return row


def _digest(value: object) -> bytes:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=_json).encode("ascii")
    ).digest()


def _json(value: object) -> object:
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return round(value.timestamp() * 1_000_000)


def _time(value: object) -> datetime:
    try:
        return datetime.fromtimestamp(int(str(value)) / 1_000_000, tz=UTC)
    except (TypeError, ValueError, OSError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    await store.write_lock.acquire()
    connection: AsyncConnection | None = None
    try:
        connection = await store.engine.connect()
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        yield connection
        await connection.commit()
    except BaseException:
        if connection is not None:
            await connection.rollback()
        raise
    finally:
        if connection is not None:
            await connection.close()
        store.write_lock.release()
