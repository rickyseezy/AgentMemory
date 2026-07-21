"""SQLite authority, lifecycle state, and deletion-saga adapter for MEM-005."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, Self, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryDependencyError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from agentmemory.memory.domain.lifecycle import (
    MemoryLifecycleAction,
    MemoryLifecycleCommit,
    MemoryLifecycleResult,
    MemoryLifecycleSnapshot,
    MemoryRecallState,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
_DIGEST_BYTES = 32
_DEPENDENCIES = (
    "audit",
    "blobs",
    "cache",
    "corrections",
    "evidence",
    "exports",
    "graph",
    "learning",
    "outbox",
    "search",
    "vectors",
)


class SqliteMemoryLifecycleRepository:
    """Read authorized lifecycle state or stage one transaction-bound transition."""

    def __init__(
        self,
        store: SqliteCoreStore,
        connection: AsyncConnection | None = None,
    ) -> None:
        """Bind the canonical store and optionally one transaction-owned connection."""
        self._store = store
        self._connection = connection

    async def get_result(self, idempotency_key: str) -> MemoryLifecycleResult | None:
        """Return an authenticated lifecycle receipt or None."""
        parameters = {"key": _digest(idempotency_key, "idempotency_key")}
        try:
            if self._connection is not None:
                return await _get_result(self._connection, parameters, idempotency_key)
            async with self._store.engine.connect() as connection:
                return await _get_result(connection, parameters, idempotency_key)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def load_authorized(
        self,
        memory_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> MemoryLifecycleSnapshot | None:
        """Authorize an explicit owner principal without disclosing absent targets."""
        parameters = {
            "memory": memory_id,
            "brain": brain_id,
            "actor": actor_id,
            "grant": grant_id,
            "at": _micros(at),
            "target_hash": hashlib.sha256(memory_id.encode()).digest(),
        }
        try:
            if self._connection is not None:
                return await _load_authorized(self._connection, parameters)
            async with self._store.engine.connect() as connection:
                return await _load_authorized(connection, parameters)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def list_due(
        self,
        at: datetime,
        limit: int,
    ) -> tuple[MemoryLifecycleSnapshot, ...]:
        """Return stable due active/archive snapshots for the injected clock boundary."""
        parameters = {"at": _micros(at), "limit": limit}
        try:
            if self._connection is not None:
                return await _list_due(self._connection, parameters)
            async with self._store.engine.connect() as connection:
                return await _list_due(connection, parameters)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def add(self, commit: MemoryLifecycleCommit) -> None:
        """Stage CAS state, receipt, event, outbox, audit, and optional deletion handoff."""
        if self._connection is None:
            raise MemoryIntegrityError
        existing = await self.get_result(commit.result.idempotency_key)
        if existing is not None:
            if existing != commit.result:
                raise MemoryConflictError
            return
        await _insert_operation(self._connection, commit)
        await _transition(self._connection, commit)
        await _insert_lifecycle_event(self._connection, commit)
        await _insert_domain_event(self._connection, commit)
        await _insert_outbox(self._connection, commit)
        if commit.plan.requires_deletion_tombstone:
            await _start_deletion(self._connection, commit)
        await _insert_audit(self._connection, commit)


class SqliteMemoryLifecycleUnitOfWorkFactory:
    """Create serialized SQLite MEM-005 lifecycle transactions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the local canonical store without opening a transaction."""
        self._store = store

    def __call__(self) -> _SqliteMemoryLifecycleUnitOfWork:
        """Return one unopened lifecycle Unit of Work."""
        return _SqliteMemoryLifecycleUnitOfWork(self._store)


class _SqliteMemoryLifecycleUnitOfWork:
    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.repository: SqliteMemoryLifecycleRepository

    async def __aenter__(self) -> Self:
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except SQLAlchemyError as error:
            if self._connection is not None:
                await self._connection.close()
            self._store.write_lock.release()
            raise MemoryDependencyError from error
        self.repository = SqliteMemoryLifecycleRepository(self._store, self._connection)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, traceback
        connection = self._connection
        if connection is None:
            raise MemoryIntegrityError
        try:
            if not self._committed:
                await connection.rollback()
        finally:
            await connection.close()
            self._connection = None
            self._store.write_lock.release()
        if isinstance(exc_value, IntegrityError):
            raise MemoryConflictError from exc_value
        if isinstance(exc_value, SQLAlchemyError):
            raise MemoryDependencyError from exc_value
        return None

    async def commit(self) -> None:
        connection = self._connection
        if connection is None or self._committed:
            raise MemoryIntegrityError
        try:
            await connection.commit()
        except IntegrityError as error:
            raise MemoryConflictError from error
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        self._committed = True


async def _load_authorized(
    connection: AsyncConnection,
    parameters: Mapping[str, object],
) -> MemoryLifecycleSnapshot | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT l.memory_id,l.brain_id,l.project_id,l.repository_id,l.checkout_id,"
                    "l.recall_state,l.pinned,l.expires_at,l.aggregate_version,l.updated_at "
                    "FROM memory_lifecycle l "
                    "JOIN memories m ON m.id=l.memory_id AND m.brain_id=l.brain_id "
                    "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor "
                    "AND g.brain_id=l.brain_id "
                    "AND (g.project_id IS NULL OR g.project_id=l.project_id) "
                    "AND (g.repository_id IS NULL OR g.repository_id=l.repository_id) "
                    "JOIN principals p ON p.id=g.principal_id AND p.status='active' "
                    "AND p.type='owner' JOIN brains b ON b.id=g.brain_id AND b.status='active' "
                    "WHERE l.memory_id=:memory AND l.brain_id=:brain "
                    "AND l.recall_state<>'forgotten' "
                    "AND g.role IN ('owner','admin','editor') AND g.valid_from<=:at "
                    "AND (g.valid_to IS NULL OR g.valid_to>:at) "
                    "AND NOT EXISTS (SELECT 1 FROM deletion_tombstones d "
                    "WHERE d.brain_id=l.brain_id "
                    "AND d.target_type IN ('memory','memory_assertion') "
                    "AND d.target_id_hash=:target_hash AND d.purge_state IN "
                    "('tombstoned','completed')) LIMIT 1"
                ),
                parameters,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _snapshot(row)


async def _list_due(
    connection: AsyncConnection,
    parameters: Mapping[str, object],
) -> tuple[MemoryLifecycleSnapshot, ...]:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT memory_id,brain_id,project_id,repository_id,checkout_id,recall_state,"
                    "pinned,expires_at,aggregate_version,updated_at FROM memory_lifecycle "
                    "WHERE recall_state IN ('active','archived') AND expires_at IS NOT NULL "
                    "AND expires_at<=:at ORDER BY expires_at,memory_id LIMIT :limit"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    return tuple(_snapshot(row) for row in rows)


def _snapshot(row: RowMapping) -> MemoryLifecycleSnapshot:
    try:
        return MemoryLifecycleSnapshot(
            str(row["memory_id"]),
            MemoryScope(
                str(row["brain_id"]),
                str(row["project_id"]),
                str(row["repository_id"]),
                None if row["checkout_id"] is None else str(row["checkout_id"]),
            ),
            MemoryRecallState(str(row["recall_state"])),
            _integer(row["pinned"]) == 1,
            None if row["expires_at"] is None else _time(row["expires_at"]),
            _integer(row["aggregate_version"]),
            _time(row["updated_at"]),
        )
    except (KeyError, TypeError, ValueError, MemoryValidationError) as error:
        raise MemoryIntegrityError from error


async def _insert_operation(connection: AsyncConnection, commit: MemoryLifecycleCommit) -> None:
    await connection.execute(
        text(
            "INSERT INTO memory_lifecycle_operations "
            "(idempotency_key,operation_id,request_sha256,memory_id,brain_id,actor_id,grant_id,"
            "action,correlation_id,causation_id,result_json,result_sha256,requested_at,completed_at,"
            "schema_version) VALUES (:key,:operation,:request,:memory,:brain,:actor,:grant,:action,"
            ":correlation,:causation,:result,:result_digest,:requested_at,:completed_at,1)"
        ),
        {
            "key": bytes.fromhex(commit.result.idempotency_key),
            "operation": commit.operation_id,
            "request": bytes.fromhex(commit.result.request_sha256),
            "memory": commit.source.memory_id,
            "brain": commit.brain_id,
            "actor": commit.actor_id,
            "grant": commit.grant_id,
            "action": commit.plan.action.value,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
            "result": _result_json(commit.result),
            "result_digest": bytes.fromhex(commit.result.result_sha256),
            "requested_at": _micros(commit.requested_at),
            "completed_at": _micros(commit.completed_at),
        },
    )


async def _transition(connection: AsyncConnection, commit: MemoryLifecycleCommit) -> None:
    source = commit.source
    result = commit.plan.result
    changed = await connection.execute(
        text(
            "UPDATE memory_lifecycle SET recall_state=:state,pinned=:pinned,expires_at=:expiry,"
            "aggregate_version=:version,updated_at=:updated WHERE memory_id=:memory "
            "AND recall_state=:expected_state AND pinned=:expected_pinned "
            "AND expires_at IS :expected_expiry AND aggregate_version=:expected_version "
            "AND updated_at=:expected_updated"
        ),
        {
            "state": result.recall_state.value,
            "pinned": int(result.pinned),
            "expiry": None if result.expires_at is None else _micros(result.expires_at),
            "version": result.version,
            "updated": _micros(result.updated_at),
            "memory": source.memory_id,
            "expected_state": source.recall_state.value,
            "expected_pinned": int(source.pinned),
            "expected_expiry": None if source.expires_at is None else _micros(source.expires_at),
            "expected_version": source.version,
            "expected_updated": _micros(source.updated_at),
        },
    )
    if changed.rowcount != 1:
        raise MemoryConflictError


async def _insert_lifecycle_event(
    connection: AsyncConnection,
    commit: MemoryLifecycleCommit,
) -> None:
    source = commit.source
    result = commit.plan.result
    await connection.execute(
        text(
            "INSERT INTO memory_lifecycle_events "
            "(operation_id,memory_id,action,before_state,after_state,before_pinned,after_pinned,"
            "before_expires_at,after_expires_at,before_version,after_version,event_type,"
            "policy_version,result_sha256,occurred_at,schema_version) VALUES "
            "(:operation,:memory,:action,:before_state,:after_state,:before_pinned,:after_pinned,"
            ":before_expiry,:after_expiry,:before_version,:after_version,:event,:policy,:digest,"
            ":occurred,1)"
        ),
        {
            "operation": commit.operation_id,
            "memory": source.memory_id,
            "action": commit.plan.action.value,
            "before_state": source.recall_state.value,
            "after_state": result.recall_state.value,
            "before_pinned": int(source.pinned),
            "after_pinned": int(result.pinned),
            "before_expiry": None if source.expires_at is None else _micros(source.expires_at),
            "after_expiry": None if result.expires_at is None else _micros(result.expires_at),
            "before_version": source.version,
            "after_version": result.version,
            "event": commit.event_type,
            "policy": commit.plan.policy_version,
            "digest": bytes.fromhex(commit.result.result_sha256),
            "occurred": _micros(commit.completed_at),
        },
    )


async def _insert_domain_event(connection: AsyncConnection, commit: MemoryLifecycleCommit) -> None:
    result = commit.plan.result
    payload = _canonical_json(
        {
            "action": commit.plan.action.value,
            "expires_at": None if result.expires_at is None else _format_time(result.expires_at),
            "memory_id": result.memory_id,
            "pinned": result.pinned,
            "policy_version": commit.plan.policy_version,
            "recall_state": result.recall_state.value,
            "result_sha256": commit.result.result_sha256,
            "version": result.version,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO domain_events "
            "(event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,payload_json,"
            "payload_hash,source_digest,missing_dependency,occurred_at,recorded_at,schema_version,"
            "aggregate_type,aggregate_id,aggregate_version,event_type,event_json,correlation_id,"
            "causation_id) VALUES "
            "(:event,:brain,'graph',:stable,'memory_assertion',:target,:payload,"
            ":payload_hash,:source_digest,NULL,:now,:now,3,'memory_lifecycle',:aggregate,:version,"
            ":event_type,:payload,:correlation,:causation)"
        ),
        {
            "event": commit.operation_id,
            "brain": commit.brain_id,
            "stable": result.memory_id,
            "target": hashlib.sha256(result.memory_id.encode()).digest(),
            "payload": payload.decode(),
            "payload_hash": hashlib.sha256(payload).digest(),
            "source_digest": hashlib.sha256(
                bytes.fromhex(commit.result.result_sha256) + payload
            ).digest(),
            "now": _micros(commit.completed_at),
            "aggregate": result.memory_id,
            "version": result.version,
            "event_type": commit.event_type,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
        },
    )


async def _insert_outbox(connection: AsyncConnection, commit: MemoryLifecycleCommit) -> None:
    payload = _canonical_json(
        {
            "action": commit.plan.action.value,
            "brain_id": commit.brain_id,
            "memory_id": commit.source.memory_id,
            "result_sha256": commit.result.result_sha256,
            "schema_version": 1,
            "version": commit.result.version,
        }
    ).decode()
    source_event = (
        await connection.execute(
            text(
                "SELECT created_by_event FROM memory_revisions WHERE memory_id=:memory "
                "AND revision=1"
            ),
            {"memory": commit.source.memory_id},
        )
    ).scalar_one()
    topic = {
        MemoryLifecycleAction.PIN: "memory.pinned.v1",
        MemoryLifecycleAction.ARCHIVE: "memory.archived.v1",
        MemoryLifecycleAction.SET_EXPIRY: "memory.expiry-set.v1",
        MemoryLifecycleAction.EXPIRE: "memory.expired.v1",
        MemoryLifecycleAction.FORGET: "memory.forgotten.v1",
    }[commit.plan.action]
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) VALUES (:id,:source,:topic,:key,:payload,'ready',100,:now,0,NULL,NULL,"
            "NULL,:digest,NULL,:now,1)"
        ),
        {
            "id": str(uuid7()),
            "source": str(source_event),
            "topic": topic,
            "key": commit.result.idempotency_key,
            "payload": payload,
            "now": _micros(commit.completed_at),
            "digest": hashlib.sha256(payload.encode()).digest(),
        },
    )


async def _start_deletion(connection: AsyncConnection, commit: MemoryLifecycleCommit) -> None:
    if commit.grant_id is None:
        raise MemoryIntegrityError
    now = _micros(commit.completed_at)
    target_hash = hashlib.sha256(commit.source.memory_id.encode()).digest()
    deletion_targets: list[tuple[str, str, bytes]] = [(commit.operation_id, "memory", target_hash)]
    await connection.execute(
        text(
            "INSERT INTO deletion_tombstones "
            "(id,brain_id,target_type,target_id_hash,effective_at,purge_state,restore_guard_version,"
            "created_at,schema_version) VALUES (:id,:brain,'memory',:target,:now,"
            "'tombstoned',1,:now,1)"
        ),
        {
            "id": commit.operation_id,
            "brain": commit.brain_id,
            "target": target_hash,
            "now": now,
        },
    )
    assertion_ids = (
        commit.source.memory_id,
        *tuple(
            str(value)
            for value in (
                await connection.execute(
                    text(
                        "SELECT id FROM memory_corrections WHERE root_memory_id=:memory ORDER BY id"
                    ),
                    {"memory": commit.source.memory_id},
                )
            ).scalars()
        ),
    )
    for assertion_id in assertion_ids:
        tombstone_id = str(uuid7())
        assertion_hash = hashlib.sha256(assertion_id.encode()).digest()
        await connection.execute(
            text(
                "INSERT INTO deletion_tombstones "
                "(id,brain_id,target_type,target_id_hash,effective_at,purge_state,"
                "restore_guard_version,created_at,schema_version) VALUES "
                "(:id,:brain,'memory_assertion',:target,:now,'tombstoned',1,:now,1)"
            ),
            {
                "id": tombstone_id,
                "brain": commit.brain_id,
                "target": assertion_hash,
                "now": now,
            },
        )
        deletion_targets.append((tombstone_id, "memory_assertion", assertion_hash))
    job_id = str(uuid7())
    request_digest = hashlib.sha256(
        commit.operation_id.encode() + target_hash + bytes.fromhex(commit.result.result_sha256)
    ).digest()
    await connection.execute(
        text(
            "INSERT INTO jobs "
            "(id,brain_id,kind,idempotency_key,state,attempts,lease_owner,lease_until,"
            "next_attempt_at,created_at,updated_at,schema_version,input_ref,request_sha256,"
            "result_sha256,completed_at,priority_class,last_error_code,parent_job_id) VALUES "
            "(:id,:brain,'governance.memory_deletion',:key,'queued',0,NULL,NULL,:now,:now,:now,1,"
            "NULL,:request,NULL,NULL,'background',NULL,NULL)"
        ),
        {
            "id": job_id,
            "brain": commit.brain_id,
            "key": f"memory.delete:{commit.result.idempotency_key}",
            "now": now,
            "request": request_digest,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO job_authorizations "
            "(job_id,actor_id,grant_id,input_ref,created_at,schema_version) "
            "VALUES (:job,:actor,:grant,NULL,:now,1)"
        ),
        {
            "job": job_id,
            "actor": commit.actor_id,
            "grant": commit.grant_id,
            "now": now,
        },
    )
    dependencies = _canonical_json(list(_DEPENDENCIES)).decode()
    await connection.execute(
        text(
            "INSERT INTO memory_deletion_manifests "
            "(operation_id,memory_id,brain_id,tombstone_id,job_id,dependency_types_json,state,"
            "created_at,updated_at,schema_version) VALUES "
            "(:operation,:memory,:brain,:tombstone,:job,:dependencies,'tombstoned',:now,:now,1)"
        ),
        {
            "operation": commit.operation_id,
            "memory": commit.source.memory_id,
            "brain": commit.brain_id,
            "tombstone": commit.operation_id,
            "job": job_id,
            "dependencies": dependencies,
            "now": now,
        },
    )
    for tombstone_id, target_type, deletion_hash in deletion_targets:
        await _insert_deletion_target(
            connection,
            commit.operation_id,
            (tombstone_id, target_type, deletion_hash, now),
        )


async def _insert_deletion_target(
    connection: AsyncConnection,
    operation_id: str,
    target: tuple[str, str, bytes, int],
) -> None:
    tombstone_id, target_type, target_hash, created_at = target
    await connection.execute(
        text(
            "INSERT INTO memory_deletion_targets "
            "(operation_id,tombstone_id,target_type,target_id_hash,created_at,schema_version) "
            "VALUES (:operation,:tombstone,:target_type,:target_hash,:created_at,1)"
        ),
        {
            "operation": operation_id,
            "tombstone": tombstone_id,
            "target_type": target_type,
            "target_hash": target_hash,
            "created_at": created_at,
        },
    )


async def _insert_audit(connection: AsyncConnection, commit: MemoryLifecycleCommit) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = _bytes(previous) if previous is not None else bytes(_DIGEST_BYTES)
    action = f"memory.{commit.plan.action.value}"
    before = _canonical_json(
        {
            "expires_at": None
            if commit.source.expires_at is None
            else _format_time(commit.source.expires_at),
            "pinned": commit.source.pinned,
            "state": commit.source.recall_state.value,
            "version": commit.source.version,
        }
    )
    after = bytes.fromhex(commit.result.result_sha256)
    fact = _canonical_json(
        {
            "action": action,
            "actor_id": commit.actor_id,
            "brain_id": commit.brain_id,
            "idempotency_key": commit.result.idempotency_key,
            "memory_id": commit.source.memory_id,
            "result_sha256": commit.result.result_sha256,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events (brain_id,actor_id,action,target_ref,idempotency_key,"
            "before_hash,after_hash,previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:now,1)"
        ),
        {
            "brain": commit.brain_id,
            "actor": commit.actor_id,
            "action": action,
            "target": f"memory:{commit.source.memory_id}",
            "key": f"memory.lifecycle:{commit.result.idempotency_key}",
            "before": hashlib.sha256(before).digest(),
            "after": after,
            "previous": previous_hash,
            "event": hashlib.sha256(previous_hash + fact).digest(),
            "now": _micros(commit.completed_at),
        },
    )


async def _get_result(
    connection: AsyncConnection,
    parameters: Mapping[str, object],
    idempotency_key: str,
) -> MemoryLifecycleResult | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT result_json,result_sha256 FROM memory_lifecycle_operations "
                    "WHERE idempotency_key=:key"
                ),
                parameters,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    document = _strict_object(str(row["result_json"]).encode())
    try:
        result = MemoryLifecycleResult(
            idempotency_key,
            _string(document, "request_sha256"),
            _string(document, "plan_sha256"),
            _string(document, "operation_id"),
            _string(document, "memory_id"),
            MemoryLifecycleAction(_string(document, "action")),
            MemoryRecallState(_string(document, "recall_state")),
            _boolean(document, "pinned"),
            _optional_document_time(document, "expires_at"),
            _document_integer(document, "version"),
            _string(document, "policy_version"),
            _string(document, "result_sha256"),
        )
    except (KeyError, TypeError, ValueError, MemoryValidationError) as error:
        raise MemoryIntegrityError from error
    if (
        _result_json(result) != str(row["result_json"])
        or _bytes(row["result_sha256"]).hex() != result.result_sha256
    ):
        raise MemoryIntegrityError
    return result


def _result_json(result: MemoryLifecycleResult) -> str:
    return _canonical_json(
        {
            "action": result.action.value,
            "expires_at": None if result.expires_at is None else _format_time(result.expires_at),
            "memory_id": result.memory_id,
            "operation_id": result.operation_id,
            "pinned": result.pinned,
            "plan_sha256": result.plan_sha256,
            "policy_version": result.policy_version,
            "recall_state": result.recall_state.value,
            "request_sha256": result.request_sha256,
            "result_sha256": result.result_sha256,
            "version": result.version,
        }
    ).decode()


def _strict_object(raw: bytes) -> dict[str, JsonValue]:
    def unique(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                raise MemoryIntegrityError
            result[key] = value
        return result

    def constant(_: str) -> Never:
        raise MemoryIntegrityError

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MemoryIntegrityError from error
    if not isinstance(value, dict):
        raise MemoryIntegrityError
    document = cast("dict[str, JsonValue]", value)
    if _canonical_json(document) != raw:
        raise MemoryIntegrityError
    return document


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise MemoryIntegrityError from error


def _digest(value: str, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_digest") from error
    if len(raw) != _DIGEST_BYTES or raw == bytes(_DIGEST_BYTES):
        raise MemoryValidationError.single(field, "invalid_digest")
    return raw


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise MemoryIntegrityError


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MemoryIntegrityError
    return value


def _document_integer(document: Mapping[str, JsonValue], field: str) -> int:
    return _integer(document[field])


def _boolean(document: Mapping[str, JsonValue], field: str) -> bool:
    value = document[field]
    if not isinstance(value, bool):
        raise MemoryIntegrityError
    return value


def _string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        raise MemoryIntegrityError
    return value


def _optional_document_time(
    document: Mapping[str, JsonValue],
    field: str,
) -> datetime | None:
    value = document[field]
    if value is None:
        return None
    if not isinstance(value, str):
        raise MemoryIntegrityError
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise MemoryIntegrityError from error
    if _format_time(parsed) != value:
        raise MemoryIntegrityError
    return parsed


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        field = "time"
        raise MemoryValidationError.single(field, "not_utc")
    return round(value.timestamp() * 1_000_000)


def _time(value: object) -> datetime:
    integer = _integer(value)
    try:
        return datetime.fromtimestamp(integer / 1_000_000, tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise MemoryIntegrityError from error


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
