"""SQLite authority, immutable lineage, and atomic MEM-004 correction adapter."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, Self, cast
from uuid import uuid7

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.memory.domain.consolidation import MemoryClass, MemoryScope, MemoryStatus
from agentmemory.memory.domain.correction import (
    CorrectionEvidence,
    CorrectionRelation,
    CorrectionTarget,
    MemoryCorrectionAssertion,
    MemoryCorrectionCommit,
    MemoryCorrectionHistory,
    MemoryCorrectionResult,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryDependencyError,
    MemoryIntegrityError,
    MemoryValidationError,
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

_ROOT_COLUMNS = """
m.id,m.brain_id,m.memory_class,m.project_id,m.repository_id,m.checkout_id,m.status,
m.valid_from,m.valid_to,m.recorded_from,m.recorded_to,m.classification,m.retention_policy_id,
m.aggregate_version,m.content_hash,r.content_json
"""

_CORRECTION_COLUMNS = """
c.id,c.root_memory_id,c.source_assertion_id,c.memory_class,c.brain_id,c.project_id,
c.repository_id,c.checkout_id,c.scope_json,c.status,c.statement_json,c.content_hash,c.relation,
c.reason,c.actor_id,c.grant_id,c.valid_from,c.valid_to,c.recorded_from,c.recorded_to,
c.classification,c.retention_policy_id,c.policy_version,c.aggregate_version
"""


class SqliteMemoryCorrectionRepository:
    """Read authorized correction state or stage one transaction-bound correction."""

    def __init__(
        self,
        store: SqliteCoreStore,
        connection: AsyncConnection | None = None,
    ) -> None:
        """Bind the local store and optionally one transaction-owned connection."""
        self._store = store
        self._connection = connection

    async def get_result(self, idempotency_key: str) -> MemoryCorrectionResult | None:
        """Return one authenticated request-bound correction receipt."""
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
        assertion_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> CorrectionTarget | None:
        """Authorize an explicit owner identity and load a root or correction assertion."""
        parameters = _authority(assertion_id, brain_id, actor_id, grant_id, at)
        try:
            if self._connection is not None:
                return await _load_target(self._connection, parameters)
            async with self._store.engine.connect() as connection:
                return await _load_target(connection, parameters)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def load_evidence_authorized(
        self,
        evidence_ids: tuple[str, ...],
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> tuple[CorrectionEvidence, ...] | None:
        """Resolve the exact canonical evidence set without existence disclosure."""
        if not evidence_ids:
            return ()
        query = text(
            "SELECT l.event_id,l.canonical_event_sha256 FROM event_task_lineage l "
            "JOIN agent_events e ON e.event_id=l.event_id AND e.brain_id=l.brain_id "
            "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor "
            "AND g.brain_id=l.brain_id "
            "AND (g.project_id IS NULL OR g.project_id=l.project_id) "
            "AND (g.repository_id IS NULL OR g.repository_id=l.repository_id) "
            "JOIN principals p ON p.id=g.principal_id AND p.status='active' AND p.type='owner' "
            "JOIN brains b ON b.id=g.brain_id AND b.status='active' "
            "WHERE l.brain_id=:brain AND l.event_id IN :events "
            "AND g.role IN ('owner','admin','editor') AND g.valid_from<=:at "
            "AND (g.valid_to IS NULL OR g.valid_to>:at) ORDER BY l.event_id"
        ).bindparams(bindparam("events", expanding=True))
        parameters: dict[str, object] = {
            "events": evidence_ids,
            "brain": brain_id,
            "actor": actor_id,
            "grant": grant_id,
            "at": _micros(at),
        }
        try:
            if self._connection is not None:
                rows = list((await self._connection.execute(query, parameters)).mappings().all())
            else:
                async with self._store.engine.connect() as connection:
                    rows = list((await connection.execute(query, parameters)).mappings().all())
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        if tuple(str(row["event_id"]) for row in rows) != evidence_ids:
            return None
        try:
            return tuple(
                CorrectionEvidence(
                    str(row["event_id"]),
                    _bytes(row["canonical_event_sha256"]).hex(),
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError, MemoryValidationError) as error:
            raise MemoryIntegrityError from error

    async def history_authorized(
        self,
        root_memory_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> MemoryCorrectionHistory | None:
        """Return the complete immutable correction chain after root authorization."""
        parameters = _authority(root_memory_id, brain_id, actor_id, grant_id, at)
        try:
            if self._connection is not None:
                return await _history(self._connection, parameters)
            async with self._store.engine.connect() as connection:
                return await _history(connection, parameters)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def add(self, commit: MemoryCorrectionCommit) -> None:
        """Stage receipt, CAS transition, assertion, evidence, event, outbox, and audit."""
        if self._connection is None:
            raise MemoryIntegrityError
        existing = await self.get_result(commit.result.idempotency_key)
        if existing is not None:
            if existing != commit.result:
                raise MemoryConflictError
            return
        current = await _load_target(
            self._connection,
            _authority(
                commit.target.assertion_id,
                commit.brain_id,
                commit.actor_id,
                commit.grant_id,
                commit.completed_at,
            ),
        )
        if current != commit.target:
            raise MemoryConflictError
        await _insert_operation(self._connection, commit)
        await _transition_source(self._connection, commit)
        await _insert_assertion(self._connection, commit)
        await _insert_evidence(self._connection, commit)
        await _insert_event(self._connection, commit)
        await _insert_outbox(self._connection, commit)
        await _insert_audit(self._connection, commit)


class SqliteMemoryCorrectionUnitOfWorkFactory:
    """Create serialized SQLite MEM-004 correction transactions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local store without opening a transaction."""
        self._store = store

    def __call__(self) -> _SqliteMemoryCorrectionUnitOfWork:
        """Return one unopened serialized correction Unit of Work."""
        return _SqliteMemoryCorrectionUnitOfWork(self._store)


class _SqliteMemoryCorrectionUnitOfWork:
    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.repository: SqliteMemoryCorrectionRepository

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
        self.repository = SqliteMemoryCorrectionRepository(self._store, self._connection)
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


def _authority(
    assertion_id: str,
    brain_id: str,
    actor_id: str,
    grant_id: str,
    at: datetime,
) -> dict[str, object]:
    return {
        "assertion": assertion_id,
        "brain": brain_id,
        "actor": actor_id,
        "grant": grant_id,
        "at": _micros(at),
    }


async def _load_target(
    connection: AsyncConnection,
    parameters: Mapping[str, object],
) -> CorrectionTarget | None:
    root_query = text(
        f"SELECT {_ROOT_COLUMNS} FROM memories m "  # noqa: S608  # nosec B608 -- fixed columns.
        "JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision "
        "JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id "
        "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor AND g.brain_id=m.brain_id "
        "AND (g.project_id IS NULL OR g.project_id=m.project_id) "
        "AND (g.repository_id IS NULL OR g.repository_id=m.repository_id) "
        "JOIN principals p ON p.id=g.principal_id AND p.status='active' AND p.type='owner' "
        "JOIN brains b ON b.id=g.brain_id AND b.status='active' "
        "WHERE m.id=:assertion AND m.brain_id=:brain "
        "AND l.recall_state='active' AND (l.expires_at IS NULL OR l.expires_at>:at) "
        "AND g.role IN ('owner','admin','editor') AND g.valid_from<=:at "
        "AND (g.valid_to IS NULL OR g.valid_to>:at) LIMIT 1"
    )
    root = (await connection.execute(root_query, parameters)).mappings().one_or_none()
    if root is not None:
        return await _root_target(connection, root)
    correction_query = text(
        f"SELECT {_CORRECTION_COLUMNS} FROM memory_corrections c "  # noqa: S608  # nosec B608.
        "JOIN memory_lifecycle l ON l.memory_id=c.root_memory_id AND l.brain_id=c.brain_id "
        "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor AND g.brain_id=c.brain_id "
        "AND (g.project_id IS NULL OR g.project_id=c.project_id) "
        "AND (g.repository_id IS NULL OR g.repository_id=c.repository_id) "
        "JOIN principals p ON p.id=g.principal_id AND p.status='active' AND p.type='owner' "
        "JOIN brains b ON b.id=g.brain_id AND b.status='active' "
        "WHERE c.id=:assertion AND c.brain_id=:brain "
        "AND l.recall_state='active' AND (l.expires_at IS NULL OR l.expires_at>:at) "
        "AND g.role IN ('owner','admin','editor') AND g.valid_from<=:at "
        "AND (g.valid_to IS NULL OR g.valid_to>:at) LIMIT 1"
    )
    correction = (await connection.execute(correction_query, parameters)).mappings().one_or_none()
    return None if correction is None else await _correction_target(connection, correction)


async def _root_target(connection: AsyncConnection, row: RowMapping) -> CorrectionTarget:
    memory_id = str(row["id"])
    evidence = tuple(
        sorted(
            str(value)
            for value in (
                await connection.execute(
                    text(
                        "SELECT event_id FROM memory_evidence WHERE memory_id=:memory "
                        "UNION SELECT event_id FROM memory_merge_evidence "
                        "WHERE survivor_memory_id=:memory"
                    ),
                    {"memory": memory_id},
                )
            ).scalars()
        )
    )
    return _target_from_row(row, memory_id, memory_id, evidence, "content_json")


async def _correction_target(connection: AsyncConnection, row: RowMapping) -> CorrectionTarget:
    assertion_id = str(row["id"])
    evidence = tuple(
        str(value)
        for value in (
            await connection.execute(
                text(
                    "SELECT event_id FROM memory_correction_evidence "
                    "WHERE correction_id=:correction ORDER BY event_id"
                ),
                {"correction": assertion_id},
            )
        ).scalars()
    )
    return _target_from_row(
        row,
        assertion_id,
        str(row["root_memory_id"]),
        evidence,
        "statement_json",
    )


def _target_from_row(
    row: RowMapping,
    assertion_id: str,
    root_memory_id: str,
    evidence: tuple[str, ...],
    statement_column: str,
) -> CorrectionTarget:
    scope = _scope(row)
    statement = _statement(str(row[statement_column]))
    try:
        return CorrectionTarget(
            assertion_id,
            root_memory_id,
            MemoryClass(str(row["memory_class"])),
            statement,
            _bytes(row["content_hash"]).hex(),
            scope,
            MemoryStatus(str(row["status"])),
            _time(row["valid_from"]),
            None if row["valid_to"] is None else _time(row["valid_to"]),
            _time(row["recorded_from"]),
            None if row["recorded_to"] is None else _time(row["recorded_to"]),
            str(row["classification"]),
            str(row["retention_policy_id"]),
            evidence,
            _integer(row["aggregate_version"]),
        )
    except (KeyError, TypeError, ValueError, MemoryValidationError) as error:
        raise MemoryIntegrityError from error


async def _history(
    connection: AsyncConnection,
    parameters: Mapping[str, object],
) -> MemoryCorrectionHistory | None:
    root_row = (
        (
            await connection.execute(
                text(
                    f"SELECT {_ROOT_COLUMNS} FROM memories m "  # noqa: S608  # nosec B608.
                    "JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision "
                    "JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id "
                    "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor "
                    "AND g.brain_id=m.brain_id "
                    "AND (g.project_id IS NULL OR g.project_id=m.project_id) "
                    "AND (g.repository_id IS NULL OR g.repository_id=m.repository_id) "
                    "JOIN principals p ON p.id=g.principal_id AND p.status='active' "
                    "AND p.type='owner' "
                    "JOIN brains b ON b.id=g.brain_id AND b.status='active' "
                    "WHERE m.id=:assertion AND m.brain_id=:brain "
                    "AND l.recall_state IN ('active','archived','expired') "
                    "AND g.role IN ('owner','admin','editor','reader','auditor') "
                    "AND g.valid_from<=:at AND (g.valid_to IS NULL OR g.valid_to>:at) LIMIT 1"
                ),
                parameters,
            )
        )
        .mappings()
        .one_or_none()
    )
    if root_row is None:
        return None
    root = await _root_target(connection, root_row)
    rows = list(
        (
            await connection.execute(
                text(
                    f"SELECT {_CORRECTION_COLUMNS} FROM memory_corrections c "  # noqa: S608  # nosec B608.
                    "WHERE c.root_memory_id=:assertion ORDER BY c.recorded_from,c.id"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    try:
        corrections = tuple([await _assertion(connection, row) for row in rows])
        return MemoryCorrectionHistory(root, corrections)
    except (KeyError, TypeError, ValueError, MemoryValidationError) as error:
        raise MemoryIntegrityError from error


async def _assertion(
    connection: AsyncConnection,
    row: RowMapping,
) -> MemoryCorrectionAssertion:
    assertion_id = str(row["id"])
    evidence_rows = list(
        (
            await connection.execute(
                text(
                    "SELECT event_id,canonical_event_sha256 FROM memory_correction_evidence "
                    "WHERE correction_id=:correction ORDER BY event_id"
                ),
                {"correction": assertion_id},
            )
        )
        .mappings()
        .all()
    )
    scope = _scope(row)
    if str(row["scope_json"]) != _canonical_json(dict(scope.canonical)).decode():
        raise MemoryIntegrityError
    return MemoryCorrectionAssertion(
        assertion_id,
        str(row["root_memory_id"]),
        str(row["source_assertion_id"]),
        MemoryClass(str(row["memory_class"])),
        _statement(str(row["statement_json"])),
        _bytes(row["content_hash"]).hex(),
        scope,
        CorrectionRelation(str(row["relation"])),
        str(row["reason"]),
        tuple(
            CorrectionEvidence(
                str(item["event_id"]),
                _bytes(item["canonical_event_sha256"]).hex(),
            )
            for item in evidence_rows
        ),
        str(row["actor_id"]),
        str(row["grant_id"]),
        _time(row["valid_from"]),
        None if row["valid_to"] is None else _time(row["valid_to"]),
        _time(row["recorded_from"]),
        None if row["recorded_to"] is None else _time(row["recorded_to"]),
        MemoryStatus(str(row["status"])),
        str(row["classification"]),
        str(row["retention_policy_id"]),
        str(row["policy_version"]),
        _integer(row["aggregate_version"]),
    )


async def _insert_operation(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    await connection.execute(
        text(
            "INSERT INTO memory_correction_operations "
            "(idempotency_key,operation_id,request_sha256,requested_assertion_id,root_memory_id,"
            "brain_id,actor_id,grant_id,correlation_id,causation_id,policy_version,result_json,"
            "result_sha256,requested_at,completed_at,schema_version) VALUES "
            "(:key,:operation,:request,:requested,:root,:brain,:actor,:grant,:correlation,"
            ":causation,:policy,:result,:result_digest,:requested_at,:completed_at,1)"
        ),
        {
            "key": bytes.fromhex(commit.result.idempotency_key),
            "operation": commit.operation_id,
            "request": bytes.fromhex(commit.result.request_sha256),
            "requested": commit.target.assertion_id,
            "root": commit.target.root_memory_id,
            "brain": commit.brain_id,
            "actor": commit.actor_id,
            "grant": commit.grant_id,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
            "policy": commit.result.policy_version,
            "result": _result_json(commit.result),
            "result_digest": bytes.fromhex(commit.result.result_sha256),
            "requested_at": _micros(commit.requested_at),
            "completed_at": _micros(commit.completed_at),
        },
    )


async def _transition_source(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    plan = commit.plan
    parameters = {
        "id": commit.target.assertion_id,
        "status": plan.source_status.value,
        "recorded_to": None
        if plan.source_recorded_to is None
        else _micros(plan.source_recorded_to),
        "source_version": plan.source_version,
        "expected_version": commit.target.aggregate_version,
        "expected_status": commit.target.status.value,
        "expected_recorded_to": None
        if commit.target.recorded_to is None
        else _micros(commit.target.recorded_to),
        "updated_at": _micros(commit.completed_at),
    }
    table = (
        "memories"
        if commit.target.assertion_id == commit.target.root_memory_id
        else "memory_corrections"
    )
    statement = text(
        f"UPDATE {table} SET status=:status,recorded_to=:recorded_to,"  # noqa: S608  # nosec B608 -- closed table selection.
        "aggregate_version=:source_version,updated_at=:updated_at WHERE id=:id "
        "AND aggregate_version=:expected_version AND status=:expected_status "
        "AND recorded_to IS :expected_recorded_to"
    )
    updated = await connection.execute(statement, parameters)
    if updated.rowcount != 1:
        raise MemoryConflictError


async def _insert_assertion(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    item = commit.plan.assertion
    await connection.execute(
        text(
            "INSERT INTO memory_corrections "
            "(id,root_memory_id,source_assertion_id,parent_correction_id,operation_id,memory_class,"
            "brain_id,project_id,repository_id,checkout_id,scope_json,status,statement_json,"
            "content_hash,relation,reason,actor_id,grant_id,valid_from,valid_to,recorded_from,"
            "recorded_to,classification,retention_policy_id,policy_version,aggregate_version,"
            "created_at,updated_at,schema_version) VALUES "
            "(:id,:root,:source,:parent,:operation,:class,:brain,:project,:repository,:checkout,"
            ":scope,:status,:statement,:content,:relation,:reason,:actor,:grant,:valid_from,"
            ":valid_to,:recorded_from,:recorded_to,:classification,:retention,:policy,:version,"
            ":created_at,:updated_at,1)"
        ),
        {
            "id": item.assertion_id,
            "root": item.root_memory_id,
            "source": item.source_assertion_id,
            "parent": None
            if item.source_assertion_id == item.root_memory_id
            else item.source_assertion_id,
            "operation": commit.operation_id,
            "class": item.memory_class.value,
            "brain": item.scope.brain_id,
            "project": item.scope.project_id,
            "repository": item.scope.repository_id,
            "checkout": item.scope.checkout_id,
            "scope": _canonical_json(dict(item.scope.canonical)).decode(),
            "status": item.status.value,
            "statement": _canonical_json({"statement": item.statement}).decode(),
            "content": bytes.fromhex(item.content_sha256),
            "relation": item.relation.value,
            "reason": item.reason,
            "actor": item.actor_id,
            "grant": item.grant_id,
            "valid_from": _micros(item.valid_from),
            "valid_to": None if item.valid_to is None else _micros(item.valid_to),
            "recorded_from": _micros(item.recorded_from),
            "recorded_to": None if item.recorded_to is None else _micros(item.recorded_to),
            "classification": item.classification,
            "retention": item.retention_policy_id,
            "policy": item.policy_version,
            "version": item.aggregate_version,
            "created_at": _micros(commit.completed_at),
            "updated_at": _micros(commit.completed_at),
        },
    )


async def _insert_evidence(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    for evidence in commit.plan.assertion.evidence:
        await connection.execute(
            text(
                "INSERT INTO memory_correction_evidence "
                "(correction_id,event_id,canonical_event_sha256,created_at,schema_version) "
                "VALUES (:correction,:event,:digest,:created_at,1)"
            ),
            {
                "correction": commit.plan.assertion.assertion_id,
                "event": evidence.event_id,
                "digest": bytes.fromhex(evidence.canonical_event_sha256),
                "created_at": _micros(commit.completed_at),
            },
        )


async def _insert_event(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    item = commit.plan.assertion
    event_json = _canonical_json(
        {
            "assertion": {
                "content_sha256": item.content_sha256,
                "id": item.assertion_id,
                "memory_class": item.memory_class.value,
                "root_memory_id": item.root_memory_id,
                "scope": dict(item.scope.canonical),
                "status": item.status.value,
            },
            "policy_version": item.policy_version,
            "reason": item.reason,
            "relationship": {
                "from": item.assertion_id,
                "to": item.source_assertion_id,
                "type": item.relation.graph_type,
            },
            "result_sha256": commit.result.result_sha256,
        }
    ).decode()
    payload = event_json.encode()
    await connection.execute(
        text(
            "INSERT INTO domain_events "
            "(event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,payload_json,"
            "payload_hash,source_digest,missing_dependency,occurred_at,recorded_at,schema_version,"
            "aggregate_type,aggregate_id,aggregate_version,event_type,event_json,correlation_id,"
            "causation_id) VALUES (:event,:brain,'graph',:stable,'memory_assertion',:target,"
            ":payload,:payload_hash,:source_digest,NULL,:now,:now,3,'memory_correction',"
            ":aggregate,1,'MemoryCorrected',:payload,:correlation,:causation)"
        ),
        {
            "event": commit.operation_id,
            "brain": commit.brain_id,
            "stable": item.assertion_id,
            "target": hashlib.sha256(item.assertion_id.encode()).digest(),
            "payload": event_json,
            "payload_hash": hashlib.sha256(payload).digest(),
            "source_digest": hashlib.sha256(
                bytes.fromhex(commit.result.result_sha256) + payload
            ).digest(),
            "now": _micros(commit.completed_at),
            "aggregate": item.assertion_id,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
        },
    )


async def _insert_outbox(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    payload = _canonical_json(
        {
            "brain_id": commit.brain_id,
            "correction_id": commit.result.correction_id,
            "policy_version": commit.result.policy_version,
            "relation": commit.result.relation.value,
            "result_sha256": commit.result.result_sha256,
            "root_memory_id": commit.result.root_memory_id,
            "schema_version": 1,
            "source_assertion_id": commit.result.source_assertion_id,
        }
    ).decode()
    source_event = (
        await connection.execute(
            text(
                "SELECT created_by_event FROM memory_revisions WHERE memory_id=:memory "
                "AND revision=1"
            ),
            {"memory": commit.result.root_memory_id},
        )
    ).scalar_one()
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) VALUES (:id,:source,'memory.corrected.v1',:key,:payload,'ready',100,"
            ":now,0,NULL,NULL,NULL,:digest,NULL,:now,1)"
        ),
        {
            "id": str(uuid7()),
            "source": str(source_event),
            "key": commit.result.idempotency_key,
            "payload": payload,
            "now": _micros(commit.completed_at),
            "digest": hashlib.sha256(payload.encode()).digest(),
        },
    )


async def _insert_audit(connection: AsyncConnection, commit: MemoryCorrectionCommit) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = _bytes(previous) if previous is not None else bytes(_DIGEST_BYTES)
    fact = _canonical_json(
        {
            "action": "memory.corrected",
            "actor_id": commit.actor_id,
            "brain_id": commit.brain_id,
            "correction_id": commit.result.correction_id,
            "idempotency_key": commit.result.idempotency_key,
            "result_sha256": commit.result.result_sha256,
            "source_assertion_id": commit.target.assertion_id,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events (brain_id,actor_id,action,target_ref,idempotency_key,"
            "before_hash,after_hash,previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,'memory.corrected',:target,:key,:before,:after,:previous,:event,:now,1)"
        ),
        {
            "brain": commit.brain_id,
            "actor": commit.actor_id,
            "target": f"memory_assertion:{commit.target.assertion_id}",
            "key": f"memory.correction:{commit.result.idempotency_key}",
            "before": bytes.fromhex(commit.target.content_sha256),
            "after": bytes.fromhex(commit.result.result_sha256),
            "previous": previous_hash,
            "event": hashlib.sha256(previous_hash + fact).digest(),
            "now": _micros(commit.completed_at),
        },
    )


async def _get_result(
    connection: AsyncConnection,
    parameters: Mapping[str, object],
    idempotency_key: str,
) -> MemoryCorrectionResult | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT result_json,result_sha256 FROM memory_correction_operations "
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
        result = MemoryCorrectionResult(
            idempotency_key,
            _string(document, "request_sha256"),
            _string(document, "plan_sha256"),
            _string(document, "correction_id"),
            _string(document, "root_memory_id"),
            _string(document, "source_assertion_id"),
            CorrectionRelation(_string(document, "relation")),
            MemoryStatus(_string(document, "source_status")),
            _document_integer(document, "source_version"),
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


def _result_json(result: MemoryCorrectionResult) -> str:
    return _canonical_json(
        {
            "correction_id": result.correction_id,
            "plan_sha256": result.plan_sha256,
            "policy_version": result.policy_version,
            "relation": result.relation.value,
            "request_sha256": result.request_sha256,
            "result_sha256": result.result_sha256,
            "root_memory_id": result.root_memory_id,
            "source_assertion_id": result.source_assertion_id,
            "source_status": result.source_status.value,
            "source_version": result.source_version,
        }
    ).decode()


def _scope(row: RowMapping) -> MemoryScope:
    scope = MemoryScope(
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        None if row["checkout_id"] is None else str(row["checkout_id"]),
    )
    if (
        "scope_json" in row
        and str(row["scope_json"]) != _canonical_json(dict(scope.canonical)).decode()
    ):
        raise MemoryIntegrityError
    return scope


def _statement(raw: str) -> str:
    document = _strict_object(raw.encode())
    if set(document) != {"statement"} or not isinstance(document["statement"], str):
        raise MemoryIntegrityError
    statement = document["statement"]
    if not statement or statement != unicodedata.normalize("NFC", statement).strip():
        raise MemoryIntegrityError
    return statement


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
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
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


def _string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        raise MemoryIntegrityError
    return value


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        field = "time"
        raise MemoryValidationError.single(field, "not_utc")
    return int(value.timestamp() * 1_000_000)


def _time(value: object) -> datetime:
    integer = _integer(value)
    try:
        return datetime.fromtimestamp(integer / 1_000_000, tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise MemoryIntegrityError from error
