"""SQLite task-evidence query and atomic MEM-001 consolidation repository."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, Self, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.memory.domain.consolidation import (
    ConsolidationCommit,
    ConsolidationResult,
    Memory,
    MemoryScope,
    TaskEvidence,
    TaskEvidenceBundle,
)
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
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

    from agentmemory.memory.domain.ports import (
        CanonicalTaskEventReader,
        MemoryConsolidationUnitOfWork,
    )
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_TERMINAL_TYPES = (
    "agentmemory.task.checkpointed.v1",
    "agentmemory.task.completed.v1",
)
_MAX_QUERY_ITEMS = 256
_MAX_QUERY_BYTES = 1024 * 1024
_DIGEST_BYTES = 32


class SqliteTaskEvidenceQuery:
    """Load one exact task snapshot through indexed metadata and authenticated bytes."""

    def __init__(self, store: SqliteCoreStore, reader: CanonicalTaskEventReader) -> None:
        """Bind canonical metadata and the narrow decryption capability."""
        self._store = store
        self._reader = reader

    async def load(
        self,
        task_id: str,
        terminal_event_id: str,
        scope: MemoryScope,
        maximum_items: int,
        maximum_bytes: int,
    ) -> TaskEvidenceBundle | None:
        """Load bounded events through the latest exact completed/checkpointed watermark."""
        if not 1 <= maximum_items <= _MAX_QUERY_ITEMS:
            _invalid("maximum_items", "out_of_range")
        if not 1 <= maximum_bytes <= _MAX_QUERY_BYTES:
            _invalid("maximum_bytes", "out_of_range")
        parameters = {**_scope_parameters(task_id, scope), "terminal_event_id": terminal_event_id}
        try:
            async with self._store.engine.connect() as connection:
                terminal = await self._terminal(connection, parameters)
                if terminal is None:
                    return None
                rows = await self._rows(
                    connection,
                    parameters,
                    terminal,
                    maximum_items + 1,
                )
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        if len(rows) > maximum_items:
            _invalid("evidence", "count_exceeded")
        evidence: list[TaskEvidence] = []
        used = 0
        for row in rows:
            event_id = str(row["event_id"])
            raw = await self._reader.read(event_id)
            item = _task_evidence(row, raw, task_id, scope)
            used += len(item.payload)
            if used > maximum_bytes:
                _invalid("evidence", "bytes_exceeded")
            evidence.append(item)
        return TaskEvidenceBundle.create(task_id, scope, tuple(evidence))

    @staticmethod
    async def _terminal(
        connection: AsyncConnection,
        parameters: Mapping[str, object],
    ) -> RowMapping | None:
        return (
            (
                await connection.execute(
                    text(
                        "SELECT event_id,occurred_at FROM event_task_lineage "
                        "WHERE brain_id=:brain_id AND project_id=:project_id "
                        "AND repository_id=:repository_id "
                        "AND checkout_id IS :checkout_id AND task_id=:task_id "
                        "AND event_id=:terminal_event_id "
                        "AND event_type IN (:checkpointed,:completed) "
                        "LIMIT 1"
                    ),
                    {
                        **parameters,
                        "checkpointed": _TERMINAL_TYPES[0],
                        "completed": _TERMINAL_TYPES[1],
                    },
                )
            )
            .mappings()
            .one_or_none()
        )

    @staticmethod
    async def _rows(
        connection: AsyncConnection,
        parameters: Mapping[str, object],
        terminal: RowMapping,
        limit: int,
    ) -> list[RowMapping]:
        return list(
            (
                await connection.execute(
                    text(
                        "SELECT * FROM event_task_lineage "
                        "WHERE brain_id=:brain_id AND project_id=:project_id "
                        "AND repository_id=:repository_id "
                        "AND checkout_id IS :checkout_id AND task_id=:task_id "
                        "AND (occurred_at<:terminal_time OR "
                        "(occurred_at=:terminal_time AND event_id<=:terminal_id)) "
                        "ORDER BY occurred_at,event_id LIMIT :limit"
                    ),
                    {
                        **parameters,
                        "terminal_time": int(terminal["occurred_at"]),
                        "terminal_id": str(terminal["event_id"]),
                        "limit": limit,
                    },
                )
            )
            .mappings()
            .all()
        )


class SqliteMemoryConsolidationAccessPolicy:
    """Authorize canonical current write grants without observing task content."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local authorization store."""
        self._store = store

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        scope: MemoryScope,
        at: datetime,
    ) -> None:
        """Require an active write-capable grant covering the exact scope."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, actor_id, grant_id, scope, at)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error


class SqliteMemoryConsolidationReceiptQuery:
    """Read and authenticate committed content-free consolidation receipts."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local store."""
        self._store = store

    async def get(self, idempotency_key: str) -> ConsolidationResult | None:
        """Return and authenticate one content-free idempotency receipt."""
        key = _digest_bytes(idempotency_key, "idempotency_key")
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT result_json,result_sha256 FROM memory_consolidations "
                                "WHERE idempotency_key=:key"
                            ),
                            {"key": key},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        return None if row is None else _result(row, idempotency_key)


class SqliteMemoryConsolidationRepository:
    """Stage canonical memory mutation records on one owned SQL transaction."""

    def __init__(self, connection: AsyncConnection) -> None:
        """Bind a transaction-owned connection supplied only by the Unit of Work."""
        self._connection = connection

    async def get(self, idempotency_key: str) -> ConsolidationResult | None:
        """Read and authenticate a receipt inside the current transaction."""
        return await _existing_result(self._connection, idempotency_key)

    async def add(self, consolidation: ConsolidationCommit) -> None:
        """Stage snapshot, lineage, domain events, outbox, audit, and receipt."""
        expected = consolidation.result
        existing = await _existing_result(self._connection, consolidation.idempotency_key)
        if existing is not None:
            if existing != expected:
                _raise_conflict()
            return
        await _verify_commit_evidence(self._connection, consolidation)
        await _insert_consolidation(self._connection, consolidation, expected)
        for memory in consolidation.memories:
            await _insert_memory(self._connection, consolidation, memory)
        await _insert_rejections(self._connection, consolidation)
        await _insert_outbox(self._connection, consolidation, expected)
        await _insert_audit(self._connection, consolidation, expected)


class SqliteMemoryConsolidationUnitOfWorkFactory:
    """Create short exclusive SQLite memory mutation transactions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the single-writer store without opening a transaction."""
        self._store = store

    def __call__(self) -> MemoryConsolidationUnitOfWork:
        """Return one unopened Unit of Work."""
        return _SqliteMemoryConsolidationUnitOfWork(self._store)


class _SqliteMemoryConsolidationUnitOfWork:
    """Own lock, connection, transaction, authorization, and repository lifetime."""

    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.access: _SqliteConnectionMemoryConsolidationAccessPolicy
        self.repository: SqliteMemoryConsolidationRepository

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
        self.access = _SqliteConnectionMemoryConsolidationAccessPolicy(self._connection)
        self.repository = SqliteMemoryConsolidationRepository(self._connection)
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
        """Commit exactly once and map storage conflicts to stable domain errors."""
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


class _SqliteConnectionMemoryConsolidationAccessPolicy:
    """Reauthorize on the same transaction that commits canonical memories."""

    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        scope: MemoryScope,
        at: datetime,
    ) -> None:
        await _authorize(self._connection, actor_id, grant_id, scope, at)


async def _authorize(
    connection: AsyncConnection,
    actor_id: str,
    grant_id: str,
    scope: MemoryScope,
    at: datetime,
) -> None:
    count = (
        await connection.execute(
            text(
                "SELECT COUNT(*) FROM scope_grants g "
                "JOIN principals p ON p.id=g.principal_id "
                "JOIN brains b ON b.id=g.brain_id "
                "WHERE g.id=:grant AND g.principal_id=:actor AND g.brain_id=:brain "
                "AND g.role IN ('owner','admin','editor','worker') "
                "AND (g.project_id IS NULL OR g.project_id=:project) "
                "AND (g.repository_id IS NULL OR g.repository_id=:repository) "
                "AND p.status='active' AND b.status='active' "
                "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now)"
            ),
            {
                "grant": grant_id,
                "actor": actor_id,
                "brain": scope.brain_id,
                "project": scope.project_id,
                "repository": scope.repository_id,
                "now": _micros(at),
            },
        )
    ).scalar_one()
    if count != 1:
        raise MemoryAuthorizationError


def _scope_parameters(task_id: str, scope: MemoryScope) -> dict[str, object]:
    return {
        "brain_id": scope.brain_id,
        "project_id": scope.project_id,
        "repository_id": scope.repository_id,
        "checkout_id": scope.checkout_id,
        "task_id": task_id,
    }


def _task_evidence(
    row: RowMapping,
    raw: bytes,
    task_id: str,
    scope: MemoryScope,
) -> TaskEvidence:
    stored_digest = _bytes(row["canonical_event_sha256"])
    if hashlib.sha256(raw).digest() != stored_digest:
        raise MemoryIntegrityError
    document = _strict_object(raw)
    expected = {
        "id": str(row["event_id"]),
        "task_id": task_id,
        "brain_id": scope.brain_id,
        "project_id": scope.project_id,
        "repository_id": scope.repository_id,
        "checkout_id": scope.checkout_id,
        "type": str(row["event_type"]),
        "classification": str(row["classification"]),
        "retention_policy_id": str(row["retention_policy_id"]),
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise MemoryIntegrityError
    payload = _event_payload(document)
    payload_sha = hashlib.sha256(payload).hexdigest()
    if "data" in document and document.get("content_sha256") != payload_sha:
        raise MemoryIntegrityError
    return TaskEvidence(
        str(row["event_id"]),
        task_id,
        scope,
        str(row["event_type"]),
        datetime.fromtimestamp(int(row["occurred_at"]) / 1_000_000, tz=UTC),
        str(row["classification"]),
        str(row["retention_policy_id"]),
        payload,
        payload_sha,
        stored_digest.hex(),
    )


def _event_payload(document: Mapping[str, JsonValue]) -> bytes:
    has_data = "data" in document
    has_reference = "dataref" in document
    if has_data == has_reference:
        raise MemoryIntegrityError
    if has_data:
        return _canonical_json(document["data"])
    reference = document["dataref"]
    if not isinstance(reference, dict):
        raise MemoryIntegrityError
    if set(reference) != {"uri", "content_sha256", "size_bytes"}:
        raise MemoryIntegrityError
    uri = reference.get("uri")
    content_sha = reference.get("content_sha256")
    size = reference.get("size_bytes")
    if (
        not isinstance(uri, str)
        or not isinstance(content_sha, str)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or len(content_sha) != _DIGEST_BYTES * 2
        or any(character not in "0123456789abcdef" for character in content_sha)
        or set(content_sha) == {"0"}
        or uri != f"cas://sha256/{content_sha}"
        or document.get("content_sha256") != content_sha
        or size < 1
    ):
        raise MemoryIntegrityError
    return _canonical_json(
        {"dataref": {"content_sha256": content_sha, "size_bytes": size, "uri": uri}}
    )


async def _existing_result(
    connection: AsyncConnection,
    idempotency_key: str,
) -> ConsolidationResult | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT result_json,result_sha256 FROM memory_consolidations "
                    "WHERE idempotency_key=:key"
                ),
                {"key": bytes.fromhex(idempotency_key)},
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _result(row, idempotency_key)


async def _verify_commit_evidence(
    connection: AsyncConnection,
    consolidation: ConsolidationCommit,
) -> None:
    parameters = _scope_parameters(consolidation.task_id, consolidation.scope)
    terminal = (
        (
            await connection.execute(
                text(
                    "SELECT occurred_at,event_type FROM event_task_lineage "
                    "WHERE event_id=:terminal AND brain_id=:brain_id AND project_id=:project_id "
                    "AND repository_id=:repository_id AND checkout_id IS :checkout_id "
                    "AND task_id=:task_id"
                ),
                {**parameters, "terminal": consolidation.source_terminal_event_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if terminal is None or str(terminal["event_type"]) not in _TERMINAL_TYPES:
        raise MemoryIntegrityError
    lineage = list(
        (
            await connection.execute(
                text(
                    "SELECT event_id,event_type,canonical_event_sha256 FROM event_task_lineage "
                    "WHERE brain_id=:brain_id AND project_id=:project_id "
                    "AND repository_id=:repository_id AND checkout_id IS :checkout_id "
                    "AND task_id=:task_id AND (occurred_at<:terminal_time OR "
                    "(occurred_at=:terminal_time AND event_id<=:terminal_id)) "
                    "ORDER BY occurred_at,event_id"
                ),
                {
                    **parameters,
                    "terminal_time": int(terminal["occurred_at"]),
                    "terminal_id": consolidation.source_terminal_event_id,
                },
            )
        )
        .mappings()
        .all()
    )
    watermark_document = [
        {
            "canonical_event_sha256": _bytes(row["canonical_event_sha256"]).hex(),
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
        }
        for row in lineage
    ]
    if hashlib.sha256(_canonical_json(watermark_document)).hexdigest() != (
        consolidation.evidence_watermark_sha256
    ):
        raise MemoryIntegrityError
    event_ids = {event_id for memory in consolidation.memories for event_id in memory.evidence_ids}
    event_ids.add(consolidation.source_terminal_event_id)
    for event_id in sorted(event_ids):
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT canonical_event_sha256 FROM event_task_lineage "
                        "WHERE event_id=:event_id AND brain_id=:brain_id "
                        "AND project_id=:project_id AND repository_id=:repository_id "
                        "AND checkout_id IS :checkout_id AND task_id=:task_id"
                    ),
                    {**parameters, "event_id": event_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None or len(_bytes(row["canonical_event_sha256"])) != _DIGEST_BYTES:
            raise MemoryIntegrityError


async def _insert_consolidation(
    connection: AsyncConnection,
    item: ConsolidationCommit,
    result: ConsolidationResult,
) -> None:
    scope = item.scope
    extractor = item.extractor
    now = _micros(item.completed_at)
    result_json = _result_json(result)
    await connection.execute(
        text(
            "INSERT INTO memory_consolidations "
            "(idempotency_key,operation_id,brain_id,actor_id,grant_id,correlation_id,"
            "causation_id,task_id,project_id,"
            "repository_id,checkout_id,source_terminal_event_id,evidence_watermark_sha256,"
            "extractor_input_sha256,extractor_id,extractor_version,model_id,model_revision,"
            "output_schema,extractor_fingerprint,promotion_policy_version,classification,"
            "retention_policy_id,promoted,rejected,result_json,result_sha256,requested_at,completed_at,"
            "created_at,updated_at,schema_version) VALUES "
            "(:key,:operation,:brain,:actor,:grant,:correlation,:causation,:task,:project,"
            ":repository,:checkout,"
            ":terminal,:watermark,:input,:extractor_id,:extractor_version,:model_id,"
            ":model_revision,:output_schema,:extractor_fingerprint,:policy,:classification,"
            ":retention,:promoted,:rejected,:result_json,:result_sha,:requested,:now,:now,:now,1)"
        ),
        {
            "key": bytes.fromhex(item.idempotency_key),
            "operation": item.operation_id,
            "brain": scope.brain_id,
            "actor": item.actor_id,
            "grant": item.grant_id,
            "correlation": item.correlation_id,
            "causation": item.causation_id,
            "task": item.task_id,
            "project": scope.project_id,
            "repository": scope.repository_id,
            "checkout": scope.checkout_id,
            "terminal": item.source_terminal_event_id,
            "watermark": bytes.fromhex(item.evidence_watermark_sha256),
            "input": bytes.fromhex(item.extractor_input_sha256),
            "extractor_id": extractor.extractor_id,
            "extractor_version": extractor.extractor_version,
            "model_id": extractor.model_id,
            "model_revision": extractor.model_revision,
            "output_schema": extractor.output_schema,
            "extractor_fingerprint": bytes.fromhex(extractor.fingerprint),
            "policy": item.promotion_policy_version,
            "classification": item.classification,
            "retention": item.retention_policy_id,
            "promoted": result.promoted,
            "rejected": result.rejected,
            "result_json": result_json,
            "result_sha": bytes.fromhex(result.result_sha256),
            "requested": _micros(item.requested_at),
            "now": now,
        },
    )


async def _insert_memory(
    connection: AsyncConnection,
    commit: ConsolidationCommit,
    memory: Memory,
) -> None:
    now = _micros(memory.recorded_from)
    scope_json = _canonical_json(dict(memory.scope.canonical)).decode()
    confidence_json = _canonical_json(dict(memory.confidence.canonical)).decode()
    await connection.execute(
        text(
            "INSERT INTO memories "
            "(id,brain_id,memory_class,project_id,repository_id,checkout_id,scope_json,status,"
            "current_revision,valid_from,valid_to,recorded_from,recorded_to,confidence_json,"
            "retention_policy_id,classification,aggregate_version,source_task_id,"
            "extractor_fingerprint,content_hash,consolidation_key,created_at,updated_at,"
            "schema_version) VALUES "
            "(:id,:brain,:class,:project,:repository,:checkout,:scope,'active',1,:valid_from,"
            ":valid_to,:recorded_from,NULL,:confidence,:retention,:classification,1,:task,"
            ":extractor,:content,:consolidation,:now,:now,1)"
        ),
        {
            "id": memory.memory_id,
            "brain": memory.scope.brain_id,
            "class": memory.memory_class.value,
            "project": memory.scope.project_id,
            "repository": memory.scope.repository_id,
            "checkout": memory.scope.checkout_id,
            "scope": scope_json,
            "valid_from": _micros(memory.valid_from),
            "valid_to": None if memory.valid_to is None else _micros(memory.valid_to),
            "recorded_from": now,
            "confidence": confidence_json,
            "retention": memory.retention_policy_id,
            "classification": memory.classification,
            "task": memory.source_task_id,
            "extractor": bytes.fromhex(memory.extractor.fingerprint),
            "content": bytes.fromhex(memory.content_sha256),
            "consolidation": bytes.fromhex(commit.idempotency_key),
            "now": now,
        },
    )
    domain_event_id = str(uuid7())
    revision_id = str(uuid7())
    content_json = _canonical_json({"statement": memory.statement}).decode()
    provenance_json = _memory_provenance_json(memory)
    await connection.execute(
        text(
            "INSERT INTO memory_revisions "
            "(id,memory_id,revision,content_hash,content_ref,content_json,provenance_json,"
            "created_by_event,created_at,schema_version) VALUES "
            "(:id,:memory,1,:content,:ref,:content_json,:provenance,:created_by,:now,1)"
        ),
        {
            "id": revision_id,
            "memory": memory.memory_id,
            "content": bytes.fromhex(memory.content_sha256),
            "ref": f"sqlite://memory-revisions/{revision_id}",
            "content_json": content_json,
            "provenance": provenance_json,
            "created_by": memory.created_by_event,
            "now": now,
        },
    )
    await _insert_memory_domain_event(
        connection,
        commit,
        memory,
        domain_event_id,
    )
    for evidence_id in memory.evidence_ids:
        digest = (
            await connection.execute(
                text(
                    "SELECT canonical_event_sha256 FROM event_task_lineage WHERE event_id=:event_id"
                ),
                {"event_id": evidence_id},
            )
        ).scalar_one()
        await connection.execute(
            text(
                "INSERT INTO memory_evidence "
                "(memory_id,event_id,relation,canonical_event_sha256,added_by_event,created_at,"
                "schema_version) VALUES (:memory,:event,'supports',:digest,:added_by,:now,1)"
            ),
            {
                "memory": memory.memory_id,
                "event": evidence_id,
                "digest": digest,
                "added_by": domain_event_id,
                "now": now,
            },
        )


async def _insert_memory_domain_event(
    connection: AsyncConnection,
    commit: ConsolidationCommit,
    memory: Memory,
    event_id: str,
) -> None:
    now = _micros(memory.recorded_from)
    content_json = _canonical_json({"statement": memory.statement}).decode()
    provenance_json = _memory_provenance_json(memory)
    event_json = _canonical_json(
        {
            "classification": memory.classification,
            "confidence": dict(memory.confidence.canonical),
            "content": cast("JsonValue", json.loads(content_json)),
            "content_sha256": memory.content_sha256,
            "evidence_ids": list(memory.evidence_ids),
            "memory_class": memory.memory_class.value,
            "memory_id": memory.memory_id,
            "provenance": cast("JsonValue", json.loads(provenance_json)),
            "scope": dict(memory.scope.canonical),
            "status": memory.status.value,
        }
    ).decode()
    payload = event_json.encode()
    source_digest = hashlib.sha256(
        _canonical_json(
            {
                "content_sha256": memory.content_sha256,
                "created_by_event": memory.created_by_event,
                "memory_id": memory.memory_id,
                "provenance_sha256": memory.provenance.provenance_sha256,
            }
        )
    ).digest()
    await connection.execute(
        text(
            "INSERT INTO domain_events "
            "(event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,"
            "payload_json,payload_hash,source_digest,missing_dependency,occurred_at,recorded_at,"
            "schema_version,aggregate_type,aggregate_id,aggregate_version,event_type,event_json,"
            "correlation_id,causation_id) VALUES "
            "(:event_id,:brain,'graph',:stable,'memory',:target,:payload,:payload_hash,"
            ":source_digest,NULL,:now,:now,2,'memory',:memory,1,'MemoryProjected',"
            ":event_json,:correlation,:causation)"
        ),
        {
            "event_id": event_id,
            "brain": memory.scope.brain_id,
            "stable": memory.memory_id,
            "target": hashlib.sha256(memory.memory_id.encode()).digest(),
            "payload": event_json,
            "payload_hash": hashlib.sha256(payload).digest(),
            "source_digest": source_digest,
            "now": now,
            "memory": memory.memory_id,
            "event_json": event_json,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
        },
    )


async def _insert_rejections(
    connection: AsyncConnection,
    commit: ConsolidationCommit,
) -> None:
    now = _micros(commit.completed_at)
    for rejection in commit.rejections:
        await connection.execute(
            text(
                "INSERT INTO memory_candidate_rejections "
                "(consolidation_key,candidate_key_sha256,memory_class,content_hash,reason_code,"
                "created_at,schema_version) VALUES "
                "(:key,:candidate,:class,:content,:reason,:now,1)"
            ),
            {
                "key": bytes.fromhex(commit.idempotency_key),
                "candidate": bytes.fromhex(rejection.candidate_key_sha256),
                "class": rejection.memory_class.value,
                "content": bytes.fromhex(rejection.content_sha256),
                "reason": rejection.reason_code,
                "now": now,
            },
        )


async def _insert_outbox(
    connection: AsyncConnection,
    commit: ConsolidationCommit,
    result: ConsolidationResult,
) -> None:
    now = _micros(commit.completed_at)
    payload = _canonical_json(
        {
            "brain_id": commit.scope.brain_id,
            "memory_ids": list(result.memory_ids),
            "result_sha256": result.result_sha256,
            "schema_version": 1,
            "task_id": commit.task_id,
        }
    ).decode()
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) VALUES "
            "(:id,:source,'memory.consolidated.v1',:key,:payload,'ready',100,:now,0,NULL,NULL,"
            "NULL,:digest,NULL,:now,1)"
        ),
        {
            "id": str(uuid7()),
            "source": commit.source_terminal_event_id,
            "key": commit.idempotency_key,
            "payload": payload,
            "now": now,
            "digest": hashlib.sha256(payload.encode()).digest(),
        },
    )


async def _insert_audit(
    connection: AsyncConnection,
    commit: ConsolidationCommit,
    result: ConsolidationResult,
) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = _bytes(previous) if previous is not None else bytes(32)
    now = _micros(commit.completed_at)
    fact = _canonical_json(
        {
            "action": "memory.task_consolidated",
            "actor_id": commit.actor_id,
            "brain_id": commit.scope.brain_id,
            "idempotency_key": commit.idempotency_key,
            "result_sha256": result.result_sha256,
            "task_id": commit.task_id,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,'memory.task_consolidated',:target,:key,:before,:after,:previous,"
            ":event_hash,:now,1)"
        ),
        {
            "brain": commit.scope.brain_id,
            "actor": commit.actor_id,
            "target": f"task:{commit.task_id}",
            "key": f"memory.consolidation:{commit.idempotency_key}",
            "before": bytes(32),
            "after": bytes.fromhex(result.result_sha256),
            "previous": previous_hash,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "now": now,
        },
    )


def _memory_provenance_json(memory: Memory) -> str:
    return _canonical_json(dict(memory.provenance.canonical)).decode()


def _result(row: RowMapping, idempotency_key: str) -> ConsolidationResult:
    document = _strict_object(str(row["result_json"]).encode())
    try:
        memory_ids = document["memory_ids"]
        if not isinstance(memory_ids, list) or not all(
            isinstance(item, str) for item in memory_ids
        ):
            raise MemoryIntegrityError
        result = ConsolidationResult(
            idempotency_key,
            _string(document, "task_id"),
            _string(document, "evidence_watermark_sha256"),
            _string(document, "extractor_fingerprint"),
            tuple(cast("list[str]", memory_ids)),
            _integer(document, "promoted"),
            _integer(document, "rejected"),
            _string(document, "result_sha256"),
        )
    except (KeyError, MemoryValidationError) as error:
        raise MemoryIntegrityError from error
    if _bytes(row["result_sha256"]).hex() != result.result_sha256:
        raise MemoryIntegrityError
    if _result_json(result) != str(row["result_json"]):
        raise MemoryIntegrityError
    return result


def _result_json(result: ConsolidationResult) -> str:
    return _canonical_json(
        {
            "evidence_watermark_sha256": result.evidence_watermark_sha256,
            "extractor_fingerprint": result.extractor_fingerprint,
            "memory_ids": list(result.memory_ids),
            "promoted": result.promoted,
            "rejected": result.rejected,
            "result_sha256": result.result_sha256,
            "task_id": result.task_id,
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
        parsed = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MemoryIntegrityError from error
    if not isinstance(parsed, dict):
        raise MemoryIntegrityError
    return cast("dict[str, JsonValue]", parsed)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError, OverflowError) as error:
        raise MemoryIntegrityError from error


def _string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        raise MemoryIntegrityError
    return value


def _integer(document: Mapping[str, JsonValue], field: str) -> int:
    value = document[field]
    if not isinstance(value, int) or isinstance(value, bool):
        raise MemoryIntegrityError
    return value


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise MemoryIntegrityError


def _digest_bytes(value: str, field: str) -> bytes:
    if (
        len(value) != _DIGEST_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
        or set(value) == {"0"}
    ):
        raise MemoryValidationError.single(field, "invalid_digest")
    return bytes.fromhex(value)


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _raise_conflict() -> Never:
    raise MemoryConflictError


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
