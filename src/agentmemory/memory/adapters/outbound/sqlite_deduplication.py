"""SQLite authority, embedding candidate search, and atomic MEM-003 merge adapter."""

from __future__ import annotations

import asyncio
import hashlib
import json
import unicodedata
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, Self, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.memory.domain.consolidation import MemoryClass, MemoryScope
from agentmemory.memory.domain.deduplication import (
    DeduplicationCommit,
    DeduplicationMode,
    DeduplicationResult,
    MemoryDeduplicationProfile,
    SemanticMemoryCandidate,
    canonical_subject,
    cosine_similarity_basis_points,
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
    from sqlalchemy.sql.elements import TextClause

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.dependency_ports import EmbeddingProviderPort

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
_MAX_CANDIDATES = 256
_DIGEST_BYTES = 32

_PROFILE_COLUMNS = """
m.id,m.brain_id,m.memory_class,m.project_id,m.repository_id,m.checkout_id,
m.valid_from,m.valid_to,m.recorded_from,m.classification,m.retention_policy_id,
m.aggregate_version,m.content_hash,r.content_json,c.promotion_policy_version
"""


class SqliteMemoryDeduplicationRepository:
    """Read canonical profiles or stage a merge on an owned connection."""

    def __init__(
        self,
        store: SqliteCoreStore,
        connection: AsyncConnection | None = None,
    ) -> None:
        """Bind the local store and optionally one transaction-owned connection."""
        self._store = store
        self._connection = connection

    async def get_result(self, idempotency_key: str) -> DeduplicationResult | None:
        """Return one strict canonical receipt without content."""
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
    ) -> MemoryDeduplicationProfile | None:
        """Authorize and load one active target in the same SQL statement."""
        parameters = {
            "memory": memory_id,
            "brain": brain_id,
            "actor": actor_id,
            "grant": grant_id,
            "at": _micros(at),
        }
        query = text(
            f"SELECT {_PROFILE_COLUMNS} FROM memories m "  # noqa: S608  # nosec B608 -- fixed projection.
            "JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision "
            "JOIN memory_consolidations c ON c.idempotency_key=m.consolidation_key "
            "JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id "
            "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor "
            "AND g.brain_id=m.brain_id "
            " AND (g.project_id IS NULL OR g.project_id=m.project_id) "
            " AND (g.repository_id IS NULL OR g.repository_id=m.repository_id) "
            "JOIN principals p ON p.id=g.principal_id AND p.status='active' "
            "JOIN brains b ON b.id=g.brain_id AND b.status='active' "
            "WHERE m.id=:memory AND m.brain_id=:brain AND m.status='active' "
            "AND l.recall_state='active' AND (l.expires_at IS NULL OR l.expires_at>:at) "
            "AND g.role IN ('owner','admin','editor','worker') AND g.valid_from<=:at "
            "AND (g.valid_to IS NULL OR g.valid_to>:at) LIMIT 1"
        )
        try:
            if self._connection is not None:
                return await _one_profile(self._connection, query, parameters)
            async with self._store.engine.connect() as connection:
                return await _one_profile(connection, query, parameters)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def find_exact(
        self,
        target: MemoryDeduplicationProfile,
        limit: int,
    ) -> tuple[MemoryDeduplicationProfile, ...]:
        """Find exact active content under identical retention/classification."""
        _validate_limit(limit)
        query = text(
            f"SELECT {_PROFILE_COLUMNS} FROM memories m "  # noqa: S608  # nosec B608 -- fixed projection.
            "JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision "
            "JOIN memory_consolidations c ON c.idempotency_key=m.consolidation_key "
            "JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id "
            "WHERE m.brain_id=:brain AND m.status='active' AND m.id<>:memory "
            "AND l.recall_state='active' "
            "AND m.content_hash=:content AND m.classification=:classification "
            "AND m.retention_policy_id=:retention ORDER BY m.recorded_from,m.id LIMIT :limit"
        )
        parameters = {
            "brain": target.scope.brain_id,
            "memory": target.memory_id,
            "content": bytes.fromhex(target.content_sha256),
            "classification": target.classification,
            "retention": target.retention_policy_id,
            "limit": limit + 1,
        }
        try:
            if self._connection is not None:
                return await _profiles(self._connection, query, parameters, limit)
            async with self._store.engine.connect() as connection:
                return await _profiles(connection, query, parameters, limit)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error

    async def add(self, commit: DeduplicationCommit) -> None:
        """Stage receipt first, then CAS statuses, redirects, evidence, event, outbox, and audit."""
        if self._connection is None:
            raise MemoryIntegrityError
        existing = await self.get_result(commit.result.idempotency_key)
        if existing is not None:
            if existing != commit.result:
                raise MemoryConflictError
            return
        await _verify_profiles(self._connection, commit)
        await _insert_operation(self._connection, commit)
        if commit.plan is not None:
            await _apply_merge(self._connection, commit)
            await _insert_merge_event(self._connection, commit)
            await _insert_outbox(self._connection, commit)
        await _insert_audit(self._connection, commit)


class SqliteSemanticMemoryCandidateFinder:
    """Use a pinned local embedding space only to rank prefiltered profiles."""

    def __init__(self, store: SqliteCoreStore, embeddings: EmbeddingProviderPort) -> None:
        """Bind canonical SQL and one adapter-selected embedding capability."""
        self._store = store
        self._embeddings = embeddings

    async def find(
        self,
        target: MemoryDeduplicationProfile,
        limit: int,
    ) -> tuple[SemanticMemoryCandidate, ...]:
        """Return deterministic scores; compatibility remains a domain decision."""
        _validate_limit(limit)
        query = text(
            f"SELECT {_PROFILE_COLUMNS} FROM memories m "  # noqa: S608  # nosec B608 -- fixed projection.
            "JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision "
            "JOIN memory_consolidations c ON c.idempotency_key=m.consolidation_key "
            "JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id "
            "WHERE m.brain_id=:brain AND m.status='active' AND m.id<>:memory "
            "AND l.recall_state='active' "
            "AND m.memory_class=:class AND m.project_id=:project AND m.repository_id=:repository "
            "AND m.checkout_id IS :checkout AND m.valid_from=:valid_from "
            "AND m.valid_to IS :valid_to "
            "AND c.promotion_policy_version=:promotion AND m.classification=:classification "
            "AND m.retention_policy_id=:retention ORDER BY m.recorded_from,m.id LIMIT :scan_limit"
        )
        parameters = {
            "brain": target.scope.brain_id,
            "memory": target.memory_id,
            "class": target.memory_class.value,
            "project": target.scope.project_id,
            "repository": target.scope.repository_id,
            "checkout": target.scope.checkout_id,
            "valid_from": _micros(target.valid_from),
            "valid_to": None if target.valid_to is None else _micros(target.valid_to),
            "promotion": target.promotion_policy_version,
            "classification": target.classification,
            "retention": target.retention_policy_id,
            "scan_limit": _MAX_CANDIDATES + 1,
        }
        try:
            async with self._store.engine.connect() as connection:
                target_statement = await _statement(connection, target.memory_id)
                rows = list((await connection.execute(query, parameters)).mappings().all())
                if len(rows) > _MAX_CANDIDATES:
                    field = "candidates"
                    raise MemoryValidationError.single(field, "count_exceeded")
                profile_items: list[tuple[MemoryDeduplicationProfile, str]] = [
                    (await _profile(connection, row), _statement_from_row(row)) for row in rows
                ]
                profiles = tuple(profile_items)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        query_vector = await self._embeddings.embed_query(target.memory_id, target_statement)
        document_vectors = await asyncio.gather(
            *(
                self._embeddings.embed_document(profile.memory_id, statement)
                for profile, statement in profiles
            )
        )
        candidates: list[SemanticMemoryCandidate] = []
        for (profile, _), vector in zip(profiles, document_vectors, strict=True):
            if (
                vector.content_id != profile.memory_id
                or vector.model_id != query_vector.model_id
                or vector.model_revision != query_vector.model_revision
            ):
                raise MemoryIntegrityError
            candidates.append(
                SemanticMemoryCandidate(
                    profile,
                    cosine_similarity_basis_points(query_vector.values, vector.values),
                )
            )
        return tuple(
            sorted(
                candidates, key=lambda item: (-item.similarity_basis_points, item.profile.memory_id)
            )[:limit]
        )


class SqliteMemoryDeduplicationUnitOfWorkFactory:
    """Create serialized SQLite MEM-003 transactions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical SQLite store without opening a transaction."""
        self._store = store

    def __call__(self) -> _SqliteMemoryDeduplicationUnitOfWork:
        """Return one unopened serialized Unit of Work."""
        return _SqliteMemoryDeduplicationUnitOfWork(self._store)


class _SqliteMemoryDeduplicationUnitOfWork:
    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.repository: SqliteMemoryDeduplicationRepository

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
        self.repository = SqliteMemoryDeduplicationRepository(self._store, self._connection)
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


async def _one_profile(
    connection: AsyncConnection,
    query: TextClause,
    parameters: Mapping[str, object],
) -> MemoryDeduplicationProfile | None:
    row = (await connection.execute(query, parameters)).mappings().one_or_none()
    return None if row is None else await _profile(connection, row)


async def _profiles(
    connection: AsyncConnection,
    query: TextClause,
    parameters: Mapping[str, object],
    limit: int,
) -> tuple[MemoryDeduplicationProfile, ...]:
    rows = list((await connection.execute(query, parameters)).mappings().all())
    if len(rows) > limit:
        field = "candidates"
        raise MemoryValidationError.single(field, "count_exceeded")
    return tuple([await _profile(connection, row) for row in rows])


async def _profile(connection: AsyncConnection, row: RowMapping) -> MemoryDeduplicationProfile:
    statement = _statement_from_row(row)
    memory_id = str(row["id"])
    evidence = {
        str(item)
        for item in (
            await connection.execute(
                text(
                    "SELECT event_id FROM memory_evidence WHERE memory_id=:memory "
                    "UNION SELECT event_id FROM memory_merge_evidence "
                    "WHERE survivor_memory_id=:memory"
                ),
                {"memory": memory_id},
            )
        ).scalars()
    }
    content = _bytes(row["content_hash"]).hex()
    scope = MemoryScope(
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        None if row["checkout_id"] is None else str(row["checkout_id"]),
    )
    valid_from = _time(row["valid_from"])
    valid_to = None if row["valid_to"] is None else _time(row["valid_to"])
    expected = hashlib.sha256(
        _canonical_json(
            {
                "memory_class": str(row["memory_class"]),
                "scope": dict(scope.canonical),
                "statement": statement,
                "valid_from": _format_time(valid_from),
                "valid_to": None if valid_to is None else _format_time(valid_to),
            }
        )
    ).hexdigest()
    if content != expected or not evidence:
        raise MemoryIntegrityError
    subject, polarity = canonical_subject(statement)
    return MemoryDeduplicationProfile(
        memory_id,
        MemoryClass(str(row["memory_class"])),
        subject,
        scope,
        valid_from,
        valid_to,
        polarity,
        str(row["promotion_policy_version"]),
        "memory-compatibility.v1",
        content,
        str(row["classification"]),
        str(row["retention_policy_id"]),
        tuple(sorted(evidence)),
        _time(row["recorded_from"]),
        _integer(row["aggregate_version"]),
    )


def _statement_from_row(row: RowMapping) -> str:
    document = _strict_object(str(row["content_json"]).encode())
    if set(document) != {"statement"} or not isinstance(document["statement"], str):
        raise MemoryIntegrityError
    statement = document["statement"]
    if not statement or statement != unicodedata.normalize("NFC", statement).strip():
        raise MemoryIntegrityError
    return statement


async def _statement(connection: AsyncConnection, memory_id: str) -> str:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT r.content_json FROM memories m JOIN memory_revisions r "
                    "ON r.memory_id=m.id AND r.revision=m.current_revision WHERE m.id=:memory"
                ),
                {"memory": memory_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise MemoryIntegrityError
    return _statement_from_row(row)


async def _verify_profiles(connection: AsyncConnection, commit: DeduplicationCommit) -> None:
    profiles = (
        (commit.target,) if commit.plan is None else (commit.plan.survivor, *commit.plan.merged)
    )
    for expected in profiles:
        row = (
            (
                await connection.execute(
                    text(
                        f"SELECT {_PROFILE_COLUMNS} FROM memories m "  # noqa: S608  # nosec B608 -- fixed projection.
                        "JOIN memory_revisions r ON r.memory_id=m.id "
                        "AND r.revision=m.current_revision "
                        "JOIN memory_consolidations c ON c.idempotency_key=m.consolidation_key "
                        "JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id "
                        "WHERE m.id=:memory AND m.brain_id=:brain AND m.status='active' "
                        "AND l.recall_state='active'"
                    ),
                    {"memory": expected.memory_id, "brain": commit.brain_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None or await _profile(connection, row) != expected:
            raise MemoryConflictError


async def _insert_operation(connection: AsyncConnection, commit: DeduplicationCommit) -> None:
    result_json = _result_json(commit.result)
    await connection.execute(
        text(
            "INSERT INTO memory_deduplication_operations "
            "(idempotency_key,operation_id,requested_memory_id,survivor_memory_id,brain_id,"
            "actor_id,grant_id,correlation_id,causation_id,mode,policy_version,result_json,"
            "result_sha256,requested_at,completed_at,schema_version) VALUES "
            "(:key,:operation,:requested,:survivor,:brain,:actor,:grant,:correlation,:causation,"
            ":mode,:policy,:result,:digest,:requested_at,:completed_at,1)"
        ),
        {
            "key": bytes.fromhex(commit.result.idempotency_key),
            "operation": commit.operation_id,
            "requested": commit.target.memory_id,
            "survivor": commit.result.survivor_memory_id,
            "brain": commit.brain_id,
            "actor": commit.actor_id,
            "grant": commit.grant_id,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
            "mode": None if commit.result.mode is None else commit.result.mode.value,
            "policy": commit.result.policy_version,
            "result": result_json,
            "digest": bytes.fromhex(commit.result.result_sha256),
            "requested_at": _micros(commit.requested_at),
            "completed_at": _micros(commit.completed_at),
        },
    )


async def _apply_merge(connection: AsyncConnection, commit: DeduplicationCommit) -> None:
    plan = commit.plan
    if plan is None:
        raise MemoryIntegrityError
    now = _micros(commit.completed_at)
    updated = await connection.execute(
        text(
            "UPDATE memories SET aggregate_version=aggregate_version+1,updated_at=:now "
            "WHERE id=:memory AND status='active' AND aggregate_version=:version"
        ),
        {"now": now, "memory": plan.survivor.memory_id, "version": plan.survivor.aggregate_version},
    )
    if updated.rowcount != 1:
        raise MemoryConflictError
    for source in plan.merged:
        changed = await connection.execute(
            text(
                "UPDATE memories SET status='merged',recorded_to=:now,aggregate_version="
                "aggregate_version+1,updated_at=:now WHERE id=:memory AND status='active' "
                "AND aggregate_version=:version"
            ),
            {"now": now, "memory": source.memory_id, "version": source.aggregate_version},
        )
        if changed.rowcount != 1:
            raise MemoryConflictError
        await connection.execute(
            text(
                "INSERT INTO memory_redirects "
                "(source_memory_id,survivor_memory_id,operation_id,mode,policy_version,"
                "created_at,schema_version) "
                "VALUES (:source,:survivor,:operation,:mode,:policy,:now,1)"
            ),
            {
                "source": source.memory_id,
                "survivor": plan.survivor.memory_id,
                "operation": commit.operation_id,
                "mode": plan.mode.value,
                "policy": plan.policy_version,
                "now": now,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO memory_merge_evidence "
                "(survivor_memory_id,source_memory_id,event_id,canonical_event_sha256,"
                "operation_id,created_at,schema_version) "
                "SELECT :survivor,:source,event_id,canonical_event_sha256,:operation,:now,1 "
                "FROM memory_evidence WHERE memory_id=:source"
            ),
            {
                "survivor": plan.survivor.memory_id,
                "source": source.memory_id,
                "operation": commit.operation_id,
                "now": now,
            },
        )
        await connection.execute(
            text(
                "INSERT OR IGNORE INTO memory_merge_evidence "
                "(survivor_memory_id,source_memory_id,event_id,canonical_event_sha256,"
                "operation_id,created_at,schema_version) "
                "SELECT :survivor,source_memory_id,event_id,canonical_event_sha256,"
                ":operation,:now,1 "
                "FROM memory_merge_evidence WHERE survivor_memory_id=:source"
            ),
            {
                "survivor": plan.survivor.memory_id,
                "source": source.memory_id,
                "operation": commit.operation_id,
                "now": now,
            },
        )


async def _insert_merge_event(connection: AsyncConnection, commit: DeduplicationCommit) -> None:
    plan = commit.plan
    if plan is None:
        raise MemoryIntegrityError
    now = _micros(commit.completed_at)
    event_json = _canonical_json(
        {
            "evidence_ids": list(plan.evidence_ids),
            "memory_id": plan.survivor.memory_id,
            "merge_mode": plan.mode.value,
            "merged_memory_ids": list(plan.source_ids),
            "policy_version": plan.policy_version,
            "result_sha256": commit.result.result_sha256,
            "status": "active",
        }
    ).decode()
    payload = event_json.encode()
    await connection.execute(
        text(
            "INSERT INTO domain_events "
            "(event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,payload_json,"
            "payload_hash,source_digest,missing_dependency,occurred_at,recorded_at,schema_version,"
            "aggregate_type,aggregate_id,aggregate_version,event_type,event_json,"
            "correlation_id,causation_id) "
            "VALUES (:event,:brain,'graph',:stable,'memory',:target,:payload,:payload_hash,"
            ":source_digest,NULL,:now,:now,3,'memory',:aggregate,:version,'MemoryMerged',:payload,"
            ":correlation,:causation)"
        ),
        {
            "event": commit.operation_id,
            "brain": commit.brain_id,
            "stable": plan.survivor.memory_id,
            "target": hashlib.sha256(plan.survivor.memory_id.encode()).digest(),
            "payload": event_json,
            "payload_hash": hashlib.sha256(payload).digest(),
            "source_digest": hashlib.sha256(
                bytes.fromhex(commit.result.result_sha256) + payload
            ).digest(),
            "now": now,
            "aggregate": plan.survivor.memory_id,
            "version": plan.survivor.aggregate_version + 1,
            "correlation": commit.correlation_id,
            "causation": commit.causation_id,
        },
    )


async def _insert_outbox(connection: AsyncConnection, commit: DeduplicationCommit) -> None:
    payload = _canonical_json(
        {
            "brain_id": commit.brain_id,
            "merged_memory_ids": list(commit.result.merged_memory_ids),
            "result_sha256": commit.result.result_sha256,
            "schema_version": 1,
            "survivor_memory_id": commit.result.survivor_memory_id,
        }
    ).decode()
    now = _micros(commit.completed_at)
    source_event_id = (
        await connection.execute(
            text(
                "SELECT created_by_event FROM memory_revisions WHERE memory_id=:memory "
                "AND revision=1"
            ),
            {"memory": commit.result.survivor_memory_id},
        )
    ).scalar_one()
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) "
            "VALUES (:id,:source,'memory.merged.v1',:key,:payload,'ready',100,:now,0,"
            "NULL,NULL,NULL,"
            ":digest,NULL,:now,1)"
        ),
        {
            "id": str(uuid7()),
            "source": str(source_event_id),
            "key": commit.result.idempotency_key,
            "payload": payload,
            "now": now,
            "digest": hashlib.sha256(payload.encode()).digest(),
        },
    )


async def _insert_audit(connection: AsyncConnection, commit: DeduplicationCommit) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = bytes(_bytes(previous)) if previous is not None else bytes(_DIGEST_BYTES)
    fact = _canonical_json(
        {
            "action": "memory.deduplicated",
            "actor_id": commit.actor_id,
            "brain_id": commit.brain_id,
            "idempotency_key": commit.result.idempotency_key,
            "result_sha256": commit.result.result_sha256,
            "target_memory_id": commit.target.memory_id,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events (brain_id,actor_id,action,target_ref,idempotency_key,"
            "before_hash,"
            "after_hash,previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,'memory.deduplicated',:target,:key,:before,:after,:previous,:event,:now,1)"
        ),
        {
            "brain": commit.brain_id,
            "actor": commit.actor_id,
            "target": f"memory:{commit.target.memory_id}",
            "key": f"memory.deduplication:{commit.result.idempotency_key}",
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
) -> DeduplicationResult | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT result_json,result_sha256 FROM memory_deduplication_operations "
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
        mode_value = document["mode"]
        mode = None if mode_value is None else DeduplicationMode(str(mode_value))
        merged = _string_list(document, "merged_memory_ids")
        evidence = _string_list(document, "evidence_ids")
        result = DeduplicationResult(
            idempotency_key,
            _string(document, "requested_memory_id"),
            _string(document, "survivor_memory_id"),
            merged,
            evidence,
            mode,
            _string(document, "policy_version"),
            _string(document, "result_sha256"),
        )
    except (KeyError, ValueError, MemoryValidationError) as error:
        raise MemoryIntegrityError from error
    if (
        _result_json(result) != str(row["result_json"])
        or _bytes(row["result_sha256"]).hex() != result.result_sha256
    ):
        raise MemoryIntegrityError
    return result


def _result_json(result: DeduplicationResult) -> str:
    return _canonical_json(
        {
            "evidence_ids": list(result.evidence_ids),
            "merged_memory_ids": list(result.merged_memory_ids),
            "mode": None if result.mode is None else result.mode.value,
            "policy_version": result.policy_version,
            "requested_memory_id": result.requested_memory_id,
            "result_sha256": result.result_sha256,
            "survivor_memory_id": result.survivor_memory_id,
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
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
    except (TypeError, ValueError) as error:
        raise MemoryIntegrityError from error


def _validate_limit(limit: int) -> None:
    if isinstance(limit, bool) or not 1 <= limit <= _MAX_CANDIDATES:
        field = "limit"
        raise MemoryValidationError.single(field, "out_of_range")


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
    if not isinstance(value, memoryview):
        raise MemoryIntegrityError
    return value.tobytes()


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MemoryIntegrityError
    return value


def _string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        raise MemoryIntegrityError
    return value


def _string_list(document: Mapping[str, JsonValue], field: str) -> tuple[str, ...]:
    value = document[field]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise MemoryIntegrityError
    return tuple(cast("list[str]", value))


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


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
