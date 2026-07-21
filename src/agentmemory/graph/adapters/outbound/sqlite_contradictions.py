"""GRA-005 authorization-first SQLite contradiction repository."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.domain.assertions import AssertionPolarity, AssertionPredicate
from agentmemory.graph.domain.contradictions import (
    AssertionAuthority,
    ConflictDimension,
    Contradiction,
    ContradictionCandidate,
    ContradictionResolution,
    ContradictionResolutionOutcome,
    ContradictionState,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_MAX_CANDIDATES = 2_000
_MAX_QUERY_IDS = 1_000
_ERR_ACTION = "contradiction repository action is not authorized"
_ERR_AUTHORIZATION = "contradiction repository scope is not authorized"
_ERR_CONFLICT = "contradiction operation conflicts with canonical state"
_ERR_INTEGRITY = "contradiction state failed integrity verification"
_ERR_STORAGE = "contradiction storage is unavailable"


class SqliteContradictionRepository:
    """Load assertion semantics and append disputes/resolutions under current authority."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical store and current authorization clock."""
        self._store = store
        self._clock = clock

    async def detection_candidates(
        self, scope: AuthorizedScope, repository_id: str
    ) -> tuple[ContradictionCandidate, ...]:
        """Load current active evidence-backed assertions without source content."""
        _require_action(scope, "graph.contradiction.detect")
        try:
            async with self._store.engine.connect() as connection:
                await _require_repository_authority(
                    connection, scope, repository_id, self._clock.now()
                )
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT c.assertion_id,c.subject_id,c.predicate,c.polarity,"
                                "c.object_id,c.valid_from,c.valid_to,"
                                "MIN(c.confidence_evidence_support,c.confidence_source_reliability,"
                                "c.confidence_extraction_quality) AS confidence,"
                                "json_group_array(s.evidence_id) AS evidence_ids,"
                                "MAX(CASE WHEN s.kind='user_statement' THEN 1 ELSE 0 END) "
                                "AS user_backed "
                                "FROM assertion_candidates AS c "
                                "JOIN assertion_lifecycle AS lifecycle "
                                "ON lifecycle.assertion_id=c.assertion_id "
                                "AND lifecycle.aggregate_version=1 AND lifecycle.status='active' "
                                "AND lifecycle.recorded_to IS NULL "
                                "JOIN assertion_evidence_snapshots AS s "
                                "ON s.assertion_id=c.assertion_id AND s.aggregate_version=1 "
                                "WHERE c.brain_id=:brain AND c.repository_id=:repository "
                                "GROUP BY c.assertion_id ORDER BY c.assertion_id LIMIT :limit"
                            ),
                            {
                                "brain": scope.brain_id.value,
                                "repository": repository_id,
                                "limit": _MAX_CANDIDATES + 1,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
                _require_candidate_bound(len(rows))
                return tuple(_decode_candidate(row) for row in rows)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def record_detection(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        repository_id: str,
        contradictions: tuple[Contradiction, ...],
    ) -> tuple[Contradiction, ...]:
        """Append an exact detection result; repeated conflict facts retain first observation."""
        _require_action(scope, "graph.contradiction.detect")
        request = _operation_digest(
            "detect",
            repository_id,
            tuple(value for item in contradictions for value in (item.id, item.detection_digest)),
        )
        result = _result_digest(contradictions)
        occurred_at = max((item.detected_at for item in contradictions), default=self._clock.now())
        try:
            async with _write_transaction(self._store) as connection:
                await _require_repository_authority(
                    connection, scope, repository_id, self._clock.now()
                )
                existing = await _operation(connection, operation_id)
                if existing is not None:
                    _verify_operation(
                        existing,
                        scope,
                        repository_id,
                        "detect",
                        request,
                        result,
                        len(contradictions),
                    )
                    return await _load_ids(
                        connection,
                        scope,
                        tuple(item.id for item in contradictions),
                        self._clock.now(),
                    )
                await _verify_conflict_assertions(
                    connection, scope.brain_id.value, repository_id, contradictions
                )
                await _insert_operation(
                    connection,
                    scope,
                    operation_id,
                    repository_id,
                    "detect",
                    request,
                    result,
                    len(contradictions),
                    occurred_at,
                )
                for contradiction in contradictions:
                    stored = await _contradiction_row(connection, contradiction.id)
                    if stored is None:
                        await _insert_contradiction(
                            connection, scope, repository_id, operation_id, contradiction
                        )
                    else:
                        _verify_conflict_row(stored, scope, repository_id, contradiction)
                return contradictions
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def get(self, scope: AuthorizedScope, contradiction_id: str) -> Contradiction | None:
        """Load a dispute only after current Repository authorization succeeds."""
        _require_action(scope, "graph.contradiction.resolve")
        try:
            async with self._store.engine.connect() as connection:
                row = await _authorized_row(connection, scope, contradiction_id, self._clock.now())
                return None if row is None else _decode_contradiction(row)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def resolve(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        contradiction: Contradiction,
        resolution: ContradictionResolution,
    ) -> Contradiction:
        """Append one evidence-backed resolution and preserve the original dispute row."""
        _require_action(scope, "graph.contradiction.resolve")
        request = _operation_digest("resolve", contradiction.id, (resolution.resolution_digest,))
        result = _digest((contradiction.id, resolution.resolution_digest))
        try:
            async with _write_transaction(self._store) as connection:
                row = await _authorized_row(connection, scope, contradiction.id, self._clock.now())
                _require_row(row)
                row = cast("RowMapping", row)
                stored = _decode_contradiction(row)
                existing = await _operation(connection, operation_id)
                if existing is not None:
                    _verify_operation(
                        existing,
                        scope,
                        str(row["repository_id"]),
                        "resolve",
                        request,
                        result,
                        1,
                    )
                    return _require_resolution_replay(stored, resolution)
                _require_unresolved(stored, contradiction)
                await _require_resolution_authority(
                    connection, scope, str(row["repository_id"]), resolution, self._clock.now()
                )
                await _require_resolution_evidence(
                    connection, scope, str(row["repository_id"]), resolution
                )
                await _insert_operation(
                    connection,
                    scope,
                    operation_id,
                    str(row["repository_id"]),
                    "resolve",
                    request,
                    result,
                    1,
                    resolution.resolved_at,
                )
                await _insert_resolution(connection, operation_id, resolution)
                return contradiction.resolve(resolution)
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def for_assertions(
        self, scope: AuthorizedScope, assertion_ids: tuple[str, ...]
    ) -> tuple[Contradiction, ...]:
        """Load all authorized disputes touching the bounded fused candidate set."""
        _require_action(scope, "graph.contradiction.query")
        if not assertion_ids or len(assertion_ids) > _MAX_QUERY_IDS:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT c.*,r.operation_id AS resolution_operation_id,r.actor_id,"
                                "r.grant_id,r.outcome,r.reason_code,r.evidence_ids_json AS "
                                "resolution_evidence_ids_json,r.resolved_at,r.resolution_digest,"
                                "r.policy_version AS resolution_policy_version "
                                "FROM graph_contradictions AS c "
                                "LEFT JOIN graph_contradiction_resolutions AS r "
                                "ON r.contradiction_id=c.contradiction_id "
                                "WHERE c.brain_id=:brain AND c.repository_id IN "
                                "(SELECT value FROM json_each(:repositories)) "
                                "AND (c.left_assertion_id IN "
                                "(SELECT value FROM json_each(:ids)) OR c.right_assertion_id IN "
                                "(SELECT value FROM json_each(:ids))) ORDER BY c.contradiction_id"
                            ),
                            {
                                "brain": scope.brain_id.value,
                                "ids": json.dumps(assertion_ids, separators=(",", ":")),
                                "repositories": json.dumps(
                                    [item.value for item in scope.repository_ids],
                                    separators=(",", ":"),
                                ),
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
                repositories = sorted({str(row["repository_id"]) for row in rows})
                for repository_id in repositories:
                    await _require_repository_authority(
                        connection, scope, repository_id, self._clock.now()
                    )
                return tuple(_decode_contradiction(row) for row in rows)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


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
                "JOIN brains AS brain ON brain.id=project.brain_id "
                "JOIN principals AS principal ON principal.id=:principal "
                "WHERE repository.id=:repository AND project.brain_id=:brain "
                "AND repository.status='active' AND project.status='active' "
                "AND brain.status='active' AND principal.status='active' AND EXISTS ("
                "SELECT 1 FROM scope_grants AS grant_row WHERE grant_row.principal_id=:principal "
                "AND grant_row.brain_id=:brain "
                "AND grant_row.role IN ('owner','admin','editor','reader') "
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


async def _authorized_row(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    contradiction_id: str,
    now: datetime,
) -> RowMapping | None:
    base = await _contradiction_row(connection, contradiction_id)
    if base is None or str(base["brain_id"]) != scope.brain_id.value:
        return None
    await _require_repository_authority(connection, scope, str(base["repository_id"]), now)
    return base


async def _contradiction_row(
    connection: AsyncConnection, contradiction_id: str
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT c.*,r.operation_id AS resolution_operation_id,r.actor_id,r.grant_id,"
                    "r.outcome,r.reason_code,r.evidence_ids_json AS resolution_evidence_ids_json,"
                    "r.resolved_at,r.resolution_digest,"
                    "r.policy_version AS resolution_policy_version "
                    "FROM graph_contradictions AS c LEFT JOIN graph_contradiction_resolutions AS r "
                    "ON r.contradiction_id=c.contradiction_id WHERE c.contradiction_id=:id LIMIT 1"
                ),
                {"id": contradiction_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _verify_conflict_assertions(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    contradictions: tuple[Contradiction, ...],
) -> None:
    ids = tuple(
        sorted(
            {
                value
                for item in contradictions
                for value in (item.left_assertion_id, item.right_assertion_id)
            }
        )
    )
    if not ids:
        return
    count = (
        await connection.execute(
            text(
                "SELECT COUNT(*) FROM assertion_candidates AS c JOIN assertion_lifecycle AS l "
                "ON l.assertion_id=c.assertion_id AND l.aggregate_version=1 AND l.status='active' "
                "AND l.recorded_to IS NULL WHERE c.brain_id=:brain AND c.repository_id=:repository "
                "AND c.assertion_id IN (SELECT value FROM json_each(:ids))"
            ),
            {
                "brain": brain_id,
                "repository": repository_id,
                "ids": json.dumps(ids, separators=(",", ":")),
            },
        )
    ).scalar_one()
    if int(count) != len(ids):
        raise GraphConflictError(_ERR_CONFLICT)


async def _require_resolution_authority(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    repository_id: str,
    resolution: ContradictionResolution,
    now: datetime,
) -> None:
    row = (
        await connection.execute(
            text(
                "SELECT 1 FROM scope_grants WHERE id=:grant AND principal_id=:principal "
                "AND brain_id=:brain AND role IN ('owner','admin','editor') "
                "AND valid_from<=:now AND (valid_to IS NULL OR valid_to>:now) "
                "AND (repository_id IS NULL OR repository_id=:repository) LIMIT 1"
            ),
            {
                "grant": resolution.grant_id,
                "principal": scope.principal_id.value,
                "brain": scope.brain_id.value,
                "repository": repository_id,
                "now": _micros(now),
            },
        )
    ).scalar_one_or_none()
    if row is None or resolution.actor_id != scope.principal_id.value:
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)


async def _require_resolution_evidence(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    repository_id: str,
    resolution: ContradictionResolution,
) -> None:
    count = (
        await connection.execute(
            text(
                "SELECT COUNT(*) FROM assertion_evidence_sources AS source "
                "LEFT JOIN assertion_evidence_revocations AS revoked "
                "ON revoked.evidence_id=source.evidence_id "
                "WHERE source.brain_id=:brain AND source.repository_id=:repository "
                "AND source.evidence_id IN (SELECT value FROM json_each(:ids)) "
                "AND revoked.evidence_id IS NULL"
            ),
            {
                "brain": scope.brain_id.value,
                "repository": repository_id,
                "ids": json.dumps(resolution.evidence_ids, separators=(",", ":")),
            },
        )
    ).scalar_one()
    if int(count) != len(resolution.evidence_ids):
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)


async def _insert_operation(  # noqa: PLR0913 -- One immutable operation envelope.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    repository_id: str,
    action: str,
    request_digest: bytes,
    result_digest: bytes,
    result_count: int,
    occurred_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO graph_contradiction_operations "
            "(operation_id,brain_id,repository_id,principal_id,scope_fingerprint,action,"
            "request_digest,result_digest,result_count,occurred_at,schema_version) VALUES "
            "(:operation,:brain,:repository,:principal,:scope,:action,:request,:result,:count,:at,1)"
        ),
        {
            "operation": operation_id,
            "brain": scope.brain_id.value,
            "repository": repository_id,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "action": action,
            "request": request_digest,
            "result": result_digest,
            "count": result_count,
            "at": _micros(occurred_at),
        },
    )


async def _insert_contradiction(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    repository_id: str,
    operation_id: str,
    contradiction: Contradiction,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO graph_contradictions "
            "(contradiction_id,brain_id,repository_id,detection_operation_id,left_assertion_id,"
            "right_assertion_id,predicate,dimension,valid_from,valid_to,evidence_ids_json,"
            "detected_at,detection_digest,policy_version,schema_version) VALUES "
            "(:id,:brain,:repository,:operation,:left,:right,:predicate,:dimension,:valid_from,"
            ":valid_to,:evidence,:detected,:digest,:policy,1)"
        ),
        {
            "id": contradiction.id,
            "brain": scope.brain_id.value,
            "repository": repository_id,
            "operation": operation_id,
            "left": contradiction.left_assertion_id,
            "right": contradiction.right_assertion_id,
            "predicate": contradiction.predicate.value,
            "dimension": contradiction.dimension.value,
            "valid_from": _micros(contradiction.valid_from),
            "valid_to": _optional_micros(contradiction.valid_to),
            "evidence": json.dumps(contradiction.evidence_ids, separators=(",", ":")),
            "detected": _micros(contradiction.detected_at),
            "digest": bytes.fromhex(contradiction.detection_digest),
            "policy": contradiction.policy_version,
        },
    )
    for evidence_id in contradiction.evidence_ids:
        await connection.execute(
            text(
                "INSERT INTO graph_contradiction_evidence "
                "(contradiction_id,evidence_id,schema_version) VALUES (:id,:evidence,1)"
            ),
            {"id": contradiction.id, "evidence": evidence_id},
        )


async def _insert_resolution(
    connection: AsyncConnection,
    operation_id: str,
    resolution: ContradictionResolution,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO graph_contradiction_resolutions "
            "(contradiction_id,operation_id,actor_id,grant_id,outcome,reason_code,"
            "evidence_ids_json,resolved_at,resolution_digest,policy_version,schema_version) VALUES "
            "(:id,:operation,:actor,:grant,:outcome,:reason,:evidence,:at,:digest,:policy,1)"
        ),
        {
            "id": resolution.contradiction_id,
            "operation": operation_id,
            "actor": resolution.actor_id,
            "grant": resolution.grant_id,
            "outcome": resolution.outcome.value,
            "reason": resolution.reason_code,
            "evidence": json.dumps(resolution.evidence_ids, separators=(",", ":")),
            "at": _micros(resolution.resolved_at),
            "digest": bytes.fromhex(resolution.resolution_digest),
            "policy": resolution.policy_version,
        },
    )


async def _operation(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM graph_contradiction_operations WHERE operation_id=:id"),
                {"id": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _verify_operation(  # noqa: PLR0913 -- Verify the complete replay envelope.
    row: RowMapping,
    scope: AuthorizedScope,
    repository_id: str,
    action: str,
    request: bytes,
    result: bytes,
    count: int,
) -> None:
    if (
        str(row["brain_id"]) != scope.brain_id.value
        or str(row["principal_id"]) != scope.principal_id.value
        or bytes(cast("bytes", row["scope_fingerprint"])) != bytes.fromhex(scope.scope_fingerprint)
        or str(row["repository_id"]) != repository_id
        or str(row["action"]) != action
        or bytes(cast("bytes", row["request_digest"])) != request
        or bytes(cast("bytes", row["result_digest"])) != result
        or int(str(row["result_count"])) != count
    ):
        raise GraphConflictError(_ERR_CONFLICT)


def _verify_conflict_row(
    row: RowMapping,
    scope: AuthorizedScope,
    repository_id: str,
    expected: Contradiction,
) -> None:
    actual = _decode_contradiction(row)
    if (
        str(row["brain_id"]) != scope.brain_id.value
        or str(row["repository_id"]) != repository_id
        or actual.id != expected.id
        or actual.left_assertion_id != expected.left_assertion_id
        or actual.right_assertion_id != expected.right_assertion_id
        or actual.dimension is not expected.dimension
        or actual.evidence_ids != expected.evidence_ids
    ):
        raise GraphConflictError(_ERR_CONFLICT)


async def _load_ids(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    ids: tuple[str, ...],
    now: datetime,
) -> tuple[Contradiction, ...]:
    values: list[Contradiction] = []
    for contradiction_id in ids:
        row = await _authorized_row(connection, scope, contradiction_id, now)
        if row is None:
            raise GraphConflictError(_ERR_CONFLICT)
        values.append(_decode_contradiction(row))
    return tuple(values)


def _decode_candidate(row: RowMapping) -> ContradictionCandidate:
    try:
        evidence = tuple(sorted(_string_list(json.loads(str(row["evidence_ids"])))))
        authority = (
            AssertionAuthority.USER_STATEMENT
            if int(str(row["user_backed"])) == 1
            else AssertionAuthority.EVIDENCE_BACKED
        )
        return ContradictionCandidate(
            str(row["assertion_id"]),
            str(row["subject_id"]),
            AssertionPredicate(str(row["predicate"])),
            str(row["object_id"]),
            AssertionPolarity(str(row["polarity"])),
            authority,
            _time(row["valid_from"]),
            None if row["valid_to"] is None else _time(row["valid_to"]),
            evidence,
            int(str(row["confidence"])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


def _decode_contradiction(row: RowMapping) -> Contradiction:
    try:
        resolution = None
        state = ContradictionState.UNRESOLVED
        if row["resolution_operation_id"] is not None:
            resolution = ContradictionResolution(
                str(row["contradiction_id"]),
                ContradictionResolutionOutcome(str(row["outcome"])),
                str(row["actor_id"]),
                str(row["grant_id"]),
                str(row["reason_code"]),
                tuple(sorted(_string_list(json.loads(str(row["resolution_evidence_ids_json"]))))),
                _time(row["resolved_at"]),
                bytes(cast("bytes", row["resolution_digest"])).hex(),
                str(row["resolution_policy_version"]),
            )
            state = ContradictionState.RESOLVED
        return Contradiction(
            str(row["contradiction_id"]),
            str(row["left_assertion_id"]),
            str(row["right_assertion_id"]),
            AssertionPredicate(str(row["predicate"])),
            ConflictDimension(str(row["dimension"])),
            _time(row["valid_from"]),
            None if row["valid_to"] is None else _time(row["valid_to"]),
            tuple(sorted(_string_list(json.loads(str(row["evidence_ids_json"]))))),
            _time(row["detected_at"]),
            state,
            bytes(cast("bytes", row["detection_digest"])).hex(),
            resolution,
            str(row["policy_version"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


def _require_resolution_replay(
    contradiction: Contradiction, resolution: ContradictionResolution
) -> Contradiction:
    if contradiction.resolution != resolution:
        raise GraphConflictError(_ERR_CONFLICT)
    return contradiction


def _operation_digest(action: str, target: str, values: tuple[str, ...]) -> bytes:
    return _digest((action, target, *values))


def _result_digest(values: tuple[Contradiction, ...]) -> bytes:
    return _digest(tuple(item.id for item in values))


def _digest(values: tuple[str, ...]) -> bytes:
    encoded = json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).digest()


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    items = cast("list[object]", value)
    if any(not isinstance(item, str) for item in items):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return tuple(cast("str", item) for item in items)


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)


def _require_candidate_bound(count: int) -> None:
    if count > _MAX_CANDIDATES:
        raise GraphIntegrityError(_ERR_INTEGRITY)


def _require_row(row: RowMapping | None) -> None:
    if row is None:
        raise GraphConflictError(_ERR_CONFLICT)


def _require_unresolved(stored: Contradiction, expected: Contradiction) -> None:
    if stored != expected or stored.state is not ContradictionState.UNRESOLVED:
        raise GraphConflictError(_ERR_CONFLICT)


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return round(value.timestamp() * 1_000_000)


def _optional_micros(value: datetime | None) -> int | None:
    return None if value is None else _micros(value)


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
