"""IDX-005 append-only SQLite artifact topology repository."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.indexing.adapters.outbound.policy_visibility import policy_visible_sql
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    ArtifactTopologyEvidence,
    ArtifactTopologyPluginKind,
    ArtifactTopologySnapshot,
    ReferenceSensitivity,
    TopologyCandidate,
    TopologyEntityKind,
    TopologyRelationCandidate,
    TopologyRelationKind,
    UnknownConstructReason,
    UnknownTopologyEvidence,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_ACTION = "artifact topology repository action is not authorized"
_ERR_AUTHORIZATION = "artifact topology repository scope is not authorized"
_ERR_CONFLICT = "artifact topology evidence conflicts with immutable history"
_ERR_STORAGE = "artifact topology storage is unavailable"
_WRITE_ROLES = frozenset({"owner", "admin", "editor", "worker"})
_READ_ROLES = frozenset({"owner", "admin", "editor", "reader", "auditor", "worker"})


class SqliteArtifactTopologyRepository:
    """Persist complete artifact outputs and temporal latest-per-source snapshots."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind canonical single-writer storage and trusted authorization time."""
        self._store = store
        self._clock = clock

    async def find_batch_by_operation(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ArtifactTopologyBatch | None:
        """Return an exact scope-bound registration replay."""
        _require_action(scope, "indexing.artifact_topology.register")
        try:
            async with self._store.engine.connect() as connection:
                row = await _batch_operation_row(connection, operation_id)
                if row is None:
                    return None
                await _authorize_row(connection, scope, row, self._clock.now(), write=True)
                _conflict_if(
                    str(row["principal_id"]) != scope.principal_id.value
                    or _blob(row["scope_fingerprint"]).hex() != scope.scope_fingerprint
                )
                return await _batch(connection, row)
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def register_batch(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        registered_at: datetime,
    ) -> ArtifactTopologyBatch:
        """Append complete observations and semantic invalidation dependencies atomically."""
        _require_action(scope, "indexing.artifact_topology.register")
        try:
            async with _write_transaction(self._store) as connection:
                existing = await _batch_operation_row(connection, operation_id)
                if existing is not None:
                    await _authorize_row(connection, scope, existing, self._clock.now(), write=True)
                    stored = await _batch(connection, existing)
                    _conflict_if(
                        stored != batch
                        or _blob(existing["scope_fingerprint"]).hex() != scope.scope_fingerprint
                    )
                    return stored
                context = await _context_row(connection, batch.source_revision_context_id)
                _unauthorized_if(context is None)
                context = cast("RowMapping", context)
                await _authorize_row(connection, scope, context, self._clock.now(), write=True)
                _conflict_if(
                    str(context["source_file_id"]) != batch.source_file_id
                    or str(context["commit_sha"]) != batch.commit_sha
                )
                observations: tuple[
                    TopologyCandidate | TopologyRelationCandidate | UnknownTopologyEvidence, ...
                ] = (*batch.candidates, *batch.relations, *batch.unknown_evidence)
                for item in observations:
                    await _validate_evidence(connection, item.evidence, context)
                previous = (
                    await connection.execute(
                        text(
                            "SELECT batch_id FROM artifact_topology_batches "
                            "WHERE brain_id=:brain AND repository_id=:repository "
                            "AND source_file_id=:source ORDER BY registered_at DESC,batch_id DESC "
                            "LIMIT 1"
                        ),
                        {
                            "brain": str(context["brain_id"]),
                            "repository": str(context["repository_id"]),
                            "source": batch.source_file_id,
                        },
                    )
                ).scalar_one_or_none()
                await connection.execute(
                    text(
                        "INSERT INTO artifact_topology_batches"
                        "(batch_id,operation_id,brain_id,project_id,repository_id,source_file_id,"
                        "source_revision_context_id,commit_sha,plugin_kind,plugin_version,"
                        "batch_digest,supersedes_batch_id,principal_id,scope_fingerprint,"
                        "registered_at,schema_version) VALUES(:batch,:operation,:brain,:project,"
                        ":repository,:source,:context,:commit,:kind,:version,:digest,:supersedes,"
                        ":principal,:scope,:registered,1)"
                    ),
                    {
                        "batch": batch.digest,
                        "operation": operation_id,
                        "brain": str(context["brain_id"]),
                        "project": str(context["project_id"]),
                        "repository": str(context["repository_id"]),
                        "source": batch.source_file_id,
                        "context": batch.source_revision_context_id,
                        "commit": batch.commit_sha,
                        "kind": batch.plugin_kind.value,
                        "version": batch.plugin_version,
                        "digest": bytes.fromhex(batch.digest),
                        "supersedes": previous,
                        "principal": scope.principal_id.value,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "registered": _micros(registered_at),
                    },
                )
                await _insert_observations(connection, batch, registered_at)
                return batch
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def snapshot(self, scope: AuthorizedScope, cutoff: datetime) -> ArtifactTopologySnapshot:
        """Load latest batches per source while preserving cross-source temporal conflicts."""
        _require_action(scope, "indexing.artifact_topology.read")
        try:
            async with self._store.engine.connect() as connection:
                await _authorize_all(connection, scope, self._clock.now(), write=False)
                repositories = tuple(value.value for value in scope.repository_ids)
                _unauthorized_if(not repositories)
                batches = await _latest_batch_ids(connection, repositories, cutoff)
                if not batches:
                    return ArtifactTopologySnapshot((), (), (), cutoff)
                candidates = await _observation_rows(
                    connection, "artifact_topology_candidates", batches, "candidate_id"
                )
                relations = await _observation_rows(
                    connection, "artifact_topology_relations", batches, "relation_id"
                )
                unknown = await _observation_rows(
                    connection, "artifact_topology_unknown_evidence", batches, "unknown_id"
                )
                return ArtifactTopologySnapshot(
                    tuple(_candidate(row) for row in candidates),
                    tuple(_relation(row) for row in relations),
                    tuple(_unknown(row) for row in unknown),
                    cutoff,
                )
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


async def _insert_observations(
    connection: AsyncConnection, batch: ArtifactTopologyBatch, registered_at: datetime
) -> None:
    for candidate in batch.candidates:
        await connection.execute(
            text(
                "INSERT INTO artifact_topology_candidates(candidate_id,batch_id,evidence_id,"
                "source_semantic_id,relative_path,classification,observed_at,entity_id,"
                "entity_kind,name,version,environment_reference,sensitivity,qualifiers_json,"
                "schema_version) VALUES(:candidate,:batch,:evidence,:semantic,:path,"
                ":classification,:observed,:entity,:kind,:name,:version,:environment,"
                ":sensitivity,:qualifiers,1)"
            ),
            {
                **_evidence_values(candidate.evidence),
                "candidate": candidate.id,
                "batch": batch.digest,
                "entity": candidate.entity_id,
                "kind": candidate.kind.value,
                "name": candidate.name,
                "version": candidate.version,
                "environment": candidate.environment_reference,
                "sensitivity": (
                    None if candidate.sensitivity is None else candidate.sensitivity.value
                ),
                "qualifiers": _json(candidate.qualifiers),
            },
        )
        await _dependency(connection, candidate.id, candidate.evidence, registered_at)
    for relation in batch.relations:
        await connection.execute(
            text(
                "INSERT INTO artifact_topology_relations(relation_id,batch_id,evidence_id,"
                "source_semantic_id,relative_path,classification,observed_at,subject_entity_id,"
                "relation_kind,object_entity_id,environment_reference,valid_from,valid_to,"
                "schema_version) VALUES(:relation,:batch,:evidence,:semantic,:path,"
                ":classification,:observed,:subject,:kind,:object,:environment,:valid_from,"
                ":valid_to,1)"
            ),
            {
                **_evidence_values(relation.evidence),
                "relation": relation.id,
                "batch": batch.digest,
                "subject": relation.subject_entity_id,
                "kind": relation.relation.value,
                "object": relation.object_entity_id,
                "environment": relation.environment_reference,
                "valid_from": _micros(relation.valid_from),
                "valid_to": None if relation.valid_to is None else _micros(relation.valid_to),
            },
        )
        await _dependency(connection, relation.id, relation.evidence, registered_at)
    for unknown in batch.unknown_evidence:
        await connection.execute(
            text(
                "INSERT INTO artifact_topology_unknown_evidence(unknown_id,batch_id,evidence_id,"
                "source_semantic_id,relative_path,classification,observed_at,reason,"
                "fragment_digest,start_line,end_line,schema_version) VALUES(:unknown,:batch,"
                ":evidence,:semantic,:path,:classification,:observed,:reason,:digest,:start,"
                ":end,1)"
            ),
            {
                **_evidence_values(unknown.evidence),
                "unknown": unknown.id,
                "batch": batch.digest,
                "reason": unknown.reason.value,
                "digest": bytes.fromhex(unknown.fragment_digest),
                "start": unknown.start_line,
                "end": unknown.end_line,
            },
        )
        await _dependency(connection, unknown.id, unknown.evidence, registered_at)


async def _dependency(
    connection: AsyncConnection,
    fact_id: str,
    evidence: ArtifactTopologyEvidence,
    registered_at: datetime,
) -> None:
    dependency_id = hashlib.sha256(
        f"artifact-topology-dependency.v1\0{fact_id}\0{evidence.source_semantic_id}\0"
        f"{evidence.evidence_id}".encode()
    ).hexdigest()
    await connection.execute(
        text(
            "INSERT INTO index_semantic_dependencies(dependency_id,repository_id,"
            "source_semantic_id,dependent_fact_id,assertion_evidence_id,registered_at,"
            "schema_version) VALUES(:id,:repository,:semantic,:fact,:evidence,:registered,1)"
        ),
        {
            "id": dependency_id,
            "repository": evidence.repository_id,
            "semantic": evidence.source_semantic_id,
            "fact": fact_id,
            "evidence": evidence.evidence_id,
            "registered": _micros(registered_at),
        },
    )


def _evidence_values(evidence: ArtifactTopologyEvidence) -> dict[str, object]:
    return {
        "evidence": evidence.evidence_id,
        "semantic": evidence.source_semantic_id,
        "path": evidence.relative_path,
        "classification": evidence.classification,
        "observed": _micros(evidence.observed_at),
    }


async def _validate_evidence(
    connection: AsyncConnection, evidence: ArtifactTopologyEvidence, context: RowMapping
) -> None:
    _conflict_if(
        evidence.brain_id != str(context["brain_id"])
        or evidence.project_id != str(context["project_id"])
        or evidence.repository_id != str(context["repository_id"])
        or evidence.source_file_id != str(context["source_file_id"])
        or evidence.source_revision_context_id != str(context["context_id"])
        or evidence.relative_path != str(context["relative_path"])
    )
    row = (
        (
            await connection.execute(
                text(
                    "SELECT source.brain_id,source.project_id,source.repository_id,"
                    "source.classification,semantic.file_revision_id FROM "
                    "assertion_evidence_sources AS source JOIN "
                    "(SELECT file_revision_id FROM symbol_revisions WHERE id=:semantic "
                    "UNION ALL SELECT file_revision_id FROM symbol_occurrences "
                    "WHERE id=:semantic) AS semantic WHERE source.evidence_id=:evidence"
                ),
                {"semantic": evidence.source_semantic_id, "evidence": evidence.evidence_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    _conflict_if(
        row is None
        or str(row["brain_id"]) != evidence.brain_id
        or str(row["project_id"]) != evidence.project_id
        or str(row["repository_id"]) != evidence.repository_id
        or str(row["classification"]) != evidence.classification
        or str(row["file_revision_id"]) != str(context["file_revision_id"])
    )


async def _batch_operation_row(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM artifact_topology_batches WHERE operation_id=:id"),
                {"id": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _context_row(connection: AsyncConnection, context_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM source_revision_contexts WHERE context_id=:id"),
                {"id": context_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _latest_batch_ids(
    connection: AsyncConnection, repositories: tuple[str, ...], cutoff: datetime
) -> tuple[str, ...]:
    statement = text(
        "SELECT batch.batch_id FROM artifact_topology_batches AS batch "  # noqa: S608  # nosec B608
        "JOIN source_files AS policy_source ON policy_source.id=batch.source_file_id "
        "WHERE batch.repository_id IN :repositories AND batch.registered_at<=:cutoff "
        "AND " + policy_visible_sql("batch.repository_id", "policy_source.relative_path") + " "
        "AND NOT EXISTS(SELECT 1 FROM artifact_topology_batches AS newer "
        "WHERE newer.brain_id=batch.brain_id AND newer.repository_id=batch.repository_id "
        "AND newer.source_file_id=batch.source_file_id AND newer.registered_at<=:cutoff "
        "AND (newer.registered_at>batch.registered_at OR "
        "(newer.registered_at=batch.registered_at AND newer.batch_id>batch.batch_id))) "
        "ORDER BY batch.batch_id"
    ).bindparams(bindparam("repositories", expanding=True))
    rows = await connection.execute(
        statement, {"repositories": repositories, "cutoff": _micros(cutoff)}
    )
    return tuple(str(value) for value in rows.scalars())


async def _observation_rows(
    connection: AsyncConnection,
    table: str,
    batches: tuple[str, ...],
    order_column: str,
) -> Sequence[RowMapping]:
    allowed = {
        ("artifact_topology_candidates", "candidate_id"),
        ("artifact_topology_relations", "relation_id"),
        ("artifact_topology_unknown_evidence", "unknown_id"),
    }
    _conflict_if((table, order_column) not in allowed)
    statement = text(
        f"SELECT observation.*,batch.brain_id,batch.project_id,batch.repository_id,"  # noqa: S608  # nosec B608
        f"batch.source_file_id,batch.source_revision_context_id FROM {table} AS observation "
        "JOIN artifact_topology_batches AS batch ON batch.batch_id=observation.batch_id "
        f"WHERE observation.batch_id IN :batches ORDER BY observation.{order_column}"  # nosec B608
    ).bindparams(bindparam("batches", expanding=True))
    return (await connection.execute(statement, {"batches": batches})).mappings().all()


async def _batch(connection: AsyncConnection, row: RowMapping) -> ArtifactTopologyBatch:
    batch_id = str(row["batch_id"])
    batches = (batch_id,)
    candidates = await _observation_rows(
        connection, "artifact_topology_candidates", batches, "candidate_id"
    )
    relations = await _observation_rows(
        connection, "artifact_topology_relations", batches, "relation_id"
    )
    unknown = await _observation_rows(
        connection, "artifact_topology_unknown_evidence", batches, "unknown_id"
    )
    return ArtifactTopologyBatch(
        ArtifactTopologyPluginKind(str(row["plugin_kind"])),
        str(row["plugin_version"]),
        str(row["source_revision_context_id"]),
        str(row["source_file_id"]),
        str(row["commit_sha"]),
        tuple(_candidate(item) for item in candidates),
        tuple(_relation(item) for item in relations),
        tuple(_unknown(item) for item in unknown),
    )


def _evidence(row: RowMapping) -> ArtifactTopologyEvidence:
    return ArtifactTopologyEvidence(
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        str(row["source_file_id"]),
        str(row["source_revision_context_id"]),
        str(row["source_semantic_id"]),
        str(row["evidence_id"]),
        str(row["relative_path"]),
        str(row["classification"]),
        _datetime(int(row["observed_at"])),
    )


def _candidate(row: RowMapping) -> TopologyCandidate:
    sensitivity = row["sensitivity"]
    return TopologyCandidate(
        _evidence(row),
        str(row["entity_id"]),
        TopologyEntityKind(str(row["entity_kind"])),
        str(row["name"]),
        _optional(row["version"]),
        _optional(row["environment_reference"]),
        None if sensitivity is None else ReferenceSensitivity(str(sensitivity)),
        _json_tuple(row["qualifiers_json"]),
    )


def _relation(row: RowMapping) -> TopologyRelationCandidate:
    valid_to = row["valid_to"]
    return TopologyRelationCandidate(
        _evidence(row),
        str(row["subject_entity_id"]),
        TopologyRelationKind(str(row["relation_kind"])),
        str(row["object_entity_id"]),
        _optional(row["environment_reference"]),
        _datetime(int(row["valid_from"])),
        None if valid_to is None else _datetime(int(valid_to)),
    )


def _unknown(row: RowMapping) -> UnknownTopologyEvidence:
    return UnknownTopologyEvidence(
        _evidence(row),
        UnknownConstructReason(str(row["reason"])),
        _blob(row["fragment_digest"]).hex(),
        int(row["start_line"]),
        int(row["end_line"]),
    )


async def _authorize_all(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    now: datetime,
    *,
    write: bool,
) -> None:
    for member in scope.members:
        for repository_id in member.repository_ids:
            await _authorize(
                connection,
                scope,
                member.project_id.value,
                repository_id.value,
                now,
                write=write,
            )


async def _authorize_row(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    row: RowMapping,
    now: datetime,
    *,
    write: bool,
) -> None:
    await _authorize(
        connection,
        scope,
        str(row["project_id"]),
        str(row["repository_id"]),
        now,
        write=write,
    )


async def _authorize(  # noqa: PLR0913 -- Authority binds complete repository scope.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    project_id: str,
    repository_id: str,
    now: datetime,
    *,
    write: bool,
) -> None:
    allowed = _WRITE_ROLES if write else _READ_ROLES
    _unauthorized_if(
        scope.role.value not in allowed
        or project_id not in {item.value for item in scope.project_ids}
        or repository_id not in {item.value for item in scope.repository_ids}
    )
    exists = (
        await connection.execute(
            text(
                "SELECT EXISTS(SELECT 1 FROM repositories AS repository JOIN "
                "project_repositories AS binding ON binding.repository_id=repository.id JOIN "
                "projects AS project ON project.id=binding.project_id WHERE "
                "repository.id=:repository AND project.id=:project AND repository.status='active' "
                "AND project.status='active' AND project.brain_id=:brain AND EXISTS(SELECT 1 "
                "FROM scope_grants AS grant_row WHERE grant_row.principal_id=:principal AND "
                "grant_row.brain_id=:brain AND grant_row.role=:role AND grant_row.valid_from<=:now "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) AND "
                "(grant_row.project_id IS NULL OR grant_row.project_id=project.id) AND "
                "(grant_row.repository_id IS NULL OR grant_row.repository_id=repository.id)))"
            ),
            {
                "repository": repository_id,
                "project": project_id,
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
                "role": scope.role.value,
                "now": _micros(now),
            },
        )
    ).scalar_one()
    _unauthorized_if(not bool(exists))


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _unauthorized_if(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _conflict_if(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise IndexingConflictError(_ERR_CONFLICT)


def _json(values: tuple[str, ...]) -> bytes:
    return json.dumps(values, separators=(",", ":")).encode()


def _json_tuple(value: object) -> tuple[str, ...]:
    parsed = json.loads(_blob(value))
    if not isinstance(parsed, list):
        raise IndexingConflictError(_ERR_CONFLICT)
    sequence = cast("list[object]", parsed)
    if any(not isinstance(item, str) for item in sequence):
        raise IndexingConflictError(_ERR_CONFLICT)
    return tuple(cast("list[str]", sequence))


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode()
    raise IndexingConflictError(_ERR_CONFLICT)


def _optional(value: object) -> str | None:
    return None if value is None else str(value)


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, UTC)


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
