"""GRA-004 SQLite bitemporal assertion and immutable VCS graph adapters."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    list_authorized_assertion_ids_for_truth,
    load_assertion_revision_snapshot,
)
from agentmemory.graph.domain.assertions import AssertionStatus
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)
from agentmemory.graph.domain.temporal_truth import (
    EvidenceRevisionAnchor,
    ResolvedVcsRevision,
    RevisionEvidencePolicy,
    RevisionEvidenceProof,
    TemporalAssertionCandidate,
    TemporalAssertionCriteria,
    VcsRevisionBatch,
    VcsRevisionSelector,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_MAX_ANCESTRY_DEPTH = 10_000
_MAX_IMPACTS_PER_EVIDENCE = 1_000
_SHA256_BYTES = 32
_ERR_ACTION = "temporal truth repository action is not authorized"
_ERR_AUTHORIZATION = "temporal truth repository scope is not authorized"
_ERR_CONFLICT = "VCS revision evidence conflicts with canonical state"
_ERR_INTEGRITY = "temporal truth evidence failed integrity verification"
_ERR_STORAGE = "temporal truth storage is unavailable"
_ERR_UNKNOWN = "VCS revision evidence is not available"


class SqliteTemporalAssertionRepository:
    """Read canonical assertion state at valid and recorded instants."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the process-wide canonical SQLite store."""
        self._store = store

    async def query(
        self,
        scope: AuthorizedScope,
        criteria: TemporalAssertionCriteria,
    ) -> tuple[TemporalAssertionCandidate, ...]:
        """Return active-at-snapshot assertions plus capture-time revision anchors."""
        if scope.action != "graph.assertion.truth.query":
            raise GraphAuthorizationError(_ERR_ACTION)
        try:
            async with self._store.engine.connect() as connection:
                assertion_ids = await list_authorized_assertion_ids_for_truth(
                    connection,
                    scope,
                    assertion_id=criteria.assertion_id,
                    subject_id=criteria.subject_id,
                    predicates=criteria.predicates,
                    valid_at=criteria.valid_at,
                    limit=criteria.limit,
                )
                candidates: list[TemporalAssertionCandidate] = []
                for assertion_id in assertion_ids:
                    snapshot = await load_assertion_revision_snapshot(
                        connection,
                        scope,
                        assertion_id,
                        criteria.recorded_at,
                    )
                    if snapshot is None:
                        continue
                    assertion, event_id, current = snapshot
                    if assertion.status is not AssertionStatus.ACTIVE:
                        continue
                    anchors = await _anchors(
                        connection,
                        scope,
                        tuple(item.evidence_id for item in assertion.evidence),
                        criteria.recorded_at,
                    )
                    candidates.append(
                        TemporalAssertionCandidate(
                            assertion,
                            event_id,
                            current,
                            tuple(anchors.get(item.evidence_id) for item in assertion.evidence),
                        )
                    )
                return _bounded_candidates(candidates, criteria.limit)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


class SqliteVcsRevisionRepository:
    """Append and query an immutable bounded commit DAG and branch-ref history."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind canonical storage and an injectable authorization clock."""
        self._store = store
        self._clock = clock

    async def append(self, scope: AuthorizedScope, batch: VcsRevisionBatch) -> str:
        """Atomically append or exactly replay one VCS observation batch."""
        if scope.action != "graph.vcs.revision.record":
            raise GraphAuthorizationError(_ERR_ACTION)
        if batch.brain_id != scope.brain_id.value:
            raise GraphAuthorizationError(_ERR_AUTHORIZATION)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_repository_authority(
                    connection,
                    scope,
                    batch.repository_id,
                    self._clock.now(),
                )
                existing = await _batch(connection, batch.operation_id)
                if existing is not None:
                    _verify_batch(existing, scope, batch)
                    return batch.digest
                await _validate_existing_commits(connection, batch)
                await _require_known_commit_references(connection, batch)
                await _insert_batch(connection, scope, batch)
                await _insert_commits_and_parents(connection, batch)
                _reject_cycle(cycle_exists=await _cycle_exists(connection, batch.repository_id))
                await _insert_refs(connection, batch)
                await _insert_impacts(connection, batch)
                return batch.digest
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def resolve(
        self,
        scope: AuthorizedScope,
        selector: VcsRevisionSelector,
        recorded_at: datetime,
    ) -> ResolvedVcsRevision:
        """Resolve an immutable commit or the ref known at the recorded-time watermark."""
        if scope.action != "graph.assertion.truth.query":
            raise GraphAuthorizationError(_ERR_ACTION)
        try:
            async with self._store.engine.connect() as connection:
                await _require_repository_authority(
                    connection,
                    scope,
                    selector.repository_id,
                    self._clock.now(),
                )
                watermark = await _graph_watermark(
                    connection,
                    scope.brain_id.value,
                    selector.repository_id,
                    recorded_at,
                )
                if selector.commit_sha is not None:
                    observed_at = await _commit_observed_at(
                        connection,
                        scope.brain_id.value,
                        selector.repository_id,
                        selector.commit_sha,
                        recorded_at,
                    )
                    observed_at = _require_observed_at(observed_at)
                    return ResolvedVcsRevision(
                        selector,
                        selector.commit_sha,
                        watermark,
                        observed_at,
                        None,
                        force_pushed=False,
                    )
                row = await _resolve_ref(
                    connection,
                    scope.brain_id.value,
                    selector.repository_id,
                    cast("str", selector.branch_name),
                    recorded_at,
                )
                row = _require_ref_row(row)
                previous = await _previous_ref(
                    connection,
                    scope.brain_id.value,
                    selector.repository_id,
                    cast("str", selector.branch_name),
                    int(str(row["observed_at"])),
                    str(row["observation_id"]),
                    recorded_at,
                )
                force_pushed = False
                if previous is not None:
                    force_pushed = not await _is_ancestor(
                        connection,
                        scope.brain_id.value,
                        selector.repository_id,
                        str(previous["commit_sha"]),
                        str(row["commit_sha"]),
                        recorded_at,
                    )
                return ResolvedVcsRevision(
                    selector,
                    str(row["commit_sha"]),
                    watermark,
                    _time(row["observed_at"]),
                    str(row["observation_id"]),
                    force_pushed=force_pushed,
                )
        except GraphAuthorizationError, GraphConflictError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def prove(
        self,
        scope: AuthorizedScope,
        evidence_id: str,
        anchor: EvidenceRevisionAnchor | None,
        resolved: ResolvedVcsRevision,
        recorded_at: datetime,
    ) -> RevisionEvidenceProof:
        """Prove ancestry and descendant invalidations for one evidence lineage."""
        if scope.action != "graph.assertion.truth.query":
            raise GraphAuthorizationError(_ERR_ACTION)
        if anchor is not None and anchor.evidence_id != evidence_id:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        try:
            async with self._store.engine.connect() as connection:
                await _require_repository_authority(
                    connection,
                    scope,
                    resolved.selector.repository_id,
                    self._clock.now(),
                )
                anchor_reachable = False
                invalidations: list[str] = []
                if anchor is not None and anchor.repository_id == resolved.selector.repository_id:
                    anchor_reachable = await _is_ancestor(
                        connection,
                        scope.brain_id.value,
                        anchor.repository_id,
                        anchor.commit_sha,
                        resolved.commit_sha,
                        recorded_at,
                    )
                    if anchor_reachable:
                        impacts = await _impacts(
                            connection,
                            scope.brain_id.value,
                            anchor.repository_id,
                            evidence_id,
                            recorded_at,
                        )
                        for commit_sha in impacts:
                            if await _is_ancestor(
                                connection,
                                scope.brain_id.value,
                                anchor.repository_id,
                                commit_sha,
                                resolved.commit_sha,
                                recorded_at,
                            ):
                                invalidations.append(commit_sha)  # noqa: PERF401
                return RevisionEvidencePolicy.proof(
                    evidence_id,
                    anchor,
                    resolved,
                    anchor_reachable=anchor_reachable,
                    reachable_invalidations=tuple(invalidations),
                )
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


async def _anchors(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    evidence_ids: tuple[str, ...],
    recorded_at: datetime,
) -> dict[str, EvidenceRevisionAnchor]:
    if not evidence_ids:
        return {}
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT a.* FROM assertion_evidence_revision_anchors AS a "
                    "JOIN assertion_evidence_sources AS s ON s.evidence_id=a.evidence_id "
                    "WHERE a.brain_id=:brain AND a.evidence_id IN "
                    "(SELECT value FROM json_each(:ids)) AND s.brain_id=:brain "
                    "AND a.revision_observed_at<=:recorded AND a.anchored_at<=:recorded "
                    "AND s.classification IN (SELECT value FROM json_each(:classifications)) "
                    "ORDER BY a.evidence_id"
                ),
                {
                    "brain": scope.brain_id.value,
                    "ids": json.dumps(evidence_ids, separators=(",", ":")),
                    "recorded": _micros(recorded_at),
                    "classifications": json.dumps(_classifications(scope), separators=(",", ":")),
                },
            )
        )
        .mappings()
        .all()
    )
    anchors: dict[str, EvidenceRevisionAnchor] = {}
    for row in rows:
        anchor = EvidenceRevisionAnchor(
            str(row["evidence_id"]),
            str(row["repository_id"]),
            str(row["checkout_id"]),
            str(row["commit_sha"]),
            None if row["branch_at_capture"] is None else str(row["branch_at_capture"]),
            _time(row["revision_observed_at"]),
        )
        if anchor.evidence_id in anchors:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        anchors[anchor.evidence_id] = anchor
    return anchors


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


async def _require_repository_authority(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    repository_id: str,
    checked_at: datetime,
) -> None:
    members = [
        {
            "project_id": member.project_id.value,
            "repository_ids": [item.value for item in member.repository_ids],
        }
        for member in scope.members
    ]
    authorized = await connection.scalar(
        text(
            "SELECT EXISTS(SELECT 1 FROM repositories AS r "
            "JOIN brains AS b ON b.id=r.brain_id "
            "JOIN principals AS p ON p.id=:principal "
            "WHERE r.id=:repository AND r.brain_id=:brain AND r.status='active' "
            "AND b.status='active' AND p.status='active' AND EXISTS ("
            "SELECT 1 FROM json_each(:members) AS m WHERE r.id IN "
            "(SELECT value FROM json_each(json_extract(m.value,'$.repository_ids')))"
            ") AND EXISTS (SELECT 1 FROM scope_grants AS g WHERE g.principal_id=:principal "
            "AND g.brain_id=:brain AND g.role IN ('owner','admin','editor','reader') "
            "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now) "
            "AND (g.repository_id IS NULL OR g.repository_id=:repository) AND ("
            "g.project_id IS NULL OR EXISTS (SELECT 1 FROM project_repositories AS pr "
            "JOIN json_each(:members) AS m ON json_extract(m.value,'$.project_id')=pr.project_id "
            "WHERE pr.repository_id=:repository AND pr.project_id=g.project_id))))"
        ),
        {
            "principal": scope.principal_id.value,
            "brain": scope.brain_id.value,
            "repository": repository_id,
            "members": json.dumps(members, sort_keys=True, separators=(",", ":")),
            "now": _micros(checked_at),
        },
    )
    if int(str(authorized)) != 1:
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)


async def _batch(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM vcs_revision_batches WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _verify_batch(
    row: RowMapping,
    scope: AuthorizedScope,
    batch: VcsRevisionBatch,
) -> None:
    actual = (
        str(row["brain_id"]),
        str(row["principal_id"]),
        _bytes(row["scope_fingerprint"]),
        str(row["repository_id"]),
        _bytes(row["batch_digest"]),
        _bytes(row["source_digest"]),
        int(str(row["node_count"])),
        int(str(row["ref_count"])),
        int(str(row["impact_count"])),
        int(str(row["observed_at"])),
    )
    expected = (
        batch.brain_id,
        scope.principal_id.value,
        scope.scope_fingerprint,
        batch.repository_id,
        batch.digest,
        batch.source_digest,
        len(batch.nodes),
        len(batch.refs),
        len(batch.impacts),
        _micros(batch.observed_at),
    )
    if actual != expected:
        raise GraphConflictError(_ERR_CONFLICT)


async def _validate_existing_commits(
    connection: AsyncConnection,
    batch: VcsRevisionBatch,
) -> None:
    for node in batch.nodes:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT brain_id,first_observed_at FROM vcs_commits "
                        "WHERE repository_id=:repository "
                        "AND commit_sha=:commit"
                    ),
                    {"repository": batch.repository_id, "commit": node.commit_sha},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            continue
        parents = (
            await connection.execute(
                text(
                    "SELECT parent_sha FROM vcs_commit_parents WHERE repository_id=:repository "
                    "AND child_sha=:commit ORDER BY parent_sha"
                ),
                {"repository": batch.repository_id, "commit": node.commit_sha},
            )
        ).scalars()
        if (
            str(row["brain_id"]) != batch.brain_id
            or int(str(row["first_observed_at"])) > _micros(batch.observed_at)
            or tuple(str(item) for item in parents) != node.parent_shas
        ):
            raise GraphConflictError(_ERR_CONFLICT)


async def _require_known_commit_references(
    connection: AsyncConnection,
    batch: VcsRevisionBatch,
) -> None:
    supplied = {item.commit_sha for item in batch.nodes}
    referenced = {
        parent for node in batch.nodes for parent in node.parent_shas if parent not in supplied
    }
    referenced.update(item.commit_sha for item in batch.refs if item.commit_sha not in supplied)
    referenced.update(
        item.invalidating_commit_sha
        for item in batch.impacts
        if item.invalidating_commit_sha not in supplied
    )
    if not referenced:
        return
    known = (
        await connection.execute(
            text(
                "SELECT commit_sha FROM vcs_commits WHERE brain_id=:brain "
                "AND repository_id=:repository AND commit_sha IN "
                "(SELECT value FROM json_each(:commits)) AND first_observed_at<=:observed"
            ),
            {
                "brain": batch.brain_id,
                "repository": batch.repository_id,
                "commits": json.dumps(sorted(referenced), separators=(",", ":")),
                "observed": _micros(batch.observed_at),
            },
        )
    ).scalars()
    if {str(item) for item in known} != referenced:
        raise GraphConflictError(_ERR_CONFLICT)


async def _insert_batch(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    batch: VcsRevisionBatch,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO vcs_revision_batches "
            "(operation_id,brain_id,principal_id,repository_id,scope_fingerprint,batch_digest,"
            "source_digest,node_count,ref_count,impact_count,observed_at,schema_version) VALUES "
            "(:operation,:brain,:principal,:repository,:scope,:batch,:source,:nodes,:refs,"
            ":impacts,:observed,1)"
        ),
        {
            "operation": batch.operation_id,
            "brain": batch.brain_id,
            "principal": scope.principal_id.value,
            "repository": batch.repository_id,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "batch": bytes.fromhex(batch.digest),
            "source": bytes.fromhex(batch.source_digest),
            "nodes": len(batch.nodes),
            "refs": len(batch.refs),
            "impacts": len(batch.impacts),
            "observed": _micros(batch.observed_at),
        },
    )


async def _insert_commits_and_parents(
    connection: AsyncConnection,
    batch: VcsRevisionBatch,
) -> None:
    for node in batch.nodes:
        await connection.execute(
            text(
                "INSERT INTO vcs_commits "
                "(brain_id,repository_id,commit_sha,first_batch_id,first_observed_at,"
                "schema_version) "
                "VALUES (:brain,:repository,:commit,:batch,:observed,1) "
                "ON CONFLICT(repository_id,commit_sha) DO NOTHING"
            ),
            {
                "brain": batch.brain_id,
                "repository": batch.repository_id,
                "commit": node.commit_sha,
                "batch": batch.operation_id,
                "observed": _micros(batch.observed_at),
            },
        )
    for node in batch.nodes:
        for parent_sha in node.parent_shas:
            await connection.execute(
                text(
                    "INSERT INTO vcs_commit_parents "
                    "(brain_id,repository_id,child_sha,parent_sha,batch_id,observed_at,"
                    "schema_version) VALUES (:brain,:repository,:child,:parent,:batch,:observed,1) "
                    "ON CONFLICT(repository_id,child_sha,parent_sha) DO NOTHING"
                ),
                {
                    "brain": batch.brain_id,
                    "repository": batch.repository_id,
                    "child": node.commit_sha,
                    "parent": parent_sha,
                    "batch": batch.operation_id,
                    "observed": _micros(batch.observed_at),
                },
            )


async def _insert_refs(connection: AsyncConnection, batch: VcsRevisionBatch) -> None:
    for reference in batch.refs:
        await connection.execute(
            text(
                "INSERT INTO vcs_ref_observations "
                "(observation_id,brain_id,repository_id,branch_name,commit_sha,batch_id,"
                "observed_at,schema_version) VALUES "
                "(:id,:brain,:repository,:branch,:commit,:batch,:observed,1)"
            ),
            {
                "id": _scoped_ref_id(batch, reference.id),
                "brain": batch.brain_id,
                "repository": batch.repository_id,
                "branch": reference.branch_name,
                "commit": reference.commit_sha,
                "batch": batch.operation_id,
                "observed": _micros(reference.observed_at),
            },
        )


async def _insert_impacts(connection: AsyncConnection, batch: VcsRevisionBatch) -> None:
    for impact in batch.impacts:
        source = (
            (
                await connection.execute(
                    text(
                        "SELECT s.brain_id,s.repository_id,a.commit_sha FROM "
                        "assertion_evidence_sources AS s JOIN "
                        "assertion_evidence_revision_anchors AS a "
                        "ON a.evidence_id=s.evidence_id WHERE s.evidence_id=:evidence"
                    ),
                    {"evidence": impact.evidence_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if source is None or (str(source["brain_id"]), str(source["repository_id"])) != (
            batch.brain_id,
            batch.repository_id,
        ):
            raise GraphConflictError(_ERR_CONFLICT)
        await connection.execute(
            text(
                "INSERT INTO vcs_evidence_impacts "
                "(impact_id,brain_id,repository_id,evidence_id,invalidating_commit_sha,batch_id,"
                "changed_at,schema_version) VALUES "
                "(:id,:brain,:repository,:evidence,:commit,:batch,:changed,1)"
            ),
            {
                "id": impact.id,
                "brain": batch.brain_id,
                "repository": batch.repository_id,
                "evidence": impact.evidence_id,
                "commit": impact.invalidating_commit_sha,
                "batch": batch.operation_id,
                "changed": _micros(impact.changed_at),
            },
        )


async def _cycle_exists(connection: AsyncConnection, repository_id: str) -> bool:
    found = await connection.scalar(
        text(
            "WITH RECURSIVE walk(origin,node,depth,path,cycle) AS ("
            "SELECT child_sha,parent_sha,1,','||child_sha||','||parent_sha||',',0 "
            "FROM vcs_commit_parents WHERE repository_id=:repository UNION ALL "
            "SELECT w.origin,p.parent_sha,w.depth+1,w.path||p.parent_sha||',',"
            "CASE WHEN instr(w.path,','||p.parent_sha||',')>0 THEN 1 ELSE 0 END "
            "FROM walk AS w JOIN vcs_commit_parents AS p ON p.repository_id=:repository "
            "AND p.child_sha=w.node WHERE w.cycle=0 AND w.depth<:depth) "
            "SELECT EXISTS(SELECT 1 FROM walk WHERE cycle=1 OR origin=node)"
        ),
        {"repository": repository_id, "depth": _MAX_ANCESTRY_DEPTH},
    )
    return int(str(found)) == 1


async def _graph_watermark(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    recorded_at: datetime,
) -> str:
    rows = (
        await connection.execute(
            text(
                "SELECT batch_digest FROM vcs_revision_batches WHERE brain_id=:brain "
                "AND repository_id=:repository AND observed_at<=:recorded "
                "ORDER BY observed_at,operation_id"
            ),
            {
                "brain": brain_id,
                "repository": repository_id,
                "recorded": _micros(recorded_at),
            },
        )
    ).scalars()
    digests = tuple(_bytes(item) for item in rows)
    if not digests:
        raise GraphConflictError(_ERR_UNKNOWN)
    payload = "\0".join(digests)
    return hashlib.sha256(f"vcs-graph-watermark.v1\0{payload}".encode()).hexdigest()


async def _commit_observed_at(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    commit_sha: str,
    recorded_at: datetime,
) -> datetime | None:
    value = await connection.scalar(
        text(
            "SELECT first_observed_at FROM vcs_commits WHERE brain_id=:brain "
            "AND repository_id=:repository AND commit_sha=:commit "
            "AND first_observed_at<=:recorded"
        ),
        {
            "brain": brain_id,
            "repository": repository_id,
            "commit": commit_sha,
            "recorded": _micros(recorded_at),
        },
    )
    return None if value is None else _time(value)


async def _resolve_ref(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    branch_name: str,
    recorded_at: datetime,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT r.* FROM vcs_ref_observations AS r JOIN vcs_revision_batches AS b "
                    "ON b.operation_id=r.batch_id WHERE r.brain_id=:brain "
                    "AND r.repository_id=:repository AND r.branch_name=:branch "
                    "AND r.observed_at<=:recorded AND b.observed_at<=:recorded "
                    "ORDER BY r.observed_at DESC,b.observed_at DESC,r.observation_id DESC LIMIT 1"
                ),
                {
                    "brain": brain_id,
                    "repository": repository_id,
                    "branch": branch_name,
                    "recorded": _micros(recorded_at),
                },
            )
        )
        .mappings()
        .one_or_none()
    )


async def _previous_ref(  # noqa: PLR0913 -- Ref identity needs all temporal coordinates.
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    branch_name: str,
    observed_at: int,
    observation_id: str,
    recorded_at: datetime,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT r.* FROM vcs_ref_observations AS r JOIN vcs_revision_batches AS b "
                    "ON b.operation_id=r.batch_id WHERE r.brain_id=:brain "
                    "AND r.repository_id=:repository AND r.branch_name=:branch "
                    "AND (r.observed_at<:observed OR (r.observed_at=:observed "
                    "AND r.observation_id<:id)) AND b.observed_at<=:recorded "
                    "ORDER BY r.observed_at DESC,r.observation_id DESC LIMIT 1"
                ),
                {
                    "brain": brain_id,
                    "repository": repository_id,
                    "branch": branch_name,
                    "observed": observed_at,
                    "id": observation_id,
                    "recorded": _micros(recorded_at),
                },
            )
        )
        .mappings()
        .one_or_none()
    )


async def _is_ancestor(  # noqa: PLR0913 -- Reachability coordinates are irreducible.
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    ancestor_sha: str,
    descendant_sha: str,
    recorded_at: datetime,
) -> bool:
    known = await connection.scalar(
        text(
            "SELECT COUNT(*) FROM vcs_commits WHERE brain_id=:brain "
            "AND repository_id=:repository AND commit_sha IN (:ancestor,:descendant) "
            "AND first_observed_at<=:recorded"
        ),
        {
            "brain": brain_id,
            "repository": repository_id,
            "ancestor": ancestor_sha,
            "descendant": descendant_sha,
            "recorded": _micros(recorded_at),
        },
    )
    required = 1 if ancestor_sha == descendant_sha else 2
    if int(str(known)) != required:
        return False
    if ancestor_sha == descendant_sha:
        return True
    found = await connection.scalar(
        text(
            "WITH RECURSIVE ancestors(commit_sha,depth,path) AS ("
            "SELECT :descendant,0,','||:descendant||',' UNION ALL "
            "SELECT p.parent_sha,a.depth+1,a.path||p.parent_sha||',' "
            "FROM ancestors AS a JOIN vcs_commit_parents AS p "
            "ON p.repository_id=:repository AND p.child_sha=a.commit_sha "
            "JOIN vcs_revision_batches AS b ON b.operation_id=p.batch_id "
            "WHERE p.brain_id=:brain AND p.observed_at<=:recorded "
            "AND b.observed_at<=:recorded AND a.depth<:depth "
            "AND instr(a.path,','||p.parent_sha||',')=0) "
            "SELECT EXISTS(SELECT 1 FROM ancestors WHERE commit_sha=:ancestor)"
        ),
        {
            "brain": brain_id,
            "repository": repository_id,
            "ancestor": ancestor_sha,
            "descendant": descendant_sha,
            "recorded": _micros(recorded_at),
            "depth": _MAX_ANCESTRY_DEPTH,
        },
    )
    return int(str(found)) == 1


async def _impacts(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    evidence_id: str,
    recorded_at: datetime,
) -> tuple[str, ...]:
    rows = (
        await connection.execute(
            text(
                "SELECT i.invalidating_commit_sha FROM vcs_evidence_impacts AS i "
                "JOIN vcs_revision_batches AS b ON b.operation_id=i.batch_id "
                "WHERE i.brain_id=:brain AND i.repository_id=:repository "
                "AND i.evidence_id=:evidence AND i.changed_at<=:recorded "
                "AND b.observed_at<=:recorded ORDER BY i.invalidating_commit_sha "
                "LIMIT :limit"
            ),
            {
                "brain": brain_id,
                "repository": repository_id,
                "evidence": evidence_id,
                "recorded": _micros(recorded_at),
                "limit": _MAX_IMPACTS_PER_EVIDENCE + 1,
            },
        )
    ).scalars()
    values = tuple(str(item) for item in rows)
    if len(values) > _MAX_IMPACTS_PER_EVIDENCE:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return values


def _scoped_ref_id(batch: VcsRevisionBatch, local_id: str) -> str:
    payload = f"vcs-ref-scoped.v1\0{batch.brain_id}\0{batch.repository_id}\0{local_id}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _classifications(scope: AuthorizedScope) -> tuple[str, ...]:
    values = ("public", "internal", "confidential", "restricted", "local_only")
    return values[: values.index(scope.classification_ceiling.value) + 1]


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return round(value.timestamp() * 1_000_000)


def _time(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _bytes(value: object) -> str:
    if not isinstance(value, bytes) or len(value) != _SHA256_BYTES:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return value.hex()


def _bounded_candidates(
    candidates: list[TemporalAssertionCandidate],
    limit: int,
) -> tuple[TemporalAssertionCandidate, ...]:
    if len(candidates) > limit:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return tuple(candidates)


def _reject_cycle(*, cycle_exists: bool) -> None:
    if cycle_exists:
        raise GraphConflictError(_ERR_CONFLICT)


def _require_observed_at(value: datetime | None) -> datetime:
    if value is None:
        raise GraphConflictError(_ERR_UNKNOWN)
    return value


def _require_ref_row(row: RowMapping | None) -> RowMapping:
    if row is None:
        raise GraphConflictError(_ERR_UNKNOWN)
    return row
