"""IDX-003 SQLite commit-graph proofs, source history, and evidence lineage."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.domain.temporal_truth import EvidenceRevisionImpact, VcsRevisionBatch
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.revision_history import (
    CommitGraphAnswer,
    CommitGraphQueryKind,
    CommitGraphSnapshot,
    ReextractionAction,
    SourceRevisionChangeKind,
    SourceRevisionHistoryCandidate,
    SourceRevisionOutcome,
    SourceRevisionTransition,
    reextraction_job_id,
)
from agentmemory.indexing.domain.revision_history_ports import SourceRevisionWork

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_MAX_ANCESTRY = 20_000
_MAX_RESULTS = 1_000
_LEASE_SECONDS = 60
_ERR_ACTION = "source revision repository action is not authorized"
_ERR_AUTHORIZATION = "source revision repository scope is not authorized"
_ERR_CONFLICT = "source revision history conflicts with durable state"
_ERR_GRAPH = "commit graph evidence is unavailable"
_ERR_INTEGRITY = "source revision history failed integrity verification"
_ERR_STORAGE = "source revision storage is unavailable"


class SqliteCommitGraphAdapter:
    """Answer Git-equivalent reachability from the canonical persisted commit DAG."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local SQLite graph evidence store."""
        self._store = store

    async def pin_commit(
        self,
        brain_id: str,
        repository_id: str,
        commit_sha: str,
        recorded_at: datetime,
        answered_at: datetime,
    ) -> CommitGraphSnapshot:
        """Pin a known commit and graph digest at an immutable recorded-time cutoff."""
        del answered_at
        try:
            async with self._store.engine.connect() as connection:
                await _require_known_commit(
                    connection, brain_id, repository_id, commit_sha, recorded_at
                )
                digest = await _graph_digest(connection, brain_id, repository_id, recorded_at)
            return CommitGraphSnapshot(
                brain_id,
                repository_id,
                commit_sha,
                digest,
                recorded_at,
            )
        except IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def pin_branch(
        self,
        brain_id: str,
        repository_id: str,
        branch_name: str,
        recorded_at: datetime,
        answered_at: datetime,
    ) -> CommitGraphSnapshot:
        """Resolve a branch once and bind its observation to the same graph digest."""
        del answered_at
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT observation_id,commit_sha FROM vcs_ref_observations "
                                "WHERE brain_id=:brain AND repository_id=:repository "
                                "AND branch_name=:branch AND observed_at<=:recorded "
                                "ORDER BY observed_at DESC,observation_id DESC LIMIT 1"
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
                row = _require_graph_row(row)
                digest = await _graph_digest(connection, brain_id, repository_id, recorded_at)
            return CommitGraphSnapshot(
                brain_id,
                repository_id,
                str(row["commit_sha"]),
                digest,
                recorded_at,
                str(row["observation_id"]),
            )
        except IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def ancestry(
        self,
        snapshot: CommitGraphSnapshot,
        ancestor_sha: str,
        descendant_sha: str,
        answered_at: datetime,
    ) -> CommitGraphAnswer:
        """Return an exact persisted `merge-base --is-ancestor` equivalent."""
        try:
            async with _write_transaction(self._store) as connection:
                await _verify_snapshot(connection, snapshot)
                existing = await _answer(
                    connection,
                    snapshot,
                    CommitGraphQueryKind.ANCESTRY,
                    ancestor_sha,
                    descendant_sha,
                )
                if existing is not None:
                    return existing
                result = await _is_ancestor(
                    connection,
                    snapshot,
                    ancestor_sha,
                    descendant_sha,
                )
                answer = CommitGraphAnswer(
                    CommitGraphQueryKind.ANCESTRY,
                    ancestor_sha,
                    descendant_sha,
                    snapshot.graph_digest,
                    result,
                    (),
                    answered_at,
                )
                await _insert_answer(connection, snapshot, answer)
                return answer
        except IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def merge_bases(
        self,
        snapshot: CommitGraphSnapshot,
        left_sha: str,
        right_sha: str,
        answered_at: datetime,
    ) -> CommitGraphAnswer:
        """Return every best common ancestor, matching `git merge-base --all`."""
        try:
            async with _write_transaction(self._store) as connection:
                await _verify_snapshot(connection, snapshot)
                existing = await _answer(
                    connection,
                    snapshot,
                    CommitGraphQueryKind.MERGE_BASE,
                    left_sha,
                    right_sha,
                )
                if existing is not None:
                    return existing
                bases = await _merge_bases(connection, snapshot, left_sha, right_sha)
                bases = _require_merge_bases(bases)
                answer = CommitGraphAnswer(
                    CommitGraphQueryKind.MERGE_BASE,
                    left_sha,
                    right_sha,
                    snapshot.graph_digest,
                    None,
                    bases,
                    answered_at,
                )
                await _insert_answer(connection, snapshot, answer)
                return answer
        except IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


class SqliteSourceRevisionRepository:
    """Process committed index events and query authorized retained source history."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind canonical storage and current-grant authorization time."""
        self._store = store
        self._clock = clock

    async def claim_next(self, claimed_at: datetime) -> SourceRevisionWork | None:
        """Lease the oldest unprocessed committed projection after grant revalidation."""
        try:
            async with _write_transaction(self._store) as connection:
                row = await _next_event(connection, claimed_at)
                if row is None:
                    return None
                await _authorize_recorded_run(connection, row, claimed_at)
                event_id = str(row["event_id"])
                await _insert_claim(connection, event_id, claimed_at)
                transition = await _transition(connection, row)
                return SourceRevisionWork(f"idx003.{event_id}", transition)
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def find_outcome(self, operation_id: str, event_id: str) -> SourceRevisionOutcome | None:
        """Resolve exact operation/event replay without mutable source inspection."""
        try:
            async with self._store.engine.connect() as connection:
                row = await _outcome_row(connection, operation_id, event_id)
                return None if row is None else _decode_outcome(row)
        except IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def complete(
        self,
        work: SourceRevisionWork,
        snapshot: CommitGraphSnapshot,
        answers: tuple[CommitGraphAnswer, ...],
        processed_at: datetime,
    ) -> SourceRevisionOutcome:
        """Append context, ancestry invalidations, graph impacts, job, and receipt atomically."""
        transition = work.transition
        _verify_completion_inputs(transition, snapshot, answers)
        try:
            async with _write_transaction(self._store) as connection:
                replay = await _outcome_row(connection, work.operation_id, transition.event_id)
                if replay is not None:
                    result = _decode_outcome(replay)
                    _conflict_if(result.transition_digest != transition.digest)
                    return result
                row = await _event_by_id(connection, transition.event_id)
                row = _require_event_row(row)
                await _authorize_recorded_run(connection, row, processed_at)
                await _insert_context(connection, transition)
                previous_context_id = await _previous_context_id(connection, transition)
                if previous_context_id is not None:
                    await _insert_context_invalidation(
                        connection,
                        previous_context_id,
                        transition,
                        transition.occurred_at,
                    )
                await _append_derived_lineage(
                    connection,
                    transition,
                    previous_context_id,
                    transition.occurred_at,
                )
                closed = await _append_revision_impacts(connection, transition, row)
                action = (
                    ReextractionAction.RETRACT
                    if transition.kind is SourceRevisionChangeKind.DELETE
                    else ReextractionAction.EXTRACT
                )
                job_id = reextraction_job_id(transition.context_id, action)
                await _insert_job(connection, job_id, transition.context_id, action, processed_at)
                outcome = SourceRevisionOutcome(
                    work.operation_id,
                    transition.event_id,
                    transition.digest,
                    transition.context_id,
                    snapshot.graph_digest,
                    tuple(sorted(answer.id for answer in answers)),
                    job_id,
                    action,
                    closed,
                    len(transition.affected_assertion_ids),
                    processed_at,
                )
                await _insert_outcome(connection, outcome)
                return outcome
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def candidates(
        self,
        scope: AuthorizedScope,
        repository_id: str,
        relative_path: str,
        recorded_at: datetime,
        limit: int,
    ) -> tuple[SourceRevisionHistoryCandidate, ...]:
        """Return append-only source contexts after current grant revalidation."""
        _require_action(scope, frozenset({"indexing.revision.history.read"}))
        try:
            async with self._store.engine.connect() as connection:
                await _authorize_scope(connection, scope, repository_id, self._clock.now())
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT context.* FROM source_revision_contexts AS context "
                                "WHERE context.brain_id=:brain "
                                "AND context.repository_id=:repository "
                                "AND (context.relative_path=:path OR context.previous_path=:path) "
                                "AND context.observed_at<=:recorded ORDER BY context.observed_at,"
                                "context.context_id LIMIT :limit"
                            ),
                            {
                                "brain": scope.brain_id.value,
                                "repository": repository_id,
                                "path": relative_path,
                                "recorded": _micros(recorded_at),
                                "limit": min(limit, _MAX_RESULTS) + 1,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
                _require_result_limit(len(rows), min(limit, _MAX_RESULTS))
                return tuple(
                    [await _history_candidate(connection, row, recorded_at) for row in rows]
                )
        except IndexingAuthorizationError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def register_lineage(  # noqa: PLR0913 -- Port binds the complete lineage mutation.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        context_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        """Append or exactly replay a source → evidence → assertion reverse edge."""
        _require_action(scope, frozenset({"indexing.revision.lineage.register"}))
        digest = _lineage_digest(context_id, evidence_id, assertion_id)
        try:
            async with _write_transaction(self._store) as connection:
                context = await _context(connection, context_id)
                context = _require_context(context)
                await _authorize_scope(
                    connection, scope, str(context["repository_id"]), self._clock.now()
                )
                replay = await _registration(connection, operation_id)
                if replay is not None:
                    _conflict_if(_blob(replay["registration_digest"]).hex() != digest)
                    return digest
                await _validate_evidence_assertion(
                    connection,
                    str(context["brain_id"]),
                    str(context["project_id"]),
                    str(context["repository_id"]),
                    evidence_id,
                    assertion_id,
                )
                await _insert_lineage(
                    connection, context_id, evidence_id, assertion_id, registered_at
                )
                await connection.execute(
                    text(
                        "INSERT INTO source_revision_lineage_registrations "
                        "(operation_id,context_id,evidence_id,assertion_id,principal_id,"
                        "scope_fingerprint,registration_digest,registered_at,schema_version) "
                        "VALUES (:operation,:context,:evidence,:assertion,:principal,:scope,"
                        ":digest,:at,1)"
                    ),
                    {
                        "operation": operation_id,
                        "context": context_id,
                        "evidence": evidence_id,
                        "assertion": assertion_id,
                        "principal": scope.principal_id.value,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "digest": bytes.fromhex(digest),
                        "at": _micros(registered_at),
                    },
                )
                return digest
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


async def _next_event(connection: AsyncConnection, claimed_at: datetime) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT event.*,run.brain_id,run.project_id,run.repository_id,"
                    "run.principal_id,run.role,run.scope_fingerprint,run.base_snapshot_id,"
                    "run.target_commit_id,run.target_snapshot_id FROM index_projection_events "
                    "AS event JOIN incremental_index_runs AS run ON run.run_id=event.run_id "
                    "JOIN incremental_index_run_revision_contexts AS context "
                    "ON context.run_id=run.run_id LEFT JOIN source_revision_processing_receipts "
                    "AS receipt ON receipt.event_id=event.event_id WHERE receipt.event_id IS NULL "
                    "AND context.revision_context='committed' AND run.target_commit_id IS NOT NULL "
                    "AND NOT EXISTS (SELECT 1 FROM source_revision_claim_snapshots AS claim "
                    "WHERE claim.event_id=event.event_id AND claim.leased_until>:now AND "
                    "claim.claim_version=(SELECT MAX(newer.claim_version) FROM "
                    "source_revision_claim_snapshots AS newer "
                    "WHERE newer.event_id=event.event_id)) "
                    "ORDER BY event.occurred_at,event.event_id LIMIT 1"
                ),
                {"now": _micros(claimed_at)},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _event_by_id(connection: AsyncConnection, event_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT event.*,run.brain_id,run.project_id,run.repository_id,"
                    "run.principal_id,run.role,run.scope_fingerprint,run.base_snapshot_id,"
                    "run.target_commit_id,run.target_snapshot_id FROM index_projection_events "
                    "AS event JOIN incremental_index_runs AS run ON run.run_id=event.run_id "
                    "WHERE event.event_id=:event"
                ),
                {"event": event_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _insert_claim(connection: AsyncConnection, event_id: str, claimed_at: datetime) -> None:
    version = int(
        await connection.scalar(
            text(
                "SELECT COALESCE(MAX(claim_version),-1)+1 FROM source_revision_claim_snapshots "
                "WHERE event_id=:event"
            ),
            {"event": event_id},
        )
    )
    await connection.execute(
        text(
            "INSERT INTO source_revision_claim_snapshots "
            "(event_id,claim_version,leased_until,claimed_at,schema_version) "
            "VALUES (:event,:version,:lease,:at,1)"
        ),
        {
            "event": event_id,
            "version": version,
            "lease": _micros(claimed_at + timedelta(seconds=_LEASE_SECONDS)),
            "at": _micros(claimed_at),
        },
    )


async def _transition(connection: AsyncConnection, event: RowMapping) -> SourceRevisionTransition:
    operation = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM incremental_index_plan_operations WHERE run_id=:run "
                    "AND ordinal=:ordinal"
                ),
                {"run": event["run_id"], "ordinal": event["ordinal"]},
            )
        )
        .mappings()
        .one()
    )
    current_revisions = _ids(event["current_file_revision_ids_json"])
    previous_revisions = _ids(event["previous_file_revision_ids_json"])
    current = (
        None if not current_revisions else await _file_revision(connection, current_revisions[0])
    )
    previous = (
        None if not previous_revisions else await _file_revision(connection, previous_revisions[0])
    )
    selected = current or previous
    if selected is None:
        raise IndexingConflictError(_ERR_INTEGRITY)
    source_file_id = str(selected["file_id"])
    previous_source_file_id = None if previous is None else str(previous["file_id"])
    affected_evidence = _ids(event["assertion_evidence_ids_json"])
    assertions = await _assertions_for_evidence(connection, affected_evidence)
    base_commit = await _snapshot_commit(connection, event["base_snapshot_id"])
    content = None if current is None else _blob(current["content_digest"]).hex()
    reintroduced = await _reintroduced_context(connection, source_file_id, content)
    kind = _change_kind(str(operation["kind"]), reintroduced=reintroduced is not None)
    return SourceRevisionTransition(
        str(event["event_id"]),
        str(event["run_id"]),
        str(event["brain_id"]),
        str(event["project_id"]),
        str(event["repository_id"]),
        source_file_id,
        previous_source_file_id,
        str(event["snapshot_id"]),
        None if previous is None else str(previous["snapshot_id"]),
        None if current is None else str(current["id"]),
        None if previous is None else str(previous["id"]),
        str(operation["relative_path"]),
        None if operation["previous_path"] is None else str(operation["previous_path"]),
        str(event["target_commit_id"]),
        base_commit,
        content,
        None if previous is None else _blob(previous["content_digest"]).hex(),
        kind,
        _ids(event["reembed_semantic_ids_json"]),
        affected_evidence,
        assertions,
        reintroduced,
        _datetime(event["occurred_at"]),
    )


def _change_kind(kind: str, *, reintroduced: bool) -> SourceRevisionChangeKind:
    if reintroduced and kind != "delete":
        return SourceRevisionChangeKind.REINTRODUCE
    mapping = {
        "add": SourceRevisionChangeKind.ADD,
        "modify": SourceRevisionChangeKind.MODIFY,
        "rename": SourceRevisionChangeKind.RENAME,
        "delete": SourceRevisionChangeKind.DELETE,
    }
    try:
        return mapping[kind]
    except KeyError as error:
        raise IndexingConflictError(_ERR_INTEGRITY) from error


async def _reintroduced_context(
    connection: AsyncConnection, source_file_id: str, content_digest: str | None
) -> str | None:
    if content_digest is None:
        return None
    value = await connection.scalar(
        text(
            "SELECT context.context_id FROM source_revision_contexts AS context "
            "JOIN source_revision_context_invalidations AS invalidation "
            "ON invalidation.context_id=context.context_id WHERE context.source_file_id=:file "
            "AND context.content_digest=:content ORDER BY context.observed_at DESC LIMIT 1"
        ),
        {"file": source_file_id, "content": bytes.fromhex(content_digest)},
    )
    return None if value is None else str(value)


async def _insert_context(
    connection: AsyncConnection, transition: SourceRevisionTransition
) -> None:
    await connection.execute(
        text(
            "INSERT INTO source_revision_contexts "
            "(context_id,event_id,run_id,brain_id,project_id,repository_id,source_file_id,"
            "previous_source_file_id,snapshot_id,previous_snapshot_id,file_revision_id,"
            "previous_file_revision_id,relative_path,previous_path,commit_sha,base_commit_sha,"
            "content_digest,previous_content_digest,change_kind,transition_digest,"
            "reintroduced_from_context_id,observed_at,schema_version) VALUES "
            "(:context,:event,:run,:brain,:project,:repository,:file,:previous_file,:snapshot,"
            ":previous_snapshot,:revision,:previous_revision,:path,:previous_path,:commit,:base,"
            ":content,:previous_content,:kind,:digest,:reintroduced,:at,1)"
        ),
        {
            "context": transition.context_id,
            "event": transition.event_id,
            "run": transition.run_id,
            "brain": transition.brain_id,
            "project": transition.project_id,
            "repository": transition.repository_id,
            "file": transition.source_file_id,
            "previous_file": transition.previous_source_file_id,
            "snapshot": transition.snapshot_id,
            "previous_snapshot": transition.previous_snapshot_id,
            "revision": transition.file_revision_id,
            "previous_revision": transition.previous_file_revision_id,
            "path": transition.relative_path,
            "previous_path": transition.previous_path,
            "commit": transition.commit_sha,
            "base": transition.base_commit_sha,
            "content": _optional_digest(transition.content_digest),
            "previous_content": _optional_digest(transition.previous_content_digest),
            "kind": transition.kind.value,
            "digest": bytes.fromhex(transition.digest),
            "reintroduced": transition.reintroduced_from_context_id,
            "at": _micros(transition.occurred_at),
        },
    )


async def _previous_context_id(
    connection: AsyncConnection, transition: SourceRevisionTransition
) -> str | None:
    if transition.previous_file_revision_id is None:
        return None
    value = await connection.scalar(
        text("SELECT context_id FROM source_revision_contexts WHERE file_revision_id=:revision"),
        {"revision": transition.previous_file_revision_id},
    )
    return None if value is None else str(value)


async def _insert_context_invalidation(
    connection: AsyncConnection,
    context_id: str,
    transition: SourceRevisionTransition,
    invalidated_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO source_revision_context_invalidations "
            "(context_id,invalidating_commit_sha,invalidating_event_id,invalidated_at,"
            "schema_version) VALUES (:context,:commit,:event,:at,1)"
        ),
        {
            "context": context_id,
            "commit": transition.commit_sha,
            "event": transition.event_id,
            "at": _micros(invalidated_at),
        },
    )


async def _append_derived_lineage(
    connection: AsyncConnection,
    transition: SourceRevisionTransition,
    previous_context_id: str | None,
    registered_at: datetime,
) -> None:
    if previous_context_id is not None:
        for evidence_id in transition.affected_evidence_ids:
            assertions = await _assertions_for_evidence(connection, (evidence_id,))
            for assertion_id in assertions:
                await _insert_lineage(
                    connection,
                    previous_context_id,
                    evidence_id,
                    assertion_id,
                    registered_at,
                )
    if not transition.current_semantic_ids:
        return
    dependencies = await _semantic_evidence(connection, transition.current_semantic_ids)
    for evidence_id in dependencies:
        for assertion_id in await _assertions_for_evidence(connection, (evidence_id,)):
            await _insert_lineage(
                connection,
                transition.context_id,
                evidence_id,
                assertion_id,
                registered_at,
            )


async def _append_revision_impacts(
    connection: AsyncConnection,
    transition: SourceRevisionTransition,
    run: RowMapping,
) -> int:
    impacts: list[EvidenceRevisionImpact] = []
    for evidence_id in transition.affected_evidence_ids:
        existing = await connection.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM vcs_evidence_impacts WHERE evidence_id=:evidence "
                "AND invalidating_commit_sha=:commit)"
            ),
            {"evidence": evidence_id, "commit": transition.commit_sha},
        )
        if not bool(existing):
            impacts.append(
                EvidenceRevisionImpact(evidence_id, transition.commit_sha, transition.occurred_at)
            )
    if not impacts:
        return len(transition.affected_evidence_ids)
    operation_id = f"idx003-impact.{transition.event_id}"
    batch = VcsRevisionBatch(
        operation_id,
        transition.brain_id,
        transition.repository_id,
        (),
        (),
        tuple(sorted(impacts, key=lambda item: item.evidence_id)),
        transition.occurred_at,
        transition.digest,
    )
    await connection.execute(
        text(
            "INSERT INTO vcs_revision_batches "
            "(operation_id,brain_id,principal_id,repository_id,scope_fingerprint,batch_digest,"
            "source_digest,node_count,ref_count,impact_count,observed_at,schema_version) VALUES "
            "(:operation,:brain,:principal,:repository,:scope,:batch,:source,0,0,:impacts,:at,1)"
        ),
        {
            "operation": batch.operation_id,
            "brain": batch.brain_id,
            "principal": str(run["principal_id"]),
            "repository": batch.repository_id,
            "scope": _blob(run["scope_fingerprint"]),
            "batch": bytes.fromhex(batch.digest),
            "source": bytes.fromhex(batch.source_digest),
            "impacts": len(batch.impacts),
            "at": _micros(batch.observed_at),
        },
    )
    for impact in batch.impacts:
        await connection.execute(
            text(
                "INSERT INTO vcs_evidence_impacts "
                "(impact_id,brain_id,repository_id,evidence_id,invalidating_commit_sha,batch_id,"
                "changed_at,schema_version) VALUES "
                "(:id,:brain,:repository,:evidence,:commit,:batch,:at,1)"
            ),
            {
                "id": impact.id,
                "brain": batch.brain_id,
                "repository": batch.repository_id,
                "evidence": impact.evidence_id,
                "commit": impact.invalidating_commit_sha,
                "batch": batch.operation_id,
                "at": _micros(impact.changed_at),
            },
        )
    return len(transition.affected_evidence_ids)


async def _insert_job(
    connection: AsyncConnection,
    job_id: str,
    context_id: str,
    action: ReextractionAction,
    queued_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO source_revision_reextraction_jobs "
            "(job_id,context_id,action,state,queued_at,schema_version) VALUES "
            "(:job,:context,:action,'queued',:at,1)"
        ),
        {
            "job": job_id,
            "context": context_id,
            "action": action.value,
            "at": _micros(queued_at),
        },
    )


async def _insert_outcome(connection: AsyncConnection, outcome: SourceRevisionOutcome) -> None:
    await connection.execute(
        text(
            "INSERT INTO source_revision_processing_receipts "
            "(operation_id,event_id,context_id,transition_digest,graph_digest,"
            "graph_answer_ids_json,job_id,action,closed_evidence_count,"
            "affected_assertion_count,processed_at,schema_version) VALUES "
            "(:operation,:event,:context,:transition,:graph,:answers,:job,:action,:closed,"
            ":assertions,:at,1)"
        ),
        {
            "operation": outcome.operation_id,
            "event": outcome.event_id,
            "context": outcome.context_id,
            "transition": bytes.fromhex(outcome.transition_digest),
            "graph": bytes.fromhex(outcome.graph_digest),
            "answers": _json(outcome.graph_answer_ids),
            "job": outcome.reextraction_job_id,
            "action": outcome.action.value,
            "closed": outcome.closed_evidence_count,
            "assertions": outcome.affected_assertion_count,
            "at": _micros(outcome.processed_at),
        },
    )


async def _outcome_row(
    connection: AsyncConnection, operation_id: str, event_id: str
) -> RowMapping | None:
    by_operation = (
        (
            await connection.execute(
                text("SELECT * FROM source_revision_processing_receipts WHERE operation_id=:id"),
                {"id": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    by_event = (
        (
            await connection.execute(
                text("SELECT * FROM source_revision_processing_receipts WHERE event_id=:event"),
                {"event": event_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if by_operation is not None and by_event is not None:
        _conflict_if(str(by_operation["event_id"]) != str(by_event["event_id"]))
    found = by_operation or by_event
    if found is not None:
        _conflict_if(
            str(found["operation_id"]) != operation_id or str(found["event_id"]) != event_id
        )
    return found


def _decode_outcome(row: RowMapping) -> SourceRevisionOutcome:
    return SourceRevisionOutcome(
        str(row["operation_id"]),
        str(row["event_id"]),
        _blob(row["transition_digest"]).hex(),
        str(row["context_id"]),
        _blob(row["graph_digest"]).hex(),
        _ids(row["graph_answer_ids_json"]),
        str(row["job_id"]),
        ReextractionAction(str(row["action"])),
        int(row["closed_evidence_count"]),
        int(row["affected_assertion_count"]),
        _datetime(row["processed_at"]),
    )


async def _history_candidate(
    connection: AsyncConnection, row: RowMapping, recorded_at: datetime
) -> SourceRevisionHistoryCandidate:
    invalidations = (
        await connection.execute(
            text(
                "SELECT invalidating_commit_sha FROM source_revision_context_invalidations "
                "WHERE context_id=:context AND invalidated_at<=:recorded "
                "ORDER BY invalidating_commit_sha"
            ),
            {"context": row["context_id"], "recorded": _micros(recorded_at)},
        )
    ).scalars()
    lineage = (
        (
            await connection.execute(
                text(
                    "SELECT evidence_id,assertion_id FROM source_revision_evidence_lineage "
                    "WHERE context_id=:context AND registered_at<=:recorded "
                    "ORDER BY evidence_id,assertion_id"
                ),
                {"context": row["context_id"], "recorded": _micros(recorded_at)},
            )
        )
        .mappings()
        .all()
    )
    return SourceRevisionHistoryCandidate(
        str(row["context_id"]),
        str(row["source_file_id"]),
        None if row["file_revision_id"] is None else str(row["file_revision_id"]),
        str(row["snapshot_id"]),
        str(row["relative_path"]),
        str(row["commit_sha"]),
        None if row["content_digest"] is None else _blob(row["content_digest"]).hex(),
        SourceRevisionChangeKind(str(row["change_kind"])),
        tuple(str(value) for value in invalidations),
        tuple(sorted({str(item["evidence_id"]) for item in lineage})),
        tuple(sorted({str(item["assertion_id"]) for item in lineage})),
        (
            None
            if row["reintroduced_from_context_id"] is None
            else str(row["reintroduced_from_context_id"])
        ),
        _datetime(row["observed_at"]),
    )


async def _insert_lineage(
    connection: AsyncConnection,
    context_id: str,
    evidence_id: str,
    assertion_id: str,
    registered_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO source_revision_evidence_lineage "
            "(context_id,evidence_id,assertion_id,registered_at,schema_version) VALUES "
            "(:context,:evidence,:assertion,:at,1) "
            "ON CONFLICT(context_id,evidence_id,assertion_id) DO NOTHING"
        ),
        {
            "context": context_id,
            "evidence": evidence_id,
            "assertion": assertion_id,
            "at": _micros(registered_at),
        },
    )


async def _semantic_evidence(
    connection: AsyncConnection, semantic_ids: tuple[str, ...]
) -> tuple[str, ...]:
    if not semantic_ids:
        return ()
    rows = (
        await connection.execute(
            text(
                "SELECT DISTINCT assertion_evidence_id FROM index_semantic_dependencies "
                "WHERE assertion_evidence_id IS NOT NULL AND source_semantic_id IN "
                "(SELECT value FROM json_each(:ids)) ORDER BY assertion_evidence_id"
            ),
            {"ids": json.dumps(semantic_ids, separators=(",", ":"))},
        )
    ).scalars()
    return tuple(str(value) for value in rows)


async def _assertions_for_evidence(
    connection: AsyncConnection, evidence_ids: tuple[str, ...]
) -> tuple[str, ...]:
    if not evidence_ids:
        return ()
    rows = (
        await connection.execute(
            text(
                "SELECT DISTINCT candidate.assertion_id FROM assertion_candidates AS candidate,"
                "json_each(candidate.evidence_ids_json) AS evidence WHERE evidence.value IN "
                "(SELECT value FROM json_each(:ids)) ORDER BY candidate.assertion_id"
            ),
            {"ids": json.dumps(evidence_ids, separators=(",", ":"))},
        )
    ).scalars()
    return tuple(str(value) for value in rows)


async def _validate_evidence_assertion(  # noqa: PLR0913 -- Exact scope and edge are inseparable.
    connection: AsyncConnection,
    brain_id: str,
    project_id: str,
    repository_id: str,
    evidence_id: str,
    assertion_id: str,
) -> None:
    value = await connection.scalar(
        text(
            "SELECT EXISTS(SELECT 1 FROM assertion_evidence_sources AS evidence "
            "JOIN assertion_candidates AS assertion ON assertion.assertion_id=:assertion "
            "WHERE evidence.evidence_id=:evidence AND evidence.brain_id=:brain "
            "AND evidence.project_id=:project AND evidence.repository_id=:repository "
            "AND EXISTS(SELECT 1 FROM json_each(assertion.evidence_ids_json) AS item "
            "WHERE item.value=evidence.evidence_id))"
        ),
        {
            "brain": brain_id,
            "project": project_id,
            "repository": repository_id,
            "evidence": evidence_id,
            "assertion": assertion_id,
        },
    )
    if not bool(value):
        raise IndexingConflictError(_ERR_CONFLICT)


async def _file_revision(connection: AsyncConnection, revision_id: str) -> RowMapping:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM file_revisions WHERE id=:revision"),
                {"revision": revision_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise IndexingConflictError(_ERR_INTEGRITY)
    return row


async def _snapshot_commit(connection: AsyncConnection, snapshot_id: object) -> str | None:
    if snapshot_id is None:
        return None
    value = await connection.scalar(
        text("SELECT commit_id FROM source_snapshots WHERE id=:snapshot"),
        {"snapshot": snapshot_id},
    )
    return None if value is None else str(value)


async def _context(connection: AsyncConnection, context_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM source_revision_contexts WHERE context_id=:context"),
                {"context": context_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _registration(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM source_revision_lineage_registrations "
                    "WHERE operation_id=:operation"
                ),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _verify_snapshot(connection: AsyncConnection, snapshot: CommitGraphSnapshot) -> None:
    await _require_known_commit(
        connection,
        snapshot.brain_id,
        snapshot.repository_id,
        snapshot.target_commit_sha,
        snapshot.recorded_at,
    )
    current = await _graph_digest(
        connection, snapshot.brain_id, snapshot.repository_id, snapshot.recorded_at
    )
    if current != snapshot.graph_digest:
        raise IndexingConflictError(_ERR_GRAPH)


async def _answer(
    connection: AsyncConnection,
    snapshot: CommitGraphSnapshot,
    kind: CommitGraphQueryKind,
    left: str,
    right: str,
) -> CommitGraphAnswer | None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM commit_graph_query_answers WHERE brain_id=:brain "
                    "AND repository_id=:repository AND query_kind=:kind "
                    "AND left_commit_sha=:left AND right_commit_sha=:right "
                    "AND graph_digest=:graph LIMIT 1"
                ),
                {
                    "brain": snapshot.brain_id,
                    "repository": snapshot.repository_id,
                    "kind": kind.value,
                    "left": left,
                    "right": right,
                    "graph": bytes.fromhex(snapshot.graph_digest),
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    answer = CommitGraphAnswer(
        CommitGraphQueryKind(str(row["query_kind"])),
        str(row["left_commit_sha"]),
        str(row["right_commit_sha"]),
        _blob(row["graph_digest"]).hex(),
        None if row["is_ancestor"] is None else bool(row["is_ancestor"]),
        _ids(row["merge_base_shas_json"]),
        _datetime(row["answered_at"]),
    )
    _conflict_if(answer.id != str(row["answer_id"]))
    return answer


async def _insert_answer(
    connection: AsyncConnection,
    snapshot: CommitGraphSnapshot,
    answer: CommitGraphAnswer,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO commit_graph_query_answers "
            "(answer_id,brain_id,repository_id,query_kind,left_commit_sha,right_commit_sha,"
            "graph_digest,is_ancestor,merge_base_shas_json,recorded_at,answered_at,schema_version) "
            "VALUES (:id,:brain,:repository,:kind,:left,:right,:graph,:ancestor,:bases,"
            ":recorded,:answered,1)"
        ),
        {
            "id": answer.id,
            "brain": snapshot.brain_id,
            "repository": snapshot.repository_id,
            "kind": answer.kind.value,
            "left": answer.left_commit_sha,
            "right": answer.right_commit_sha,
            "graph": bytes.fromhex(answer.graph_digest),
            "ancestor": answer.is_ancestor,
            "bases": _json(answer.merge_base_shas),
            "recorded": _micros(snapshot.recorded_at),
            "answered": _micros(answer.answered_at),
        },
    )


async def _merge_bases(
    connection: AsyncConnection,
    snapshot: CommitGraphSnapshot,
    left: str,
    right: str,
) -> tuple[str, ...]:
    await _require_known_commit(
        connection, snapshot.brain_id, snapshot.repository_id, left, snapshot.recorded_at
    )
    await _require_known_commit(
        connection, snapshot.brain_id, snapshot.repository_id, right, snapshot.recorded_at
    )
    left_ancestors = await _ancestors(connection, snapshot, left)
    right_ancestors = await _ancestors(connection, snapshot, right)
    common = tuple(sorted(left_ancestors & right_ancestors))
    best: list[str] = []
    for candidate in common:
        dominated = False
        for other in common:
            if candidate != other and await _is_ancestor(connection, snapshot, candidate, other):
                dominated = True
                break
        if not dominated:
            best.append(candidate)
    return tuple(best)


async def _ancestors(
    connection: AsyncConnection, snapshot: CommitGraphSnapshot, commit_sha: str
) -> set[str]:
    rows = (
        await connection.execute(
            text(
                "WITH RECURSIVE ancestors(commit_sha,depth,path) AS ("
                "SELECT :commit,0,','||:commit||',' UNION ALL "
                "SELECT parent.parent_sha,ancestor.depth+1,ancestor.path||parent.parent_sha||',' "
                "FROM ancestors AS ancestor JOIN vcs_commit_parents AS parent "
                "ON parent.repository_id=:repository AND parent.child_sha=ancestor.commit_sha "
                "JOIN vcs_revision_batches AS batch ON batch.operation_id=parent.batch_id "
                "WHERE parent.brain_id=:brain AND parent.observed_at<=:recorded "
                "AND batch.observed_at<=:recorded AND ancestor.depth<:depth "
                "AND instr(ancestor.path,','||parent.parent_sha||',')=0) "
                "SELECT commit_sha FROM ancestors"
            ),
            {
                "commit": commit_sha,
                "repository": snapshot.repository_id,
                "brain": snapshot.brain_id,
                "recorded": _micros(snapshot.recorded_at),
                "depth": _MAX_ANCESTRY,
            },
        )
    ).scalars()
    return {str(value) for value in rows}


async def _is_ancestor(
    connection: AsyncConnection,
    snapshot: CommitGraphSnapshot,
    ancestor: str,
    descendant: str,
) -> bool:
    await _require_known_commit(
        connection, snapshot.brain_id, snapshot.repository_id, ancestor, snapshot.recorded_at
    )
    await _require_known_commit(
        connection, snapshot.brain_id, snapshot.repository_id, descendant, snapshot.recorded_at
    )
    return ancestor in await _ancestors(connection, snapshot, descendant)


async def _require_known_commit(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str,
    commit_sha: str,
    recorded_at: datetime,
) -> None:
    value = await connection.scalar(
        text(
            "SELECT EXISTS(SELECT 1 FROM vcs_commits WHERE brain_id=:brain "
            "AND repository_id=:repository AND commit_sha=:commit "
            "AND first_observed_at<=:recorded)"
        ),
        {
            "brain": brain_id,
            "repository": repository_id,
            "commit": commit_sha,
            "recorded": _micros(recorded_at),
        },
    )
    if not bool(value):
        raise IndexingConflictError(_ERR_GRAPH)


async def _graph_digest(
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
    digests = tuple(_blob(value).hex() for value in rows)
    if not digests:
        raise IndexingConflictError(_ERR_GRAPH)
    payload = "\0".join(digests)
    return hashlib.sha256(f"vcs-graph-watermark.v1\0{payload}".encode()).hexdigest()


async def _authorize_recorded_run(
    connection: AsyncConnection, run: RowMapping, now: datetime
) -> None:
    value = await connection.scalar(
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
            "brain": str(run["brain_id"]),
            "project": str(run["project_id"]),
            "repository": str(run["repository_id"]),
            "principal": str(run["principal_id"]),
            "role": str(run["role"]),
            "now": _micros(now),
        },
    )
    if not bool(value):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


async def _authorize_scope(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    repository_id: str,
    now: datetime,
) -> None:
    if repository_id not in {item.value for item in scope.repository_ids}:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    project_id = scope.project_ids[0].value if len(scope.project_ids) == 1 else None
    if project_id is None:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    value = await connection.scalar(
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
            "brain": scope.brain_id.value,
            "project": project_id,
            "repository": repository_id,
            "principal": scope.principal_id.value,
            "role": scope.role.value,
            "now": _micros(now),
        },
    )
    if not bool(value):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _verify_completion_inputs(
    transition: SourceRevisionTransition,
    snapshot: CommitGraphSnapshot,
    answers: tuple[CommitGraphAnswer, ...],
) -> None:
    _conflict_if(
        transition.brain_id != snapshot.brain_id
        or transition.repository_id != snapshot.repository_id
        or transition.commit_sha != snapshot.target_commit_sha
        or any(answer.graph_digest != snapshot.graph_digest for answer in answers)
        or tuple(sorted(answers, key=lambda item: item.id)) != answers
    )


def _lineage_digest(context_id: str, evidence_id: str, assertion_id: str) -> str:
    payload = json.dumps(
        [context_id, evidence_id, assertion_id], separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(f"source-revision-lineage.v1\0{payload}".encode()).hexdigest()


def _ids(value: object) -> tuple[str, ...]:
    try:
        decoded = json.loads(_blob(value).decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IndexingConflictError(_ERR_INTEGRITY) from error
    if not isinstance(decoded, list):
        raise IndexingConflictError(_ERR_INTEGRITY)
    items = cast("list[object]", decoded)
    if any(not isinstance(item, str) for item in items):
        raise IndexingConflictError(_ERR_INTEGRITY)
    result = tuple(cast("str", item) for item in items)
    if result != tuple(sorted(set(result))):
        raise IndexingConflictError(_ERR_INTEGRITY)
    return result


def _json(values: Sequence[str]) -> bytes:
    return json.dumps(list(values), separators=(",", ":"), ensure_ascii=True).encode()


def _optional_digest(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise IndexingConflictError(_ERR_INTEGRITY)


def _datetime(value: object) -> datetime:
    return datetime.fromtimestamp(int(str(value)) / 1_000_000, tz=UTC)


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _require_action(scope: AuthorizedScope, allowed: frozenset[str]) -> None:
    if scope.action not in allowed:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _conflict_if(condition: bool) -> None:  # noqa: FBT001 -- Guard reads as a predicate.
    if condition:
        raise IndexingConflictError(_ERR_CONFLICT)


def _require_graph_row(row: RowMapping | None) -> RowMapping:
    if row is None:
        raise IndexingConflictError(_ERR_GRAPH)
    return row


def _require_context(row: RowMapping | None) -> RowMapping:
    if row is None:
        raise IndexingConflictError(_ERR_CONFLICT)
    return row


def _require_event_row(row: RowMapping | None) -> RowMapping:
    if row is None:
        raise IndexingConflictError(_ERR_INTEGRITY)
    return row


def _require_merge_bases(values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        raise IndexingConflictError(_ERR_GRAPH)
    return values


def _require_result_limit(count: int, limit: int) -> None:
    if count > limit:
        raise IndexingValidationError(_ERR_INTEGRITY)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    connection = await store.engine.connect()
    try:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        yield connection
        await connection.commit()
    except BaseException:
        await connection.rollback()
        raise
    finally:
        await connection.close()
