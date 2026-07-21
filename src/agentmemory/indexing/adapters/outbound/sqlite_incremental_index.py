"""IDX-002 append-only SQLite plans, checkpoints, lineage, bindings, and outbox."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.indexing.adapters.outbound.sqlite_code_index import append_indexed_file
from agentmemory.indexing.domain.code_entities import SourceSnapshot
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.incremental import (
    IndexOperation,
    IndexOperationKind,
    IndexOperationReason,
    IndexPlan,
    IndexProjectionEvent,
    IndexRun,
    IndexRunState,
    PriorIndexedUnit,
)
from agentmemory.indexing.domain.incremental_ports import (
    CompletedIndexManifest,
    IndexOperationCommit,
    IndexWork,
    ProjectionImpact,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_ACTION = "incremental index repository action is not authorized"
_ERR_AUTHORIZATION = "incremental index repository scope is not authorized"
_ERR_CONFLICT = "incremental index operation conflicts with durable history"
_ERR_INTEGRITY = "incremental index history failed integrity verification"
_ERR_STORAGE = "incremental index storage is unavailable"
_USER_ACTIONS = frozenset({"indexing.run.start", "indexing.run.read", "indexing.run.cancel"})
_WRITE_ROLES = frozenset({"owner", "admin", "editor", "worker"})
_READ_ROLES = frozenset({"owner", "admin", "editor", "reader", "auditor", "worker"})
_LEASE_SECONDS = 60
_DEPENDENCY_LIMIT = 100_000


class SqliteIncrementalIndexRepository:
    """Serve authorized API use cases and trusted worker operations over one journal."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical single-writer store and trusted authorization clock."""
        self._store = store
        self._clock = clock

    async def latest_completed(self, scope: AuthorizedScope) -> CompletedIndexManifest | None:
        """Load the latest authorized completed snapshot or legacy full snapshot."""
        _require_action(scope, _USER_ACTIONS)
        try:
            async with self._store.engine.connect() as connection:
                row = await _latest_completed_snapshot(connection, scope)
                if row is None:
                    return None
                await _authorize(
                    connection,
                    scope,
                    str(row["project_id"]),
                    str(row["repository_id"]),
                    self._clock.now(),
                    write=False,
                )
                snapshot = _source_snapshot(row)
                units = await _manifest_units(connection, snapshot)
                return CompletedIndexManifest(snapshot, units)
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def find_by_operation(self, scope: AuthorizedScope, operation_id: str) -> IndexRun | None:
        """Resolve idempotency before mutable worktree state is inspected again."""
        _require_action(scope, frozenset({"indexing.run.start"}))
        try:
            async with self._store.engine.connect() as connection:
                root = await _run_root_by_operation(connection, operation_id)
                if root is None:
                    return None
                await _authorize(
                    connection,
                    scope,
                    str(root["project_id"]),
                    str(root["repository_id"]),
                    self._clock.now(),
                    write=True,
                )
                latest = _require_row(await _latest_run_snapshot(connection, str(root["run_id"])))
                return _decode_run(root, latest)
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def start(
        self,
        scope: AuthorizedScope,
        run: IndexRun,
        snapshot: SourceSnapshot,
        plan: IndexPlan,
    ) -> IndexRun:
        """Atomically append source snapshot, immutable plan, and queued checkpoint."""
        _require_action(scope, frozenset({"indexing.run.start"}))
        _require_run_scope(scope, run)
        _require_exact_start(run, snapshot, plan)
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(
                    connection,
                    scope,
                    run.project_id,
                    run.repository_id,
                    self._clock.now(),
                    write=True,
                )
                existing = await _run_root_by_identity(connection, run.id, run.operation_id)
                if existing is not None:
                    work = await _load_work(connection, run.id)
                    _conflict_if(
                        work.run != run
                        or work.snapshot != snapshot
                        or work.plan != plan
                        or _blob(existing["scope_fingerprint"]).hex() != scope.scope_fingerprint
                    )
                    return work.run
                await _insert_source_snapshot(connection, scope, run, snapshot)
                await _insert_run_root(connection, scope, run)
                for operation in plan.operations:
                    await _insert_plan_operation(connection, run.id, operation)
                await _insert_run_snapshot(connection, run, 0)
                return run
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def get(self, scope: AuthorizedScope, run_id: str) -> IndexRun | None:
        """Return current progress after revalidating repository authority."""
        _require_action(scope, frozenset({"indexing.run.read"}))
        try:
            async with self._store.engine.connect() as connection:
                root = await _run_root_by_id(connection, run_id)
                if root is None:
                    return None
                await _authorize(
                    connection,
                    scope,
                    str(root["project_id"]),
                    str(root["repository_id"]),
                    self._clock.now(),
                    write=False,
                )
                return _decode_run(
                    root, _require_row(await _latest_run_snapshot(connection, run_id))
                )
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def request_cancel(
        self,
        scope: AuthorizedScope,
        run_id: str,
        operation_id: str,
        requested_at: datetime,
    ) -> IndexRun:
        """Append one exact cancellation receipt and monotonic run snapshot."""
        _require_action(scope, frozenset({"indexing.run.cancel"}))
        request_digest = _hash_document(
            {"operation_id": operation_id, "requested_at": _micros(requested_at), "run_id": run_id}
        )
        try:
            async with _write_transaction(self._store) as connection:
                root = _require_row(await _run_root_by_id(connection, run_id))
                await _authorize(
                    connection,
                    scope,
                    str(root["project_id"]),
                    str(root["repository_id"]),
                    self._clock.now(),
                    write=True,
                )
                latest_row = _require_row(await _latest_run_snapshot(connection, run_id))
                current = _decode_run(root, latest_row)
                existing = await _cancellation(connection, run_id, operation_id)
                if existing is not None:
                    _conflict_if(
                        str(existing["operation_id"]) != operation_id
                        or str(existing["run_id"]) != run_id
                        or _blob(existing["request_digest"]) != request_digest
                        or _blob(existing["scope_fingerprint"]).hex() != scope.scope_fingerprint
                    )
                    return current
                await connection.execute(
                    text(
                        "INSERT INTO incremental_index_cancellations(operation_id,run_id,"
                        "principal_id,scope_fingerprint,requested_at,request_digest) VALUES "
                        "(:operation,:run,:principal,:scope,:at,:digest)"
                    ),
                    {
                        "operation": operation_id,
                        "run": run_id,
                        "principal": scope.principal_id.value,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "at": _micros(requested_at),
                        "digest": request_digest,
                    },
                )
                if current.state in {
                    IndexRunState.CANCELLED,
                    IndexRunState.COMPLETED,
                    IndexRunState.FAILED,
                }:
                    return current
                updated = current.request_cancel(requested_at)
                await _insert_run_snapshot(
                    connection, updated, int(latest_row["snapshot_version"]) + 1
                )
                return updated
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def claim_next(self, claimed_at: datetime) -> IndexWork | None:
        """Claim or resume the oldest run after checking the original grant is still active."""
        try:
            async with _write_transaction(self._store) as connection:
                candidate = await _next_run_candidate(connection)
                if candidate is None:
                    return None
                run_id = str(candidate["run_id"])
                root = _require_row(await _run_root_by_id(connection, run_id))
                await _authorize_recorded_run(connection, root, claimed_at)
                latest_row = _require_row(await _latest_run_snapshot(connection, run_id))
                current = _decode_run(root, latest_row)
                if current.state is IndexRunState.QUEUED:
                    current = current.begin(claimed_at)
                    await _insert_run_snapshot(
                        connection, current, int(latest_row["snapshot_version"]) + 1
                    )
                snapshot = _source_snapshot(
                    _require_row(await _source_snapshot_row(connection, current.target_snapshot_id))
                )
                plan = await _load_plan(connection, run_id)
                return IndexWork(current, snapshot, plan)
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def current(self, run_id: str) -> IndexRun:
        """Load trusted current worker state and authenticate its digest."""
        try:
            async with self._store.engine.connect() as connection:
                root = _require_row(await _run_root_by_id(connection, run_id))
                snapshot = _require_row(await _latest_run_snapshot(connection, run_id))
                return _decode_run(root, snapshot)
        except IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def impact(self, semantic_ids: tuple[str, ...]) -> ProjectionImpact:
        """Resolve a bounded transitive topology closure without source content."""
        if not semantic_ids:
            return ProjectionImpact((), ())
        try:
            async with self._store.engine.connect() as connection:
                facts, evidence = await _dependency_closure(connection, semantic_ids)
                return ProjectionImpact(tuple(sorted(facts)), tuple(sorted(evidence)))
        except IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def commit_operation(
        self,
        previous: IndexRun,
        current: IndexRun,
        commit: IndexOperationCommit,
    ) -> IndexRun:
        """Atomically append file evidence, binding, lineage, outbox, and checkpoint."""
        _require_checkpoint(previous, current, commit.operation)
        try:
            async with _write_transaction(self._store) as connection:
                root = _require_row(await _run_root_by_id(connection, previous.id))
                await _authorize_recorded_run(connection, root, self._clock.now())
                latest_row = _require_row(await _latest_run_snapshot(connection, previous.id))
                stored = _decode_run(root, latest_row)
                if stored == current:
                    return stored
                _conflict_if(stored != previous)
                planned = await _plan_operation(connection, previous.id, commit.operation.ordinal)
                _conflict_if(planned != commit.operation)
                await _append_operation_result(connection, previous, commit)
                await _insert_run_snapshot(
                    connection, current, int(latest_row["snapshot_version"]) + 1
                )
                return current
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def save_state(self, previous: IndexRun, current: IndexRun) -> IndexRun:
        """Append one exact terminal or cancellation lifecycle transition."""
        _conflict_if(previous.id != current.id)
        try:
            async with _write_transaction(self._store) as connection:
                root = _require_row(await _run_root_by_id(connection, previous.id))
                await _authorize_recorded_run(connection, root, self._clock.now())
                latest_row = _require_row(await _latest_run_snapshot(connection, previous.id))
                stored = _decode_run(root, latest_row)
                if stored == current:
                    return stored
                _conflict_if(stored != previous)
                await _insert_run_snapshot(
                    connection, current, int(latest_row["snapshot_version"]) + 1
                )
                return current
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def next_projection(self, claimed_at: datetime) -> IndexProjectionEvent | None:
        """Lease one event; crashed delivery becomes eligible after sixty seconds."""
        try:
            async with _write_transaction(self._store) as connection:
                row = await _next_projection_event(connection, claimed_at)
                if row is None:
                    return None
                event = _decode_projection_event(row)
                latest = await _latest_delivery(connection, event.id)
                version = 0 if latest is None else int(latest["snapshot_version"]) + 1
                attempt = 1 if latest is None else int(latest["attempt"]) + 1
                await _insert_delivery(
                    connection,
                    event.id,
                    version,
                    "leased",
                    attempt,
                    claimed_at + timedelta(seconds=_LEASE_SECONDS),
                    claimed_at,
                )
                return event
        except IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def projection_succeeded(self, event_id: str, delivered_at: datetime) -> None:
        """Append an exact completed delivery receipt or replay it."""
        try:
            async with _write_transaction(self._store) as connection:
                latest = _require_row(await _latest_delivery(connection, event_id))
                if str(latest["state"]) == "completed":
                    return
                _conflict_if(str(latest["state"]) != "leased")
                await _insert_delivery(
                    connection,
                    event_id,
                    int(latest["snapshot_version"]) + 1,
                    "completed",
                    int(latest["attempt"]),
                    None,
                    delivered_at,
                )
        except IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


async def _insert_source_snapshot(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    run: IndexRun,
    snapshot: SourceSnapshot,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO source_snapshots(id,operation_id,brain_id,project_id,repository_id,"
            "principal_id,scope_fingerprint,commit_id,working_digest,created_at) VALUES "
            "(:id,:operation,:brain,:project,:repository,:principal,:scope,:commit,:working,:at)"
        ),
        {
            "id": snapshot.id,
            "operation": f"idx2-{run.id}",
            "brain": snapshot.brain_id,
            "project": snapshot.project_id,
            "repository": snapshot.repository_id,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "commit": snapshot.commit_id,
            "working": bytes.fromhex(snapshot.working_digest),
            "at": _micros(snapshot.created_at),
        },
    )


async def _insert_run_root(
    connection: AsyncConnection, scope: AuthorizedScope, run: IndexRun
) -> None:
    await connection.execute(
        text(
            "INSERT INTO incremental_index_runs(run_id,operation_id,brain_id,project_id,"
            "repository_id,principal_id,role,scope_fingerprint,base_snapshot_id,"
            "target_snapshot_id,target_commit_id,working_digest,implementation_fingerprint,"
            "plan_digest,total_operations,changed_operations,detected_at) VALUES "
            "(:run,:operation,:brain,:project,:repository,:principal,:role,:scope,:base,:target,"
            ":commit,:working,:implementation,:plan,:total,:changed,:detected)"
        ),
        {
            "run": run.id,
            "operation": run.operation_id,
            "brain": run.brain_id,
            "project": run.project_id,
            "repository": run.repository_id,
            "principal": scope.principal_id.value,
            "role": scope.role.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "base": run.base_snapshot_id,
            "target": run.target_snapshot_id,
            "commit": run.target_commit_id,
            "working": bytes.fromhex(run.working_digest),
            "implementation": bytes.fromhex(run.implementation_fingerprint),
            "plan": bytes.fromhex(run.plan_digest),
            "total": run.total_operations,
            "changed": run.changed_operations,
            "detected": _micros(run.detected_at),
        },
    )


async def _insert_plan_operation(
    connection: AsyncConnection, run_id: str, operation: IndexOperation
) -> None:
    await connection.execute(
        text(
            "INSERT INTO incremental_index_plan_operations(run_id,ordinal,operation_digest,kind,"
            "reason,relative_path,previous_path,content_digest,cache_key,previous_source_file_id,"
            "previous_file_revision_id,previous_semantic_ids_json,generated) VALUES "
            "(:run,:ordinal,:digest,:kind,:reason,:path,:previous_path,:content,:cache,"
            ":previous_file,:previous_revision,:semantic,:generated)"
        ),
        {
            "run": run_id,
            "ordinal": operation.ordinal,
            "digest": bytes.fromhex(operation.id),
            "kind": operation.kind.value,
            "reason": operation.reason.value,
            "path": operation.relative_path,
            "previous_path": operation.previous_path,
            "content": _optional_digest(operation.content_digest),
            "cache": _optional_digest(operation.cache_key),
            "previous_file": operation.previous_source_file_id,
            "previous_revision": operation.previous_file_revision_id,
            "semantic": _json_ids(operation.previous_semantic_ids),
            "generated": operation.generated,
        },
    )


async def _insert_run_snapshot(connection: AsyncConnection, run: IndexRun, version: int) -> None:
    digest = _run_snapshot_digest(run)
    await connection.execute(
        text(
            "INSERT INTO incremental_index_run_snapshots(run_id,snapshot_version,cursor,"
            "indexed_count,reused_count,deleted_count,failed_count,state,started_at,updated_at,"
            "completed_at,failure_code,snapshot_digest) VALUES (:run,:version,:cursor,:indexed,"
            ":reused,:deleted,:failed,:state,:started,:updated,:completed,:failure,:digest)"
        ),
        {
            "run": run.id,
            "version": version,
            "cursor": run.cursor,
            "indexed": run.indexed_count,
            "reused": run.reused_count,
            "deleted": run.deleted_count,
            "failed": run.failed_count,
            "state": run.state.value,
            "started": None if run.started_at is None else _micros(run.started_at),
            "updated": _micros(run.updated_at),
            "completed": None if run.completed_at is None else _micros(run.completed_at),
            "failure": run.failure_code,
            "digest": digest,
        },
    )


async def _append_operation_result(
    connection: AsyncConnection,
    run: IndexRun,
    commit: IndexOperationCommit,
) -> None:
    operation = commit.operation
    indexed = commit.indexed_file
    if indexed is not None:
        _conflict_if(
            indexed.revision.snapshot_id != run.target_snapshot_id
            or indexed.file.repository_id != run.repository_id
        )
        await append_indexed_file(connection, indexed)
    if operation.kind is not IndexOperationKind.DELETE:
        await _insert_binding(connection, run, commit)
    if operation.previous_path is not None:
        await _insert_lineage(connection, run, commit)
    if commit.projection_event is not None:
        await _insert_projection_event(connection, commit.projection_event)


async def _insert_binding(
    connection: AsyncConnection, run: IndexRun, commit: IndexOperationCommit
) -> None:
    operation = commit.operation
    if commit.indexed_file is None:
        source_file_id = cast("str", operation.previous_source_file_id)
        file_revision_id = cast("str", operation.previous_file_revision_id)
        semantic_ids = operation.previous_semantic_ids
    else:
        source_file_id = commit.indexed_file.file.id
        file_revision_id = commit.indexed_file.revision.id
        semantic_ids = tuple(sorted(item.id for item in commit.indexed_file.symbol_revisions))
    await connection.execute(
        text(
            "INSERT INTO snapshot_file_bindings(snapshot_id,relative_path,source_file_id,"
            "file_revision_id,cache_key,semantic_ids_json,binding_kind,operation_digest) VALUES "
            "(:snapshot,:path,:file,:revision,:cache,:semantic,:kind,:operation)"
        ),
        {
            "snapshot": run.target_snapshot_id,
            "path": operation.relative_path,
            "file": source_file_id,
            "revision": file_revision_id,
            "cache": bytes.fromhex(cast("str", operation.cache_key)),
            "semantic": _json_ids(semantic_ids),
            "kind": operation.kind.value,
            "operation": bytes.fromhex(operation.id),
        },
    )


async def _insert_lineage(
    connection: AsyncConnection, run: IndexRun, commit: IndexOperationCommit
) -> None:
    operation = commit.operation
    _conflict_if(
        operation.previous_source_file_id is None
        or commit.indexed_file is None
        or operation.kind not in {IndexOperationKind.ADD, IndexOperationKind.RENAME}
    )
    kind = "copy" if operation.reason is IndexOperationReason.COPIED_CONTENT else "rename"
    indexed = commit.indexed_file
    if indexed is None:
        raise IndexingConflictError(_ERR_CONFLICT)
    target_file_id = indexed.file.id
    lineage_id = _hash_hex(
        f"source-file-lineage.v1\0{run.target_snapshot_id}\0"
        f"{operation.previous_source_file_id}\0{target_file_id}\0{kind}".encode()
    )
    await connection.execute(
        text(
            "INSERT INTO source_file_lineage(lineage_id,repository_id,snapshot_id,"
            "from_source_file_id,to_source_file_id,kind,operation_digest) VALUES "
            "(:id,:repository,:snapshot,:source,:target,:kind,:operation)"
        ),
        {
            "id": lineage_id,
            "repository": run.repository_id,
            "snapshot": run.target_snapshot_id,
            "source": operation.previous_source_file_id,
            "target": target_file_id,
            "kind": kind,
            "operation": bytes.fromhex(operation.id),
        },
    )


async def _insert_projection_event(
    connection: AsyncConnection, event: IndexProjectionEvent
) -> None:
    await connection.execute(
        text(
            "INSERT INTO index_projection_events(event_id,run_id,operation_digest,ordinal,"
            "snapshot_id,previous_file_revision_ids_json,current_file_revision_ids_json,"
            "affected_semantic_ids_json,dependent_fact_ids_json,assertion_evidence_ids_json,"
            "reembed_semantic_ids_json,occurred_at,event_digest) VALUES (:event,:run,:operation,"
            ":ordinal,:snapshot,:previous,:current,:affected,:facts,:evidence,:reembed,:at,:digest)"
        ),
        {
            "event": event.id,
            "run": event.run_id,
            "operation": bytes.fromhex(event.operation_id),
            "ordinal": event.ordinal,
            "snapshot": event.snapshot_id,
            "previous": _json_ids(event.previous_file_revision_ids),
            "current": _json_ids(event.current_file_revision_ids),
            "affected": _json_ids(event.affected_semantic_ids),
            "facts": _json_ids(event.dependent_fact_ids),
            "evidence": _json_ids(event.assertion_evidence_ids),
            "reembed": _json_ids(event.reembed_semantic_ids),
            "at": _micros(event.occurred_at),
            "digest": bytes.fromhex(event.id),
        },
    )


async def _insert_delivery(  # noqa: PLR0913 -- Every lease coordinate is persisted.
    connection: AsyncConnection,
    event_id: str,
    version: int,
    state: str,
    attempt: int,
    leased_until: datetime | None,
    updated_at: datetime,
) -> None:
    digest = _hash_document(
        {
            "attempt": attempt,
            "event_id": event_id,
            "leased_until": None if leased_until is None else _micros(leased_until),
            "state": state,
            "updated_at": _micros(updated_at),
            "version": version,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO index_projection_delivery_snapshots(event_id,snapshot_version,state,"
            "attempt,leased_until,updated_at,delivery_digest) VALUES "
            "(:event,:version,:state,:attempt,:leased,:updated,:digest)"
        ),
        {
            "event": event_id,
            "version": version,
            "state": state,
            "attempt": attempt,
            "leased": None if leased_until is None else _micros(leased_until),
            "updated": _micros(updated_at),
            "digest": digest,
        },
    )


async def _latest_completed_snapshot(
    connection: AsyncConnection, scope: AuthorizedScope
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT snapshot.* FROM source_snapshots AS snapshot "
                    "LEFT JOIN incremental_index_runs AS run "
                    "ON run.target_snapshot_id=snapshot.id "
                    "WHERE snapshot.brain_id=:brain AND snapshot.project_id=:project "
                    "AND snapshot.repository_id=:repository AND (run.run_id IS NULL OR EXISTS("
                    "SELECT 1 FROM incremental_index_run_snapshots AS state "
                    "WHERE state.run_id=run.run_id AND state.state='completed')) "
                    "ORDER BY snapshot.created_at DESC,snapshot.id DESC LIMIT 1"
                ),
                {
                    "brain": scope.brain_id.value,
                    "project": scope.project_ids[0].value,
                    "repository": scope.repository_ids[0].value,
                },
            )
        )
        .mappings()
        .one_or_none()
    )


async def _manifest_units(
    connection: AsyncConnection, snapshot: SourceSnapshot
) -> tuple[PriorIndexedUnit, ...]:
    bindings = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM snapshot_file_bindings WHERE snapshot_id=:snapshot "
                    "ORDER BY relative_path"
                ),
                {"snapshot": snapshot.id},
            )
        )
        .mappings()
        .all()
    )
    if bindings:
        bound_units: list[PriorIndexedUnit] = []
        for row in bindings:
            revision_id = str(row["file_revision_id"])
            bound_units.append(
                PriorIndexedUnit(
                    str(row["relative_path"]),
                    str(row["source_file_id"]),
                    revision_id,
                    await _revision_content_digest(connection, revision_id),
                    _blob(row["cache_key"]).hex(),
                    _decode_ids(row["semantic_ids_json"]),
                )
            )
        return tuple(bound_units)
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT revision.id AS revision_id,revision.content_digest,source_file.id "
                    "AS file_id,source_file.relative_path FROM file_revisions AS revision JOIN "
                    "source_files AS source_file ON source_file.id=revision.file_id "
                    "WHERE revision.snapshot_id=:snapshot ORDER BY source_file.relative_path"
                ),
                {"snapshot": snapshot.id},
            )
        )
        .mappings()
        .all()
    )
    result: list[PriorIndexedUnit] = []
    for row in rows:
        revision_id = str(row["revision_id"])
        semantic_ids = await _revision_semantic_ids(connection, revision_id)
        result.append(
            PriorIndexedUnit(
                str(row["relative_path"]),
                str(row["file_id"]),
                revision_id,
                _blob(row["content_digest"]).hex(),
                _hash_hex(f"legacy-index-cache.v1\0{revision_id}".encode()),
                semantic_ids,
            )
        )
    return tuple(result)


async def _dependency_closure(
    connection: AsyncConnection, semantic_ids: tuple[str, ...]
) -> tuple[set[str], set[str]]:
    frontier = set(semantic_ids)
    visited = set(semantic_ids)
    facts: set[str] = set()
    evidence: set[str] = set()
    while frontier:
        if len(visited) > _DEPENDENCY_LIMIT:
            raise IndexingValidationError(_ERR_INTEGRITY)
        batch = tuple(sorted(frontier))
        frontier.clear()
        statement = text(
            "SELECT source_semantic_id,dependent_fact_id,assertion_evidence_id "
            "FROM index_semantic_dependencies WHERE source_semantic_id IN :ids"
        ).bindparams(bindparam("ids", expanding=True))
        rows = (await connection.execute(statement, {"ids": batch})).mappings().all()
        for row in rows:
            fact = None if row["dependent_fact_id"] is None else str(row["dependent_fact_id"])
            item_evidence = (
                None if row["assertion_evidence_id"] is None else str(row["assertion_evidence_id"])
            )
            if fact is not None:
                facts.add(fact)
                if fact not in visited:
                    visited.add(fact)
                    frontier.add(fact)
            if item_evidence is not None:
                evidence.add(item_evidence)
    return facts, evidence


async def _authorize(  # noqa: PLR0913 -- Authority binds the complete repository scope.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    project_id: str,
    repository_id: str,
    now: datetime,
    *,
    write: bool,
) -> None:
    allowed = _WRITE_ROLES if write else _READ_ROLES
    if (
        scope.role.value not in allowed
        or project_id not in {item.value for item in scope.project_ids}
        or repository_id not in {item.value for item in scope.repository_ids}
    ):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    authorized = await _active_authority(
        connection,
        scope.brain_id.value,
        project_id,
        repository_id,
        scope.principal_id.value,
        scope.role.value,
        now,
    )
    if not authorized:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


async def _authorize_recorded_run(
    connection: AsyncConnection, root: RowMapping, now: datetime
) -> None:
    if str(root["role"]) not in _WRITE_ROLES or not await _active_authority(
        connection,
        str(root["brain_id"]),
        str(root["project_id"]),
        str(root["repository_id"]),
        str(root["principal_id"]),
        str(root["role"]),
        now,
    ):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


async def _active_authority(  # noqa: PLR0913 -- Exact current grant query.
    connection: AsyncConnection,
    brain_id: str,
    project_id: str,
    repository_id: str,
    principal_id: str,
    role: str,
    now: datetime,
) -> bool:
    value = (
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
                "brain": brain_id,
                "project": project_id,
                "repository": repository_id,
                "principal": principal_id,
                "role": role,
                "now": _micros(now),
            },
        )
    ).scalar_one()
    return bool(value)


async def _run_root_by_id(connection: AsyncConnection, run_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM incremental_index_runs WHERE run_id=:run"),
                {"run": run_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _run_root_by_operation(
    connection: AsyncConnection, operation_id: str
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM incremental_index_runs WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _run_root_by_identity(
    connection: AsyncConnection, run_id: str, operation_id: str
) -> RowMapping | None:
    by_run = await _run_root_by_id(connection, run_id)
    by_operation = await _run_root_by_operation(connection, operation_id)
    if by_run is not None and by_operation is not None:
        _conflict_if(str(by_run["run_id"]) != str(by_operation["run_id"]))
    return by_run if by_run is not None else by_operation


async def _latest_run_snapshot(connection: AsyncConnection, run_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM incremental_index_run_snapshots WHERE run_id=:run "
                    "ORDER BY snapshot_version DESC LIMIT 1"
                ),
                {"run": run_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _next_run_candidate(connection: AsyncConnection) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT root.run_id FROM incremental_index_runs AS root JOIN "
                    "incremental_index_run_snapshots AS state ON state.run_id=root.run_id "
                    "WHERE state.snapshot_version=(SELECT MAX(latest.snapshot_version) FROM "
                    "incremental_index_run_snapshots AS latest WHERE latest.run_id=root.run_id) "
                    "AND state.state IN ('queued','running','cancelling') "
                    "ORDER BY root.detected_at,root.run_id LIMIT 1"
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _load_work(connection: AsyncConnection, run_id: str) -> IndexWork:
    root = _require_row(await _run_root_by_id(connection, run_id))
    state = _require_row(await _latest_run_snapshot(connection, run_id))
    run = _decode_run(root, state)
    snapshot = _source_snapshot(
        _require_row(await _source_snapshot_row(connection, run.target_snapshot_id))
    )
    return IndexWork(run, snapshot, await _load_plan(connection, run_id))


async def _load_plan(connection: AsyncConnection, run_id: str) -> IndexPlan:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM incremental_index_plan_operations WHERE run_id=:run "
                    "ORDER BY ordinal"
                ),
                {"run": run_id},
            )
        )
        .mappings()
        .all()
    )
    plan = IndexPlan(tuple(_decode_operation(row) for row in rows))
    root = _require_row(await _run_root_by_id(connection, run_id))
    _conflict_if(plan.digest != _blob(root["plan_digest"]).hex())
    return plan


async def _plan_operation(connection: AsyncConnection, run_id: str, ordinal: int) -> IndexOperation:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM incremental_index_plan_operations "
                    "WHERE run_id=:run AND ordinal=:ordinal"
                ),
                {"run": run_id, "ordinal": ordinal},
            )
        )
        .mappings()
        .one_or_none()
    )
    return _decode_operation(_require_row(row))


async def _source_snapshot_row(connection: AsyncConnection, snapshot_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM source_snapshots WHERE id=:id"), {"id": snapshot_id}
            )
        )
        .mappings()
        .one_or_none()
    )


async def _cancellation(
    connection: AsyncConnection, run_id: str, operation_id: str
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM incremental_index_cancellations WHERE run_id=:run "
                    "OR operation_id=:operation"
                ),
                {"run": run_id, "operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _next_projection_event(
    connection: AsyncConnection, claimed_at: datetime
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT event.* FROM index_projection_events AS event LEFT JOIN "
                    "index_projection_delivery_snapshots AS delivery ON delivery.event_id="
                    "event.event_id AND delivery.snapshot_version=(SELECT MAX("
                    "latest.snapshot_version) "
                    "FROM index_projection_delivery_snapshots AS latest WHERE latest.event_id="
                    "event.event_id) WHERE delivery.state IS NULL OR (delivery.state='leased' "
                    "AND delivery.leased_until<=:now) ORDER BY event.occurred_at,"
                    "event.event_id LIMIT 1"
                ),
                {"now": _micros(claimed_at)},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _latest_delivery(connection: AsyncConnection, event_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM index_projection_delivery_snapshots WHERE event_id=:event "
                    "ORDER BY snapshot_version DESC LIMIT 1"
                ),
                {"event": event_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _revision_content_digest(connection: AsyncConnection, revision_id: str) -> str:
    value = (
        await connection.execute(
            text("SELECT content_digest FROM file_revisions WHERE id=:id"), {"id": revision_id}
        )
    ).scalar_one()
    return _blob(value).hex()


async def _revision_semantic_ids(connection: AsyncConnection, revision_id: str) -> tuple[str, ...]:
    values = (
        await connection.execute(
            text("SELECT id FROM symbol_revisions WHERE file_revision_id=:revision ORDER BY id"),
            {"revision": revision_id},
        )
    ).scalars()
    return tuple(str(value) for value in values)


def _decode_run(root: RowMapping, state: RowMapping) -> IndexRun:
    run = IndexRun(
        str(root["run_id"]),
        str(root["operation_id"]),
        str(root["brain_id"]),
        str(root["project_id"]),
        str(root["repository_id"]),
        None if root["base_snapshot_id"] is None else str(root["base_snapshot_id"]),
        str(root["target_snapshot_id"]),
        None if root["target_commit_id"] is None else str(root["target_commit_id"]),
        _blob(root["working_digest"]).hex(),
        _blob(root["implementation_fingerprint"]).hex(),
        _blob(root["plan_digest"]).hex(),
        int(root["total_operations"]),
        int(root["changed_operations"]),
        int(state["cursor"]),
        int(state["indexed_count"]),
        int(state["reused_count"]),
        int(state["deleted_count"]),
        int(state["failed_count"]),
        IndexRunState(str(state["state"])),
        _datetime(int(root["detected_at"])),
        None if state["started_at"] is None else _datetime(int(state["started_at"])),
        _datetime(int(state["updated_at"])),
        None if state["completed_at"] is None else _datetime(int(state["completed_at"])),
        None if state["failure_code"] is None else str(state["failure_code"]),
    )
    _conflict_if(_run_snapshot_digest(run) != _blob(state["snapshot_digest"]))
    return run


def _decode_operation(row: RowMapping) -> IndexOperation:
    operation = IndexOperation(
        int(row["ordinal"]),
        IndexOperationKind(str(row["kind"])),
        IndexOperationReason(str(row["reason"])),
        str(row["relative_path"]),
        None if row["previous_path"] is None else str(row["previous_path"]),
        _optional_hex(row["content_digest"]),
        _optional_hex(row["cache_key"]),
        None if row["previous_source_file_id"] is None else str(row["previous_source_file_id"]),
        (
            None
            if row["previous_file_revision_id"] is None
            else str(row["previous_file_revision_id"])
        ),
        _decode_ids(row["previous_semantic_ids_json"]),
        bool(row["generated"]),
    )
    _conflict_if(operation.id != _blob(row["operation_digest"]).hex())
    return operation


def _decode_projection_event(row: RowMapping) -> IndexProjectionEvent:
    event = IndexProjectionEvent(
        str(row["run_id"]),
        _blob(row["operation_digest"]).hex(),
        int(row["ordinal"]),
        str(row["snapshot_id"]),
        _decode_ids(row["previous_file_revision_ids_json"]),
        _decode_ids(row["current_file_revision_ids_json"]),
        _decode_ids(row["affected_semantic_ids_json"]),
        _decode_ids(row["dependent_fact_ids_json"]),
        _decode_ids(row["assertion_evidence_ids_json"]),
        _decode_ids(row["reembed_semantic_ids_json"]),
        _datetime(int(row["occurred_at"])),
    )
    _conflict_if(event.id != str(row["event_id"]) or _blob(row["event_digest"]).hex() != event.id)
    return event


def _source_snapshot(row: RowMapping) -> SourceSnapshot:
    return SourceSnapshot(
        str(row["id"]),
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        None if row["commit_id"] is None else str(row["commit_id"]),
        _blob(row["working_digest"]).hex(),
        _datetime(int(cast("int", row["created_at"]))),
    )


def _run_snapshot_digest(run: IndexRun) -> bytes:
    return _hash_document(
        {
            "completed_at": None if run.completed_at is None else _micros(run.completed_at),
            "cursor": run.cursor,
            "deleted_count": run.deleted_count,
            "failed_count": run.failed_count,
            "failure_code": run.failure_code,
            "indexed_count": run.indexed_count,
            "reused_count": run.reused_count,
            "run_id": run.id,
            "started_at": None if run.started_at is None else _micros(run.started_at),
            "state": run.state.value,
            "updated_at": _micros(run.updated_at),
        }
    )


def _require_exact_start(run: IndexRun, snapshot: SourceSnapshot, plan: IndexPlan) -> None:
    _conflict_if(
        run.target_snapshot_id != snapshot.id
        or run.brain_id != snapshot.brain_id
        or run.project_id != snapshot.project_id
        or run.repository_id != snapshot.repository_id
        or run.target_commit_id != snapshot.commit_id
        or run.working_digest != snapshot.working_digest
        or run.plan_digest != plan.digest
        or run.total_operations != len(plan.operations)
        or run.changed_operations != plan.changed_count
        or run.state is not IndexRunState.QUEUED
    )


def _require_run_scope(scope: AuthorizedScope, run: IndexRun) -> None:
    if (
        run.brain_id != scope.brain_id.value
        or run.project_id not in {item.value for item in scope.project_ids}
        or run.repository_id not in {item.value for item in scope.repository_ids}
    ):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _require_checkpoint(previous: IndexRun, current: IndexRun, operation: IndexOperation) -> None:
    _conflict_if(
        previous.id != current.id
        or current.cursor != previous.cursor + 1
        or operation.ordinal != previous.cursor
    )


def _require_action(scope: AuthorizedScope, allowed: frozenset[str]) -> None:
    if scope.action not in allowed:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _require_row(row: RowMapping | None) -> RowMapping:
    if row is None:
        raise IndexingConflictError(_ERR_CONFLICT)
    return row


def _conflict_if(condition: bool) -> None:  # noqa: FBT001 -- Guard reads as a predicate.
    if condition:
        raise IndexingConflictError(_ERR_CONFLICT)


def _json_ids(values: Sequence[str]) -> bytes:
    return json.dumps(list(values), separators=(",", ":"), ensure_ascii=True).encode()


def _decode_ids(value: object) -> tuple[str, ...]:
    try:
        decoded = json.loads(_blob(value))
    except (TypeError, ValueError, UnicodeDecodeError) as error:
        raise IndexingConflictError(_ERR_INTEGRITY) from error
    if not isinstance(decoded, list):
        raise IndexingConflictError(_ERR_INTEGRITY)
    result_values: list[str] = []
    for item in cast("list[object]", decoded):
        if not isinstance(item, str):
            raise IndexingConflictError(_ERR_INTEGRITY)
        result_values.append(item)
    result = tuple(result_values)
    if result != tuple(sorted(set(result))):
        raise IndexingConflictError(_ERR_INTEGRITY)
    return result


def _hash_document(document: Mapping[str, object]) -> bytes:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode()).digest()


def _hash_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _optional_digest(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


def _optional_hex(value: object) -> str | None:
    return None if value is None else _blob(value).hex()


def _blob(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IndexingConflictError(_ERR_INTEGRITY)
    return value


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
