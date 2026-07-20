"""SQLite ING-003 authorization, causal source, and shadow replay repository."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Self

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
)
from agentmemory.ingestion.domain.ordered_replay import (
    OrderedProjectionState,
    OrderedReductionInput,
    OrderedReplayRun,
    RecordedOperationEvidence,
    ReplayRunRequest,
    ReplayRunState,
    ReplaySourcePage,
    ReplaySourceRecord,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_STORAGE = "Ordered replay storage is unavailable"
_ERR_INTEGRITY = "Ordered replay evidence failed integrity verification"
_ERR_CONFLICT = "Ordered replay operation identity conflicts with committed input"
_ERR_FORBIDDEN = "Ordered replay access is not active"
_ZERO_DIGEST = "0" * 64
_MAX_FAILURE_CODE = 64

_SOURCE_FILTER = """
e.brain_id=:brain
AND (e.ingested_at < :watermark_time OR
     (e.ingested_at = :watermark_time AND e.event_id <= :watermark_event))
AND (:from_time IS NULL OR e.ingested_at >= :from_time)
AND (:to_time IS NULL OR e.ingested_at <= :to_time)
AND (:from_event IS NULL OR e.event_id >= :from_event)
AND (:to_event IS NULL OR e.event_id <= :to_event)
"""


class SqliteOrderedReplayAccessPolicy:
    """Authorize exact actor/Brain/grant tuples against canonical current state."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local store."""
        self._store = store

    async def authorize(self, request: ReplayRunRequest, now_microseconds: int) -> None:
        """Reject inactive principals, Brains, grants, and validity windows."""
        try:
            async with self._store.engine.connect() as connection:
                count = (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM scope_grants g "
                            "JOIN principals p ON p.id=g.principal_id "
                            "JOIN brains b ON b.id=g.brain_id WHERE g.id=:grant "
                            "AND g.principal_id=:actor AND g.brain_id=:brain "
                            "AND p.status='active' AND b.status='active' "
                            "AND g.valid_from<=:now AND "
                            "(g.valid_to IS NULL OR g.valid_to>:now)"
                        ),
                        {
                            "actor": request.actor_id,
                            "brain": request.brain_id,
                            "grant": request.grant_id,
                            "now": now_microseconds,
                        },
                    )
                ).scalar_one()
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        if count != 1:
            raise IngestionAuthorizationError(_ERR_FORBIDDEN)


class SqliteOrderedReplayRepository:
    """Own one generation-isolated replay lifecycle in the canonical SQLite store."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the shared single-writer store."""
        self._store = store

    async def create(
        self,
        request: ReplayRunRequest,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Capture immutable bounds, source count, and selected-range baselines."""
        async with _WriteTransaction(self._store) as transaction:
            exact = await _run_row(transaction.connection, request.operation_id)
            if exact is not None:
                if _bytes(exact["request_sha256"]).hex() != request.request_sha256:
                    raise IngestionConflictError(_ERR_CONFLICT)
                await transaction.commit()
                return _restore_run(exact)
            semantic = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT * FROM ordered_replay_runs WHERE request_sha256=:request "
                            "OR (brain_id=:brain AND projection_name=:projection "
                            "AND projection_generation=:generation) ORDER BY operation_id LIMIT 1"
                        ),
                        {
                            "brain": request.brain_id,
                            "generation": request.projection_generation,
                            "projection": request.projection_name,
                            "request": bytes.fromhex(request.request_sha256),
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
            if semantic is not None:
                if _bytes(semantic["request_sha256"]).hex() != request.request_sha256:
                    raise IngestionConflictError(_ERR_CONFLICT)
                await transaction.commit()
                return _restore_run(semantic)
            latest = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT ingested_at,event_id FROM agent_events WHERE brain_id=:brain "
                            "ORDER BY ingested_at DESC,event_id DESC LIMIT 1"
                        ),
                        {"brain": request.brain_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            watermark_time = now_microseconds if latest is None else int(str(latest["ingested_at"]))
            watermark_event = request.operation_id if latest is None else str(latest["event_id"])
            values = _selection_values(request, watermark_time, watermark_event)
            # Static SQL fragment; every runtime value remains a bound parameter.
            count_query = (
                "SELECT COUNT(*) FROM agent_events e JOIN agent_event_envelopes x "  # noqa: S608  # nosec B608
                f"ON x.event_id=e.event_id WHERE {_SOURCE_FILTER}"
            )
            source_count = int(
                str(
                    (
                        await transaction.connection.execute(
                            text(count_query),
                            values,
                        )
                    ).scalar_one()
                )
            )
            await transaction.connection.execute(
                text(
                    "INSERT INTO ordered_replay_runs "
                    "(operation_id,brain_id,actor_id,grant_id,projection_name,"
                    "projection_generation,code_fingerprint,request_sha256,from_ingested_at,"
                    "to_ingested_at,from_event_id,to_event_id,source_watermark_ingested_at,"
                    "source_watermark_event_id,state,source_count,processed_count,created_at,"
                    "updated_at,schema_version) VALUES (:operation,:brain,:actor,:grant,"
                    ":projection,:generation,:fingerprint,:request,:from_time,:to_time,"
                    ":from_event,:to_event,:watermark_time,:watermark_event,'queued',"
                    ":source_count,0,:now,:now,1)"
                ),
                {
                    **values,
                    "actor": request.actor_id,
                    "fingerprint": request.code_fingerprint,
                    "generation": request.projection_generation,
                    "grant": request.grant_id,
                    "now": now_microseconds,
                    "operation": request.operation_id,
                    "projection": request.projection_name,
                    "request": bytes.fromhex(request.request_sha256),
                    "source_count": source_count,
                },
            )
            # Static SQL fragment; every runtime value remains a bound parameter.
            snapshot_query = (
                "INSERT INTO ordered_replay_sources "  # noqa: S608  # nosec B608
                "(operation_id,event_id,source_ordinal,source_ingested_at,created_at,"
                "schema_version) SELECT :operation,e.event_id,ROW_NUMBER() OVER (ORDER BY "
                "x.ordering_key,CASE WHEN x.sequence IS NULL THEN 1 ELSE 0 END,x.sequence,"
                "e.ingested_at,e.event_id),e.ingested_at,:now,1 FROM agent_events e "
                "JOIN agent_event_envelopes x ON x.event_id=e.event_id WHERE "
                f"{_SOURCE_FILTER}"
            )
            snapshot = await transaction.connection.execute(
                text(snapshot_query),
                values | {"now": now_microseconds, "operation": request.operation_id},
            )
            if max(snapshot.rowcount, 0) != source_count:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            await _seed_baselines(transaction.connection, request, now_microseconds)
            row = await _required_run_row(transaction.connection, request.operation_id)
            await transaction.commit()
            return _restore_run(row)

    async def get(self, operation_id: str) -> OrderedReplayRun | None:
        """Return one content-free replay status without source content."""
        try:
            async with self._store.engine.connect() as connection:
                row = await _run_row(connection, operation_id)
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return None if row is None else _restore_run(row)

    async def claim(
        self,
        operation_id: str,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> OrderedReplayRun:
        """Claim queued, partial, or expired work and preserve committed cursor state."""
        if lease_until_microseconds <= now_microseconds:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            result = await transaction.connection.execute(
                text(
                    "UPDATE ordered_replay_runs SET state='building',failure_code=NULL,"
                    "lease_owner=:owner,lease_until=:lease,updated_at=:now WHERE "
                    "operation_id=:operation AND (state IN ('queued','partial') OR "
                    "(state IN ('building','validating') AND lease_until<=:now))"
                ),
                {
                    "lease": lease_until_microseconds,
                    "now": now_microseconds,
                    "operation": operation_id,
                    "owner": owner,
                },
            )
            if result.rowcount != 1:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            row = await _required_run_row(transaction.connection, operation_id)
            await transaction.commit()
            return _restore_run(row)

    async def read_page(self, run: OrderedReplayRun, limit: int) -> ReplaySourcePage:
        """Read a bounded page ordered by key, sequence, ingestion time, and event ID."""
        if not 1 <= limit <= 4096:  # noqa: PLR2004 -- Public port maximum is normative.
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        page_query = (
            "SELECT s.event_id,s.source_ingested_at AS ingested_at,s.source_ordinal,"
            "e.schema_version AS event_schema_version,x.ordering_key,x.sequence,"
            "x.canonical_sha256,r.operation_id,r.profile_id,r.model_revision,r.purpose,"
            "r.result_sha256 AS recorded_result_sha256,"
            "r.result_ref AS recorded_result_ref,"
            "p.profile_id AS provider_profile_id,"
            "p.brain_id AS provider_brain_id,"
            "p.state AS provider_state,"
            "p.result_sha256 AS provider_result_sha256,"
            "p.result_ref AS provider_result_ref FROM ordered_replay_sources s "
            "JOIN agent_events e ON e.event_id=s.event_id "
            "JOIN agent_event_envelopes x ON x.event_id=s.event_id "
            "LEFT JOIN recorded_reduction_inputs r ON "
            "r.event_id=s.event_id AND r.projection_name=:projection "
            "LEFT JOIN provider_operation_results p ON "
            "p.operation_id=r.operation_id WHERE s.operation_id=:operation "
            "AND s.source_ordinal>:processed "
            "ORDER BY s.source_ordinal LIMIT :limit"
        )
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(page_query),
                            {
                                "limit": limit,
                                "operation": run.request.operation_id,
                                "processed": run.processed_count,
                                "projection": run.request.projection_name,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        records = tuple(_source_record(row, run.request) for row in rows)
        return ReplaySourcePage(
            records,
            run.processed_count + len(records) == run.source_count,
        )

    async def shadow_state(
        self,
        operation_id: str,
        ordering_key: str,
    ) -> OrderedProjectionState | None:
        """Read one generation-isolated final key state."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT ordering_key,applied_sequence,state_sha256 FROM "
                                "ordered_replay_shadow_states WHERE operation_id=:operation "
                                "AND ordering_key=:ordering"
                            ),
                            {"operation": operation_id, "ordering": ordering_key},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return None if row is None else _state(row)

    async def append(  # noqa: PLR0913 -- CAS requires complete immutable replay evidence.
        self,
        run: OrderedReplayRun,
        source: ReplaySourceRecord,
        prior_state_sha256: str,
        state: OrderedProjectionState | None,
        state_sha256: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Append history/state and cursor in one exact leased transaction."""
        if source.source_ordinal != run.processed_count + 1:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            await transaction.connection.execute(
                text(
                    "INSERT INTO ordered_replay_shadow_history "
                    "(operation_id,event_id,ordering_key,event_sequence,event_schema_version,"
                    "canonical_sha256,projection_sha256,prior_state_sha256,state_sha256,"
                    "recorded_operation_id,source_ingested_at,source_ordinal,created_at,"
                    "schema_version) VALUES (:operation,:event,:ordering,:sequence,:event_schema,"
                    ":canonical,:projection,:prior,:state,:recorded,:ingested,:ordinal,:now,1)"
                ),
                {
                    "canonical": bytes.fromhex(source.reduction.canonical_sha256),
                    "event": source.reduction.event_id,
                    "event_schema": source.reduction.event_schema_version,
                    "ingested": source.ingested_at_microseconds,
                    "now": now_microseconds,
                    "operation": run.request.operation_id,
                    "ordering": source.reduction.ordering_key,
                    "ordinal": source.source_ordinal,
                    "prior": bytes.fromhex(prior_state_sha256),
                    "projection": bytes.fromhex(source.reduction.projection_sha256),
                    "recorded": (
                        None
                        if source.reduction.recorded_operation is None
                        else source.reduction.recorded_operation.operation_id
                    ),
                    "sequence": source.reduction.event_sequence,
                    "state": bytes.fromhex(state_sha256),
                },
            )
            if state is not None:
                state_result = await transaction.connection.execute(
                    text(
                        "INSERT INTO ordered_replay_shadow_states "
                        "(operation_id,ordering_key,applied_sequence,state_sha256,updated_at,"
                        "schema_version) VALUES (:operation,:ordering,:sequence,:state,:now,1) "
                        "ON CONFLICT(operation_id,ordering_key) DO UPDATE SET "
                        "applied_sequence=excluded.applied_sequence,"
                        "state_sha256=excluded.state_sha256,updated_at=excluded.updated_at "
                        "WHERE ordered_replay_shadow_states.applied_sequence < "
                        "excluded.applied_sequence"
                    ),
                    {
                        "now": now_microseconds,
                        "operation": run.request.operation_id,
                        "ordering": state.ordering_key,
                        "sequence": state.applied_sequence,
                        "state": bytes.fromhex(state.state_sha256),
                    },
                )
                if state_result.rowcount != 1:
                    raise IngestionIntegrityError(_ERR_INTEGRITY)
            updated = await transaction.connection.execute(
                text(
                    "UPDATE ordered_replay_runs SET processed_count=processed_count+1,"
                    "cursor_ingested_at=:ingested,cursor_event_id=:event,updated_at=:now "
                    "WHERE operation_id=:operation AND state='building' "
                    "AND lease_owner=:owner AND processed_count=:processed"
                ),
                {
                    "event": source.reduction.event_id,
                    "ingested": source.ingested_at_microseconds,
                    "now": now_microseconds,
                    "operation": run.request.operation_id,
                    "owner": run.lease_owner,
                    "processed": run.processed_count,
                },
            )
            if updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            row = await _required_run_row(transaction.connection, run.request.operation_id)
            await transaction.commit()
            return _restore_run(row)

    async def begin_validation(
        self,
        run: OrderedReplayRun,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> OrderedReplayRun:
        """CAS a complete building cursor into validation."""
        async with _WriteTransaction(self._store) as transaction:
            updated = await transaction.connection.execute(
                text(
                    "UPDATE ordered_replay_runs SET state='validating',lease_until=:lease,"
                    "updated_at=:now WHERE operation_id=:operation AND state='building' "
                    "AND lease_owner=:owner AND processed_count=source_count"
                ),
                {
                    "lease": lease_until_microseconds,
                    "now": now_microseconds,
                    "operation": run.request.operation_id,
                    "owner": run.lease_owner,
                },
            )
            if updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            row = await _required_run_row(transaction.connection, run.request.operation_id)
            await transaction.commit()
            return _restore_run(row)

    async def shadow_states(
        self,
        operation_id: str,
    ) -> tuple[OrderedProjectionState, ...]:
        """Return final shadow states in deterministic ordering-key order."""
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT ordering_key,applied_sequence,state_sha256 FROM "
                                "ordered_replay_shadow_states WHERE operation_id=:operation "
                                "ORDER BY ordering_key"
                            ),
                            {"operation": operation_id},
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return tuple(_state(row) for row in rows)

    async def live_states(self, run: OrderedReplayRun) -> tuple[OrderedProjectionState, ...]:
        """Return live states at each selected key's highest comparable source sequence."""
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "WITH ranked AS (SELECT h.ordering_key,h.event_sequence,"
                                "h.state_sha256,ROW_NUMBER() OVER (PARTITION BY h.ordering_key "
                                "ORDER BY h.event_sequence DESC,h.event_id DESC) AS rank "
                                "FROM ordered_projection_history h JOIN "
                                "ordered_replay_shadow_history s ON s.event_id=h.event_id "
                                "AND s.operation_id=:operation WHERE h.projection_name=:projection "
                                "AND h.brain_id=:brain AND h.event_sequence IS NOT NULL) "
                                "SELECT ordering_key,event_sequence AS applied_sequence,"
                                "state_sha256 FROM ranked WHERE rank=1 ORDER BY ordering_key"
                            ),
                            {
                                "brain": run.request.brain_id,
                                "operation": run.request.operation_id,
                                "projection": run.request.projection_name,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return tuple(_state(row) for row in rows)

    async def finish_validation(
        self,
        run: OrderedReplayRun,
        shadow_digest: str,
        live_digest: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Persist ready/superseded comparison without changing live query state."""
        target = "ready" if shadow_digest == live_digest else "superseded"
        async with _WriteTransaction(self._store) as transaction:
            updated = await transaction.connection.execute(
                text(
                    "UPDATE ordered_replay_runs SET state=:state,shadow_digest=:shadow,"
                    "live_digest=:live,lease_owner=NULL,lease_until=NULL,completed_at=:now,"
                    "updated_at=:now WHERE operation_id=:operation AND state='validating' "
                    "AND lease_owner=:owner AND processed_count=source_count"
                ),
                {
                    "live": bytes.fromhex(live_digest),
                    "now": now_microseconds,
                    "operation": run.request.operation_id,
                    "owner": run.lease_owner,
                    "shadow": bytes.fromhex(shadow_digest),
                    "state": target,
                },
            )
            if updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            if target == "ready":
                await transaction.connection.execute(
                    text(
                        "UPDATE ordered_replay_required_events SET state='resolved',"
                        "replay_operation_id=:operation,resolved_at=:now WHERE state='pending' "
                        "AND event_id IN (SELECT event_id FROM ordered_replay_shadow_history "
                        "WHERE operation_id=:operation)"
                    ),
                    {"now": now_microseconds, "operation": run.request.operation_id},
                )
            await _append_replay_audit(
                transaction.connection,
                run,
                f"ingestion.ordered_replay.{target}",
                now_microseconds,
                shadow_digest,
                live_digest,
            )
            row = await _required_run_row(transaction.connection, run.request.operation_id)
            await transaction.commit()
            return _restore_run(row)

    async def mark_partial(
        self,
        run: OrderedReplayRun,
        failure_code: str,
        now_microseconds: int,
    ) -> OrderedReplayRun:
        """Release one exact lease with a bounded content-free failure code."""
        if not failure_code or len(failure_code) > _MAX_FAILURE_CODE:
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            updated = await transaction.connection.execute(
                text(
                    "UPDATE ordered_replay_runs SET state='partial',failure_code=:failure,"
                    "lease_owner=NULL,lease_until=NULL,updated_at=:now WHERE "
                    "operation_id=:operation AND state IN ('building','validating') "
                    "AND lease_owner=:owner"
                ),
                {
                    "failure": failure_code,
                    "now": now_microseconds,
                    "operation": run.request.operation_id,
                    "owner": run.lease_owner,
                },
            )
            if updated.rowcount != 1:
                raise IngestionIntegrityError(_ERR_INTEGRITY)
            row = await _required_run_row(transaction.connection, run.request.operation_id)
            await transaction.commit()
            return _restore_run(row)

    async def next_runnable(self, now_microseconds: int) -> str | None:
        """Return oldest runnable work without taking its lease."""
        try:
            async with self._store.engine.connect() as connection:
                value = (
                    await connection.execute(
                        text(
                            "SELECT operation_id FROM ordered_replay_runs WHERE "
                            "state IN ('queued','partial') OR "
                            "(state IN ('building','validating') AND lease_until<=:now) "
                            "ORDER BY created_at,operation_id LIMIT 1"
                        ),
                        {"now": now_microseconds},
                    )
                ).scalar_one_or_none()
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return None if value is None else str(value)

    async def recover_expired(self, now_microseconds: int) -> int:
        """Convert stale building/validation leases to resumable partial state."""
        async with _WriteTransaction(self._store) as transaction:
            result = await transaction.connection.execute(
                text(
                    "UPDATE ordered_replay_runs SET state='partial',"
                    "failure_code='lease_expired',lease_owner=NULL,lease_until=NULL,"
                    "updated_at=:now WHERE state IN ('building','validating') "
                    "AND lease_until<=:now"
                ),
                {"now": now_microseconds},
            )
            await transaction.commit()
            return max(result.rowcount, 0)


class _WriteTransaction:
    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self.connection: AsyncConnection
        self._committed = False

    async def __aenter__(self) -> Self:
        await self._store.write_lock.acquire()
        try:
            self.connection = await self._store.engine.connect()
            await self.connection.exec_driver_sql("BEGIN IMMEDIATE")
        except SQLAlchemyError as error:
            if hasattr(self, "connection"):
                await self.connection.close()
            self._store.write_lock.release()
            raise IngestionDependencyError(_ERR_STORAGE) from error
        except BaseException:
            if hasattr(self, "connection"):
                await self.connection.close()
            self._store.write_lock.release()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, traceback
        storage_error = exc if isinstance(exc, SQLAlchemyError) else None
        try:
            if not self._committed:
                try:
                    await self.connection.rollback()
                except SQLAlchemyError as error:
                    storage_error = error
        finally:
            try:
                await self.connection.close()
            finally:
                self._store.write_lock.release()
        if storage_error is not None:
            raise IngestionDependencyError(_ERR_STORAGE) from storage_error
        return None

    async def commit(self) -> None:
        try:
            await self.connection.commit()
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        self._committed = True


def _selection_values(
    request: ReplayRunRequest,
    watermark_time: int,
    watermark_event: str,
) -> dict[str, object]:
    return {
        "brain": request.brain_id,
        "from_event": request.from_event_id,
        "from_time": request.from_ingested_at_microseconds,
        "to_event": request.to_event_id,
        "to_time": request.to_ingested_at_microseconds,
        "watermark_event": watermark_event,
        "watermark_time": watermark_time,
    }


async def _seed_baselines(
    connection: AsyncConnection,
    request: ReplayRunRequest,
    now_microseconds: int,
) -> None:
    first_sequences = (
        (
            await connection.execute(
                text(
                    "SELECT x.ordering_key,MIN(x.sequence) AS first_sequence FROM "
                    "ordered_replay_sources s JOIN agent_event_envelopes x "
                    "ON x.event_id=s.event_id WHERE s.operation_id=:operation "
                    "AND x.sequence IS NOT NULL GROUP BY x.ordering_key"
                ),
                {"operation": request.operation_id},
            )
        )
        .mappings()
        .all()
    )
    for selected in first_sequences:
        baseline = (
            (
                await connection.execute(
                    text(
                        "SELECT event_sequence,state_sha256 FROM ordered_projection_history "
                        "WHERE projection_name=:projection AND brain_id=:brain "
                        "AND ordering_key=:ordering AND event_sequence<:sequence "
                        "ORDER BY event_sequence DESC,event_id DESC LIMIT 1"
                    ),
                    {
                        "brain": request.brain_id,
                        "ordering": str(selected["ordering_key"]),
                        "projection": request.projection_name,
                        "sequence": int(str(selected["first_sequence"])),
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
        if baseline is None:
            continue
        await connection.execute(
            text(
                "INSERT INTO ordered_replay_shadow_states "
                "(operation_id,ordering_key,applied_sequence,state_sha256,updated_at,"
                "schema_version) VALUES (:operation,:ordering,:sequence,:state,:now,1)"
            ),
            {
                "now": now_microseconds,
                "operation": request.operation_id,
                "ordering": str(selected["ordering_key"]),
                "sequence": int(str(baseline["event_sequence"])),
                "state": _bytes(baseline["state_sha256"]),
            },
        )


def _source_record(row: RowMapping, request: ReplayRunRequest) -> ReplaySourceRecord:
    operation_id = row["operation_id"]
    evidence: RecordedOperationEvidence | None = None
    if operation_id is not None:
        recorded_result = _bytes(row["recorded_result_sha256"])
        if (
            str(row["provider_state"]) != "completed"
            or str(row["profile_id"]) != str(row["provider_profile_id"])
            or str(row["provider_brain_id"]) != request.brain_id
            or recorded_result != _bytes(row["provider_result_sha256"])
            or str(row["recorded_result_ref"]) != str(row["provider_result_ref"])
        ):
            raise IngestionIntegrityError(_ERR_INTEGRITY)
        evidence = RecordedOperationEvidence(
            str(operation_id),
            str(row["profile_id"]),
            str(row["model_revision"]),
            str(row["purpose"]),
            recorded_result.hex(),
        )
    event_id = str(row["event_id"])
    canonical = _bytes(row["canonical_sha256"]).hex()
    projection_document = json.dumps(
        {"canonical_sha256": canonical, "event_id": event_id, "schema_version": 1},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    raw_sequence = row["sequence"]
    return ReplaySourceRecord(
        int(str(row["source_ordinal"])),
        int(str(row["ingested_at"])),
        OrderedReductionInput(
            event_id,
            str(row["ordering_key"]),
            None if raw_sequence is None else int(str(raw_sequence)),
            int(str(row["event_schema_version"])),
            canonical,
            hashlib.sha256(projection_document).hexdigest(),
            evidence is not None,
            evidence,
        ),
    )


async def _run_row(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM ordered_replay_runs WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _required_run_row(connection: AsyncConnection, operation_id: str) -> RowMapping:
    row = await _run_row(connection, operation_id)
    if row is None:
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    return row


def _restore_run(row: RowMapping) -> OrderedReplayRun:
    request = ReplayRunRequest(
        str(row["operation_id"]),
        str(row["brain_id"]),
        str(row["actor_id"]),
        str(row["grant_id"]),
        str(row["projection_name"]),
        str(row["projection_generation"]),
        str(row["code_fingerprint"]),
        _optional_int(row["from_ingested_at"]),
        _optional_int(row["to_ingested_at"]),
        _optional_str(row["from_event_id"]),
        _optional_str(row["to_event_id"]),
    )
    return OrderedReplayRun(
        request,
        ReplayRunState(str(row["state"])),
        int(str(row["source_watermark_ingested_at"])),
        str(row["source_watermark_event_id"]),
        int(str(row["source_count"])),
        int(str(row["processed_count"])),
        _optional_int(row["cursor_ingested_at"]),
        _optional_str(row["cursor_event_id"]),
        _optional_digest(row["shadow_digest"]),
        _optional_digest(row["live_digest"]),
        _optional_str(row["failure_code"]),
        _optional_str(row["lease_owner"]),
        _optional_int(row["lease_until"]),
        int(str(row["created_at"])),
        int(str(row["updated_at"])),
        _optional_int(row["completed_at"]),
    )


def _state(row: RowMapping) -> OrderedProjectionState:
    return OrderedProjectionState(
        str(row["ordering_key"]),
        int(str(row["applied_sequence"])),
        _bytes(row["state_sha256"]).hex(),
    )


async def _append_replay_audit(  # noqa: PLR0913 -- Hash-chain fact is explicit.
    connection: AsyncConnection,
    run: OrderedReplayRun,
    action: str,
    occurred_at: int,
    shadow_digest: str,
    live_digest: str,
) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = previous if isinstance(previous, bytes) else bytes(32)
    fact = json.dumps(
        {
            "action": action,
            "brain_id": run.request.brain_id,
            "live_digest": live_digest,
            "operation_id": run.request.operation_id,
            "shadow_digest": shadow_digest,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event_hash,:now,1)"
        ),
        {
            "action": action,
            "actor": run.request.actor_id,
            "after": bytes.fromhex(shadow_digest),
            "before": bytes.fromhex(live_digest),
            "brain": run.request.brain_id,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"ordered-replay:{run.request.operation_id}:{action}",
            "now": occurred_at,
            "previous": previous_hash,
            "target": run.request.operation_id,
        },
    )


def _optional_int(value: object) -> int | None:
    return None if value is None else int(str(value))


def _optional_str(value: object) -> str | None:
    return None if value is None else str(value)


def _optional_digest(value: object) -> str | None:
    return None if value is None else _bytes(value).hex()


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IngestionIntegrityError(_ERR_INTEGRITY)
    return value
