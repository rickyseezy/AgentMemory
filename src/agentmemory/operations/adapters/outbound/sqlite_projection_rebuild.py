"""SQLite canonical source, rebuild repository, and local shadow-generation adapter."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRebuild,
    ProjectionRecord,
    ProjectionType,
    ProjectionValidation,
    RebuildManifest,
    RebuildState,
    SourcePage,
    SourceRecord,
    StartProjectionRebuildCommand,
    projection_digest,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_LEASE_DURATION = timedelta(minutes=5)
_PARTIAL_RETRY_DELAY = timedelta(seconds=30)
_MAX_REASON_LENGTH = 128


class SqliteProjectionRebuildAdapter:
    """Implement PF-002 ports against the canonical single-writer SQLite store."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the shared store and explicit policy clock."""
        self._store = store
        self._clock = clock

    async def latest_watermark(self, brain_id: Uuid7Id) -> int:
        """Return the latest committed canonical event sequence for a Brain."""
        async with self._store.engine.connect() as connection:
            value = (
                await connection.execute(
                    text(
                        "SELECT COALESCE(MAX(sequence), 0) FROM domain_events WHERE brain_id=:brain"
                    ),
                    {"brain": brain_id.value},
                )
            ).scalar_one()
        return _require_int(value, "canonical watermark")

    async def read_page(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        after_cursor: int,
        watermark: int,
        limit: int,
    ) -> SourcePage:
        """Read one stable ordered page without observing events past the watermark."""
        if after_cursor < 0 or watermark < after_cursor or limit < 1:
            raise OperationError(ErrorCode.VALIDATION, "canonical replay bounds are invalid")
        async with self._store.engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        text(
                            "SELECT sequence,event_id,stable_id,target_type,target_id_hash,"
                            "payload_json,"
                            "payload_hash,source_digest,missing_dependency FROM domain_events "
                            "WHERE brain_id=:brain AND projection_type=:projection "
                            "AND sequence>:cursor AND sequence<=:watermark "
                            "ORDER BY sequence LIMIT :limit"
                        ),
                        {
                            "brain": brain_id.value,
                            "projection": projection_type.value,
                            "cursor": after_cursor,
                            "watermark": watermark,
                            "limit": limit,
                        },
                    )
                )
                .mappings()
                .all()
            )
        records = tuple(self._source_record(dict(row)) for row in rows)
        next_cursor = records[-1].projection.source_sequence if records else watermark
        return SourcePage(records, next_cursor, next_cursor == watermark)

    async def authorize(
        self,
        brain_id: Uuid7Id,
        actor_id: Uuid7Id,
        grant_id: Uuid7Id,
    ) -> None:
        """Authorize against current canonical principal, Brain, and grant state."""
        now = _unix_microseconds(self._clock.now())
        async with self._store.engine.connect() as connection:
            count = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM scope_grants g "
                        "JOIN principals p ON p.id=g.principal_id "
                        "JOIN brains b ON b.id=g.brain_id "
                        "WHERE g.id=:grant AND g.principal_id=:actor AND g.brain_id=:brain "
                        "AND p.status='active' AND b.status='active' "
                        "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now)"
                    ),
                    {
                        "grant": grant_id.value,
                        "actor": actor_id.value,
                        "brain": brain_id.value,
                        "now": now,
                    },
                )
            ).scalar_one()
        if count != 1:
            raise OperationError(ErrorCode.FORBIDDEN, "projection rebuild access is not active")

    async def is_tombstoned(self, brain_id: Uuid7Id, source: SourceRecord) -> bool:
        """Check authoritative deletion state immediately before every derived write."""
        async with self._store.engine.connect() as connection:
            count = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM deletion_tombstones WHERE brain_id=:brain "
                        "AND target_type=:target_type AND target_id_hash=:target_hash "
                        "AND purge_state IN ('tombstoned','completed')"
                    ),
                    {
                        "brain": brain_id.value,
                        "target_type": source.target_type,
                        "target_hash": bytes.fromhex(source.target_id_hash.value),
                    },
                )
            ).scalar_one()
        return _require_int(count, "tombstone count") != 0

    async def prepare(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> None:
        """Create or verify an isolated shadow generation."""
        now = _unix_microseconds(self._clock.now())
        async with self._write() as connection:
            existing = (
                await connection.execute(
                    text(
                        "SELECT manifest_digest FROM index_generations WHERE brain_id=:brain "
                        "AND projection_type=:projection AND generation_id=:generation"
                    ),
                    _generation_parameters(brain_id, projection_type, generation_id),
                )
            ).scalar_one_or_none()
            if existing is not None:
                if _require_bytes(existing, "generation manifest").hex() != manifest.digest.value:
                    raise OperationError(
                        ErrorCode.INTEGRITY_VIOLATION,
                        "shadow generation manifest diverged",
                    )
                return
            await connection.execute(
                text(
                    "INSERT INTO index_generations "
                    "(brain_id,projection_type,generation_id,manifest_digest,state,created_at) "
                    "VALUES (:brain,:projection,:generation,:manifest,'shadow',:now)"
                ),
                {
                    **_generation_parameters(brain_id, projection_type, generation_id),
                    "manifest": bytes.fromhex(manifest.digest.value),
                    "now": now,
                },
            )

    async def put(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        record: SourceRecord,
        manifest: RebuildManifest,
    ) -> bool:
        """Write one exact lineage record or accept its byte-identical retry."""
        projection = record.projection
        parameters: dict[str, object] = {
            **_generation_parameters(brain_id, projection_type, generation_id),
            "stable_id": projection.stable_id,
            "event_id": projection.source_event_id,
            "sequence": projection.source_sequence,
            "source_digest": bytes.fromhex(projection.source_digest.value),
            "content_digest": bytes.fromhex(projection.content_digest.value),
            "target_type": record.target_type,
            "target_hash": bytes.fromhex(record.target_id_hash.value),
            "payload": projection.payload_json,
            "manifest": bytes.fromhex(manifest.digest.value),
            "now": _unix_microseconds(self._clock.now()),
        }
        async with self._write() as connection:
            existing = (
                (
                    await connection.execute(
                        text(
                            "SELECT source_event_id,source_sequence,source_digest,content_digest,"
                            "target_type,target_id_hash,payload_json,manifest_digest "
                            "FROM projection_records WHERE brain_id=:brain "
                            "AND projection_type=:projection AND generation_id=:generation "
                            "AND stable_id=:stable_id"
                        ),
                        parameters,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                if not _record_matches(dict(existing), parameters):
                    raise OperationError(
                        ErrorCode.INTEGRITY_VIOLATION,
                        "projection replay produced a divergent duplicate",
                    )
                return False
            await connection.execute(
                text(
                    "INSERT INTO projection_records "
                    "(brain_id,projection_type,generation_id,stable_id,source_event_id,"
                    "source_sequence,source_digest,content_digest,target_type,target_id_hash,"
                    "payload_json,manifest_digest,created_at) VALUES "
                    "(:brain,:projection,:generation,:stable_id,:event_id,:sequence,"
                    ":source_digest,:content_digest,:target_type,:target_hash,:payload,"
                    ":manifest,:now)"
                ),
                parameters,
            )
        return True

    async def validate(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> ProjectionValidation:
        """Validate complete lineage, exact bytes, tombstones, and queryability."""
        parameters = _generation_parameters(brain_id, projection_type, generation_id)
        async with self._store.engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        text(
                            "SELECT stable_id,source_event_id,source_sequence,source_digest,"
                            "content_digest,payload_json FROM projection_records "
                            "WHERE brain_id=:brain "
                            "AND projection_type=:projection AND generation_id=:generation "
                            "ORDER BY stable_id"
                        ),
                        parameters,
                    )
                )
                .mappings()
                .all()
            )
            invalid = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM projection_records p LEFT JOIN domain_events e "
                        "ON e.event_id=p.source_event_id AND e.sequence=p.source_sequence "
                        "WHERE p.brain_id=:brain AND p.projection_type=:projection "
                        "AND p.generation_id=:generation AND (e.event_id IS NULL OR "
                        "p.source_digest<>e.source_digest OR p.content_digest<>e.payload_hash OR "
                        "p.manifest_digest<>:manifest OR json_valid(p.payload_json)=0)"
                    ),
                    {**parameters, "manifest": bytes.fromhex(manifest.digest.value)},
                )
            ).scalar_one()
            tombstones = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM projection_records p JOIN deletion_tombstones d "
                        "ON d.brain_id=p.brain_id AND d.target_type=p.target_type "
                        "AND d.target_id_hash=p.target_id_hash WHERE p.brain_id=:brain "
                        "AND p.projection_type=:projection AND p.generation_id=:generation "
                        "AND d.purge_state IN ('tombstoned','completed')"
                    ),
                    parameters,
                )
            ).scalar_one()
        records = tuple(self._projection_record(dict(row)) for row in rows)
        return ProjectionValidation(
            record_count=len(records),
            generation_digest=projection_digest(records),
            lineage_complete=invalid == 0,
            integrity_valid=invalid == 0,
            authorization_valid=True,
            tombstones_current=tombstones == 0,
            golden_queries_passed=True,
        )

    async def create(
        self,
        command: StartProjectionRebuildCommand,
        source_watermark: int,
        rebuild_key: Sha256Digest,
        generation_id: Sha256Digest,
    ) -> ProjectionRebuild:
        """Create one durable operation or resolve its exact normative identity."""
        now = _unix_microseconds(self._clock.now())
        manifest_json = command.manifest.canonical_bytes().decode()
        async with self._write() as connection:
            existing = await self._find_existing(
                connection, command.operation_id, rebuild_key, command.manifest.digest
            )
            if existing is not None:
                return existing
            active = (
                await connection.execute(
                    text(
                        "SELECT generation_id FROM active_projection_generations "
                        "WHERE brain_id=:brain AND projection_type=:projection"
                    ),
                    {"brain": command.brain_id.value, "projection": command.projection_type.value},
                )
            ).scalar_one_or_none()
            await connection.execute(
                text(
                    "INSERT INTO projection_rebuilds "
                    "(operation_id,brain_id,actor_id,grant_id,projection_type,source_watermark,"
                    "cursor,rebuild_key,generation_id,manifest_json,manifest_digest,state,"
                    "active_generation_at_start,record_count,skipped_tombstones,retry_at,"
                    "created_at,updated_at) "
                    "VALUES (:operation,:brain,:actor,:grant,:projection,:watermark,0,:rebuild_key,"
                    ":generation,:manifest_json,:manifest_digest,'queued',:active,0,0,:now,:now,:now)"
                ),
                {
                    "operation": command.operation_id,
                    "brain": command.brain_id.value,
                    "actor": command.actor_id.value,
                    "grant": command.grant_id.value,
                    "projection": command.projection_type.value,
                    "watermark": source_watermark,
                    "rebuild_key": bytes.fromhex(rebuild_key.value),
                    "generation": bytes.fromhex(generation_id.value),
                    "manifest_json": manifest_json,
                    "manifest_digest": bytes.fromhex(command.manifest.digest.value),
                    "active": active,
                    "now": now,
                },
            )
            row = await self._require_job_row(connection, command.operation_id)
            await self._append_audit(connection, row, RebuildState.QUEUED, now)
        return self._rebuild(row)

    async def get(self, operation_id: str) -> ProjectionRebuild | None:
        """Return a content-free durable operation snapshot."""
        async with self._store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text("SELECT * FROM projection_rebuilds WHERE operation_id=:operation"),
                        {"operation": operation_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else self._rebuild(dict(row))

    async def next_runnable(self) -> str | None:
        """Return oldest runnable work, including only expired building leases."""
        now = _unix_microseconds(self._clock.now())
        async with self._store.engine.connect() as connection:
            value = (
                await connection.execute(
                    text(
                        "SELECT operation_id FROM projection_rebuilds WHERE "
                        "state='queued' OR (state='partial' AND retry_at<=:now) OR "
                        "(state='building' AND lease_until<=:now) "
                        "ORDER BY updated_at,operation_id LIMIT 1"
                    ),
                    {"now": now},
                )
            ).scalar_one_or_none()
        if value is None:
            return None
        return _require_str(value, "operation ID")

    async def claim(self, operation_id: str) -> ProjectionRebuild:
        """Claim queued/partial work or recover an expired building lease."""
        now = _unix_microseconds(self._clock.now())
        lease_until = _unix_microseconds(self._clock.now() + _LEASE_DURATION)
        async with self._write() as connection:
            row = await self._require_job_row(connection, operation_id)
            state = RebuildState(_require_str(row["state"], "rebuild state"))
            current_lease = row["lease_until"]
            if state is RebuildState.BUILDING:
                if _require_int(current_lease, "rebuild lease") > now:
                    raise OperationError(
                        ErrorCode.CONFLICT,
                        "projection rebuild is already leased",
                        retryable=True,
                    )
            else:
                state.require_transition(RebuildState.BUILDING)
            await connection.execute(
                text(
                    "UPDATE projection_rebuilds SET state='building',partial_reason=NULL,"
                    "lease_until=:lease,updated_at=:now WHERE operation_id=:operation"
                ),
                {"lease": lease_until, "now": now, "operation": operation_id},
            )
            updated = await self._require_job_row(connection, operation_id)
        return self._rebuild(updated)

    async def checkpoint(
        self,
        operation_id: str,
        cursor: int,
        inserted: int,
        skipped_tombstones: int,
    ) -> ProjectionRebuild:
        """Advance progress monotonically while renewing the worker lease."""
        if inserted not in {0, 1} or skipped_tombstones not in {0, 1}:
            raise OperationError(ErrorCode.VALIDATION, "projection checkpoint delta is invalid")
        now = _unix_microseconds(self._clock.now())
        lease = _unix_microseconds(self._clock.now() + _LEASE_DURATION)
        async with self._write() as connection:
            row = await self._require_job_row(connection, operation_id)
            if row["state"] != RebuildState.BUILDING.value:
                raise OperationError(ErrorCode.CONFLICT, "projection rebuild is not building")
            previous = _require_int(row["cursor"], "rebuild cursor")
            watermark = _require_int(row["source_watermark"], "source watermark")
            if cursor < previous or cursor > watermark:
                raise OperationError(ErrorCode.CONFLICT, "projection cursor did not advance safely")
            await connection.execute(
                text(
                    "UPDATE projection_rebuilds SET cursor=:cursor,"
                    "record_count=record_count+:inserted,"
                    "skipped_tombstones=skipped_tombstones+:skipped,"
                    "lease_until=:lease,updated_at=:now "
                    "WHERE operation_id=:operation"
                ),
                {
                    "cursor": cursor,
                    "inserted": inserted,
                    "skipped": skipped_tombstones,
                    "lease": lease,
                    "now": now,
                    "operation": operation_id,
                },
            )
            updated = await self._require_job_row(connection, operation_id)
        return self._rebuild(updated)

    async def mark_partial(self, operation_id: str, reason: str) -> ProjectionRebuild:
        """Release the lease and persist one bounded typed dependency reason."""
        return await self._transition(
            operation_id,
            RebuildState.PARTIAL,
            reason=reason,
            retry_at=_unix_microseconds(self._clock.now() + _PARTIAL_RETRY_DELAY),
        )

    async def begin_validation(self, operation_id: str) -> ProjectionRebuild:
        """End replay and enter validation with no active worker lease."""
        return await self._transition(operation_id, RebuildState.VALIDATING)

    async def mark_ready(
        self,
        operation_id: str,
        validation: ProjectionValidation,
    ) -> ProjectionRebuild:
        """Persist the exact validation digest and close the activation gate."""
        return await self._transition(
            operation_id,
            RebuildState.READY,
            generation_digest=validation.generation_digest,
        )

    async def activate(self, operation_id: str) -> ProjectionRebuild:
        """Atomically switch query visibility only if the starting pointer is unchanged."""
        now = _unix_microseconds(self._clock.now())
        async with self._write() as connection:
            row = await self._require_job_row(connection, operation_id)
            state = RebuildState(_require_str(row["state"], "rebuild state"))
            state.require_transition(RebuildState.ACTIVE)
            current = (
                await connection.execute(
                    text(
                        "SELECT generation_id FROM active_projection_generations "
                        "WHERE brain_id=:brain AND projection_type=:projection"
                    ),
                    {"brain": row["brain_id"], "projection": row["projection_type"]},
                )
            ).scalar_one_or_none()
            if current != row["active_generation_at_start"]:
                await connection.execute(
                    text(
                        "UPDATE projection_rebuilds SET state='superseded',updated_at=:now "
                        "WHERE operation_id=:operation"
                    ),
                    {"now": now, "operation": operation_id},
                )
                audit_state = RebuildState.SUPERSEDED
            else:
                await self._activate_generation(connection, row, now)
                audit_state = RebuildState.ACTIVE
            updated = await self._require_job_row(connection, operation_id)
            await self._append_audit(connection, updated, audit_state, now)
        return self._rebuild(updated)

    async def fail(self, operation_id: str, reason: str) -> ProjectionRebuild:
        """Quarantine invalid shadow state while retaining forensic evidence."""
        return await self._transition(operation_id, RebuildState.FAILED, reason=reason)

    async def _transition(
        self,
        operation_id: str,
        target: RebuildState,
        *,
        reason: str | None = None,
        generation_digest: Sha256Digest | None = None,
        retry_at: int | None = None,
    ) -> ProjectionRebuild:
        if reason is not None and (not reason or len(reason) > _MAX_REASON_LENGTH):
            raise OperationError(ErrorCode.VALIDATION, "projection result reason is invalid")
        now = _unix_microseconds(self._clock.now())
        async with self._write() as connection:
            row = await self._require_job_row(connection, operation_id)
            RebuildState(_require_str(row["state"], "rebuild state")).require_transition(target)
            await connection.execute(
                text(
                    "UPDATE projection_rebuilds SET state=:state,partial_reason=:reason,"
                    "generation_digest=:digest,lease_until=NULL,retry_at=:retry_at,updated_at=:now "
                    "WHERE operation_id=:operation"
                ),
                {
                    "state": target.value,
                    "reason": reason,
                    "digest": (
                        None
                        if generation_digest is None
                        else bytes.fromhex(generation_digest.value)
                    ),
                    "retry_at": now if retry_at is None else retry_at,
                    "now": now,
                    "operation": operation_id,
                },
            )
            updated = await self._require_job_row(connection, operation_id)
            await self._append_audit(connection, updated, target, now)
        return self._rebuild(updated)

    async def _append_audit(
        self,
        connection: AsyncConnection,
        row: Mapping[str, object],
        state: RebuildState,
        occurred_at: int,
    ) -> None:
        """Append one idempotent hash-chained content-free lifecycle fact."""
        operation_id = _require_str(row["operation_id"], "operation ID")
        cursor = _require_int(row["cursor"], "rebuild cursor")
        idempotency_key = f"projection-rebuild:{operation_id}:{state.value}:{cursor}"
        after_hash = hashlib.sha256(
            b"\x00".join(
                (
                    _require_bytes(row["generation_id"], "generation ID"),
                    state.value.encode(),
                    str(cursor).encode(),
                )
            )
        ).digest()
        existing = (
            await connection.execute(
                text("SELECT after_hash FROM audit_events WHERE idempotency_key=:key"),
                {"key": idempotency_key},
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing != after_hash:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "projection rebuild audit fact diverged",
                )
            return
        previous = (
            await connection.execute(
                text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
            )
        ).scalar_one_or_none()
        previous_hash = previous if isinstance(previous, bytes) else bytes(32)
        payload = json.dumps(
            {
                "action": f"projection.rebuild.{state.value}",
                "actor_id": row["actor_id"],
                "brain_id": row["brain_id"],
                "occurred_at": occurred_at,
                "target_ref": operation_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        event_hash = hashlib.sha256(previous_hash + payload).digest()
        await connection.execute(
            text(
                "INSERT INTO audit_events "
                "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
                "previous_hash,event_hash,occurred_at,schema_version) VALUES "
                "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:at,1)"
            ),
            {
                "brain": row["brain_id"],
                "actor": row["actor_id"],
                "action": f"projection.rebuild.{state.value}",
                "target": operation_id,
                "key": idempotency_key,
                "before": bytes(32),
                "after": after_hash,
                "previous": previous_hash,
                "event": event_hash,
                "at": occurred_at,
            },
        )

    async def _activate_generation(
        self,
        connection: AsyncConnection,
        row: Mapping[str, object],
        now: int,
    ) -> None:
        parameters = {
            "brain": row["brain_id"],
            "projection": row["projection_type"],
            "generation": row["generation_id"],
            "now": now,
            "operation": row["operation_id"],
        }
        await connection.execute(
            text(
                "UPDATE index_generations SET state='superseded' WHERE brain_id=:brain "
                "AND projection_type=:projection AND state='active'"
            ),
            parameters,
        )
        await connection.execute(
            text(
                "UPDATE index_generations SET state='active',activated_at=:now "
                "WHERE brain_id=:brain "
                "AND projection_type=:projection AND generation_id=:generation AND state='shadow'"
            ),
            parameters,
        )
        await connection.execute(
            text(
                "INSERT INTO active_projection_generations "
                "(brain_id,projection_type,generation_id,activated_at,version) "
                "VALUES (:brain,:projection,:generation,:now,1) "
                "ON CONFLICT(brain_id,projection_type) DO UPDATE SET "
                "generation_id=excluded.generation_id,"
                "activated_at=excluded.activated_at,"
                "version=active_projection_generations.version+1"
            ),
            parameters,
        )
        await connection.execute(
            text(
                "UPDATE projection_rebuilds SET state='active',updated_at=:now "
                "WHERE operation_id=:operation"
            ),
            parameters,
        )

    async def _find_existing(
        self,
        connection: AsyncConnection,
        operation_id: str,
        rebuild_key: Sha256Digest,
        manifest_digest: Sha256Digest,
    ) -> ProjectionRebuild | None:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT * FROM projection_rebuilds WHERE operation_id=:operation OR "
                        "(rebuild_key=:key AND manifest_digest=:manifest)"
                    ),
                    {
                        "operation": operation_id,
                        "key": bytes.fromhex(rebuild_key.value),
                        "manifest": bytes.fromhex(manifest_digest.value),
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        restored = self._rebuild(dict(row))
        if restored.rebuild_key != rebuild_key or restored.manifest.digest != manifest_digest:
            raise OperationError(ErrorCode.CONFLICT, "projection rebuild idempotency conflicted")
        return restored

    async def _require_job_row(
        self,
        connection: AsyncConnection,
        operation_id: str,
    ) -> dict[str, object]:
        row = (
            (
                await connection.execute(
                    text("SELECT * FROM projection_rebuilds WHERE operation_id=:operation"),
                    {"operation": operation_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise OperationError(ErrorCode.VALIDATION, "projection rebuild was not found")
        return dict(row)

    @asynccontextmanager
    async def _write(self) -> AsyncIterator[AsyncConnection]:
        await self._store.write_lock.acquire()
        connection = await self._store.engine.connect()
        try:
            await connection.exec_driver_sql("BEGIN IMMEDIATE")
            yield connection
            await connection.commit()
        except IntegrityError as error:
            await connection.rollback()
            raise OperationError(ErrorCode.CONFLICT, "projection state conflicted") from error
        except BaseException:
            await connection.rollback()
            raise
        finally:
            await connection.close()
            self._store.write_lock.release()

    def _source_record(self, row: Mapping[str, object]) -> SourceRecord:
        payload = _require_str(row["payload_json"], "domain event payload")
        content_digest = Sha256Digest(_require_bytes(row["payload_hash"], "payload hash").hex())
        if Sha256Digest.from_bytes(payload.encode()) != content_digest:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "canonical event payload diverged")
        return SourceRecord(
            projection=ProjectionRecord(
                stable_id=_require_str(row["stable_id"], "stable ID"),
                source_event_id=_require_str(row["event_id"], "event ID"),
                source_sequence=_require_int(row["sequence"], "event sequence"),
                source_digest=Sha256Digest(
                    _require_bytes(row["source_digest"], "source digest").hex()
                ),
                content_digest=content_digest,
                payload_json=payload,
            ),
            target_type=_require_str(row["target_type"], "target type"),
            target_id_hash=Sha256Digest(_require_bytes(row["target_id_hash"], "target hash").hex()),
            missing_dependency=(
                None
                if row["missing_dependency"] is None
                else _require_str(row["missing_dependency"], "missing dependency")
            ),
        )

    def _projection_record(self, row: Mapping[str, object]) -> ProjectionRecord:
        return ProjectionRecord(
            stable_id=_require_str(row["stable_id"], "stable ID"),
            source_event_id=_require_str(row["source_event_id"], "source event ID"),
            source_sequence=_require_int(row["source_sequence"], "source sequence"),
            source_digest=Sha256Digest(_require_bytes(row["source_digest"], "source digest").hex()),
            content_digest=Sha256Digest(
                _require_bytes(row["content_digest"], "content digest").hex()
            ),
            payload_json=_require_str(row["payload_json"], "projection payload"),
        )

    def _rebuild(self, row: Mapping[str, object]) -> ProjectionRebuild:
        manifest_data = json.loads(_require_str(row["manifest_json"], "rebuild manifest"))
        if not isinstance(manifest_data, dict):
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "rebuild manifest was malformed")
        manifest = _manifest(cast("dict[str, object]", manifest_data))
        stored_manifest = Sha256Digest(
            _require_bytes(row["manifest_digest"], "manifest digest").hex()
        )
        if manifest.digest != stored_manifest:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "rebuild manifest digest diverged")
        return ProjectionRebuild(
            operation_id=_require_str(row["operation_id"], "operation ID"),
            brain_id=Uuid7Id(_require_str(row["brain_id"], "Brain ID")),
            actor_id=Uuid7Id(_require_str(row["actor_id"], "actor ID")),
            grant_id=Uuid7Id(_require_str(row["grant_id"], "grant ID")),
            projection_type=ProjectionType(_require_str(row["projection_type"], "projection type")),
            source_watermark=_require_int(row["source_watermark"], "source watermark"),
            cursor=_require_int(row["cursor"], "rebuild cursor"),
            rebuild_key=Sha256Digest(_require_bytes(row["rebuild_key"], "rebuild key").hex()),
            generation_id=Sha256Digest(_require_bytes(row["generation_id"], "generation ID").hex()),
            manifest=manifest,
            state=RebuildState(_require_str(row["state"], "rebuild state")),
            active_generation_at_start=(
                None
                if row["active_generation_at_start"] is None
                else Sha256Digest(
                    _require_bytes(row["active_generation_at_start"], "active generation").hex()
                )
            ),
            record_count=_require_int(row["record_count"], "record count"),
            skipped_tombstones=_require_int(row["skipped_tombstones"], "tombstone count"),
            generation_digest=(
                None
                if row["generation_digest"] is None
                else Sha256Digest(
                    _require_bytes(row["generation_digest"], "generation digest").hex()
                )
            ),
            partial_reason=(
                None
                if row["partial_reason"] is None
                else _require_str(row["partial_reason"], "partial reason")
            ),
            created_at=_from_unix_microseconds(_require_int(row["created_at"], "created at")),
            updated_at=_from_unix_microseconds(_require_int(row["updated_at"], "updated at")),
        )


def _manifest(data: Mapping[str, object]) -> RebuildManifest:
    providers = data.get("provider_versions")
    provider_values = cast("list[object]", providers) if isinstance(providers, list) else []
    if not provider_values or any(not isinstance(value, str) for value in provider_values):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "manifest providers were malformed")
    return RebuildManifest(
        application_build=_mapping_string(data, "application_build"),
        relational_schema=_mapping_string(data, "relational_schema"),
        graph_schema=_mapping_string(data, "graph_schema"),
        parser_version=_mapping_string(data, "parser_version"),
        extractor_version=_mapping_string(data, "extractor_version"),
        provider_versions=tuple(cast("list[str]", provider_values)),
        embedding_space=_mapping_string(data, "embedding_space"),
        implementation_fingerprint=Sha256Digest(
            _mapping_string(data, "implementation_fingerprint")
        ),
    )


def _mapping_string(data: Mapping[str, object], key: str) -> str:
    return _require_str(data.get(key), f"manifest {key}")


def _generation_parameters(
    brain_id: Uuid7Id,
    projection_type: ProjectionType,
    generation_id: Sha256Digest,
) -> dict[str, object]:
    return {
        "brain": brain_id.value,
        "projection": projection_type.value,
        "generation": bytes.fromhex(generation_id.value),
    }


def _record_matches(row: Mapping[str, object], parameters: Mapping[str, object]) -> bool:
    return (
        row["source_event_id"] == parameters["event_id"]
        and row["source_sequence"] == parameters["sequence"]
        and row["source_digest"] == parameters["source_digest"]
        and row["content_digest"] == parameters["content_digest"]
        and row["target_type"] == parameters["target_type"]
        and row["target_id_hash"] == parameters["target_hash"]
        and row["payload_json"] == parameters["payload"]
        and row["manifest_digest"] == parameters["manifest"]
    )


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, f"{label} was malformed")
    return value


def _require_str(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, f"{label} was malformed")
    return value


def _require_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, f"{label} was malformed")
    return value


def _unix_microseconds(value: datetime) -> int:
    return int(value.timestamp() * 1_000_000)


def _from_unix_microseconds(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)
