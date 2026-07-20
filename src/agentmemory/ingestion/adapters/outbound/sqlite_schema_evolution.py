"""SQLite resumable schema migration with Brain-encrypted derived views."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Never

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.adapters.outbound.envelope_crypto import decrypt_agent_event
from agentmemory.ingestion.domain.capture import EncryptedAgentEvent
from agentmemory.ingestion.domain.errors import (
    IngestionConflictError,
    IngestionDependencyError,
    IngestionIntegrityError,
)
from agentmemory.ingestion.domain.schema_evolution import (
    EventSchemaKey,
    EventSchemaOutcome,
    EventSchemaSource,
    SchemaEvolutionDisposition,
    SchemaMigrationProgress,
    SchemaMigrationState,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.ingestion.adapters.outbound.envelope_crypto import BrainKeyProvider
    from agentmemory.ingestion.domain.ports import (
        AgentEventEnvelopeEncryptor,
        CanonicalEventSourceReader,
    )
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_STORAGE = "Event schema migration storage is unavailable"
_ERR_CONFLICT = "Event schema migration identity conflicted"
_ERR_SOURCE = "Original canonical event lineage failed integrity verification"


class SqliteCanonicalEventSourceReader:
    """Authenticate and decrypt existing immutable AgentEvent envelope bytes."""

    def __init__(self, store: SqliteCoreStore, keys: BrainKeyProvider) -> None:
        """Bind the canonical store and Brain key boundary."""
        self._store = store
        self._keys = keys

    async def read(self, event_id: str) -> bytes:
        """Return exact canonical bytes only after every envelope binding verifies."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT e.brain_id,e.classification,x.envelope_version,x.algorithm,"
                                "x.brain_key_id,x.data_key_id,x.payload_nonce,x.ciphertext,"
                                "x.wrapped_data_key_nonce,x.wrapped_data_key,x.aad_sha256,"
                                "x.canonical_sha256 FROM agent_events e "
                                "JOIN agent_event_envelopes x ON x.event_id=e.event_id "
                                "WHERE e.event_id=:event_id"
                            ),
                            {"event_id": event_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        if row is None:
            raise IngestionIntegrityError(_ERR_SOURCE)
        encrypted = _encrypted(row)
        brain_id = str(row["brain_id"])
        key = await self._keys.current(brain_id)
        if key.key_id != encrypted.brain_key_id:
            raise IngestionIntegrityError(_ERR_SOURCE)
        plaintext = decrypt_agent_event(
            encrypted,
            key,
            event_id=event_id,
            brain_id=brain_id,
            classification=str(row["classification"]),
        )
        if _bytes(row["canonical_sha256"]).hex() != encrypted.canonical_sha256:
            raise IngestionIntegrityError(_ERR_SOURCE)
        return plaintext


class SqliteEventSchemaMigrationRepository:
    """Persist one encrypted view/quarantine and checkpoint in one transaction."""

    def __init__(
        self,
        store: SqliteCoreStore,
        reader: CanonicalEventSourceReader,
        encryptor: AgentEventEnvelopeEncryptor,
        clock: Clock,
    ) -> None:
        """Bind local-only persistence, source reader, encryption, and clock ports."""
        self._store = store
        self._reader = reader
        self._encryptor = encryptor
        self._clock = clock

    async def start_or_resume(
        self,
        operation_id: str,
        target: EventSchemaKey,
    ) -> SchemaMigrationProgress:
        """Capture one source watermark or reopen an exact interrupted run."""
        now = self._now()
        async with self._store.write_lock:
            try:
                async with self._store.engine.connect() as connection:
                    await connection.exec_driver_sql("BEGIN IMMEDIATE")
                    row = (
                        (
                            await connection.execute(
                                text(
                                    "SELECT * FROM event_schema_migrations "
                                    "WHERE operation_id=:operation_id"
                                ),
                                {"operation_id": operation_id},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        watermark = (
                            await connection.execute(
                                text(
                                    "SELECT MAX(event_id) FROM event_schema_sources "
                                    "WHERE schema_family=:family"
                                ),
                                {"family": target.family},
                            )
                        ).scalar_one()
                        total = (
                            await connection.execute(
                                text(
                                    "SELECT COUNT(*) FROM event_schema_sources "
                                    "WHERE schema_family=:family AND "
                                    "(:watermark IS NULL OR event_id<=:watermark)"
                                ),
                                {"family": target.family, "watermark": watermark},
                            )
                        ).scalar_one()
                        await connection.execute(
                            text(
                                "INSERT INTO event_schema_migrations "
                                "(operation_id,schema_family,target_major,target_version,state,"
                                "cursor_event_id,source_watermark_event_id,scanned,upcasted,"
                                "current_count,quarantined,total,started_at,updated_at,"
                                "schema_version) "
                                "VALUES (:operation_id,:family,:major,:version,'running',NULL,"
                                ":watermark,0,0,0,0,:total,:now,:now,1)"
                            ),
                            {
                                "operation_id": operation_id,
                                "family": target.family,
                                "major": target.major,
                                "version": target.version,
                                "watermark": watermark,
                                "total": int(total),
                                "now": now,
                            },
                        )
                    else:
                        _require_target(row, target)
                        if str(row["state"]) != SchemaMigrationState.COMPLETED:
                            await connection.execute(
                                text(
                                    "UPDATE event_schema_migrations SET state='running',"
                                    "updated_at=:now WHERE operation_id=:operation_id"
                                ),
                                {"operation_id": operation_id, "now": now},
                            )
                    await connection.commit()
            except (IntegrityError, SQLAlchemyError) as error:
                raise IngestionDependencyError(_ERR_STORAGE) from error
        progress = await self.get(operation_id)
        if progress is None:  # pragma: no cover - inserted/read in one repository call.
            raise IngestionIntegrityError(_ERR_SOURCE)
        return progress

    async def load_after(
        self,
        operation_id: str,
        cursor: str | None,
        limit: int,
    ) -> tuple[EventSchemaSource, ...]:
        """Decrypt one bounded page under the operation's captured watermark."""
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT s.event_id,s.schema_family,s.schema_major,"
                                "s.event_schema_version,s.original_canonical_sha256 "
                                "FROM event_schema_sources s JOIN event_schema_migrations m "
                                "ON m.operation_id=:operation_id "
                                "WHERE s.schema_family=m.schema_family "
                                "AND (m.source_watermark_event_id IS NULL "
                                "OR s.event_id<=m.source_watermark_event_id) "
                                "AND (:cursor IS NULL OR s.event_id>:cursor) "
                                "ORDER BY s.event_id LIMIT :limit"
                            ),
                            {
                                "operation_id": operation_id,
                                "cursor": cursor,
                                "limit": limit,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        sources: list[EventSchemaSource] = []
        for row in rows:
            event_id = str(row["event_id"])
            plaintext = await self._reader.read(event_id)
            sources.append(
                EventSchemaSource(
                    event_id,
                    EventSchemaKey(
                        str(row["schema_family"]),
                        int(row["schema_major"]),
                        int(row["event_schema_version"]),
                    ),
                    plaintext,
                    _bytes(row["original_canonical_sha256"]).hex(),
                )
            )
        return tuple(sources)

    async def store_and_checkpoint(
        self,
        operation_id: str,
        outcome: EventSchemaOutcome,
    ) -> SchemaMigrationProgress:
        """Encrypt a view or retain quarantine evidence, then advance once."""
        encrypted: EncryptedAgentEvent | None = None
        scope: RowMapping | None = None
        if outcome.disposition is not SchemaEvolutionDisposition.QUARANTINED:
            scope = await self._scope(outcome.event_id)
            if outcome.derived_bytes is None:
                raise AssertionError  # pragma: no cover - domain invariant.
            encrypted = await self._encryptor.encrypt(
                event_id=outcome.event_id,
                brain_id=str(scope["brain_id"]),
                classification=str(scope["classification"]),
                plaintext=outcome.derived_bytes,
            )
        now = self._now()
        async with self._store.write_lock:
            try:
                async with self._store.engine.connect() as connection:
                    await connection.exec_driver_sql("BEGIN IMMEDIATE")
                    run = (
                        (
                            await connection.execute(
                                text(
                                    "SELECT * FROM event_schema_migrations "
                                    "WHERE operation_id=:operation_id"
                                ),
                                {"operation_id": operation_id},
                            )
                        )
                        .mappings()
                        .one()
                    )
                    _require_target(run, outcome.target_schema)
                    existing = await _outcome_exists(connection, outcome.event_id)
                    if not existing:
                        cursor = run["cursor_event_id"]
                        if cursor is not None and outcome.event_id <= str(cursor):
                            _conflict()
                        if encrypted is None:
                            await _insert_quarantine(
                                connection,
                                operation_id,
                                outcome,
                                now,
                            )
                        else:
                            await _insert_view(
                                connection,
                                operation_id,
                                outcome,
                                encrypted,
                                now,
                            )
                        statement = {
                            SchemaEvolutionDisposition.CURRENT: (
                                "UPDATE event_schema_migrations SET scanned=scanned+1,"
                                "current_count=current_count+1,cursor_event_id=:event_id,"
                                "state='running',updated_at=:now WHERE operation_id=:operation_id"
                            ),
                            SchemaEvolutionDisposition.UPCASTED: (
                                "UPDATE event_schema_migrations SET scanned=scanned+1,"
                                "upcasted=upcasted+1,cursor_event_id=:event_id,"
                                "state='running',updated_at=:now WHERE operation_id=:operation_id"
                            ),
                            SchemaEvolutionDisposition.QUARANTINED: (
                                "UPDATE event_schema_migrations SET scanned=scanned+1,"
                                "quarantined=quarantined+1,cursor_event_id=:event_id,"
                                "state='running',updated_at=:now WHERE operation_id=:operation_id"
                            ),
                        }[outcome.disposition]
                        await connection.execute(
                            text(statement),
                            {
                                "event_id": outcome.event_id,
                                "now": now,
                                "operation_id": operation_id,
                            },
                        )
                    await connection.commit()
            except IngestionConflictError:
                raise
            except (IntegrityError, SQLAlchemyError) as error:
                raise IngestionDependencyError(_ERR_STORAGE) from error
        progress = await self.get(operation_id)
        if progress is None:  # pragma: no cover - stored/read in one repository call.
            raise IngestionIntegrityError(_ERR_SOURCE)
        return progress

    async def mark_interrupted(self, operation_id: str) -> SchemaMigrationProgress:
        """Release running state without changing committed views or cursor."""
        return await self._transition(operation_id, "interrupted", require_complete=False)

    async def complete(self, operation_id: str) -> SchemaMigrationProgress:
        """Complete only when every captured source has an outcome."""
        return await self._transition(operation_id, "completed", require_complete=True)

    async def _transition(
        self,
        operation_id: str,
        state: str,
        *,
        require_complete: bool,
    ) -> SchemaMigrationProgress:
        statement = (
            "UPDATE event_schema_migrations SET state=:state,updated_at=:now "
            "WHERE operation_id=:operation_id AND scanned=total"
            if require_complete
            else "UPDATE event_schema_migrations SET state=:state,updated_at=:now "
            "WHERE operation_id=:operation_id"
        )
        async with self._store.write_lock:
            try:
                async with self._store.engine.begin() as connection:
                    result = await connection.execute(
                        text(statement),
                        {"state": state, "now": self._now(), "operation_id": operation_id},
                    )
                    if result.rowcount != 1:
                        _conflict()
            except IngestionConflictError:
                raise
            except SQLAlchemyError as error:
                raise IngestionDependencyError(_ERR_STORAGE) from error
        progress = await self.get(operation_id)
        if progress is None:  # pragma: no cover - updated/read in one repository call.
            raise IngestionIntegrityError(_ERR_SOURCE)
        return progress

    async def get(self, operation_id: str) -> SchemaMigrationProgress | None:
        """Return durable content-free progress for an operator query."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM event_schema_migrations "
                                "WHERE operation_id=:operation_id"
                            ),
                            {"operation_id": operation_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return None if row is None else _progress(row)

    async def _scope(self, event_id: str) -> RowMapping:
        try:
            async with self._store.engine.connect() as connection:
                return (
                    (
                        await connection.execute(
                            text(
                                "SELECT brain_id,classification FROM agent_events "
                                "WHERE event_id=:event_id"
                            ),
                            {"event_id": event_id},
                        )
                    )
                    .mappings()
                    .one()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error

    def _now(self) -> int:
        return round(self._clock.now().timestamp() * 1_000_000)


def _progress(row: RowMapping) -> SchemaMigrationProgress:
    return SchemaMigrationProgress(
        str(row["operation_id"]),
        SchemaMigrationState(str(row["state"])),
        EventSchemaKey(
            str(row["schema_family"]),
            int(row["target_major"]),
            int(row["target_version"]),
        ),
        None if row["cursor_event_id"] is None else str(row["cursor_event_id"]),
        int(row["scanned"]),
        int(row["upcasted"]),
        int(row["current_count"]),
        int(row["quarantined"]),
        int(row["total"]),
    )


def _require_target(row: RowMapping, target: EventSchemaKey) -> None:
    actual = (
        str(row["schema_family"]),
        int(row["target_major"]),
        int(row["target_version"]),
    )
    if actual != (target.family, target.major, target.version):
        raise IngestionConflictError(_ERR_CONFLICT)


async def _outcome_exists(connection: AsyncConnection, event_id: str) -> bool:
    execute = connection.execute
    count = (
        await execute(
            text(
                "SELECT (SELECT COUNT(*) FROM event_schema_views WHERE event_id=:event_id) + "
                "(SELECT COUNT(*) FROM event_schema_quarantine WHERE event_id=:event_id)"
            ),
            {"event_id": event_id},
        )
    ).scalar_one()
    return bool(count)


async def _insert_view(
    connection: AsyncConnection,
    operation_id: str,
    outcome: EventSchemaOutcome,
    encrypted: EncryptedAgentEvent,
    now: int,
) -> None:
    trace = json.dumps(
        [
            {
                "input_sha256": item.input_sha256,
                "output_sha256": item.output_sha256,
                "source": item.source.token,
                "target": item.target.token,
                "upcaster_id": item.upcaster_id,
            }
            for item in outcome.steps
        ],
        separators=(",", ":"),
        sort_keys=True,
    )
    await connection.execute(
        text(
            "INSERT INTO event_schema_views "
            "(event_id,operation_id,target_major,target_version,original_sha256,derived_sha256,"
            "trace_sha256,trace_json,envelope_version,algorithm,brain_key_id,data_key_id,"
            "payload_nonce,ciphertext,wrapped_data_key_nonce,wrapped_data_key,aad_sha256,"
            "created_at,schema_version) VALUES "
            "(:event_id,:operation_id,:major,:version,:original,:derived,:trace_sha,:trace_json,"
            ":envelope_version,:algorithm,:brain_key_id,:data_key_id,:payload_nonce,:ciphertext,"
            ":wrapped_nonce,:wrapped_key,:aad,:now,1)"
        ),
        {
            "event_id": outcome.event_id,
            "operation_id": operation_id,
            "major": outcome.target_schema.major,
            "version": outcome.target_schema.version,
            "original": bytes.fromhex(outcome.original_sha256),
            "derived": bytes.fromhex(outcome.derived_sha256 or ""),
            "trace_sha": bytes.fromhex(outcome.trace_sha256),
            "trace_json": trace,
            "envelope_version": encrypted.envelope_version,
            "algorithm": encrypted.algorithm,
            "brain_key_id": encrypted.brain_key_id,
            "data_key_id": encrypted.data_key_id,
            "payload_nonce": encrypted.payload_nonce,
            "ciphertext": encrypted.ciphertext,
            "wrapped_nonce": encrypted.wrapped_data_key_nonce,
            "wrapped_key": encrypted.wrapped_data_key,
            "aad": bytes.fromhex(encrypted.aad_sha256),
            "now": now,
        },
    )


async def _insert_quarantine(
    connection: AsyncConnection,
    operation_id: str,
    outcome: EventSchemaOutcome,
    now: int,
) -> None:
    if outcome.quarantine_reason is None:
        raise AssertionError  # pragma: no cover - domain invariant.
    await connection.execute(
        text(
            "INSERT INTO event_schema_quarantine "
            "(event_id,operation_id,source_major,source_version,target_major,target_version,"
            "original_sha256,reason_code,quarantined_at,schema_version) VALUES "
            "(:event_id,:operation_id,:source_major,:source_version,:target_major,:target_version,"
            ":original,:reason,:now,1)"
        ),
        {
            "event_id": outcome.event_id,
            "operation_id": operation_id,
            "source_major": outcome.source_schema.major,
            "source_version": outcome.source_schema.version,
            "target_major": outcome.target_schema.major,
            "target_version": outcome.target_schema.version,
            "original": bytes.fromhex(outcome.original_sha256),
            "reason": outcome.quarantine_reason.value,
            "now": now,
        },
    )


def _encrypted(row: RowMapping) -> EncryptedAgentEvent:
    return EncryptedAgentEvent(
        int(row["envelope_version"]),
        str(row["algorithm"]),
        str(row["brain_key_id"]),
        str(row["data_key_id"]),
        _bytes(row["payload_nonce"]),
        _bytes(row["ciphertext"]),
        _bytes(row["wrapped_data_key_nonce"]),
        _bytes(row["wrapped_data_key"]),
        _bytes(row["aad_sha256"]).hex(),
        _bytes(row["canonical_sha256"]).hex(),
    )


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise IngestionIntegrityError(_ERR_SOURCE)


def _conflict() -> Never:
    raise IngestionConflictError(_ERR_CONFLICT)
