"""SQLite scope resolution and atomic encrypted AgentEvent capture."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Self
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.adapters.outbound.sqlite_capabilities import (
    SqliteAdapterCapabilityQueryRepository,
)
from agentmemory.ingestion.domain.agent_event import (
    ResolvedAgentEventIdentity,
)
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionConflictError,
    IngestionDependencyError,
)

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from agentmemory.ingestion.domain.adapter_capability import RegisteredAdapterCapabilities
    from agentmemory.ingestion.domain.agent_event import AgentEventIdentity, AgentEventProvenance
    from agentmemory.ingestion.domain.capture import AdmittedAgentEvent, EncryptedAgentEvent
    from agentmemory.ingestion.domain.ports import (
        AgentEventRepository,
        AgentEventUnitOfWork,
        ArtifactRepository,
        IngestionAuditRepository,
        OutboxRepository,
    )
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

    from .sqlite_backpressure import SqliteCaptureCapacityEnforcer

_SCOPE_QUERY = """
SELECT p.id AS principal_id, b.id AS brain_id, project.id AS project_id,
       repository.id AS repository_id, checkout.id AS checkout_id
FROM scope_grants AS grant
JOIN principals AS p ON p.id = grant.principal_id AND p.status = 'active'
JOIN brains AS b ON b.id = grant.brain_id AND b.status = 'active'
JOIN projects AS project ON project.id = :project_id
  AND project.brain_id = b.id AND project.status = 'active'
JOIN project_repositories AS mapping ON mapping.project_id = project.id
JOIN repositories AS repository ON repository.id = mapping.repository_id
  AND repository.id = :repository_id AND repository.brain_id = b.id
  AND repository.status = 'active'
LEFT JOIN checkouts AS checkout ON checkout.id = :checkout_id
  AND checkout.brain_id = b.id AND checkout.repository_id = repository.id
  AND checkout.status = 'active'
WHERE grant.principal_id = :principal_id AND grant.brain_id = :brain_id
  AND grant.role = 'owner' AND grant.valid_from <= :now
  AND (grant.valid_to IS NULL OR grant.valid_to > :now)
  AND (:checkout_id IS NULL OR checkout.id IS NOT NULL)
"""
_ERR_REGISTRY_UNAVAILABLE = "Adapter descriptor registry is unavailable"
_ERR_ADAPTER_UNREGISTERED = "Agent adapter is not registered"
_ERR_SCOPE_UNAVAILABLE = "AgentEvent scope resolution is unavailable"
_ERR_SCOPE_DENIED = "AgentEvent scope is not authorized"
_ERR_ALREADY_COMMITTED = "AgentEvent transaction was already committed"
_ERR_EVENT_CONFLICT = "AgentEvent identity or order conflicted"
_ERR_COMMIT = "AgentEvent durable commit failed"
_ERR_ID_REUSE = "AgentEvent ID was reused for different content"
_ERR_ENQUEUE = "AgentEvent durable enqueue failed"
_ERR_STORAGE_MALFORMED = "AgentEvent storage was malformed"


class SqliteAdapterCapabilityRegistry:
    """Read exact active adapter capability manifests from canonical daemon state."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Bind the sole canonical read engine."""
        self._capabilities = SqliteAdapterCapabilityQueryRepository(engine)

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
    ) -> RegisteredAdapterCapabilities:
        """Load exact immutable declaration and latest effective evidence."""
        try:
            registration = await self._capabilities.get(adapter_id, adapter_version)
        except (IngestionDependencyError, ValueError) as error:
            raise IngestionDependencyError(_ERR_REGISTRY_UNAVAILABLE) from error
        if registration is None:
            raise IngestionAuthorizationError(_ERR_ADAPTER_UNREGISTERED)
        if registration.manifest.adapter_digest != adapter_digest:
            raise IngestionAuthorizationError(_ERR_ADAPTER_UNREGISTERED)
        return registration


class SqliteAgentEventScopeResolver:
    """Resolve untrusted claims only through active canonical identity relationships."""

    def __init__(self, engine: AsyncEngine, clock: Clock) -> None:
        """Bind current identity state and the policy clock."""
        self._engine = engine
        self._clock = clock

    async def resolve(
        self,
        claim: AgentEventIdentity,
        provenance: AgentEventProvenance,
    ) -> ResolvedAgentEventIdentity:
        """Return exact authoritative scope; provenance never grants authority."""
        del provenance
        parameters = {
            "brain_id": claim.brain_id,
            "principal_id": claim.principal_id,
            "project_id": claim.project_id,
            "repository_id": claim.repository_id,
            "checkout_id": claim.checkout_id,
            "now": _unix_microseconds(self._clock.now()),
        }
        try:
            async with self._engine.connect() as connection:
                row = (
                    (await connection.execute(text(_SCOPE_QUERY), parameters))
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_SCOPE_UNAVAILABLE) from error
        if row is None:
            raise IngestionAuthorizationError(_ERR_SCOPE_DENIED)
        return ResolvedAgentEventIdentity(
            brain_id=str(row["brain_id"]),
            principal_id=str(row["principal_id"]),
            project_id=str(row["project_id"]),
            repository_id=str(row["repository_id"]),
            checkout_id=None if row["checkout_id"] is None else str(row["checkout_id"]),
        )


class SqliteAgentEventUnitOfWork:
    """Own one serialized FULL-durability event/outbox/audit transaction."""

    def __init__(
        self,
        store: SqliteCoreStore,
        clock: Clock,
        capacity: SqliteCaptureCapacityEnforcer | None = None,
    ) -> None:
        """Bind the single-writer store and policy clock."""
        self._store = store
        self._clock = clock
        self._capacity = capacity
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.events: AgentEventRepository
        self.artifacts: ArtifactRepository
        self.outbox: OutboxRepository
        self.audit: IngestionAuditRepository

    async def __aenter__(self) -> Self:
        """Acquire the sole writer and begin before exposing the repository."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except SQLAlchemyError as error:
            if self._connection is not None:
                await self._connection.close()
                self._connection = None
            self._store.write_lock.release()
            raise IngestionDependencyError(_ERR_COMMIT) from error
        except BaseException:
            if self._connection is not None:
                await self._connection.close()
                self._connection = None
            self._store.write_lock.release()
            raise
        connection = self._require_connection()
        self.events = SqliteAgentEventRepository(connection, self._capacity)
        self.artifacts = SqliteArtifactRepository(connection)
        self.outbox = SqliteOutboxRepository(connection)
        self.audit = SqliteIngestionAuditRepository(connection)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back uncommitted state and release the single-writer lock."""
        connection = self._require_connection()
        storage_error = exc if isinstance(exc, SQLAlchemyError) else None
        try:
            if not self._committed:
                try:
                    await connection.rollback()
                except SQLAlchemyError as error:
                    storage_error = error
        finally:
            try:
                await connection.close()
            finally:
                self._connection = None
                self._store.write_lock.release()
        if storage_error is not None:
            raise IngestionDependencyError(_ERR_COMMIT) from storage_error
        return None

    async def commit(self) -> None:
        """Commit once and translate disk/race failures into typed safe errors."""
        if self._committed:
            raise IngestionConflictError(_ERR_ALREADY_COMMITTED)
        try:
            await self._require_connection().commit()
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_EVENT_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_COMMIT) from error
        self._committed = True

    def _require_connection(self) -> AsyncConnection:
        if self._connection is None:
            msg = "AgentEvent Unit of Work is not active"
            raise RuntimeError(msg)
        return self._connection


class SqliteAgentEventUnitOfWorkFactory:
    """Create a fresh append transaction per command."""

    def __init__(
        self,
        store: SqliteCoreStore,
        clock: Clock,
        capacity: SqliteCaptureCapacityEnforcer | None = None,
    ) -> None:
        """Retain stable dependencies only; transactions are created per call."""
        self._store = store
        self._clock = clock
        self._capacity = capacity

    def __call__(self) -> AgentEventUnitOfWork:
        """Return one unopened transaction."""
        return SqliteAgentEventUnitOfWork(self._store, self._clock, self._capacity)


class SqliteAgentEventRepository:
    """Persist only the canonical event index and authenticated envelope."""

    def __init__(
        self,
        connection: AsyncConnection,
        capacity: SqliteCaptureCapacityEnforcer | None = None,
    ) -> None:
        """Bind this aggregate repository to its owning transaction."""
        self._connection = connection
        self._capacity = capacity

    async def append(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
        artifact_id: str | None,
    ) -> AppendAgentEventResult:
        """Insert canonical facts or identify a byte-identical idempotent retry."""
        event = admitted.event
        if self._capacity is not None:
            await self._capacity.assert_admissible(self._connection, event.event_id)
        existing = (
            (
                await self._connection.execute(
                    text(
                        "SELECT e.payload_hash, e.ingested_at, x.canonical_sha256, "
                        "x.clock_skew_microseconds "
                        "FROM agent_events AS e JOIN agent_event_envelopes AS x "
                        "ON x.event_id = e.event_id WHERE e.event_id = :event_id"
                    ),
                    {"event_id": event.event_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing is not None:
            exact = _bytes(existing["payload_hash"]) == bytes.fromhex(
                event.content_sha256
            ) and _bytes(existing["canonical_sha256"]) == bytes.fromhex(encrypted.canonical_sha256)
            if not exact:
                raise IngestionConflictError(_ERR_ID_REUSE)
            return AppendAgentEventResult(
                event.event_id,
                AppendDisposition.DUPLICATE,
                int(existing["ingested_at"]),
                int(existing["clock_skew_microseconds"]),
            )
        now = _unix_microseconds(admitted.ingested_at)
        try:
            await self._insert_event(admitted, encrypted, artifact_id, now)
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_EVENT_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error
        return AppendAgentEventResult(
            event.event_id,
            AppendDisposition.ACCEPTED,
            now,
            admitted.clock_skew_microseconds,
        )

    async def _insert_event(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
        artifact_id: str | None,
        now: int,
    ) -> None:
        event = admitted.event
        identity = admitted.identity
        await self._connection.execute(
            text(
                "INSERT INTO agent_events "
                "(event_id, brain_id, type, payload_hash, classification, occurred_at, "
                "ingested_at, payload_ref, schema_version) VALUES "
                "(:event_id, :brain_id, :type, :payload_hash, :classification, "
                ":occurred_at, :ingested_at, :payload_ref, 1)"
            ),
            {
                "event_id": event.event_id,
                "brain_id": identity.brain_id,
                "type": event.event_type.value,
                "payload_hash": bytes.fromhex(event.content_sha256),
                "classification": event.classification.value,
                "occurred_at": _unix_microseconds(event.occurred_at),
                "ingested_at": now,
                "payload_ref": artifact_id,
            },
        )
        await self._insert_envelope(admitted, encrypted, now)

    async def _insert_envelope(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
        now: int,
    ) -> None:
        event = admitted.event
        identity = admitted.identity
        await self._connection.execute(
            text(
                "INSERT INTO agent_event_envelopes "
                "(event_id, principal_id, project_id, repository_id, checkout_id, "
                "ordering_key, sequence, correlation_id, causation_id, retention_policy_id, "
                "canonical_sha256, envelope_version, algorithm, brain_key_id, data_key_id, "
                "payload_nonce, ciphertext, wrapped_data_key_nonce, wrapped_data_key, "
                "aad_sha256, clock_skew_microseconds, adapter_id, adapter_version, "
                "adapter_digest, capability_manifest_sha256, capture_method, created_at, "
                "schema_version) VALUES "
                "(:event_id, :principal_id, :project_id, :repository_id, :checkout_id, "
                ":ordering_key, :sequence, :correlation_id, :causation_id, :retention, "
                ":canonical_sha256, :envelope_version, :algorithm, :brain_key_id, :data_key_id, "
                ":payload_nonce, :ciphertext, :wrapped_nonce, :wrapped_key, :aad, :clock_skew, "
                ":adapter_id, :adapter_version, :adapter_digest, :capability_manifest, "
                ":capture_method, :created_at, 1)"
            ),
            {
                "event_id": event.event_id,
                "principal_id": identity.principal_id,
                "project_id": identity.project_id,
                "repository_id": identity.repository_id,
                "checkout_id": identity.checkout_id,
                "ordering_key": event.ordering_key,
                "sequence": event.sequence,
                "correlation_id": event.correlation_id,
                "causation_id": event.causation_id,
                "retention": event.retention_policy_id,
                "canonical_sha256": bytes.fromhex(encrypted.canonical_sha256),
                "envelope_version": encrypted.envelope_version,
                "algorithm": encrypted.algorithm,
                "brain_key_id": encrypted.brain_key_id,
                "data_key_id": encrypted.data_key_id,
                "payload_nonce": encrypted.payload_nonce,
                "ciphertext": encrypted.ciphertext,
                "wrapped_nonce": encrypted.wrapped_data_key_nonce,
                "wrapped_key": encrypted.wrapped_data_key,
                "aad": bytes.fromhex(encrypted.aad_sha256),
                "clock_skew": admitted.clock_skew_microseconds,
                "adapter_id": event.provenance.adapter_id,
                "adapter_version": event.provenance.adapter_version,
                "adapter_digest": bytes.fromhex(event.provenance.adapter_digest),
                "capability_manifest": bytes.fromhex(event.provenance.capability_manifest_digest),
                "capture_method": event.provenance.capture_method.value,
                "created_at": now,
            },
        )


class SqliteArtifactRepository:
    """Deduplicate Brain-scoped immutable CAS metadata inside the append UoW."""

    def __init__(self, connection: AsyncConnection) -> None:
        """Bind artifact persistence to its owning Unit of Work connection."""
        self._connection = connection

    async def ensure_reference(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> str | None:
        """Return one artifact identity, or None when canonical content is inline."""
        reference = admitted.event.payload_reference
        if reference is None:
            return None
        digest = bytes.fromhex(reference.content_sha256)
        try:
            existing = (
                (
                    await self._connection.execute(
                        text(
                            "SELECT id,media_type,byte_length,encryption_key_ref,blob_uri,"
                            "classification FROM artifacts WHERE brain_id=:brain AND sha256=:digest"
                        ),
                        {"brain": admitted.identity.brain_id, "digest": digest},
                    )
                )
                .mappings()
                .one_or_none()
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error
        if existing is not None:
            if (
                str(existing["media_type"]) != admitted.event.datacontenttype
                or int(str(existing["byte_length"])) != reference.size_bytes
                or str(existing["encryption_key_ref"]) != encrypted.brain_key_id
                or str(existing["blob_uri"]) != reference.uri
                or str(existing["classification"]) != admitted.event.classification.value
            ):
                raise IngestionConflictError(_ERR_EVENT_CONFLICT)
            return str(existing["id"])
        artifact_id = str(uuid7())
        now = _unix_microseconds(admitted.ingested_at)
        try:
            await self._connection.execute(
                text(
                    "INSERT INTO artifacts "
                    "(id,brain_id,sha256,media_type,byte_length,encryption_key_ref,blob_uri,"
                    "classification,created_at,updated_at,schema_version) VALUES "
                    "(:id,:brain,:digest,:media_type,:byte_length,:key_ref,:uri,:classification,"
                    ":now,:now,1)"
                ),
                {
                    "brain": admitted.identity.brain_id,
                    "byte_length": reference.size_bytes,
                    "classification": admitted.event.classification.value,
                    "digest": digest,
                    "id": artifact_id,
                    "key_ref": encrypted.brain_key_id,
                    "media_type": admitted.event.datacontenttype,
                    "now": now,
                    "uri": reference.uri,
                },
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error
        return artifact_id


class SqliteOutboxRepository:
    """Append one checksum-bound local dispatch intent without committing."""

    def __init__(self, connection: AsyncConnection) -> None:
        """Bind outbox persistence to its owning Unit of Work connection."""
        self._connection = connection

    async def enqueue(self, admitted: AdmittedAgentEvent) -> None:
        """Create the ready message in the same transaction as its source event."""
        event = admitted.event
        now = _unix_microseconds(admitted.ingested_at)
        payload = json.dumps(
            {
                "brain_id": admitted.identity.brain_id,
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "schema_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        payload_bytes = payload.encode("utf-8")
        try:
            await self._connection.execute(
                text(
                    "INSERT INTO outbox_messages "
                    "(id, source_event_id, topic, message_key, payload, status, priority, "
                    "not_before, attempts, payload_sha256, created_at, schema_version) VALUES "
                    "(:id, :source_event_id, :topic, :message_key, :payload, 'ready', 100, "
                    ":created_at, 0, :payload_sha256, :created_at, 1)"
                ),
                {
                    "id": str(uuid7()),
                    "source_event_id": event.event_id,
                    "topic": (
                        f"am.local.{admitted.identity.brain_id}.ingestion.agent-event-appended.v1"
                    ),
                    "message_key": event.ordering_key,
                    "payload": payload,
                    "payload_sha256": hashlib.sha256(payload_bytes).digest(),
                    "created_at": now,
                },
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error


class SqliteIngestionAuditRepository:
    """Append event-acceptance facts to the canonical audit chain."""

    def __init__(self, connection: AsyncConnection) -> None:
        """Bind audit persistence to its owning Unit of Work connection."""
        self._connection = connection

    async def append_agent_event(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> None:
        """Append one content-free acceptance fact without committing."""
        event = admitted.event
        now = _unix_microseconds(admitted.ingested_at)
        try:
            previous = (
                await self._connection.execute(
                    text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
                )
            ).scalar_one_or_none()
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error
        previous_hash = previous if isinstance(previous, bytes) else bytes(32)
        fact = json.dumps(
            {
                "action": "agent_event.appended",
                "actor_id": admitted.identity.principal_id,
                "brain_id": admitted.identity.brain_id,
                "event_type": event.event_type.value,
                "occurred_at": now,
                "target_ref": event.event_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        try:
            await self._connection.execute(
                text(
                    "INSERT INTO audit_events "
                    "(brain_id, actor_id, action, target_ref, idempotency_key, before_hash, "
                    "after_hash, previous_hash, event_hash, occurred_at, schema_version) VALUES "
                    "(:brain_id, :actor_id, 'agent_event.appended', :target_ref, :key, :before, "
                    ":after, :previous, :event_hash, :occurred_at, 1)"
                ),
                {
                    "brain_id": admitted.identity.brain_id,
                    "actor_id": admitted.identity.principal_id,
                    "target_ref": event.event_id,
                    "key": f"agent-event:{event.event_id}",
                    "before": bytes(32),
                    "after": bytes.fromhex(encrypted.canonical_sha256),
                    "previous": previous_hash,
                    "event_hash": hashlib.sha256(previous_hash + fact).digest(),
                    "occurred_at": now,
                },
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error

    async def append_agent_event_conflict(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> None:
        """Persist one deduplicated ID/order conflict and hash-chained audit fact."""
        event = admitted.event
        now = _unix_microseconds(admitted.ingested_at)
        try:
            existing = (
                (
                    await self._connection.execute(
                        text(
                            "SELECT e.event_id,x.canonical_sha256 FROM agent_events e "
                            "JOIN agent_event_envelopes x ON x.event_id=e.event_id "
                            "WHERE e.event_id=:event OR "
                            "(x.ordering_key=:ordering_key AND x.sequence=:sequence) "
                            "ORDER BY CASE WHEN e.event_id=:event THEN 0 ELSE 1 END LIMIT 1"
                        ),
                        {
                            "event": event.event_id,
                            "ordering_key": event.ordering_key,
                            "sequence": event.sequence,
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
            expected = bytes(32) if existing is None else _bytes(existing["canonical_sha256"])
            identity_source = (
                f"event:{event.event_id}"
                if existing is not None and str(existing["event_id"]) == event.event_id
                else f"order:{event.ordering_key}:{event.sequence}"
            )
            identity_hash = hashlib.sha256(identity_source.encode()).hexdigest()
            actual = bytes.fromhex(encrypted.canonical_sha256)
            inserted = await self._connection.execute(
                text(
                    "INSERT INTO idempotency_conflicts "
                    "(id,brain_id,namespace,identity_key,expected_sha256,actual_sha256,"
                    "source_message_id,detected_at,schema_version) VALUES "
                    "(:id,:brain,'agent_event',:identity,:expected,:actual,NULL,:now,1) "
                    "ON CONFLICT(namespace,identity_key,actual_sha256) DO NOTHING"
                ),
                {
                    "actual": actual,
                    "brain": admitted.identity.brain_id,
                    "expected": expected,
                    "id": str(uuid7()),
                    "identity": identity_hash,
                    "now": now,
                },
            )
            if inserted.rowcount != 1:
                return
            previous = (
                await self._connection.execute(
                    text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
                )
            ).scalar_one_or_none()
            previous_hash = previous if isinstance(previous, bytes) else bytes(32)
            fact = json.dumps(
                {
                    "action": "agent_event.idempotency_conflict",
                    "brain_id": admitted.identity.brain_id,
                    "identity_hash": identity_hash,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            await self._connection.execute(
                text(
                    "INSERT INTO audit_events "
                    "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
                    "previous_hash,event_hash,occurred_at,schema_version) VALUES "
                    "(:brain,:actor,'agent_event.idempotency_conflict',:target,:key,:before,"
                    ":after,:previous,:event_hash,:now,1)"
                ),
                {
                    "actor": admitted.identity.principal_id,
                    "after": actual,
                    "before": expected,
                    "brain": admitted.identity.brain_id,
                    "event_hash": hashlib.sha256(previous_hash + fact).digest(),
                    "key": f"agent-event-conflict:{identity_hash}:{encrypted.canonical_sha256}",
                    "now": now,
                    "previous": previous_hash,
                    "target": f"agent-event:{identity_hash}",
                },
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error


def _unix_microseconds(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IngestionDependencyError(_ERR_STORAGE_MALFORMED)
    return value
