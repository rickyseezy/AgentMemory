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
    from agentmemory.ingestion.domain.ports import AgentEventRepository, AgentEventUnitOfWork
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

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

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the single-writer store and policy clock."""
        self._store = store
        self._clock = clock
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.events: AgentEventRepository

    async def __aenter__(self) -> Self:
        """Acquire the sole writer and begin before exposing the repository."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        self.events = SqliteAgentEventRepository(self._require_connection(), self._clock)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back uncommitted state and release the single-writer lock."""
        connection = self._require_connection()
        try:
            if not self._committed:
                await connection.rollback()
        finally:
            await connection.close()
            self._connection = None
            self._store.write_lock.release()
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

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Retain stable dependencies only; transactions are created per call."""
        self._store = store
        self._clock = clock

    def __call__(self) -> AgentEventUnitOfWork:
        """Return one unopened transaction."""
        return SqliteAgentEventUnitOfWork(self._store, self._clock)


class SqliteAgentEventRepository:
    """Persist event index, encrypted envelope, outbox, and chained audit fact."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind repositories to their owning transaction and policy clock."""
        self._connection = connection
        self._clock = clock

    async def append(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
    ) -> AppendAgentEventResult:
        """Insert all facts or return only a byte-identical idempotent retry."""
        event = admitted.event
        existing = (
            (
                await self._connection.execute(
                    text(
                        "SELECT e.payload_hash, e.ingested_at, x.canonical_sha256 "
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
            )
        now = _unix_microseconds(admitted.ingested_at)
        try:
            await self._insert_event(admitted, encrypted, now)
            await self._insert_outbox(admitted, now)
            await self._insert_audit(admitted, encrypted, now)
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_EVENT_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_ENQUEUE) from error
        return AppendAgentEventResult(event.event_id, AppendDisposition.ACCEPTED, now)

    async def _insert_event(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
        now: int,
    ) -> None:
        event = admitted.event
        identity = admitted.identity
        await self._connection.execute(
            text(
                "INSERT INTO agent_events "
                "(event_id, brain_id, type, payload_hash, classification, occurred_at, "
                "ingested_at, schema_version) VALUES "
                "(:event_id, :brain_id, :type, :payload_hash, :classification, "
                ":occurred_at, :ingested_at, 1)"
            ),
            {
                "event_id": event.event_id,
                "brain_id": identity.brain_id,
                "type": event.event_type.value,
                "payload_hash": bytes.fromhex(event.content_sha256),
                "classification": event.classification.value,
                "occurred_at": _unix_microseconds(event.occurred_at),
                "ingested_at": now,
            },
        )
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

    async def _insert_outbox(self, admitted: AdmittedAgentEvent, now: int) -> None:
        event = admitted.event
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
        await self._connection.execute(
            text(
                "INSERT INTO outbox_messages "
                "(id, source_event_id, topic, message_key, payload, status, created_at, "
                "schema_version) VALUES "
                "(:id, :source_event_id, :topic, :message_key, :payload, 'ready', :created_at, 1)"
            ),
            {
                "id": str(uuid7()),
                "source_event_id": event.event_id,
                "topic": (
                    f"am.local.{admitted.identity.brain_id}.ingestion.agent-event-appended.v1"
                ),
                "message_key": event.ordering_key,
                "payload": payload,
                "created_at": now,
            },
        )

    async def _insert_audit(
        self,
        admitted: AdmittedAgentEvent,
        encrypted: EncryptedAgentEvent,
        now: int,
    ) -> None:
        event = admitted.event
        previous = (
            await self._connection.execute(
                text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
            )
        ).scalar_one_or_none()
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


def _unix_microseconds(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IngestionDependencyError(_ERR_STORAGE_MALFORMED)
    return value
