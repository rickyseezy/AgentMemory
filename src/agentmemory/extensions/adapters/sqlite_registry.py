"""PF-003 SQLite repository, authorization, audit, and outbox Unit of Work."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.extensions.domain.errors import (
    AdapterAuthorizationError,
    AdapterConflictError,
    AdapterStorageError,
)
from agentmemory.extensions.domain.models import (
    AdapterAuthorizationRequest,
    AdapterCapability,
    AdapterKind,
    AdapterManifest,
    AdapterPermission,
    AdapterProbeEvidence,
    AdapterRegistration,
    AdapterRegistrationState,
    ProtocolVersion,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.extensions.domain.ports import (
        AdapterEventSink,
        AdapterRegistrationEvent,
        AdapterRegistrationRepository,
    )
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_STORAGE = "adapter extension storage is unavailable"
_ERR_MALFORMED = "adapter extension storage is malformed"
_ERR_CONFLICT = "adapter extension identity conflicted"
_ERR_COMMITTED = "adapter extension transaction was already committed"
_ERR_INACTIVE = "adapter extension Unit of Work is not active"
_ERR_AUTHORIZATION = "adapter registration is not authorized"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_PROTOCOL_COMPONENTS = 2

_REGISTRATION_SELECT = """
SELECT r.registration_id,r.brain_id,r.actor_id,r.grant_id,r.adapter_id,r.adapter_version,
       r.adapter_kind,r.package_digest,r.manifest_digest,r.evidence_digest,
       r.registration_digest,r.manifest_json,r.evidence_json,r.state,r.registered_at
FROM adapter_extension_registrations AS r
"""


class SystemAdapterIdentityGenerator:
    """Generate local UUIDv7 registration and event identities."""

    def new(self) -> str:
        """Return one lowercase RFC 9562 UUIDv7 string."""
        return str(uuid7())


class SqliteAdapterRegistrationAuthorization:
    """Resolve current actor/grant/Brain authority before registry candidate reads."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local authorization store."""
        self._store = store

    async def authorize(self, request: AdapterAuthorizationRequest) -> None:
        """Require an active owner/admin grant for the exact Brain and actor."""
        now = _microseconds(request.requested_at)
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    await connection.execute(
                        text(
                            "SELECT g.role FROM scope_grants AS g "
                            "JOIN principals AS p ON p.id=g.principal_id "
                            "JOIN brains AS b ON b.id=g.brain_id "
                            "WHERE g.id=:grant AND g.principal_id=:actor AND g.brain_id=:brain "
                            "AND p.status='active' AND b.status='active' "
                            "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now)"
                        ),
                        {
                            "actor": request.actor_id,
                            "brain": request.brain_id,
                            "grant": request.grant_id,
                            "now": now,
                        },
                    )
                ).one_or_none()
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error
        if row is None or str(row[0]) not in {"owner", "admin"}:
            raise AdapterAuthorizationError(_ERR_AUTHORIZATION)


class SqliteAdapterRegistrationUnitOfWork:
    """Own one serialized registry, domain-event, audit, and outbox transaction."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the durable store without acquiring resources early."""
        self._store = store
        self._connection: AsyncConnection | None = None
        self._repository: AdapterRegistrationRepository | None = None
        self._audit: AdapterEventSink | None = None
        self._outbox: AdapterEventSink | None = None
        self._committed = False

    @property
    def repository(self) -> AdapterRegistrationRepository:
        """Return the active transaction-scoped repository."""
        if self._repository is None:
            raise RuntimeError(_ERR_INACTIVE)
        return self._repository

    @property
    def audit(self) -> AdapterEventSink:
        """Return the active hash-chain audit sink."""
        if self._audit is None:
            raise RuntimeError(_ERR_INACTIVE)
        return self._audit

    @property
    def outbox(self) -> AdapterEventSink:
        """Return the active durable integration-event sink."""
        if self._outbox is None:
            raise RuntimeError(_ERR_INACTIVE)
        return self._outbox

    async def __aenter__(self) -> Self:
        """Acquire sole-writer authority and begin an immediate transaction."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        connection = self._require_connection()
        self._repository = SqliteAdapterRegistrationRepository(connection)
        self._audit = _SqliteAdapterAuditSink(connection)
        self._outbox = _SqliteAdapterOutboxSink(connection)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Roll back unfinished work and always release sole-writer authority."""
        _ = exc_type, exc_value, traceback
        connection = self._require_connection()
        try:
            if not self._committed:
                await connection.rollback()
        finally:
            await connection.close()
            self._connection = None
            self._repository = None
            self._audit = None
            self._outbox = None
            self._store.write_lock.release()

    async def commit(self) -> None:
        """Commit exactly once with closed conflict/storage translation."""
        if self._committed:
            raise AdapterConflictError(_ERR_COMMITTED)
        try:
            await self._require_connection().commit()
        except IntegrityError as error:
            raise AdapterConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error
        self._committed = True

    def _require_connection(self) -> AsyncConnection:
        if self._connection is None:
            raise RuntimeError(_ERR_INACTIVE)
        return self._connection


class SqliteAdapterRegistrationUnitOfWorkFactory:
    """Create a fresh PF-003 registration transaction for each command."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the shared local store."""
        self._store = store

    def __call__(self) -> SqliteAdapterRegistrationUnitOfWork:
        """Return one inactive transaction."""
        return SqliteAdapterRegistrationUnitOfWork(self._store)


class SqliteAdapterRegistrationRepository:
    """Map immutable registration aggregates to canonical relational facts."""

    def __init__(self, connection: AsyncConnection) -> None:
        """Bind an active transaction-owned connection."""
        self._connection = connection

    async def replay(self, operation_id: str, request_digest: str) -> AdapterRegistration | None:
        """Return an exact completed operation or reject key reuse."""
        try:
            row = (
                (
                    await self._connection.execute(
                        text(
                            _REGISTRATION_SELECT + " JOIN adapter_extension_operations AS o "
                            "ON o.registration_id=r.registration_id "
                            "WHERE o.operation_id=:operation_id"
                        ),
                        {"operation_id": operation_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            operation = (
                await self._connection.execute(
                    text(
                        "SELECT request_digest FROM adapter_extension_operations "
                        "WHERE operation_id=:operation_id"
                    ),
                    {"operation_id": operation_id},
                )
            ).scalar_one()
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error
        if str(operation) != request_digest:
            raise AdapterConflictError(_ERR_CONFLICT)
        return _restore_registration(row)

    async def get_version(
        self,
        brain_id: str,
        adapter_id: str,
        adapter_version: str,
    ) -> AdapterRegistration | None:
        """Load one active immutable version only within the authorized Brain."""
        try:
            row = (
                (
                    await self._connection.execute(
                        text(
                            _REGISTRATION_SELECT
                            + " WHERE r.brain_id=:brain AND r.adapter_id=:adapter "
                            "AND r.adapter_version=:version AND r.state='active'"
                        ),
                        {
                            "adapter": adapter_id,
                            "brain": brain_id,
                            "version": adapter_version,
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error
        return None if row is None else _restore_registration(row)

    async def save(
        self,
        operation_id: str,
        request_digest: str,
        registration: AdapterRegistration,
    ) -> None:
        """Stage the aggregate and its immutable idempotency receipt."""
        manifest = _canonical_bytes(registration.manifest.to_document())
        evidence = _canonical_bytes(_evidence_document(registration.evidence))
        try:
            await self._connection.execute(
                text(
                    "INSERT INTO adapter_extension_registrations "
                    "(registration_id,brain_id,actor_id,grant_id,adapter_id,adapter_version,"
                    "adapter_kind,package_digest,manifest_digest,evidence_digest,"
                    "registration_digest,manifest_json,evidence_json,state,registered_at,"
                    "schema_version) VALUES (:registration,:brain,:actor,:grant,:adapter,:version,"
                    ":kind,:package,:manifest_digest,:evidence_digest,:registration_digest,"
                    ":manifest,:evidence,:state,:registered_at,1)"
                ),
                {
                    "actor": registration.actor_id,
                    "adapter": registration.manifest.adapter_id,
                    "brain": registration.brain_id,
                    "evidence": evidence,
                    "evidence_digest": registration.evidence.evidence_digest,
                    "grant": registration.grant_id,
                    "kind": registration.manifest.kind.value,
                    "manifest": manifest,
                    "manifest_digest": registration.manifest_digest,
                    "package": registration.package_digest,
                    "registered_at": _microseconds(registration.registered_at),
                    "registration": registration.registration_id,
                    "registration_digest": registration.registration_digest,
                    "state": registration.state.value,
                    "version": registration.manifest.adapter_version,
                },
            )
            await self._insert_operation(operation_id, request_digest, registration)
        except IntegrityError as error:
            raise AdapterConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error

    async def link_operation(
        self,
        operation_id: str,
        request_digest: str,
        registration: AdapterRegistration,
    ) -> None:
        """Stage an additional idempotency receipt without duplicating effective state."""
        try:
            await self._insert_operation(
                operation_id,
                request_digest,
                registration,
            )
        except IntegrityError as error:
            raise AdapterConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error

    async def _insert_operation(
        self,
        operation_id: str,
        request_digest: str,
        registration: AdapterRegistration,
    ) -> None:
        await self._connection.execute(
            text(
                "INSERT INTO adapter_extension_operations "
                "(operation_id,request_digest,registration_id,completed_at,schema_version) "
                "VALUES (:operation,:request,:registration,:completed,1)"
            ),
            {
                "completed": _microseconds(registration.registered_at),
                "operation": operation_id,
                "registration": registration.registration_id,
                "request": request_digest,
            },
        )


class _SqliteAdapterAuditSink:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def append(self, event: AdapterRegistrationEvent) -> None:
        payload = _event_bytes(event)
        now = _microseconds(event.occurred_at)
        previous = (
            await self._connection.execute(
                text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
            )
        ).scalar_one_or_none()
        previous_hash = bytes(32) if previous is None else _bytes(previous)
        after_hash = bytes.fromhex(event.registration_digest)
        try:
            await self._connection.execute(
                text(
                    "INSERT INTO agent_events "
                    "(event_id,brain_id,type,payload_hash,classification,occurred_at,ingested_at,"
                    "payload_ref,schema_version) VALUES "
                    "(:event,:brain,:type,:payload_hash,'internal',:now,:now,NULL,1)"
                ),
                {
                    "brain": event.brain_id,
                    "event": event.event_id,
                    "now": now,
                    "payload_hash": hashlib.sha256(payload).digest(),
                    "type": event.event_type,
                },
            )
            await self._connection.execute(
                text(
                    "INSERT INTO audit_events "
                    "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
                    "previous_hash,event_hash,occurred_at,schema_version) VALUES "
                    "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:now,1)"
                ),
                {
                    "action": "adapter.registration.activate",
                    "actor": event.actor_id,
                    "after": after_hash,
                    "before": bytes(32),
                    "brain": event.brain_id,
                    "event": hashlib.sha256(previous_hash + payload).digest(),
                    "key": f"adapter.registration:{event.registration_id}",
                    "now": now,
                    "previous": previous_hash,
                    "target": f"adapter:{event.adapter_id}",
                },
            )
        except IntegrityError as error:
            raise AdapterConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error


class _SqliteAdapterOutboxSink:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def append(self, event: AdapterRegistrationEvent) -> None:
        payload = _event_bytes(event)
        now = _microseconds(event.occurred_at)
        try:
            await self._connection.execute(
                text(
                    "INSERT INTO outbox_messages "
                    "(id,source_event_id,topic,message_key,payload,status,priority,not_before,"
                    "attempts,lease_owner,lease_until,completed_at,payload_sha256,last_error_code,"
                    "created_at,schema_version) VALUES "
                    "(:id,:source,:topic,:key,:payload,'ready',100,:now,0,NULL,NULL,NULL,:digest,"
                    "NULL,:now,1)"
                ),
                {
                    "digest": hashlib.sha256(payload).digest(),
                    "id": f"adapter-extension-outbox-{event.event_id}",
                    "key": event.registration_id,
                    "now": now,
                    "payload": payload.decode(),
                    "source": event.event_id,
                    "topic": "adapter.registration.activated.v1",
                },
            )
        except IntegrityError as error:
            raise AdapterConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise AdapterStorageError(_ERR_STORAGE) from error


def _restore_registration(row: RowMapping) -> AdapterRegistration:
    try:
        manifest_document = _object(_bytes(row["manifest_json"]))
        evidence_document = _object(_bytes(row["evidence_json"]))
        manifest = AdapterManifest.create(
            schema_version=_integer(manifest_document, "schema_version"),
            adapter_id=_string(manifest_document, "adapter_id"),
            adapter_version=_string(manifest_document, "adapter_version"),
            kind=AdapterKind(_string(manifest_document, "kind")),
            package_digest=_string(manifest_document, "package_digest"),
            signature_digest=_string(manifest_document, "signature_digest"),
            signer_identity=_string(manifest_document, "signer_identity"),
            protocol_min=_protocol(_string(manifest_document, "protocol_min")),
            protocol_max=_protocol(_string(manifest_document, "protocol_max")),
            capabilities=_capabilities(manifest_document, "capabilities"),
            requested_permissions=_permissions(manifest_document, "requested_permissions"),
        )
        evidence = AdapterProbeEvidence(
            manifest_digest=_string(evidence_document, "manifest_digest"),
            package_digest=_string(evidence_document, "package_digest"),
            negotiated_protocol=_protocol(_string(evidence_document, "negotiated_protocol")),
            declared_capabilities=_capabilities(
                evidence_document,
                "declared_capabilities",
            ),
            observed_capabilities=_capabilities(
                evidence_document,
                "observed_capabilities",
            ),
            runtime_digest=_string(evidence_document, "runtime_digest"),
            probed_at=_datetime(_string(evidence_document, "probed_at")),
            evidence_digest=_string(evidence_document, "evidence_digest"),
        )
        registration = AdapterRegistration.create(
            registration_id=str(row["registration_id"]),
            brain_id=str(row["brain_id"]),
            actor_id=str(row["actor_id"]),
            grant_id=str(row["grant_id"]),
            manifest=manifest,
            evidence=evidence,
            state=AdapterRegistrationState(str(row["state"])),
            registered_at=_from_microseconds(int(row["registered_at"])),
        )
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise AdapterStorageError(_ERR_MALFORMED) from error
    exact = (
        manifest.adapter_id == str(row["adapter_id"])
        and manifest.adapter_version == str(row["adapter_version"])
        and manifest.kind.value == str(row["adapter_kind"])
        and registration.package_digest == str(row["package_digest"])
        and registration.manifest_digest == str(row["manifest_digest"])
        and evidence.evidence_digest == str(row["evidence_digest"])
        and registration.registration_digest == str(row["registration_digest"])
    )
    if not exact:
        raise AdapterStorageError(_ERR_MALFORMED)
    return registration


def _evidence_document(evidence: AdapterProbeEvidence) -> dict[str, object]:
    return {
        "declared_capabilities": [item.value for item in evidence.declared_capabilities],
        "evidence_digest": evidence.evidence_digest,
        "manifest_digest": evidence.manifest_digest,
        "negotiated_protocol": str(evidence.negotiated_protocol),
        "observed_capabilities": [item.value for item in evidence.observed_capabilities],
        "package_digest": evidence.package_digest,
        "probed_at": evidence.probed_at.isoformat().replace("+00:00", "Z"),
        "runtime_digest": evidence.runtime_digest,
    }


def _event_bytes(event: AdapterRegistrationEvent) -> bytes:
    return _canonical_bytes(
        {
            "adapter_id": event.adapter_id,
            "adapter_kind": event.adapter_kind,
            "actor_id": event.actor_id,
            "brain_id": event.brain_id,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "evidence_digest": event.evidence_digest,
            "grant_id": event.grant_id,
            "manifest_digest": event.manifest_digest,
            "package_digest": event.package_digest,
            "registration_digest": event.registration_digest,
            "registration_id": event.registration_id,
        }
    )


def _object(value: bytes) -> dict[str, object]:
    decoded = json.loads(value)
    if not isinstance(decoded, dict):
        raise AdapterStorageError(_ERR_MALFORMED)
    return cast("dict[str, object]", decoded)


def _string(document: dict[str, object], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        raise AdapterStorageError(_ERR_MALFORMED)
    return value


def _integer(document: dict[str, object], field: str) -> int:
    value = document[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterStorageError(_ERR_MALFORMED)
    return value


def _capabilities(document: dict[str, object], field: str) -> tuple[AdapterCapability, ...]:
    return tuple(AdapterCapability(item) for item in _string_list(document, field))


def _permissions(document: dict[str, object], field: str) -> tuple[AdapterPermission, ...]:
    return tuple(AdapterPermission(item) for item in _string_list(document, field))


def _string_list(document: dict[str, object], field: str) -> tuple[str, ...]:
    values = document[field]
    if not isinstance(values, list):
        raise AdapterStorageError(_ERR_MALFORMED)
    result: list[str] = []
    for item in cast("list[object]", values):
        if not isinstance(item, str):
            raise AdapterStorageError(_ERR_MALFORMED)
        result.append(item)
    return tuple(result)


def _protocol(value: str) -> ProtocolVersion:
    components = value.split(".")
    if len(components) != _PROTOCOL_COMPONENTS or any(
        not item.isascii() or not item.isdecimal() for item in components
    ):
        raise AdapterStorageError(_ERR_MALFORMED)
    parsed = ProtocolVersion(int(components[0]), int(components[1]))
    if str(parsed) != value:
        raise AdapterStorageError(_ERR_MALFORMED)
    return parsed


def _datetime(value: str) -> datetime:
    if not value.endswith("Z"):
        raise AdapterStorageError(_ERR_MALFORMED)
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() != UTC.utcoffset(None):
        raise AdapterStorageError(_ERR_MALFORMED)
    return result


def _canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _microseconds(value: datetime) -> int:
    delta = value - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _from_microseconds(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise AdapterStorageError(_ERR_MALFORMED)
