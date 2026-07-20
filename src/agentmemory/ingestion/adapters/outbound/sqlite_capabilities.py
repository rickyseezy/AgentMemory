"""SQLite adapter capability registration, observations, warnings, and queries."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    AdapterCapabilityObservation,
    CapabilityChangeDisposition,
    CapabilityChangeResult,
    CapabilityCompatibilityImpact,
    CapabilityCompatibilityWarning,
    EvidenceAvailability,
    RegisteredAdapterCapabilities,
)
from agentmemory.ingestion.domain.agent_event import (
    CaptureCapability,
    CaptureMethod,
    EventFamily,
)
from agentmemory.ingestion.domain.errors import (
    IngestionConflictError,
    IngestionDependencyError,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from agentmemory.ingestion.domain.ports import AdapterCapabilityRepository
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_STORAGE = "Adapter capability storage is unavailable"
_ERR_MALFORMED = "Adapter capability storage is malformed"
_ERR_CONFLICT = "Adapter capability identity conflicted"
_ERR_COMMITTED = "Adapter capability transaction was already committed"
_MAX_WARNING_RESULTS = 100

_REGISTRATION_SELECT = """
SELECT m.descriptor_json, m.manifest_sha256 AS stored_manifest_sha256,
       m.adapter_id, m.adapter_version, m.adapter_digest, m.status, m.manifest_format,
       o.observation_id, o.operation_id, o.manifest_sha256, o.revision,
       o.availability_json, o.observed_at
FROM agent_adapter_manifests AS m
JOIN agent_adapter_capability_observations AS o
  ON o.adapter_id = m.adapter_id
 AND o.adapter_version = m.adapter_version
 AND o.adapter_digest = m.adapter_digest
WHERE m.adapter_id = :adapter_id
  AND m.adapter_version = :adapter_version
  AND m.status = 'active'
  AND m.manifest_format = 'capability-matrix-v1'
  AND o.revision = (
    SELECT MAX(latest.revision)
    FROM agent_adapter_capability_observations AS latest
    WHERE latest.adapter_id = m.adapter_id
      AND latest.adapter_version = m.adapter_version
  )
"""

_OBSERVATION_REGISTRATION_SELECT = """
SELECT m.descriptor_json, m.manifest_sha256 AS stored_manifest_sha256,
       m.adapter_id, m.adapter_version, m.adapter_digest, m.status, m.manifest_format,
       o.observation_id, o.operation_id, o.manifest_sha256, o.revision,
       o.availability_json, o.observed_at
FROM agent_adapter_manifests AS m
JOIN agent_adapter_capability_observations AS o
  ON o.adapter_id = m.adapter_id
 AND o.adapter_version = m.adapter_version
 AND o.adapter_digest = m.adapter_digest
WHERE o.observation_id = :observation_id
  AND m.manifest_format = 'capability-matrix-v1'
"""


class SystemIngestionIdentityGenerator:
    """Generate local UUIDv7 identities without host or provider coupling."""

    def new(self) -> str:
        """Return one lowercase UUIDv7 string."""
        return str(uuid7())


class SqliteAdapterCapabilityUnitOfWork:
    """Own one serialized manifest/observation/audit transaction."""

    def __init__(
        self,
        store: SqliteCoreStore,
        clock: Clock,
        identities: SystemIngestionIdentityGenerator,
    ) -> None:
        """Bind the store and deterministic command dependencies."""
        """Bind stable local dependencies."""
        self._store = store
        self._clock = clock
        self._identities = identities
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.capabilities: AdapterCapabilityRepository

    async def __aenter__(self) -> Self:
        """Acquire the sole writer and expose a transaction-scoped repository."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        self.capabilities = SqliteAdapterCapabilityRepository(
            self._require_connection(),
            self._clock,
            self._identities,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back uncommitted work and always release writer ownership."""
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
        """Commit once with typed conflict/dependency translation."""
        if self._committed:
            raise IngestionConflictError(_ERR_COMMITTED)
        try:
            await self._require_connection().commit()
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        self._committed = True

    def _require_connection(self) -> AsyncConnection:
        if self._connection is None:
            message = "Adapter capability Unit of Work is not active"
            raise RuntimeError(message)
        return self._connection


class SqliteAdapterCapabilityUnitOfWorkFactory:
    """Create one fresh adapter capability transaction per command."""

    def __init__(
        self,
        store: SqliteCoreStore,
        clock: Clock,
        identities: SystemIngestionIdentityGenerator,
    ) -> None:
        """Bind dependencies shared by each fresh transaction."""
        self._store = store
        self._clock = clock
        self._identities = identities

    def __call__(self) -> SqliteAdapterCapabilityUnitOfWork:
        """Return a fresh transaction for one application command."""
        return SqliteAdapterCapabilityUnitOfWork(
            self._store,
            self._clock,
            self._identities,
        )


class SqliteAdapterCapabilityRepository:
    """Map capability aggregates to immutable relational facts."""

    def __init__(
        self,
        connection: AsyncConnection,
        clock: Clock,
        identities: SystemIngestionIdentityGenerator,
    ) -> None:
        """Bind a transaction-scoped connection and local fact dependencies."""
        self._connection = connection
        self._clock = clock
        self._identities = identities

    async def replay(
        self,
        operation_id: str,
        request_sha256: str,
    ) -> CapabilityChangeResult | None:
        """Replay an exact receipt and reject operation-ID reuse with different input."""
        try:
            row = (
                (
                    await self._connection.execute(
                        text(
                            "SELECT request_sha256, observation_id, disposition, warnings_json "
                            "FROM agent_adapter_capability_commands "
                            "WHERE operation_id = :operation_id"
                        ),
                        {"operation_id": operation_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        if row is None:
            return None
        if _bytes(row["request_sha256"]) != bytes.fromhex(request_sha256):
            raise IngestionConflictError(_ERR_CONFLICT)
        registration = await _load_observation_registration(
            self._connection,
            str(row["observation_id"]),
        )
        warnings = _decode_warnings(str(row["warnings_json"]))
        return CapabilityChangeResult(
            registration,
            CapabilityChangeDisposition.DUPLICATE,
            warnings,
        )

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> RegisteredAdapterCapabilities | None:
        """Return one exact active registered version."""
        return await _load_latest_registration(
            self._connection,
            adapter_id,
            adapter_version,
        )

    async def latest(self, adapter_id: str) -> RegisteredAdapterCapabilities | None:
        """Return the most recently inserted active matrix manifest."""
        try:
            row = (
                (
                    await self._connection.execute(
                        text(
                            "SELECT adapter_version FROM agent_adapter_manifests AS m "
                            "WHERE adapter_id = :adapter_id AND status = 'active' "
                            "AND manifest_format = 'capability-matrix-v1' "
                            "ORDER BY created_at DESC, rowid DESC LIMIT 1"
                        ),
                        {"adapter_id": adapter_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return (
            None
            if row is None
            else await _load_latest_registration(
                self._connection,
                adapter_id,
                str(row["adapter_version"]),
            )
        )

    async def persist(
        self,
        result: CapabilityChangeResult,
        operation_id: str,
        request_sha256: str,
    ) -> None:
        """Append missing manifest/observation/warnings, receipt, and chained audit."""
        registration = result.registration
        now = _unix_microseconds(self._clock.now())
        try:
            await self._insert_manifest(registration.manifest, now)
            inserted = await self._insert_observation(registration.observation, now)
            if inserted:
                await self._insert_warnings(registration, result.warnings, now)
            await self._insert_command(result, operation_id, request_sha256, now)
            await self._insert_audit(result, operation_id, now)
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error

    async def _insert_manifest(
        self,
        manifest: AdapterCapabilityManifest,
        now: int,
    ) -> None:
        row = (
            await self._connection.execute(
                text(
                    "SELECT manifest_sha256, manifest_format FROM agent_adapter_manifests "
                    "WHERE adapter_id=:adapter_id AND adapter_version=:adapter_version"
                ),
                {
                    "adapter_id": manifest.adapter_id,
                    "adapter_version": manifest.adapter_version,
                },
            )
        ).mappings().one_or_none()
        if row is not None:
            exact = (
                _bytes(row["manifest_sha256"]) == bytes.fromhex(manifest.manifest_sha256)
                and row["manifest_format"] == "capability-matrix-v1"
            )
            if not exact:
                raise IngestionConflictError(_ERR_CONFLICT)
            return
        await self._connection.execute(
            text(
                "INSERT INTO agent_adapter_manifests "
                "(adapter_id, adapter_version, adapter_digest, manifest_sha256, "
                "descriptor_json, status, created_at, schema_version, manifest_format) "
                "VALUES (:adapter_id, :adapter_version, :adapter_digest, :manifest_sha256, "
                ":descriptor_json, 'active', :created_at, 1, 'capability-matrix-v1')"
            ),
            {
                "adapter_id": manifest.adapter_id,
                "adapter_version": manifest.adapter_version,
                "adapter_digest": bytes.fromhex(manifest.adapter_digest),
                "manifest_sha256": bytes.fromhex(manifest.manifest_sha256),
                "descriptor_json": _encode_manifest(manifest),
                "created_at": now,
            },
        )

    async def _insert_observation(
        self,
        observation: AdapterCapabilityObservation,
        now: int,
    ) -> bool:
        exists = (
            await self._connection.execute(
                text(
                    "SELECT 1 FROM agent_adapter_capability_observations "
                    "WHERE observation_id=:observation_id"
                ),
                {"observation_id": observation.observation_id},
            )
        ).first()
        if exists is not None:
            return False
        await self._connection.execute(
            text(
                "INSERT INTO agent_adapter_capability_observations "
                "(observation_id, operation_id, adapter_id, adapter_version, adapter_digest, "
                "manifest_sha256, revision, availability_json, observed_at, created_at, "
                "schema_version) VALUES (:observation_id, :operation_id, :adapter_id, "
                ":adapter_version, :adapter_digest, :manifest_sha256, :revision, "
                ":availability_json, :observed_at, :created_at, 1)"
            ),
            {
                "observation_id": observation.observation_id,
                "operation_id": observation.operation_id,
                "adapter_id": observation.adapter_id,
                "adapter_version": observation.adapter_version,
                "adapter_digest": bytes.fromhex(observation.adapter_digest),
                "manifest_sha256": bytes.fromhex(observation.capability_manifest_digest),
                "revision": observation.revision,
                "availability_json": _encode_availability(
                    observation.evidence_availability
                ),
                "observed_at": _unix_microseconds(observation.observed_at),
                "created_at": now,
            },
        )
        return True

    async def _insert_warnings(
        self,
        registration: RegisteredAdapterCapabilities,
        warnings: tuple[CapabilityCompatibilityWarning, ...],
        now: int,
    ) -> None:
        for warning in warnings:
            await self._connection.execute(
                text(
                    "INSERT INTO agent_adapter_compatibility_warnings "
                    "(warning_id, observation_id, adapter_id, adapter_version, capability, "
                    "previous_status, current_status, impact, warning_code, created_at, "
                    "schema_version) VALUES (:warning_id, :observation_id, :adapter_id, "
                    ":adapter_version, :capability, :previous_status, :current_status, "
                    ":impact, :warning_code, :created_at, 1)"
                ),
                {
                    "warning_id": self._identities.new(),
                    "observation_id": registration.observation.observation_id,
                    "adapter_id": registration.manifest.adapter_id,
                    "adapter_version": registration.manifest.adapter_version,
                    "capability": warning.capability.value,
                    "previous_status": warning.previous_status.value,
                    "current_status": warning.current_status.value,
                    "impact": warning.impact.value,
                    "warning_code": warning.code,
                    "created_at": now,
                },
            )

    async def _insert_command(
        self,
        result: CapabilityChangeResult,
        operation_id: str,
        request_sha256: str,
        now: int,
    ) -> None:
        await self._connection.execute(
            text(
                "INSERT INTO agent_adapter_capability_commands "
                "(operation_id, request_sha256, observation_id, disposition, warnings_json, "
                "created_at, schema_version) VALUES (:operation_id, :request_sha256, "
                ":observation_id, :disposition, :warnings_json, :created_at, 1)"
            ),
            {
                "operation_id": operation_id,
                "request_sha256": bytes.fromhex(request_sha256),
                "observation_id": result.registration.observation.observation_id,
                "disposition": result.disposition.value,
                "warnings_json": _encode_warnings(result.warnings),
                "created_at": now,
            },
        )

    async def _insert_audit(
        self,
        result: CapabilityChangeResult,
        operation_id: str,
        now: int,
    ) -> None:
        previous = (
            await self._connection.execute(
                text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
            )
        ).scalar_one_or_none()
        previous_hash = previous if isinstance(previous, bytes) else bytes(32)
        registration = result.registration
        fact = json.dumps(
            {
                "action": f"agent_adapter.{result.disposition.value}",
                "adapter_id": registration.manifest.adapter_id,
                "adapter_version": registration.manifest.adapter_version,
                "observation_id": registration.observation.observation_id,
                "occurred_at": now,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        after = hashlib.sha256(
            _encode_availability(
                registration.observation.evidence_availability
            ).encode()
        ).digest()
        await self._connection.execute(
            text(
                "INSERT INTO audit_events "
                "(brain_id, actor_id, action, target_ref, idempotency_key, before_hash, "
                "after_hash, previous_hash, event_hash, occurred_at, schema_version) VALUES "
                "(NULL, 'installation', :action, :target, :key, :before, :after, :previous, "
                ":event_hash, :occurred_at, 1)"
            ),
            {
                "action": f"agent_adapter.{result.disposition.value}",
                "target": (
                    f"{registration.manifest.adapter_id}@"
                    f"{registration.manifest.adapter_version}"
                ),
                "key": f"adapter-capability:{operation_id}",
                "before": previous_hash,
                "after": after,
                "previous": previous_hash,
                "event_hash": hashlib.sha256(previous_hash + fact).digest(),
                "occurred_at": now,
            },
        )


class SqliteAdapterCapabilityQueryRepository:
    """Read registered capability matrices and compatibility warnings."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Bind the canonical read engine."""
        self._engine = engine

    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
    ) -> RegisteredAdapterCapabilities | None:
        """Return exact current evidence for one version."""
        try:
            async with self._engine.connect() as connection:
                return await _load_latest_registration(
                    connection,
                    adapter_id,
                    adapter_version,
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error

    async def list_active(self) -> tuple[RegisteredAdapterCapabilities, ...]:
        """Return all active versions with current evidence in stable display order."""
        try:
            async with self._engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT adapter_id, adapter_version "
                                "FROM agent_adapter_manifests "
                                "WHERE status='active' "
                                "AND manifest_format='capability-matrix-v1' "
                                "ORDER BY adapter_id, adapter_version"
                            )
                        )
                    )
                    .mappings()
                    .all()
                )
                results = [
                    await _load_latest_registration(
                        connection,
                        str(row["adapter_id"]),
                        str(row["adapter_version"]),
                    )
                    for row in rows
                ]
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return tuple(item for item in results if item is not None)

    async def warnings(
        self,
        adapter_id: str,
        adapter_version: str,
        *,
        maximum: int = 100,
    ) -> tuple[CapabilityCompatibilityWarning, ...]:
        """Return newest bounded warnings for one exact adapter version."""
        if not 1 <= maximum <= _MAX_WARNING_RESULTS:
            message = "Capability warning limit must be between 1 and 100"
            raise ValueError(message)
        try:
            async with self._engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT capability, previous_status, current_status, impact, "
                                "warning_code FROM agent_adapter_compatibility_warnings "
                                "WHERE adapter_id=:adapter_id "
                                "AND adapter_version=:adapter_version "
                                "ORDER BY created_at DESC, warning_id DESC LIMIT :maximum"
                            ),
                            {
                                "adapter_id": adapter_id,
                                "adapter_version": adapter_version,
                                "maximum": maximum,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_STORAGE) from error
        return tuple(_warning_from_mapping(row) for row in rows)


async def _load_latest_registration(
    connection: AsyncConnection,
    adapter_id: str,
    adapter_version: str,
) -> RegisteredAdapterCapabilities | None:
    try:
        row = (
            (
                await connection.execute(
                    text(_REGISTRATION_SELECT),
                    {
                        "adapter_id": adapter_id,
                        "adapter_version": adapter_version,
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
    except SQLAlchemyError as error:
        raise IngestionDependencyError(_ERR_STORAGE) from error
    return None if row is None else _registration(row)


async def _load_observation_registration(
    connection: AsyncConnection,
    observation_id: str,
) -> RegisteredAdapterCapabilities:
    try:
        row = (
            (
                await connection.execute(
                    text(_OBSERVATION_REGISTRATION_SELECT),
                    {"observation_id": observation_id},
                )
            )
            .mappings()
            .one_or_none()
        )
    except SQLAlchemyError as error:
        raise IngestionDependencyError(_ERR_STORAGE) from error
    if row is None:
        raise IngestionDependencyError(_ERR_MALFORMED)
    return _registration(row)


def _registration(row: RowMapping) -> RegisteredAdapterCapabilities:
    try:
        manifest = _decode_manifest(str(row["descriptor_json"]))
        observation = AdapterCapabilityObservation.create(
            observation_id=str(row["observation_id"]),
            operation_id=str(row["operation_id"]),
            adapter_id=str(row["adapter_id"]),
            adapter_version=str(row["adapter_version"]),
            adapter_digest=_bytes(row["adapter_digest"]).hex(),
            capability_manifest_digest=_bytes(row["manifest_sha256"]).hex(),
            revision=int(row["revision"]),
            evidence_availability=_decode_availability(str(row["availability_json"])),
            observed_at=_datetime(int(row["observed_at"])),
        )
        stored_manifest = _bytes(row["stored_manifest_sha256"]).hex()
        if stored_manifest != manifest.manifest_sha256:
            raise IngestionDependencyError(_ERR_MALFORMED)
        return RegisteredAdapterCapabilities(manifest, observation)
    except (KeyError, TypeError, ValueError) as error:
        raise IngestionDependencyError(_ERR_MALFORMED) from error


def _encode_manifest(manifest: AdapterCapabilityManifest) -> str:
    return json.dumps(
        {
            "adapter_digest": manifest.adapter_digest,
            "adapter_id": manifest.adapter_id,
            "adapter_version": manifest.adapter_version,
            "evidence_availability": [
                {"capability": item.capability.value, "status": item.status.value}
                for item in manifest.evidence_availability
            ],
            "schema_major": manifest.schema_major,
            "supported_families": [item.value for item in manifest.supported_families],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_manifest(value: str) -> AdapterCapabilityManifest:
    document = cast("dict[str, object]", json.loads(value))
    availability = cast("Sequence[dict[str, str]]", document["evidence_availability"])
    families = cast("Sequence[str]", document["supported_families"])
    return AdapterCapabilityManifest.create(
        adapter_id=str(document["adapter_id"]),
        adapter_version=str(document["adapter_version"]),
        adapter_digest=str(document["adapter_digest"]),
        schema_major=int(cast("int", document["schema_major"])),
        supported_families=tuple(EventFamily(item) for item in families),
        evidence_availability=tuple(
            EvidenceAvailability(
                CaptureCapability(item["capability"]),
                CaptureMethod(item["status"]),
            )
            for item in availability
        ),
    )


def _encode_availability(value: tuple[EvidenceAvailability, ...]) -> str:
    return json.dumps(
        [
            {"capability": item.capability.value, "status": item.status.value}
            for item in value
        ],
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_availability(value: str) -> tuple[EvidenceAvailability, ...]:
    document = cast("Sequence[dict[str, str]]", json.loads(value))
    return tuple(
        EvidenceAvailability(
            CaptureCapability(item["capability"]),
            CaptureMethod(item["status"]),
        )
        for item in document
    )


def _encode_warnings(value: tuple[CapabilityCompatibilityWarning, ...]) -> str:
    return json.dumps(
        [
            {
                "capability": item.capability.value,
                "code": item.code,
                "current_status": item.current_status.value,
                "impact": item.impact.value,
                "previous_status": item.previous_status.value,
            }
            for item in value
        ],
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_warnings(value: str) -> tuple[CapabilityCompatibilityWarning, ...]:
    try:
        document = cast("Sequence[dict[str, str]]", json.loads(value))
        return tuple(_warning_from_mapping(item) for item in document)
    except (KeyError, TypeError, ValueError) as error:
        raise IngestionDependencyError(_ERR_MALFORMED) from error


def _warning_from_mapping(
    item: RowMapping | dict[str, str],
) -> CapabilityCompatibilityWarning:
    return CapabilityCompatibilityWarning(
        CaptureCapability(str(item["capability"])),
        CaptureMethod(str(item["previous_status"])),
        CaptureMethod(str(item["current_status"])),
        CapabilityCompatibilityImpact(str(item["impact"])),
        str(item.get("warning_code", item.get("code"))),
    )


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IngestionDependencyError(_ERR_MALFORMED)
    return value


def _unix_microseconds(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)
