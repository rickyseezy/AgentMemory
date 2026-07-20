"""ID-002 transactional SQLite Checkout observation persistence."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Self

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.identity.domain.checkout import (
    CheckoutAggregate,
    CheckoutEvent,
    CheckoutObservation,
)
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
)
from agentmemory.identity.domain.value_objects import Fingerprint, StableId

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.value_objects import DeviceIdentity, VcsIdentity
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_AUTHORIZATION = """
SELECT 1 FROM scope_grants AS g
JOIN principals AS p ON p.id = g.principal_id
JOIN brains AS b ON b.id = g.brain_id
WHERE g.id = :grant_id AND g.principal_id = :actor_id AND g.brain_id = :brain_id
  AND g.role = 'owner' AND p.status = 'active' AND b.status = 'active'
  AND g.valid_from <= :now AND (g.valid_to IS NULL OR g.valid_to > :now)
"""

_OPERATION_OBSERVATION = """
SELECT o.checkout_id, o.brain_id, o.aggregate_version,
  o.repository_id, o.device_id, o.volume_fingerprint, o.path_fingerprint,
  o.logical_path_fingerprint, o.file_fingerprint, o.checkout_fingerprint,
  o.worktree_fingerprint, o.common_directory_fingerprint, o.branch, o.head_commit,
  o.dirty_digest, o.remote_fingerprints_json
FROM checkout_observations AS o
WHERE o.brain_id = :brain_id AND o.operation_id = :operation_id
"""


class SqliteCheckoutObservationUnitOfWork:
    """Own one serialized transaction for authorization and canonical observation writes."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the local canonical store and injected clock."""
        self._store = store
        self._clock = clock
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.authorization: SqliteCheckoutObservationAuthorization
        self.checkouts: SqliteCheckoutObservationRepository

    async def __aenter__(self) -> Self:
        """Acquire the single writer before checking authorization or continuity."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        connection = self._require_connection()
        self.authorization = SqliteCheckoutObservationAuthorization(connection, self._clock)
        self.checkouts = SqliteCheckoutObservationRepository(connection, self._clock)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unfinished changes and always release writer ownership."""
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
        """Commit the observation once, translating database races to a domain conflict."""
        if self._committed:
            raise IdentityConflictError
        try:
            await self._require_connection().commit()
        except IntegrityError as error:
            raise IdentityConflictError from error
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        self._committed = True

    def _require_connection(self) -> AsyncConnection:
        if self._connection is None:
            msg = "Checkout observation Unit of Work is not active"
            raise RuntimeError(msg)
        return self._connection


class SqliteCheckoutObservationUnitOfWorkFactory:
    """Create one fresh ID-002 Unit of Work for every command."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Keep only stable infrastructure dependencies."""
        self._store = store
        self._clock = clock

    def __call__(self) -> SqliteCheckoutObservationUnitOfWork:
        """Return one unopened Checkout observation transaction."""
        return SqliteCheckoutObservationUnitOfWork(self._store, self._clock)


class SqliteCheckoutObservationAuthorization:
    """Authorize mutation against current grant state in the owning transaction."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind authorization to the owning transaction and policy clock."""
        self._connection = connection
        self._clock = clock

    async def authorize(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        """Deny absent, expired, revoked, wrong-principal, or wrong-Brain grants."""
        try:
            row = (
                await self._connection.execute(
                    text(_AUTHORIZATION),
                    {
                        "brain_id": brain_id.value,
                        "actor_id": actor_id.value,
                        "grant_id": grant_id.value,
                        "now": _unix_microseconds(self._clock.now()),
                    },
                )
            ).first()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        if row is None:
            raise IdentityAuthorizationError


class SqliteCheckoutObservationRepository:
    """Map immutable domain values to versioned snapshots, events, and observation history."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind persistence to the owning transaction and observation clock."""
        self._connection = connection
        self._clock = clock

    async def require_repository(
        self,
        brain_id: StableId,
        repository_id: StableId,
    ) -> None:
        """Require an active Repository owned by the authorized Brain."""
        try:
            row = (
                await self._connection.execute(
                    text(
                        "SELECT 1 FROM repositories WHERE id = :repository_id "
                        "AND brain_id = :brain_id AND status = 'active'"
                    ),
                    {
                        "brain_id": brain_id.value,
                        "repository_id": repository_id.value,
                    },
                )
            ).first()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        if row is None:
            raise IdentityConflictError

    async def find_operation(
        self,
        brain_id: StableId,
        operation_id: str,
    ) -> CheckoutAggregate | None:
        """Return the exact historical aggregate version produced by a prior command."""
        try:
            row = (
                (
                    await self._connection.execute(
                        text(_OPERATION_OBSERVATION),
                        {"brain_id": brain_id.value, "operation_id": operation_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        return None if row is None else _aggregate(row)

    async def find_continuity(
        self,
        brain_id: StableId,
        repository_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity,
    ) -> tuple[CheckoutAggregate, ...]:
        """Load bounded candidates selected only by deterministic continuity evidence."""
        query = """
        SELECT c.id AS checkout_id, c.brain_id, c.version AS aggregate_version,
          c.repository_id, c.device_id, c.volume_fingerprint,
          c.canonical_path_hash AS path_fingerprint,
          COALESCE(c.logical_path_hash, c.canonical_path_hash) AS logical_path_fingerprint,
          c.file_fingerprint, c.checkout_fingerprint,
          c.worktree_id AS worktree_fingerprint, c.common_directory_fingerprint,
          c.branch, c.head_commit, c.dirty_digest,
          COALESCE(c.remote_fingerprints_json, '[]') AS remote_fingerprints_json
        FROM checkouts AS c
        WHERE c.brain_id = :brain_id AND c.repository_id = :repository_id
          AND c.device_id = :device_id AND c.status = 'active'
          AND (
            (:checkout IS NOT NULL AND c.checkout_fingerprint = :checkout)
            OR (:file IS NOT NULL AND c.file_fingerprint = :file
                AND c.volume_fingerprint = :volume)
            OR (:worktree IS NOT NULL AND :common IS NOT NULL
                AND c.worktree_id = :worktree
                AND c.common_directory_fingerprint = :common)
          )
        ORDER BY c.id LIMIT 3
        """
        parameters = {
            "brain_id": brain_id.value,
            "repository_id": repository_id.value,
            "device_id": device.device_id.value,
            "volume": _binary(device.volume_fingerprint),
            "file": _optional_binary(device.file_fingerprint),
            "checkout": _optional_binary(vcs.checkout_fingerprint),
            "worktree": _optional_binary(vcs.worktree_fingerprint),
            "common": _optional_binary(vcs.common_directory_fingerprint),
        }
        try:
            rows = (await self._connection.execute(text(query), parameters)).mappings().all()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        return tuple(_aggregate(row) for row in rows)

    async def append(
        self,
        operation_id: str,
        event_id: StableId,
        aggregate: CheckoutAggregate,
        event: CheckoutEvent,
        *,
        expected_previous_version: int | None,
    ) -> None:
        """Compare-and-swap the snapshot then append event and immutable observation."""
        now = _unix_microseconds(self._clock.now())
        try:
            if expected_previous_version is None:
                await self._insert_checkout(aggregate, now)
            else:
                await self._update_checkout(aggregate, expected_previous_version, now)
            event_json = _event_json(event)
            await self._connection.execute(
                text(
                    "INSERT INTO domain_events "
                    "(event_id, brain_id, aggregate_type, aggregate_id, aggregate_version, "
                    "event_type, event_json, correlation_id, causation_id, occurred_at, "
                    "recorded_at, schema_version) VALUES "
                    "(:event_id, :brain_id, 'checkout', :checkout_id, :version, :event_type, "
                    ":event_json, :operation_id, NULL, :now, :now, 1)"
                ),
                {
                    "event_id": event_id.value,
                    "brain_id": aggregate.brain_id.value,
                    "checkout_id": aggregate.checkout_id.value,
                    "version": aggregate.version,
                    "event_type": event.event_type.value,
                    "event_json": event_json,
                    "operation_id": operation_id,
                    "now": now,
                },
            )
            await self._insert_observation(operation_id, event_id, aggregate, now)
        except IntegrityError as error:
            raise IdentityConflictError from error
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error

    async def _insert_checkout(self, aggregate: CheckoutAggregate, now: int) -> None:
        values = _snapshot_values(aggregate, now)
        await self._connection.execute(
            text(
                "INSERT INTO checkouts "
                "(id, brain_id, repository_id, device_id, canonical_path_hash, logical_path_hash, "
                "volume_fingerprint, file_fingerprint, checkout_fingerprint, worktree_id, "
                "common_directory_fingerprint, branch, head_commit, dirty_digest, "
                "remote_fingerprints_json, last_seen_at, status, version, created_at, updated_at, "
                "schema_version) VALUES "
                "(:id, :brain_id, :repository_id, :device_id, :path, :logical_path, :volume, "
                ":file, :checkout, :worktree, :common, :branch, :head, :dirty, :remotes, :now, "
                "'active', :version, :now, :now, 1)"
            ),
            values,
        )

    async def _update_checkout(
        self,
        aggregate: CheckoutAggregate,
        expected_previous_version: int,
        now: int,
    ) -> None:
        values = _snapshot_values(aggregate, now)
        values["expected_version"] = expected_previous_version
        result = await self._connection.execute(
            text(
                "UPDATE checkouts SET canonical_path_hash = :path, "
                "logical_path_hash = :logical_path, volume_fingerprint = :volume, "
                "file_fingerprint = :file, checkout_fingerprint = :checkout, "
                "worktree_id = :worktree, common_directory_fingerprint = :common, "
                "branch = :branch, head_commit = :head, dirty_digest = :dirty, "
                "remote_fingerprints_json = :remotes, last_seen_at = :now, "
                "version = :version, updated_at = :now "
                "WHERE id = :id AND brain_id = :brain_id AND version = :expected_version "
                "AND status = 'active'"
            ),
            values,
        )
        if result.rowcount != 1:
            raise IdentityConflictError

    async def _insert_observation(
        self,
        operation_id: str,
        event_id: StableId,
        aggregate: CheckoutAggregate,
        now: int,
    ) -> None:
        values = _snapshot_values(aggregate, now)
        values.update({"operation_id": operation_id, "event_id": event_id.value})
        await self._connection.execute(
            text(
                "INSERT INTO checkout_observations "
                "(operation_id, event_id, brain_id, checkout_id, aggregate_version, "
                "repository_id, device_id, volume_fingerprint, path_fingerprint, "
                "logical_path_fingerprint, file_fingerprint, checkout_fingerprint, "
                "worktree_fingerprint, common_directory_fingerprint, branch, head_commit, "
                "dirty_digest, remote_fingerprints_json, observed_at, schema_version) VALUES "
                "(:operation_id, :event_id, :brain_id, :id, :version, :repository_id, "
                ":device_id, :volume, :path, :logical_path, :file, :checkout, :worktree, "
                ":common, :branch, :head, :dirty, :remotes, :now, 1)"
            ),
            values,
        )


def _aggregate(row: RowMapping) -> CheckoutAggregate:
    observation = CheckoutObservation(
        repository_id=StableId(str(row["repository_id"])),
        device_id=StableId(str(row["device_id"])),
        volume_fingerprint=_fingerprint(row["volume_fingerprint"]),
        path_fingerprint=_fingerprint(row["path_fingerprint"]),
        logical_path_fingerprint=_fingerprint(row["logical_path_fingerprint"]),
        file_fingerprint=_optional_fingerprint(row["file_fingerprint"]),
        checkout_fingerprint=_optional_fingerprint(row["checkout_fingerprint"]),
        worktree_fingerprint=_optional_fingerprint(row["worktree_fingerprint"]),
        common_directory_fingerprint=_optional_fingerprint(row["common_directory_fingerprint"]),
        branch=None if row["branch"] is None else str(row["branch"]),
        head_commit=None if row["head_commit"] is None else str(row["head_commit"]),
        dirty_digest=_optional_fingerprint(row["dirty_digest"]),
        remote_fingerprints=tuple(
            Fingerprint(value) for value in json.loads(str(row["remote_fingerprints_json"]))
        ),
    )
    return CheckoutAggregate(
        StableId(str(row["checkout_id"])),
        StableId(str(row["brain_id"])),
        observation,
        int(row["aggregate_version"]),
    )


def _snapshot_values(aggregate: CheckoutAggregate, now: int) -> dict[str, object]:
    observation = aggregate.current
    return {
        "id": aggregate.checkout_id.value,
        "brain_id": aggregate.brain_id.value,
        "repository_id": observation.repository_id.value,
        "device_id": observation.device_id.value,
        "volume": _binary(observation.volume_fingerprint),
        "path": _binary(observation.path_fingerprint),
        "logical_path": _binary(observation.logical_path_fingerprint),
        "file": _optional_binary(observation.file_fingerprint),
        "checkout": _optional_binary(observation.checkout_fingerprint),
        "worktree": _optional_binary(observation.worktree_fingerprint),
        "common": _optional_binary(observation.common_directory_fingerprint),
        "branch": observation.branch,
        "head": observation.head_commit,
        "dirty": _optional_binary(observation.dirty_digest),
        "remotes": json.dumps(
            [value.value for value in observation.remote_fingerprints],
            separators=(",", ":"),
        ),
        "version": aggregate.version,
        "now": now,
    }


def _event_json(event: CheckoutEvent) -> str:
    observation = event.observation
    return json.dumps(
        {
            "branch": observation.branch,
            "checkout_id": event.checkout_id.value,
            "checkout_fingerprint": _optional_value(observation.checkout_fingerprint),
            "common_directory_fingerprint": _optional_value(
                observation.common_directory_fingerprint
            ),
            "device_id": observation.device_id.value,
            "dirty_digest": _optional_value(observation.dirty_digest),
            "event_type": event.event_type.value,
            "file_fingerprint": _optional_value(observation.file_fingerprint),
            "head_commit": observation.head_commit,
            "logical_path_fingerprint": observation.logical_path_fingerprint.value,
            "path_fingerprint": observation.path_fingerprint.value,
            "previous_path_fingerprint": (
                None
                if event.previous_path_fingerprint is None
                else event.previous_path_fingerprint.value
            ),
            "repository_id": observation.repository_id.value,
            "remote_fingerprints": [value.value for value in observation.remote_fingerprints],
            "schema_version": 1,
            "volume_fingerprint": observation.volume_fingerprint.value,
            "worktree_fingerprint": _optional_value(observation.worktree_fingerprint),
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _binary(value: Fingerprint) -> bytes:
    return bytes.fromhex(value.value)


def _optional_binary(value: Fingerprint | None) -> bytes | None:
    return None if value is None else _binary(value)


def _optional_value(value: Fingerprint | None) -> str | None:
    return None if value is None else value.value


def _fingerprint(value: object) -> Fingerprint:
    if not isinstance(value, bytes):
        raise IdentityDependencyError
    return Fingerprint(value.hex())


def _optional_fingerprint(value: object) -> Fingerprint | None:
    return None if value is None else _fingerprint(value)


def _unix_microseconds(value: datetime) -> int:
    return int(value.timestamp() * 1_000_000)
