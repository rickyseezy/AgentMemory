"""ID-003 transactional SQLite repository-topology persistence."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Self, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
)
from agentmemory.identity.domain.topology import (
    ProjectRepositoryLink,
    RepositoryLinkHistoryEntry,
    RepositoryRelationType,
    RepositoryTopologyCandidate,
    TopologyConfirmationSource,
    TopologyEndpointType,
    TopologyEvidence,
    TopologyEvidenceKind,
    TopologyEvidenceStrength,
    TopologyLinkEventType,
)
from agentmemory.identity.domain.value_objects import Fingerprint, StableId

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

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


class SqliteRepositoryTopologyReadRepository:
    """Validate candidate endpoint ownership on a read-only engine connection."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Bind the canonical identity database."""
        self._engine = engine

    async def require_candidate(self, candidate: RepositoryTopologyCandidate) -> None:
        """Reject missing, inactive, wrong-type, and cross-Brain endpoints."""
        try:
            async with self._engine.connect() as connection:
                await _require_candidate(connection, candidate)
        except IdentityConflictError:
            raise
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error


class SqliteRepositoryLinkUnitOfWork:
    """Own one serialized transaction for repository-link confirmation."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical store and policy clock."""
        self._store = store
        self._clock = clock
        self._connection: AsyncConnection | None = None
        self._committed = False
        self.authorization: SqliteRepositoryLinkAuthorization
        self.links: SqliteProjectRepositoryLinkRepository

    async def __aenter__(self) -> Self:
        """Acquire the single writer before authorization and duplicate checks."""
        await self._store.write_lock.acquire()
        try:
            self._connection = await self._store.engine.connect()
            await self._connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            self._store.write_lock.release()
            raise
        connection = self._require_connection()
        self.authorization = SqliteRepositoryLinkAuthorization(connection, self._clock)
        self.links = SqliteProjectRepositoryLinkRepository(connection, self._clock)
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
        """Commit once and translate database races to bounded domain failures."""
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
            msg = "Repository link Unit of Work is not active"
            raise RuntimeError(msg)
        return self._connection


class SqliteRepositoryLinkUnitOfWorkFactory:
    """Create a fresh ID-003 Unit of Work for every command."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Keep only stable infrastructure dependencies."""
        self._store = store
        self._clock = clock

    def __call__(self) -> SqliteRepositoryLinkUnitOfWork:
        """Return one unopened repository-link transaction."""
        return SqliteRepositoryLinkUnitOfWork(self._store, self._clock)


class SqliteRepositoryLinkAuthorization:
    """Authorize topology mutation in the same transaction as its write."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind the owning transaction and policy clock."""
        self._connection = connection
        self._clock = clock

    async def authorize(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        """Require an active exact owner grant for the candidate Brain."""
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


class SqliteProjectRepositoryLinkRepository:
    """Map the aggregate to its snapshot, history, event, and current read projection."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind persistence to the owning write transaction."""
        self._connection = connection
        self._clock = clock

    async def require_candidate(self, candidate: RepositoryTopologyCandidate) -> None:
        """Require active endpoint entities owned by one Brain."""
        try:
            await _require_candidate(self._connection, candidate)
        except IdentityConflictError:
            raise
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error

    async def find_operation(
        self,
        brain_id: StableId,
        operation_id: str,
    ) -> tuple[str, ProjectRepositoryLink] | None:
        """Load the exact result and request digest of an idempotent command."""
        try:
            row = (
                (
                    await self._connection.execute(
                        text(
                            "SELECT link_id, request_digest FROM "
                            "repository_topology_link_history "
                            "WHERE brain_id = :brain_id AND operation_id = :operation_id"
                        ),
                        {"brain_id": brain_id.value, "operation_id": operation_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            aggregate = await self._load_link(brain_id, StableId(str(row["link_id"])))
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        if aggregate is None:
            raise IdentityConflictError
        return bytes(row["request_digest"]).hex(), aggregate

    async def find_link(
        self,
        brain_id: StableId,
        link_id: StableId,
    ) -> ProjectRepositoryLink | None:
        """Load an active aggregate and all immutable history versions."""
        try:
            return await self._load_link(brain_id, link_id)
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error

    async def find_active(
        self,
        candidate: RepositoryTopologyCandidate,
    ) -> ProjectRepositoryLink | None:
        """Find existing active state by immutable endpoint identities."""
        try:
            row = (
                await self._connection.execute(
                    text(
                        "SELECT id FROM repository_topology_links "
                        "WHERE brain_id = :brain_id AND subject_type = :subject_type "
                        "AND subject_id = :subject_id AND target_type = :target_type "
                        "AND target_id = :target_id AND status = 'active'"
                    ),
                    _candidate_values(candidate),
                )
            ).first()
            if row is None:
                return None
            return await self._load_link(candidate.brain_id, StableId(str(row[0])))
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error

    async def append(
        self,
        request_digest: str,
        event_id: StableId,
        aggregate: ProjectRepositoryLink,
        *,
        expected_previous_version: int | None,
    ) -> None:
        """Compare-and-swap current state and append canonical provenance."""
        now = _unix_microseconds(self._clock.now())
        try:
            if expected_previous_version is None:
                await self._insert_snapshot(aggregate, now)
            else:
                await self._update_snapshot(aggregate, expected_previous_version, now)
            await self._insert_event(event_id, aggregate, now)
            await self._insert_history(request_digest, event_id, aggregate, now)
            await self._update_project_projection(aggregate, now)
        except IntegrityError as error:
            raise IdentityConflictError from error
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error

    async def _load_link(
        self,
        brain_id: StableId,
        link_id: StableId,
    ) -> ProjectRepositoryLink | None:
        snapshot = (
            (
                await self._connection.execute(
                    text(
                        "SELECT * FROM repository_topology_links "
                        "WHERE id = :id AND brain_id = :brain_id AND status = 'active'"
                    ),
                    {"id": link_id.value, "brain_id": brain_id.value},
                )
            )
            .mappings()
            .one_or_none()
        )
        if snapshot is None:
            return None
        history_rows = (
            (
                await self._connection.execute(
                    text(
                        "SELECT * FROM repository_topology_link_history "
                        "WHERE link_id = :id ORDER BY version"
                    ),
                    {"id": link_id.value},
                )
            )
            .mappings()
            .all()
        )
        return _aggregate(snapshot, history_rows)

    async def _insert_snapshot(self, aggregate: ProjectRepositoryLink, now: int) -> None:
        values = _snapshot_values(aggregate, now)
        await self._connection.execute(
            text(
                "INSERT INTO repository_topology_links "
                "(id, brain_id, subject_type, subject_id, relation_type, target_type, "
                "target_id, component_root_fingerprint, status, valid_from, valid_to, version, "
                "created_at, updated_at, schema_version) VALUES "
                "(:id, :brain_id, :subject_type, :subject_id, :relation_type, :target_type, "
                ":target_id, :component, 'active', :valid_from, :valid_to, :version, :now, "
                ":now, 1)"
            ),
            values,
        )

    async def _update_snapshot(
        self,
        aggregate: ProjectRepositoryLink,
        expected_previous_version: int,
        now: int,
    ) -> None:
        values = _snapshot_values(aggregate, now)
        values["expected_version"] = expected_previous_version
        result = await self._connection.execute(
            text(
                "UPDATE repository_topology_links SET relation_type = :relation_type, "
                "component_root_fingerprint = :component, valid_to = :valid_to, "
                "version = :version, updated_at = :now WHERE id = :id AND brain_id = :brain_id "
                "AND version = :expected_version AND status = 'active'"
            ),
            values,
        )
        if result.rowcount != 1:
            raise IdentityConflictError

    async def _insert_event(
        self,
        event_id: StableId,
        aggregate: ProjectRepositoryLink,
        now: int,
    ) -> None:
        history = aggregate.history[-1]
        event_type = (
            TopologyLinkEventType.CONFIRMED
            if history.previous_version is None
            else TopologyLinkEventType.CORRECTED
        )
        await self._connection.execute(
            text(
                "INSERT INTO domain_events "
                "(event_id, brain_id, aggregate_type, aggregate_id, aggregate_version, "
                "event_type, event_json, correlation_id, causation_id, occurred_at, "
                "recorded_at, schema_version) VALUES "
                "(:event_id, :brain_id, 'project_repository_link', :link_id, :version, "
                ":event_type, :event_json, :operation_id, NULL, :effective_at, :now, 1)"
            ),
            {
                "event_id": event_id.value,
                "brain_id": aggregate.brain_id.value,
                "link_id": aggregate.link_id.value,
                "version": aggregate.version,
                "event_type": event_type.value,
                "event_json": _event_json(aggregate),
                "operation_id": history.operation_id,
                "effective_at": history.effective_at,
                "now": now,
            },
        )

    async def _insert_history(
        self,
        request_digest: str,
        event_id: StableId,
        aggregate: ProjectRepositoryLink,
        now: int,
    ) -> None:
        history = aggregate.history[-1]
        values = _snapshot_values(aggregate, now)
        values.update(
            {
                "operation_id": history.operation_id,
                "request_digest": bytes.fromhex(request_digest),
                "event_id": event_id.value,
                "actor_id": history.actor_id.value,
                "grant_id": history.grant_id.value,
                "confirmation_source": history.confirmation_source.value,
                "correction_reason": history.correction_reason,
                "effective_at": history.effective_at,
                "evidence_json": _evidence_json(history.evidence),
            }
        )
        await self._connection.execute(
            text(
                "INSERT INTO repository_topology_link_history "
                "(link_id, brain_id, version, operation_id, request_digest, event_id, "
                "subject_type, subject_id, relation_type, target_type, target_id, "
                "component_root_fingerprint, evidence_json, actor_id, grant_id, "
                "confirmation_source, correction_reason, effective_at, recorded_at, "
                "schema_version) VALUES "
                "(:id, :brain_id, :version, :operation_id, :request_digest, :event_id, "
                ":subject_type, :subject_id, :relation_type, :target_type, :target_id, "
                ":component, :evidence_json, :actor_id, :grant_id, :confirmation_source, "
                ":correction_reason, :effective_at, :now, 1)"
            ),
            values,
        )

    async def _update_project_projection(
        self,
        aggregate: ProjectRepositoryLink,
        now: int,
    ) -> None:
        if aggregate.relation_type is not RepositoryRelationType.PROJECT_USES_REPOSITORY:
            return
        role = "component" if aggregate.component_root_fingerprint is not None else "primary"
        await self._connection.execute(
            text(
                "INSERT INTO project_repositories "
                "(project_id, repository_id, relation_type, created_at, updated_at, "
                "schema_version) VALUES (:project, :repository, :role, :now, :now, 1) "
                "ON CONFLICT(project_id, repository_id) DO UPDATE SET "
                "relation_type = excluded.relation_type, updated_at = excluded.updated_at"
            ),
            {
                "project": aggregate.subject_id.value,
                "repository": aggregate.target_id.value,
                "role": role,
                "now": now,
            },
        )


async def _require_candidate(
    connection: AsyncConnection,
    candidate: RepositoryTopologyCandidate,
) -> None:
    subject_statement = text(
        "SELECT 1 FROM projects WHERE id = :id AND brain_id = :brain_id AND status = 'active'"
        if candidate.subject_type is TopologyEndpointType.PROJECT
        else "SELECT 1 FROM repositories WHERE id = :id "
        "AND brain_id = :brain_id AND status = 'active'"
    )
    repository_statement = text(
        "SELECT 1 FROM repositories WHERE id = :id AND brain_id = :brain_id AND status = 'active'"
    )
    endpoint_exists: list[bool] = []
    for statement, entity_id in (
        (subject_statement, candidate.subject_id),
        (repository_statement, candidate.target_id),
    ):
        row = (
            await connection.execute(
                statement,
                {"id": entity_id.value, "brain_id": candidate.brain_id.value},
            )
        ).first()
        endpoint_exists.append(row is not None)
    if not all(endpoint_exists):
        raise IdentityConflictError


def _candidate_values(candidate: RepositoryTopologyCandidate) -> dict[str, object]:
    return {
        "brain_id": candidate.brain_id.value,
        "subject_type": candidate.subject_type.value,
        "subject_id": candidate.subject_id.value,
        "target_type": candidate.target_type.value,
        "target_id": candidate.target_id.value,
    }


def _snapshot_values(aggregate: ProjectRepositoryLink, now: int) -> dict[str, object]:
    return {
        "id": aggregate.link_id.value,
        "brain_id": aggregate.brain_id.value,
        "subject_type": aggregate.subject_type.value,
        "subject_id": aggregate.subject_id.value,
        "relation_type": aggregate.relation_type.value,
        "target_type": aggregate.target_type.value,
        "target_id": aggregate.target_id.value,
        "component": _optional_binary(aggregate.component_root_fingerprint),
        "valid_from": aggregate.valid_from,
        "valid_to": aggregate.valid_to,
        "version": aggregate.version,
        "now": now,
    }


def _aggregate(
    snapshot: RowMapping,
    history_rows: Sequence[RowMapping],
) -> ProjectRepositoryLink:
    history = tuple(_history_entry(row) for row in history_rows)
    latest = history[-1]
    return ProjectRepositoryLink(
        link_id=StableId(str(snapshot["id"])),
        brain_id=StableId(str(snapshot["brain_id"])),
        subject_type=TopologyEndpointType(str(snapshot["subject_type"])),
        subject_id=StableId(str(snapshot["subject_id"])),
        relation_type=RepositoryRelationType(str(snapshot["relation_type"])),
        target_type=TopologyEndpointType(str(snapshot["target_type"])),
        target_id=StableId(str(snapshot["target_id"])),
        component_root_fingerprint=_optional_fingerprint(snapshot["component_root_fingerprint"]),
        evidence=latest.evidence,
        valid_from=int(snapshot["valid_from"]),
        valid_to=None if snapshot["valid_to"] is None else int(snapshot["valid_to"]),
        version=int(snapshot["version"]),
        history=history,
    )


def _history_entry(row: RowMapping) -> RepositoryLinkHistoryEntry:
    evidence_payload = json.loads(str(row["evidence_json"]))
    evidence = tuple(
        TopologyEvidence(
            Fingerprint(str(item["digest"])),
            TopologyEvidenceKind(str(item["kind"])),
            TopologyEvidenceStrength(str(item["strength"])),
        )
        for item in evidence_payload
    )
    version = int(row["version"])
    return RepositoryLinkHistoryEntry(
        version=version,
        previous_version=None if version == 1 else version - 1,
        operation_id=str(row["operation_id"]),
        actor_id=StableId(str(row["actor_id"])),
        grant_id=StableId(str(row["grant_id"])),
        confirmation_source=TopologyConfirmationSource(str(row["confirmation_source"])),
        relation_type=RepositoryRelationType(str(row["relation_type"])),
        component_root_fingerprint=_optional_fingerprint(row["component_root_fingerprint"]),
        evidence=evidence,
        correction_reason=(
            None if row["correction_reason"] is None else str(row["correction_reason"])
        ),
        effective_at=int(row["effective_at"]),
    )


def _evidence_json(evidence: tuple[TopologyEvidence, ...]) -> str:
    return json.dumps(
        [
            {
                "digest": item.digest.value,
                "kind": item.kind.value,
                "strength": item.strength.value,
            }
            for item in evidence
        ],
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _event_json(aggregate: ProjectRepositoryLink) -> str:
    history = aggregate.history[-1]
    return json.dumps(
        {
            "actor_id": history.actor_id.value,
            "component_root_fingerprint": (
                None
                if aggregate.component_root_fingerprint is None
                else aggregate.component_root_fingerprint.value
            ),
            "confirmation_source": history.confirmation_source.value,
            "correction_reason": history.correction_reason,
            "evidence": json.loads(_evidence_json(history.evidence)),
            "grant_id": history.grant_id.value,
            "relation_type": aggregate.relation_type.value,
            "subject_id": aggregate.subject_id.value,
            "subject_type": aggregate.subject_type.value,
            "target_id": aggregate.target_id.value,
            "target_type": aggregate.target_type.value,
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _optional_binary(value: Fingerprint | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value.value)


def _optional_fingerprint(value: object) -> Fingerprint | None:
    return None if value is None else Fingerprint(cast("bytes", value).hex())


def _unix_microseconds(value: datetime) -> int:
    return int(value.timestamp() * 1_000_000)
