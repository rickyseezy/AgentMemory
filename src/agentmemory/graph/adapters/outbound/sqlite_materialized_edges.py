"""GRA-003 canonical SQLite projection work, authorization, and integrity journals."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    list_assertion_projection_snapshots,
    load_assertion_projection_snapshot,
)
from agentmemory.graph.domain.assertions import AssertionEventType
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)
from agentmemory.graph.domain.materialized_edges import (
    EdgeIntegrityFinding,
    MaterializedAssertionEdge,
    MaterializedEdgeProjectionJob,
    ProjectionEdgeStatus,
    ProjectionJobFailureCode,
)
from agentmemory.graph.domain.models import GraphClassification
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable, Mapping, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.graph.domain.assertions import Assertion
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_OWNER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_MAX_ATTEMPTS = 12
_MAX_INTEGRITY_SCOPES = 100
_DIGEST_HEX_LENGTH = 64
_DIGEST_BYTE_LENGTH = 32
_ERR_ACTION = "materialized edge SQLite action is not authorized"
_ERR_AUTHORIZATION = "materialized edge projection is not authorized"
_ERR_CONFLICT = "materialized edge projection work conflicted with canonical state"
_ERR_GENERATION = "active graph projection generation is invalid"
_ERR_INTEGRITY = "materialized edge canonical state failed integrity verification"
_ERR_STORAGE = "materialized edge canonical storage is unavailable"

_JOB_COLUMNS = (
    "source_event_id,assertion_id,brain_id,principal_id,project_id,repository_id,checkout_id,"
    "classification,aggregate_version,event_digest,created_at,attempts,lease_owner,lease_until"
)


class SqliteCanonicalAssertionProjectionSource:
    """Read authorized current assertion state from the canonical SQLite ledger."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind only the canonical process-wide store."""
        self._store = store

    async def current_for_event(
        self,
        scope: AuthorizedScope,
        source_event_id: str,
        assertion_id: str,
    ) -> tuple[Assertion, str, datetime]:
        """Validate one trigger and return current lifecycle state from one read snapshot."""
        _require_action(scope, {"graph.assertion.materialize"})
        try:
            async with self._store.engine.connect() as connection:
                trigger = (
                    (
                        await connection.execute(
                            text(
                                "SELECT event_type,aggregate_version FROM domain_events "
                                "WHERE event_id=:event AND brain_id=:brain "
                                "AND aggregate_type='assertion' AND aggregate_id=:assertion "
                                "AND stable_id=:assertion LIMIT 1"
                            ),
                            {
                                "event": source_event_id,
                                "brain": scope.brain_id.value,
                                "assertion": assertion_id,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                _require_authorized(trigger is not None and _valid_lifecycle_event(trigger))
                snapshot = await load_assertion_projection_snapshot(
                    connection,
                    scope,
                    assertion_id,
                )
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

        if snapshot is None:
            raise GraphAuthorizationError(_ERR_AUTHORIZATION)
        return snapshot

    async def expected_edges(
        self,
        scope: AuthorizedScope,
        generation_id: str,
        projected_at: datetime,
    ) -> tuple[MaterializedAssertionEdge, ...]:
        """Build deterministic expected edges from one bounded canonical read snapshot."""
        del projected_at
        _require_action(scope, {"graph.assertion.edge.integrity"})
        _require_digest(generation_id, _ERR_GENERATION)
        try:
            async with self._store.engine.connect() as connection:
                snapshots = await list_assertion_projection_snapshots(connection, scope)
        except GraphAuthorizationError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error
        return tuple(
            MaterializedAssertionEdge.from_assertion(
                assertion,
                source_event_id=event_id,
                generation_id=generation_id,
                projected_at=occurred_at,
            )
            for assertion, event_id, occurred_at in snapshots
        )


class SqliteMaterializedEdgeWorkRepository:
    """Lease and finalize assertion-edge work with exact SQLite compare-and-swap guards."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the shared serialized write boundary."""
        self._store = store

    async def claim_next(
        self,
        owner: str,
        now: datetime,
        lease_until: datetime,
    ) -> MaterializedEdgeProjectionJob | None:
        """Recover expired leases and claim one due event deterministically."""
        if _OWNER.fullmatch(owner) is None or lease_until <= now:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        try:
            async with _write_transaction(self._store) as connection:
                at = _micros(now)
                await connection.execute(
                    text(
                        "UPDATE assertion_edge_projection_jobs SET state='quarantined',"
                        "lease_owner=NULL,lease_until=NULL,last_error_code='dependency_unavailable',"
                        "updated_at=:now WHERE state='leased' AND lease_until<=:now "
                        "AND attempts>=:maximum"
                    ),
                    {"now": at, "maximum": _MAX_ATTEMPTS},
                )
                await connection.execute(
                    text(
                        "UPDATE assertion_edge_projection_jobs SET state='ready',lease_owner=NULL,"
                        "lease_until=NULL,last_error_code='dependency_unavailable',updated_at=:now "
                        "WHERE state='leased' AND lease_until<=:now AND attempts<:maximum"
                    ),
                    {"now": at, "maximum": _MAX_ATTEMPTS},
                )
                row = (
                    (
                        await connection.execute(
                            text(
                                f"SELECT {_JOB_COLUMNS} FROM assertion_edge_projection_jobs "  # noqa: S608  # nosec B608
                                "WHERE state='ready' AND not_before<=:now AND attempts<:maximum "
                                "ORDER BY created_at,source_event_id LIMIT 1"
                            ),
                            {"now": at, "maximum": _MAX_ATTEMPTS},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return None
                updated = await connection.execute(
                    text(
                        "UPDATE assertion_edge_projection_jobs SET state='leased',"
                        "attempts=attempts+1,lease_owner=:owner,lease_until=:lease,updated_at=:now,"
                        "last_error_code=NULL WHERE source_event_id=:event AND state='ready' "
                        "AND attempts=:attempts AND not_before<=:now"
                    ),
                    {
                        "owner": owner,
                        "lease": _micros(lease_until),
                        "now": at,
                        "event": str(row["source_event_id"]),
                        "attempts": int(str(row["attempts"])),
                    },
                )
                _require_no_conflict(updated.rowcount != 1)
                claimed = dict(row)
                claimed["attempts"] = int(str(row["attempts"])) + 1
                claimed["lease_owner"] = owner
                claimed["lease_until"] = _micros(lease_until)
                return _decode_job(claimed)
        except GraphConflictError, GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def complete(
        self,
        job: MaterializedEdgeProjectionJob,
        generation_id: str,
        projection_digest: str,
        status: ProjectionEdgeStatus,
        completed_at: datetime,
    ) -> None:
        """Append one immutable receipt and complete only the exact live lease."""
        _require_digest(generation_id, _ERR_GENERATION)
        _require_digest(projection_digest, _ERR_INTEGRITY)
        expected_status = (
            ProjectionEdgeStatus.ACTIVE
            if job.aggregate_version == 1
            else ProjectionEdgeStatus.RETIRED
        )
        if status is not expected_status:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        try:
            async with _write_transaction(self._store) as connection:
                existing = await _receipt(connection, job.source_event_id)
                expected = (
                    job.assertion_id,
                    job.brain_id,
                    generation_id,
                    projection_digest,
                    status.value,
                    job.aggregate_version,
                    _micros(completed_at),
                )
                if existing is not None:
                    _require_no_conflict(_receipt_tuple(existing) != expected)
                    return
                _require_no_conflict(completed_at > job.lease_until)
                inserted = await connection.execute(
                    text(
                        "INSERT INTO assertion_edge_projection_receipts "
                        "(source_event_id,assertion_id,brain_id,generation_id,projection_digest,"
                        "projection_status,aggregate_version,completed_at,schema_version) VALUES "
                        "(:event,:assertion,:brain,:generation,:digest,:status,:version,:at,1)"
                    ),
                    {
                        "event": job.source_event_id,
                        "assertion": job.assertion_id,
                        "brain": job.brain_id,
                        "generation": bytes.fromhex(generation_id),
                        "digest": bytes.fromhex(projection_digest),
                        "status": status.value,
                        "version": job.aggregate_version,
                        "at": _micros(completed_at),
                    },
                )
                updated = await connection.execute(
                    text(
                        "UPDATE assertion_edge_projection_jobs SET state='completed',"
                        "lease_owner=NULL,lease_until=NULL,completed_at=:at,updated_at=:at,"
                        "last_error_code=NULL WHERE source_event_id=:event AND state='leased' "
                        "AND lease_owner=:owner AND lease_until=:lease AND attempts=:attempts"
                    ),
                    {
                        "at": _micros(completed_at),
                        "event": job.source_event_id,
                        "owner": job.lease_owner,
                        "lease": _micros(job.lease_until),
                        "attempts": job.attempts,
                    },
                )
                _require_no_conflict(inserted.rowcount != 1 or updated.rowcount != 1)
        except GraphConflictError, GraphIntegrityError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def retry(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        not_before: datetime,
        attempted_at: datetime,
    ) -> None:
        """Release the exact lease into a bounded delayed retry state."""
        if not_before <= attempted_at or attempted_at > job.lease_until:
            raise GraphConflictError(_ERR_CONFLICT)
        await self._finish_attempt(job, code, attempted_at, not_before=not_before)

    async def quarantine(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        at: datetime,
    ) -> None:
        """Quarantine the exact current lease without persisting exception content."""
        await self._finish_attempt(job, code, at, not_before=None)

    async def _finish_attempt(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
        at: datetime,
        *,
        not_before: datetime | None,
    ) -> None:
        if not _is_failure_code(code) or at > job.lease_until:
            raise GraphConflictError(_ERR_CONFLICT)
        state = "quarantined" if not_before is None else "ready"
        next_attempt = _micros(at if not_before is None else not_before)
        try:
            async with _write_transaction(self._store) as connection:
                updated = await connection.execute(
                    text(
                        "UPDATE assertion_edge_projection_jobs SET state=:state,"
                        "lease_owner=NULL,lease_until=NULL,last_error_code=:code,"
                        "not_before=:next,updated_at=:at WHERE source_event_id=:event "
                        "AND state='leased' AND lease_owner=:owner AND lease_until=:lease "
                        "AND attempts=:attempts"
                    ),
                    {
                        "state": state,
                        "code": code.value,
                        "next": next_attempt,
                        "at": _micros(at),
                        "event": job.source_event_id,
                        "owner": job.lease_owner,
                        "lease": _micros(job.lease_until),
                        "attempts": job.attempts,
                    },
                )
                _require_no_conflict(updated.rowcount != 1)
        except GraphConflictError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


class SqliteMaterializedEdgeAuthorization:
    """Reauthorize one projection job against current principal, Brain, grant, and topology."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical authorization store."""
        self._store = store

    async def authorize(
        self,
        job: MaterializedEdgeProjectionJob,
        action: str,
        at: datetime,
    ) -> AuthorizedScope:
        """Return an exact current scope or fail without exposing candidate existence."""
        if action != "graph.assertion.materialize":
            raise GraphAuthorizationError(_ERR_ACTION)
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(_AUTHORIZE_JOB),
                            {
                                "event": job.source_event_id,
                                "assertion": job.assertion_id,
                                "brain": job.brain_id,
                                "principal": job.principal_id,
                                "project": job.project_id,
                                "repository": job.repository_id,
                                "checkout": job.checkout_id,
                                "classification": job.classification.value,
                                "version": job.aggregate_version,
                                "digest": bytes.fromhex(job.event_digest),
                                "lease_owner": job.lease_owner,
                                "lease_until": _micros(job.lease_until),
                                "attempts": job.attempts,
                                "at": _micros(at),
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error
        if not rows:
            raise GraphAuthorizationError(_ERR_AUTHORIZATION)
        roles = tuple(RetrievalRole(str(row["role"])) for row in rows)
        role = min(roles, key=_role_order)
        grant_version = _grant_version((str(row["id"]), int(str(row["version"]))) for row in rows)
        return AuthorizedScope.create(
            brain_id=StableId(job.brain_id),
            principal_id=StableId(job.principal_id),
            role=role,
            mode=RetrievalScopeMode.SELECTED,
            members=(
                ScopeMember(
                    StableId(job.project_id),
                    (StableId(job.repository_id),),
                    () if job.checkout_id is None else (StableId(job.checkout_id),),
                ),
            ),
            classification_ceiling=Classification.LOCAL_ONLY,
            temporal_scope=TemporalScope(None, None),
            grant_version=grant_version,
            policy_version=int(str(rows[0]["policy_version"])),
            security_epoch=int(str(rows[0]["security_epoch"])),
            action=action,
            purpose="assertion_edge_projection",
        )


class SqliteMaterializedEdgeGenerationResolver:
    """Resolve the current graph generation from canonical SQLite activation state."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the sole active-generation authority."""
        self._store = store

    async def active_generation(self, brain_id: str) -> str | None:
        """Return the active graph generation digest after strict decoding."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    await connection.execute(
                        text(
                            "SELECT generation_id FROM active_projection_generations "
                            "WHERE brain_id=:brain AND projection_type='graph' LIMIT 1"
                        ),
                        {"brain": brain_id},
                    )
                ).one_or_none()
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error
        if row is None:
            return None
        generation_id = _bytes(row[0]).hex()
        _require_digest(generation_id, _ERR_GENERATION)
        return generation_id


class SqliteMaterializedEdgeIntegrityJournal:
    """Append immutable idempotent integrity findings and repair transitions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical audit-evidence store."""
        self._store = store

    async def record(
        self,
        scope: AuthorizedScope,
        findings: tuple[EdgeIntegrityFinding, ...],
    ) -> None:
        """Append exact findings before any graph mutation."""
        _require_action(scope, {"graph.assertion.edge.integrity"})
        try:
            async with _write_transaction(self._store) as connection:
                for finding in findings:
                    await _insert_or_verify_finding(connection, scope, finding)
        except GraphConflictError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def repaired(
        self,
        scope: AuthorizedScope,
        finding: EdgeIntegrityFinding,
        repaired_at: datetime,
    ) -> None:
        """Append one exact repair completion only after its finding exists."""
        _require_action(scope, {"graph.assertion.edge.integrity"})
        values = {
            "finding": finding.id,
            "brain": scope.brain_id.value,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "at": _micros(repaired_at),
        }
        try:
            async with _write_transaction(self._store) as connection:
                await connection.execute(
                    text(
                        "INSERT OR IGNORE INTO assertion_edge_integrity_repairs "
                        "(finding_id,brain_id,principal_id,scope_fingerprint,repaired_at,"
                        "schema_version) VALUES (:finding,:brain,:principal,:scope,:at,1)"
                    ),
                    values,
                )
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT brain_id,principal_id,scope_fingerprint,repaired_at "
                                "FROM assertion_edge_integrity_repairs WHERE finding_id=:finding"
                            ),
                            {"finding": finding.id},
                        )
                    )
                    .mappings()
                    .one()
                )
                _require_no_conflict(
                    str(row["brain_id"]) != values["brain"]
                    or str(row["principal_id"]) != values["principal"]
                    or _bytes(row["scope_fingerprint"]) != values["scope"]
                    or int(str(row["repaired_at"])) != values["at"]
                )
        except GraphConflictError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


class SqliteMaterializedEdgeIntegrityScopeSource:
    """Resolve bounded owner/admin/editor scopes for periodic graph integrity scans."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical authorization and active-generation store."""
        self._store = store

    async def integrity_scopes(
        self,
        at: datetime,
        limit: int,
    ) -> tuple[tuple[AuthorizedScope, str], ...]:
        """Build at most limit deterministic current Brain scopes."""
        if not 1 <= limit <= _MAX_INTEGRITY_SCOPES:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(_INTEGRITY_SCOPES),
                            {"at": _micros(at), "limit": limit},
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error
        by_brain: dict[str, list[RowMapping]] = defaultdict(list)
        for row in rows:
            by_brain[str(row["brain_id"])].append(row)
        return tuple(_integrity_scope(brain_rows) for _, brain_rows in sorted(by_brain.items()))


_AUTHORIZE_JOB = """
SELECT g.id,g.role,g.version,b.version AS policy_version,i.security_epoch
FROM assertion_edge_projection_jobs AS j
JOIN principals AS p ON p.id=j.principal_id AND p.status='active'
JOIN brains AS b ON b.id=j.brain_id AND b.status='active'
JOIN installation_state AS i ON i.singleton_key='local'
JOIN projects AS project ON project.id=j.project_id AND project.brain_id=j.brain_id
  AND project.status='active'
JOIN project_repositories AS pr ON pr.project_id=project.id
  AND pr.repository_id=j.repository_id
JOIN repositories AS repository ON repository.id=pr.repository_id
  AND repository.brain_id=j.brain_id AND repository.status='active'
LEFT JOIN checkouts AS checkout ON checkout.id=j.checkout_id
  AND checkout.repository_id=j.repository_id AND checkout.brain_id=j.brain_id
JOIN scope_grants AS g ON g.principal_id=j.principal_id AND g.brain_id=j.brain_id
WHERE j.source_event_id=:event AND j.assertion_id=:assertion AND j.brain_id=:brain
  AND j.principal_id=:principal AND j.project_id=:project AND j.repository_id=:repository
  AND ((j.checkout_id IS NULL AND :checkout IS NULL) OR j.checkout_id=:checkout)
  AND j.classification=:classification AND j.aggregate_version=:version
  AND j.event_digest=:digest AND j.state='leased' AND j.lease_owner=:lease_owner
  AND j.lease_until=:lease_until AND j.lease_until>:at AND j.attempts=:attempts
  AND (j.checkout_id IS NULL OR checkout.status='active')
  AND g.role IN ('owner','admin','editor','reader')
  AND g.valid_from<=:at AND (g.valid_to IS NULL OR g.valid_to>:at)
  AND (g.project_id IS NULL OR g.project_id=j.project_id)
  AND (g.repository_id IS NULL OR g.repository_id=j.repository_id)
ORDER BY g.id
"""

_INTEGRITY_SCOPES = """
WITH active_brains AS (
  SELECT brain_id,generation_id FROM active_projection_generations
  WHERE projection_type='graph' ORDER BY brain_id LIMIT :limit
)
SELECT active.brain_id,active.generation_id,g.id AS grant_id,g.principal_id,g.role,g.version,
       brain.version AS policy_version,installation.security_epoch,
       project.id AS project_id,pr.repository_id,checkout.id AS checkout_id
FROM active_brains AS active
JOIN brains AS brain ON brain.id=active.brain_id AND brain.status='active'
JOIN installation_state AS installation ON installation.singleton_key='local'
JOIN scope_grants AS g ON g.brain_id=active.brain_id
JOIN principals AS principal ON principal.id=g.principal_id AND principal.status='active'
JOIN projects AS project ON project.brain_id=active.brain_id AND project.status='active'
JOIN project_repositories AS pr ON pr.project_id=project.id
JOIN repositories AS repository ON repository.id=pr.repository_id
  AND repository.brain_id=active.brain_id AND repository.status='active'
LEFT JOIN checkouts AS checkout ON checkout.repository_id=repository.id
  AND checkout.brain_id=active.brain_id AND checkout.status='active'
WHERE g.role IN ('owner','admin','editor')
  AND g.valid_from<=:at AND (g.valid_to IS NULL OR g.valid_to>:at)
  AND (g.project_id IS NULL OR g.project_id=project.id)
  AND (g.repository_id IS NULL OR g.repository_id=repository.id)
ORDER BY active.brain_id,
  CASE g.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
  g.principal_id,g.id,project.id,repository.id,checkout.id
"""


async def _insert_or_verify_finding(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    finding: EdgeIntegrityFinding,
) -> None:
    values = {
        "finding": finding.id,
        "brain": scope.brain_id.value,
        "principal": scope.principal_id.value,
        "scope": bytes.fromhex(scope.scope_fingerprint),
        "generation": bytes.fromhex(finding.generation_id),
        "assertion": finding.assertion_id,
        "kind": finding.kind.value,
        "expected": _optional_digest(finding.expected_digest),
        "actual": _optional_digest(finding.actual_digest),
        "at": _micros(finding.detected_at),
    }
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO assertion_edge_integrity_findings "
            "(finding_id,brain_id,principal_id,scope_fingerprint,generation_id,assertion_id,"
            "kind,expected_digest,actual_digest,detected_at,schema_version) VALUES "
            "(:finding,:brain,:principal,:scope,:generation,:assertion,:kind,:expected,:actual,"
            ":at,1)"
        ),
        values,
    )
    row = (
        (
            await connection.execute(
                text(
                    "SELECT brain_id,principal_id,scope_fingerprint,generation_id,assertion_id,"
                    "kind,expected_digest,actual_digest,detected_at FROM "
                    "assertion_edge_integrity_findings WHERE finding_id=:finding"
                ),
                {"finding": finding.id},
            )
        )
        .mappings()
        .one()
    )
    actual = (
        str(row["brain_id"]),
        str(row["principal_id"]),
        _bytes(row["scope_fingerprint"]),
        _bytes(row["generation_id"]),
        str(row["assertion_id"]),
        str(row["kind"]),
        _optional_bytes(row["expected_digest"]),
        _optional_bytes(row["actual_digest"]),
        int(str(row["detected_at"])),
    )
    expected = tuple(
        values[key]
        for key in (
            "brain",
            "principal",
            "scope",
            "generation",
            "assertion",
            "kind",
            "expected",
            "actual",
            "at",
        )
    )
    if actual != expected:
        raise GraphConflictError(_ERR_CONFLICT)


async def _receipt(connection: AsyncConnection, event_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT assertion_id,brain_id,generation_id,projection_digest,"
                    "projection_status,aggregate_version,completed_at FROM "
                    "assertion_edge_projection_receipts WHERE source_event_id=:event"
                ),
                {"event": event_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _receipt_tuple(row: RowMapping) -> tuple[object, ...]:
    return (
        str(row["assertion_id"]),
        str(row["brain_id"]),
        _bytes(row["generation_id"]).hex(),
        _bytes(row["projection_digest"]).hex(),
        str(row["projection_status"]),
        int(str(row["aggregate_version"])),
        int(str(row["completed_at"])),
    )


def _decode_job(row: Mapping[str, object]) -> MaterializedEdgeProjectionJob:
    return MaterializedEdgeProjectionJob(
        source_event_id=str(row["source_event_id"]),
        assertion_id=str(row["assertion_id"]),
        brain_id=str(row["brain_id"]),
        principal_id=str(row["principal_id"]),
        project_id=str(row["project_id"]),
        repository_id=str(row["repository_id"]),
        checkout_id=None if row["checkout_id"] is None else str(row["checkout_id"]),
        classification=GraphClassification(str(row["classification"])),
        aggregate_version=int(str(row["aggregate_version"])),
        event_digest=_bytes(row["event_digest"]).hex(),
        occurred_at=_time(row["created_at"]),
        attempts=int(str(row["attempts"])),
        lease_owner=str(row["lease_owner"]),
        lease_until=_time(row["lease_until"]),
    )


def _valid_lifecycle_event(row: RowMapping) -> bool:
    event_type = str(row["event_type"])
    version = int(str(row["aggregate_version"]))
    return (version, event_type) in {
        (1, AssertionEventType.ACTIVATED.value),
        (2, AssertionEventType.DISPUTED.value),
    }


def _grant_version(rows: Iterable[tuple[str, int]]) -> int:
    identities = sorted(set(rows))
    payload = ":".join(f"{identity}:{version}" for identity, version in identities)
    return int.from_bytes(hashlib.sha256(payload.encode()).digest()[:8], "big") or 1


def _integrity_scope(rows: Sequence[RowMapping]) -> tuple[AuthorizedScope, str]:
    if not rows:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    principal_id = str(rows[0]["principal_id"])
    brain_id = str(rows[0]["brain_id"])
    generation = _bytes(rows[0]["generation_id"])
    policy_version = int(str(rows[0]["policy_version"]))
    security_epoch = int(str(rows[0]["security_epoch"]))
    if any(
        str(row["brain_id"]) != brain_id
        or _bytes(row["generation_id"]) != generation
        or int(str(row["policy_version"])) != policy_version
        or int(str(row["security_epoch"])) != security_epoch
        for row in rows
    ):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    selected = tuple(row for row in rows if str(row["principal_id"]) == principal_id)
    repositories: dict[str, set[str]] = defaultdict(set)
    checkouts: dict[str, set[str]] = defaultdict(set)
    for row in selected:
        project_id = str(row["project_id"])
        repositories[project_id].add(str(row["repository_id"]))
        if row["checkout_id"] is not None:
            checkouts[project_id].add(str(row["checkout_id"]))
    members = tuple(
        ScopeMember(
            StableId(project_id),
            tuple(StableId(value) for value in sorted(repositories[project_id])),
            tuple(StableId(value) for value in sorted(checkouts[project_id])),
        )
        for project_id in sorted(repositories)
    )
    roles = tuple(RetrievalRole(str(row["role"])) for row in selected)
    normalized_grants = tuple((str(row["grant_id"]), int(str(row["version"]))) for row in selected)
    scope = AuthorizedScope.create(
        brain_id=StableId(brain_id),
        principal_id=StableId(principal_id),
        role=min(roles, key=_role_order),
        mode=RetrievalScopeMode.SELECTED,
        members=members,
        classification_ceiling=Classification.LOCAL_ONLY,
        temporal_scope=TemporalScope(None, None),
        grant_version=_grant_version(normalized_grants),
        policy_version=policy_version,
        security_epoch=security_epoch,
        action="graph.assertion.edge.integrity",
        purpose="assertion_edge_integrity",
    )
    generation_id = generation.hex()
    _require_digest(generation_id, _ERR_GENERATION)
    return scope, generation_id


def _role_order(role: RetrievalRole) -> int:
    return {
        RetrievalRole.OWNER: 0,
        RetrievalRole.ADMIN: 1,
        RetrievalRole.EDITOR: 2,
        RetrievalRole.READER: 3,
        RetrievalRole.AUDITOR: 4,
        RetrievalRole.ADAPTER: 5,
        RetrievalRole.WORKER: 6,
    }[role]


def _require_action(scope: AuthorizedScope, allowed: set[str]) -> None:
    if scope.action not in allowed:
        raise GraphAuthorizationError(_ERR_ACTION)


def _is_failure_code(value: object) -> bool:
    return isinstance(value, ProjectionJobFailureCode)


def _require_digest(value: object, message: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != _DIGEST_HEX_LENGTH
        or set(value) == {"0"}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise GraphIntegrityError(message)


def _optional_digest(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


def _optional_bytes(value: object) -> bytes | None:
    return None if value is None else _bytes(value)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTE_LENGTH:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return value


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return round(value.timestamp() * 1_000_000)


def _time(value: object) -> datetime:
    if isinstance(value, bool):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return datetime.fromtimestamp(int(str(value)) / 1_000_000, tz=UTC)


def _require_authorized(condition: bool) -> None:  # noqa: FBT001
    if not condition:
        raise GraphAuthorizationError(_ERR_AUTHORIZATION)


def _require_no_conflict(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise GraphConflictError(_ERR_CONFLICT)


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
