"""GRA-002 scoped SQLite evidence and assertion repositories."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.domain.assertions import (
    Assertion,
    AssertionCandidate,
    AssertionConfidence,
    AssertionEventType,
    AssertionEvidenceReference,
    AssertionEvidenceRevocation,
    AssertionExtractor,
    AssertionLifecycleEvent,
    AssertionPolarity,
    AssertionPredicate,
    AssertionScope,
    AssertionStatus,
    AssertionTemporal,
    EvidenceKind,
    ResolvedAssertionEvidence,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Mapping
    from uuid import UUID

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.graph.domain.assertion_ports import (
        AssertionEvidenceCatalog,
        AssertionEvidenceRepository,
        AssertionRepository,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_PROMPT_EVENT = "agentmemory.prompt.received.v1"
_ERR_ACTION = "assertion repository action is not authorized"
_ERR_SCOPE = "assertion repository scope is not authorized"
_ERR_CONFLICT = "assertion operation conflicted with canonical state"
_ERR_INTEGRITY = "canonical assertion state failed integrity verification"
_ERR_EVIDENCE = "canonical assertion evidence failed integrity verification"
_ERR_SOURCE = "assertion evidence source was not found or authorized"
_ERR_STORAGE = "canonical assertion storage is unavailable"
_DIGEST_BYTES = 32
_DISPUTED_VERSION = 2
_MAX_PROJECTION_ASSERTIONS = 10_000

_AUTHORIZED_SCOPE = """
EXISTS (
  SELECT 1 FROM scope_grants AS active_grant
  JOIN principals AS principal ON principal.id=active_grant.principal_id
  JOIN brains AS brain ON brain.id=active_grant.brain_id
  WHERE active_grant.principal_id=:principal_id
    AND active_grant.brain_id=:brain_id
    AND active_grant.role IN ('owner','admin','editor','reader')
    AND active_grant.valid_from<=:now
    AND (active_grant.valid_to IS NULL OR active_grant.valid_to>:now)
    AND (active_grant.project_id IS NULL OR active_grant.project_id={project})
    AND (active_grant.repository_id IS NULL OR active_grant.repository_id={repository})
    AND principal.status='active' AND brain.status='active'
) AND EXISTS (
  SELECT 1 FROM json_each(:members) AS member
  WHERE json_extract(member.value, '$.project_id')={project}
    AND {repository} IN (
      SELECT value FROM json_each(json_extract(member.value, '$.repository_ids'))
    )
    AND (
      json_array_length(json_extract(member.value, '$.checkout_ids'))=0
      OR {checkout} IN (
        SELECT value FROM json_each(json_extract(member.value, '$.checkout_ids'))
      )
    )
)
"""


class SqliteAssertionRepository:
    """Persist and load assertions through one immutable AuthorizedScope."""

    def __init__(self, store: SqliteCoreStore, scope: AuthorizedScope) -> None:
        """Bind the shared store and immutable operation scope."""
        self._store = store
        self._scope = scope

    async def propose(self, operation_id: str, candidate: AssertionCandidate) -> AssertionCandidate:
        """Append an exact idempotent candidate without granting authority."""
        self._require_action("graph.assertion.propose")
        self._require_scope(candidate.scope)
        digest = _request_digest("propose", candidate.id, candidate.revision_id)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_current_authority(
                    connection, self._scope, candidate.scope, candidate.temporal.recorded_from
                )
                existing = await _operation(connection, operation_id)
                if existing is not None:
                    _verify_operation(
                        existing,
                        self._scope,
                        "propose",
                        candidate.id,
                        digest,
                        None,
                        AssertionStatus.CANDIDATE,
                        0,
                    )
                    stored = await _candidate(connection, self._scope, candidate.id)
                    _require_no_conflict(stored != candidate)
                    return _present(stored)
                stored = await _candidate(connection, self._scope, candidate.id)
                _require_no_conflict(stored is not None and stored != candidate)
                await _insert_operation(
                    connection,
                    self._scope,
                    operation_id,
                    "propose",
                    candidate.id,
                    digest,
                    None,
                    AssertionStatus.CANDIDATE,
                    0,
                    candidate.temporal.recorded_from,
                )
                if stored is None:
                    await _insert_candidate(connection, operation_id, candidate)
                return candidate
        except GraphConflictError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def get_candidate(self, candidate_id: str) -> AssertionCandidate | None:
        """Return a currently authorized exact candidate without cross-scope disclosure."""
        self._require_action_any({"graph.assertion.activate", "graph.assertion.propose"})
        try:
            async with self._store.engine.connect() as connection:
                return await _candidate(connection, self._scope, candidate_id)
        except GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def get_assertion(self, assertion_id: str) -> Assertion | None:
        """Return the latest authorized lifecycle revision and its activation evidence."""
        self._require_action_any({"graph.assertion.activate", "graph.assertion.reconcile"})
        try:
            async with self._store.engine.connect() as connection:
                return await _assertion(connection, self._scope, assertion_id)
        except GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def activate(
        self,
        operation_id: str,
        assertion: Assertion,
        event: AssertionLifecycleEvent,
    ) -> Assertion:
        """Atomically append activation, evidence snapshots, and projection event."""
        self._require_action("graph.assertion.activate")
        self._require_scope(assertion.scope)
        if assertion.status is not AssertionStatus.ACTIVE:
            raise GraphConflictError(_ERR_CONFLICT)
        digest = _request_digest("activate", assertion.revision_id, event.digest)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_current_authority(
                    connection, self._scope, assertion.scope, event.occurred_at
                )
                existing = await _operation(connection, operation_id)
                if existing is not None:
                    _verify_operation(
                        existing,
                        self._scope,
                        "activate",
                        assertion.id,
                        digest,
                        event.event_id,
                        AssertionStatus.ACTIVE,
                        1,
                    )
                    stored = await _assertion(connection, self._scope, assertion.id)
                    _require_no_conflict(stored != assertion)
                    return _present(stored)
                candidate = await _candidate(connection, self._scope, assertion.id)
                _require_no_conflict(
                    candidate is None or candidate.revision_id != assertion.revision_id
                )
                _require_no_conflict(
                    await _assertion(connection, self._scope, assertion.id) is not None
                )
                if candidate is None:
                    raise GraphIntegrityError(_ERR_INTEGRITY)
                resolved = await _resolve_evidence(
                    connection, self._scope, candidate.evidence_ids, event.occurred_at
                )
                _require_no_conflict(resolved != assertion.evidence)
                await _insert_operation(
                    connection,
                    self._scope,
                    operation_id,
                    "activate",
                    assertion.id,
                    digest,
                    event.event_id,
                    AssertionStatus.ACTIVE,
                    1,
                    event.occurred_at,
                )
                await _insert_domain_event(connection, assertion, event, 1)
                await _insert_lifecycle(connection, operation_id, assertion, event, 1)
                await _insert_evidence_snapshots(connection, assertion)
                return assertion
        except GraphConflictError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def dispute(
        self,
        operation_id: str,
        assertion: Assertion,
        event: AssertionLifecycleEvent,
    ) -> Assertion:
        """Atomically append a dispute only when every activation source is unusable."""
        self._require_action("graph.assertion.reconcile")
        self._require_scope(assertion.scope)
        if assertion.status is not AssertionStatus.DISPUTED:
            raise GraphConflictError(_ERR_CONFLICT)
        digest = _request_digest("dispute", assertion.revision_id, event.digest)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_current_authority(
                    connection, self._scope, assertion.scope, event.occurred_at
                )
                existing = await _operation(connection, operation_id)
                if existing is not None:
                    _verify_operation(
                        existing,
                        self._scope,
                        "dispute",
                        assertion.id,
                        digest,
                        event.event_id,
                        AssertionStatus.DISPUTED,
                        2,
                    )
                    stored = await _assertion(connection, self._scope, assertion.id)
                    _require_no_conflict(stored != assertion)
                    return _present(stored)
                current = await _assertion(connection, self._scope, assertion.id)
                _require_no_conflict(
                    current is None or current.status is not AssertionStatus.ACTIVE
                )
                if current is None:
                    raise GraphIntegrityError(_ERR_INTEGRITY)
                resolved = await _resolve_evidence(
                    connection,
                    self._scope,
                    tuple(item.evidence_id for item in current.evidence),
                    event.occurred_at,
                )
                _require_no_conflict(
                    any(item.usable and item.scope == current.scope for item in resolved)
                )
                expected = current.reconcile_evidence(resolved, event.occurred_at)
                _require_no_conflict(expected != assertion)
                await _insert_operation(
                    connection,
                    self._scope,
                    operation_id,
                    "dispute",
                    assertion.id,
                    digest,
                    event.event_id,
                    AssertionStatus.DISPUTED,
                    2,
                    event.occurred_at,
                )
                await _insert_domain_event(connection, assertion, event, 2)
                await _insert_lifecycle(connection, operation_id, assertion, event, 2)
                return assertion
        except GraphConflictError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    def _require_action(self, expected: str) -> None:
        if self._scope.action != expected:
            raise GraphAuthorizationError(_ERR_ACTION)

    def _require_action_any(self, expected: set[str]) -> None:
        if self._scope.action not in expected:
            raise GraphAuthorizationError(_ERR_ACTION)

    def _require_scope(self, coordinates: AssertionScope) -> None:
        if not _scope_contains(self._scope, coordinates):
            raise GraphAuthorizationError(_ERR_SCOPE)


class SqliteAssertionEvidenceRepository:
    """Resolve typed immutable evidence under current SQL authorization."""

    def __init__(self, store: SqliteCoreStore, scope: AuthorizedScope) -> None:
        """Bind the shared store and immutable operation scope."""
        self._store = store
        self._scope = scope

    async def resolve(
        self,
        evidence_ids: tuple[str, ...],
        resolved_at: datetime,
    ) -> tuple[ResolvedAssertionEvidence, ...]:
        """Resolve stable handles and independently verify their canonical sources."""
        if self._scope.action not in {
            "graph.assertion.activate",
            "graph.assertion.reconcile",
        }:
            raise GraphAuthorizationError(_ERR_ACTION)
        try:
            async with self._store.engine.connect() as connection:
                return await _resolve_evidence(connection, self._scope, evidence_ids, resolved_at)
        except GraphIntegrityError:
            raise
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


class SqliteAssertionEvidenceCatalog:
    """Register canonical source handles and append evidence revocations."""

    def __init__(
        self,
        store: SqliteCoreStore,
        scope: AuthorizedScope,
        event_id_factory: Callable[[], UUID],
    ) -> None:
        """Bind the shared store and immutable operation scope."""
        self._store = store
        self._scope = scope
        self._event_id_factory = event_id_factory

    async def register(
        self,
        reference: AssertionEvidenceReference,
        registered_at: datetime,
    ) -> ResolvedAssertionEvidence:
        """Derive evidence metadata from a captured event and optional CAS artifact."""
        if self._scope.action != "graph.assertion.evidence.register":
            raise GraphAuthorizationError(_ERR_ACTION)
        try:
            async with _write_transaction(self._store) as connection:
                source = await _canonical_source(connection, self._scope, reference, registered_at)
                existing = await _evidence_source(
                    connection, self._scope, reference.evidence_id, registered_at
                )
                if existing is not None:
                    _require_no_conflict(existing != source)
                    return existing
                await connection.execute(
                    text(
                        "INSERT INTO assertion_evidence_sources "
                        "(evidence_id,brain_id,project_id,repository_id,checkout_id,"
                        "classification,kind,event_id,artifact_id,span_start,span_end,"
                        "source_digest,occurred_at,registered_at,schema_version) VALUES "
                        "(:evidence,:brain,:project,:repository,:checkout,:classification,"
                        ":kind,:event,:artifact,:span_start,:span_end,:digest,:occurred,:now,1)"
                    ),
                    {
                        "evidence": source.evidence_id,
                        "brain": source.scope.brain_id,
                        "project": source.scope.project_id,
                        "repository": source.scope.repository_id,
                        "checkout": source.scope.checkout_id,
                        "classification": source.scope.classification,
                        "kind": source.kind.value,
                        "event": reference.event_id,
                        "artifact": reference.artifact_id,
                        "span_start": reference.span_start,
                        "span_end": reference.span_end,
                        "digest": bytes.fromhex(source.source_digest),
                        "occurred": _micros(source.occurred_at),
                        "now": _micros(registered_at),
                    },
                )
                await _anchor_evidence_revision(connection, source, registered_at)
                return source
        except GraphConflictError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error

    async def revoke(self, revocation: AssertionEvidenceRevocation) -> tuple[Assertion, ...]:
        """Atomically revoke one source and dispute every assertion left unsupported."""
        if self._scope.action != "graph.assertion.evidence.revoke":
            raise GraphAuthorizationError(_ERR_ACTION)
        request_digest = _request_digest(
            "revoke",
            revocation.evidence_id,
            revocation.reason.value,
            str(_micros(revocation.revoked_at)),
        )
        try:
            async with _write_transaction(self._store) as connection:
                source = await _evidence_source(
                    connection,
                    self._scope,
                    revocation.evidence_id,
                    revocation.revoked_at,
                )
                _require_authorized(source is not None, _ERR_SOURCE)
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT evidence_id,operation_id,principal_id,scope_fingerprint,"
                                "request_digest,reason,revoked_at FROM "
                                "assertion_evidence_revocations WHERE evidence_id=:evidence "
                                "OR operation_id=:operation"
                            ),
                            {
                                "evidence": revocation.evidence_id,
                                "operation": revocation.operation_id,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    _require_no_conflict(
                        str(row["evidence_id"]) != revocation.evidence_id
                        or str(row["operation_id"]) != revocation.operation_id
                        or str(row["principal_id"]) != self._scope.principal_id.value
                        or _bytes(row["scope_fingerprint"]).hex() != self._scope.scope_fingerprint
                        or _bytes(row["request_digest"]) != request_digest
                        or str(row["reason"]) != revocation.reason.value
                        or int(str(row["revoked_at"])) != _micros(revocation.revoked_at)
                    )
                    return await _revocation_disputes(
                        connection,
                        self._scope,
                        revocation.evidence_id,
                    )
                await connection.execute(
                    text(
                        "INSERT INTO assertion_evidence_revocations "
                        "(evidence_id,operation_id,principal_id,scope_fingerprint,request_digest,"
                        "reason,revoked_at,schema_version) VALUES "
                        "(:evidence,:operation,:principal,:scope,:request,:reason,:at,1)"
                    ),
                    {
                        "evidence": revocation.evidence_id,
                        "operation": revocation.operation_id,
                        "principal": self._scope.principal_id.value,
                        "scope": bytes.fromhex(self._scope.scope_fingerprint),
                        "request": request_digest,
                        "reason": revocation.reason.value,
                        "at": _micros(revocation.revoked_at),
                    },
                )
                return await _cascade_evidence_revocation(
                    connection,
                    self._scope,
                    revocation,
                    self._event_id_factory,
                )
        except GraphAuthorizationError, GraphConflictError:
            raise
        except IntegrityError as error:
            raise GraphConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error


class SqliteAssertionRepositoryFactory:
    """Create scope-bound GRA-002 adapters over the shared local store."""

    def __init__(
        self,
        store: SqliteCoreStore,
        event_id_factory: Callable[[], UUID] = uuid7,
    ) -> None:
        """Bind the process-wide canonical SQLite store."""
        self._store = store
        self._event_id_factory = event_id_factory

    def assertions(self, scope: AuthorizedScope) -> AssertionRepository:
        """Create one scope-bound canonical assertion repository."""
        return cast("AssertionRepository", SqliteAssertionRepository(self._store, scope))

    def evidence(self, scope: AuthorizedScope) -> AssertionEvidenceRepository:
        """Create one scope-bound evidence resolver."""
        return cast(
            "AssertionEvidenceRepository",
            SqliteAssertionEvidenceRepository(self._store, scope),
        )

    def evidence_catalog(self, scope: AuthorizedScope) -> AssertionEvidenceCatalog:
        """Create one scope-bound trusted evidence catalog."""
        return cast(
            "AssertionEvidenceCatalog",
            SqliteAssertionEvidenceCatalog(
                self._store,
                scope,
                self._event_id_factory,
            ),
        )


async def load_assertion_projection_snapshot(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    assertion_id: str,
) -> tuple[Assertion, str, datetime] | None:
    """Load one current assertion and its exact latest lifecycle event in one SQL snapshot."""
    assertion = await _assertion(connection, scope, assertion_id)
    if assertion is None:
        return None
    row = (
        (
            await connection.execute(
                text(
                    "SELECT l.event_id,l.event_digest,l.aggregate_version,l.status,"
                    "d.source_digest,d.event_type,d.occurred_at FROM assertion_lifecycle AS l "
                    "JOIN domain_events AS d ON d.event_id=l.event_id "
                    "WHERE l.assertion_id=:assertion AND d.brain_id=:brain "
                    "AND d.aggregate_type='assertion' AND d.aggregate_id=:assertion "
                    "ORDER BY l.aggregate_version DESC LIMIT 1"
                ),
                {"assertion": assertion_id, "brain": scope.brain_id.value},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    version = int(str(row["aggregate_version"]))
    expected_event = AssertionEventType.ACTIVATED if version == 1 else AssertionEventType.DISPUTED
    if (
        version not in {1, _DISPUTED_VERSION}
        or str(row["status"]) != assertion.status.value
        or str(row["event_type"]) != expected_event.value
        or _bytes(row["event_digest"]) != _bytes(row["source_digest"])
    ):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return assertion, str(row["event_id"]), _time(row["occurred_at"])


async def list_assertion_projection_snapshots(
    connection: AsyncConnection,
    scope: AuthorizedScope,
) -> tuple[tuple[Assertion, str, datetime], ...]:
    """Load a bounded deterministic current assertion set for one integrity scope."""
    parameters = {
        **_scope_parameters(scope, _now_micros()),
        "limit": _MAX_PROJECTION_ASSERTIONS + 1,
    }
    rows = (
        await connection.execute(
            text(
                "SELECT c.assertion_id FROM assertion_candidates AS c "  # noqa: S608  # nosec B608
                "WHERE c.brain_id=:brain_id AND c.classification IN "
                "(SELECT value FROM json_each(:classifications)) AND "
                + _authorized_scope_sql("c")
                + " ORDER BY c.assertion_id LIMIT :limit"
            ),
            parameters,
        )
    ).all()
    if len(rows) > _MAX_PROJECTION_ASSERTIONS:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    snapshots: list[tuple[Assertion, str, datetime]] = []
    for row in rows:
        snapshot = await load_assertion_projection_snapshot(connection, scope, str(row[0]))
        if snapshot is None:
            raise GraphIntegrityError(_ERR_INTEGRITY)
        snapshots.append(snapshot)
    return tuple(snapshots)


async def list_authorized_assertion_ids_for_truth(  # noqa: PLR0913 -- Query coordinates.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    *,
    assertion_id: str | None,
    subject_id: str | None,
    predicates: tuple[AssertionPredicate, ...],
    valid_at: datetime,
    limit: int,
) -> tuple[str, ...]:
    """List bounded valid-time candidates under current authorization."""
    parameters = {
        **_scope_parameters(scope, _now_micros()),
        "assertion": assertion_id,
        "subject": subject_id,
        "predicates": json.dumps([item.value for item in predicates], separators=(",", ":")),
        "has_predicates": int(bool(predicates)),
        "valid_at": _micros(valid_at),
        "limit": limit + 1,
    }
    rows = (
        await connection.execute(
            text(
                "SELECT c.assertion_id FROM assertion_candidates AS c "  # noqa: S608  # nosec B608
                "WHERE c.brain_id=:brain_id AND c.classification IN "
                "(SELECT value FROM json_each(:classifications)) AND "
                + _authorized_scope_sql("c")
                + " AND (:assertion IS NULL OR c.assertion_id=:assertion) "
                "AND (:subject IS NULL OR c.subject_id=:subject) "
                "AND (:has_predicates=0 OR c.predicate IN "
                "(SELECT value FROM json_each(:predicates))) "
                "AND c.valid_from<=:valid_at AND (c.valid_to IS NULL OR c.valid_to>:valid_at) "
                "ORDER BY c.assertion_id LIMIT :limit"
            ),
            parameters,
        )
    ).all()
    if len(rows) > limit:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return tuple(str(row[0]) for row in rows)


async def load_assertion_revision_snapshot(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    assertion_id: str,
    recorded_at: datetime,
) -> tuple[Assertion, str, bool] | None:
    """Reconstruct the canonical assertion lifecycle known at recorded_at."""
    candidate = await _candidate(connection, scope, assertion_id)
    if candidate is None:
        return None
    row = (
        (
            await connection.execute(
                text(
                    "SELECT l.aggregate_version,l.status,l.recorded_from,l.recorded_to,"
                    "l.event_id,l.event_digest,l.created_at,d.source_digest,d.event_type "
                    "FROM assertion_lifecycle AS l JOIN domain_events AS d "
                    "ON d.event_id=l.event_id "
                    "WHERE l.assertion_id=:id AND l.created_at<=:recorded "
                    "ORDER BY l.aggregate_version DESC LIMIT 1"
                ),
                {"id": assertion_id, "recorded": _micros(recorded_at)},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    evidence_rows = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM assertion_evidence_snapshots WHERE assertion_id=:id "
                    "ORDER BY evidence_id"
                ),
                {"id": assertion_id},
            )
        )
        .mappings()
        .all()
    )
    latest = (
        (
            await connection.execute(
                text(
                    "SELECT aggregate_version,status FROM assertion_lifecycle "
                    "WHERE assertion_id=:id ORDER BY aggregate_version DESC LIMIT 1"
                ),
                {"id": assertion_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if latest is None:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    version = int(str(row["aggregate_version"]))
    status = AssertionStatus(str(row["status"]))
    expected_event = AssertionEventType.ACTIVATED if version == 1 else AssertionEventType.DISPUTED
    if (
        version not in {1, _DISPUTED_VERSION}
        or str(row["event_type"]) != expected_event.value
        or _bytes(row["event_digest"]) != _bytes(row["source_digest"])
    ):
        raise GraphIntegrityError(_ERR_INTEGRITY)
    evidence = tuple(_decode_snapshot(item) for item in evidence_rows)
    try:
        active = candidate.activate(evidence, _time(row["recorded_from"]))
        current = (
            int(str(latest["aggregate_version"])) == 1
            and AssertionStatus(str(latest["status"])) is AssertionStatus.ACTIVE
        )
        if version == 1 and status is AssertionStatus.ACTIVE:
            next_recorded = await connection.scalar(
                text(
                    "SELECT MIN(created_at) FROM assertion_lifecycle "
                    "WHERE assertion_id=:id AND aggregate_version>:version"
                ),
                {"id": assertion_id, "version": version},
            )
            if next_recorded is not None:
                active = replace(
                    active,
                    temporal=AssertionTemporal(
                        active.temporal.valid_from,
                        active.temporal.valid_to,
                        active.temporal.recorded_from,
                        _time(next_recorded),
                    ),
                )
            return active, str(row["event_id"]), current
        if version == _DISPUTED_VERSION and status is AssertionStatus.DISPUTED:
            if row["recorded_to"] is None:
                raise GraphIntegrityError(_ERR_INTEGRITY)
            disputed = active.reconcile_evidence((), _time(row["recorded_to"]))
            return disputed, str(row["event_id"]), False
    except (TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error
    raise GraphIntegrityError(_ERR_INTEGRITY)


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


async def _candidate(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    candidate_id: str,
) -> AssertionCandidate | None:
    parameters = {**_scope_parameters(scope, _now_micros()), "id": candidate_id}
    row = (
        (
            await connection.execute(
                text(
                    "SELECT c.* FROM assertion_candidates AS c WHERE c.assertion_id=:id "  # noqa: S608  # nosec B608
                    "AND c.brain_id=:brain_id AND c.classification IN "
                    "(SELECT value FROM json_each(:classifications)) AND "
                    + _authorized_scope_sql("c")
                    + " LIMIT 1"
                ),
                parameters,
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _decode_candidate(row)


async def _assertion(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    assertion_id: str,
) -> Assertion | None:
    candidate = await _candidate(connection, scope, assertion_id)
    if candidate is None:
        return None
    row = (
        (
            await connection.execute(
                text(
                    "SELECT aggregate_version,status,recorded_from,recorded_to FROM "
                    "assertion_lifecycle WHERE assertion_id=:id "
                    "ORDER BY aggregate_version DESC LIMIT 1"
                ),
                {"id": assertion_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    evidence_rows = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM assertion_evidence_snapshots WHERE assertion_id=:id "
                    "ORDER BY evidence_id"
                ),
                {"id": assertion_id},
            )
        )
        .mappings()
        .all()
    )
    evidence = tuple(_decode_snapshot(item) for item in evidence_rows)
    try:
        active = candidate.activate(evidence, _time(row["recorded_from"]))
        status = AssertionStatus(str(row["status"]))
        if int(str(row["aggregate_version"])) == 1 and status is AssertionStatus.ACTIVE:
            return active
        if (
            int(str(row["aggregate_version"])) == _DISPUTED_VERSION
            and status is AssertionStatus.DISPUTED
        ):
            recorded_to = row["recorded_to"]
            if recorded_to is None:
                raise GraphIntegrityError(_ERR_INTEGRITY)
            return active.reconcile_evidence((), _time(recorded_to))
    except (ValueError, TypeError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error
    raise GraphIntegrityError(_ERR_INTEGRITY)


async def _resolve_evidence(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    evidence_ids: tuple[str, ...],
    resolved_at: datetime,
) -> tuple[ResolvedAssertionEvidence, ...]:
    if not evidence_ids:
        return ()
    parameters = {
        **_scope_parameters(scope, _micros(resolved_at)),
        "ids": json.dumps(sorted(set(evidence_ids)), separators=(",", ":")),
        "resolved_at": _micros(resolved_at),
    }
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT s.*,e.type AS event_type,e.payload_ref,x.canonical_sha256,"  # noqa: S608  # nosec B608
                    "x.principal_id AS source_principal_id,"
                    "a.sha256 AS artifact_sha256,a.byte_length,r.revoked_at "
                    "FROM assertion_evidence_sources AS s "
                    "JOIN agent_events AS e ON e.event_id=s.event_id AND e.brain_id=s.brain_id "
                    "JOIN agent_event_envelopes AS x ON x.event_id=e.event_id "
                    "LEFT JOIN artifacts AS a ON a.id=s.artifact_id AND a.brain_id=s.brain_id "
                    "LEFT JOIN assertion_evidence_revocations AS r ON r.evidence_id=s.evidence_id "
                    "WHERE s.evidence_id IN (SELECT value FROM json_each(:ids)) "
                    "AND s.registered_at<=:resolved_at "
                    "AND s.brain_id=:brain_id AND s.classification IN "
                    "(SELECT value FROM json_each(:classifications)) AND "
                    + _authorized_scope_sql("s")
                    + " ORDER BY s.evidence_id"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    tombstones = await _tombstone_keys(connection, scope.brain_id.value)
    return tuple(
        _decode_source(row, scope.principal_id.value, resolved_at, tombstones) for row in rows
    )


async def _evidence_source(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    evidence_id: str,
    resolved_at: datetime,
) -> ResolvedAssertionEvidence | None:
    resolved = await _resolve_evidence(connection, scope, (evidence_id,), resolved_at)
    return None if not resolved else resolved[0]


async def _cascade_evidence_revocation(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    revocation: AssertionEvidenceRevocation,
    event_id_factory: Callable[[], UUID],
) -> tuple[Assertion, ...]:
    assertion_ids = await _dependent_assertion_ids(
        connection,
        revocation.evidence_id,
    )
    disputed: list[Assertion] = []
    for assertion_id in assertion_ids:
        current = await _assertion(connection, scope, assertion_id)
        if current is None:
            continue
        if current.status is AssertionStatus.DISPUTED:
            disputed.append(current)
            continue
        evidence = await _resolve_evidence(
            connection,
            scope,
            tuple(item.evidence_id for item in current.evidence),
            revocation.revoked_at,
        )
        reconciled = current.reconcile_evidence(evidence, revocation.revoked_at)
        if reconciled.status is AssertionStatus.ACTIVE:
            continue
        operation_id = _cascade_operation_id(revocation.operation_id, current.id)
        _require_no_conflict(await _operation(connection, operation_id) is not None)
        event = AssertionLifecycleEvent.create(
            event_id=str(event_id_factory()),
            operation_id=operation_id,
            assertion=reconciled,
            event_type=AssertionEventType.DISPUTED,
            occurred_at=revocation.revoked_at,
        )
        await _insert_operation(
            connection,
            scope,
            operation_id,
            "dispute",
            reconciled.id,
            _request_digest("dispute", reconciled.revision_id, event.digest),
            event.event_id,
            AssertionStatus.DISPUTED,
            _DISPUTED_VERSION,
            revocation.revoked_at,
        )
        await _insert_domain_event(
            connection,
            reconciled,
            event,
            _DISPUTED_VERSION,
        )
        await _insert_lifecycle(
            connection,
            operation_id,
            reconciled,
            event,
            _DISPUTED_VERSION,
        )
        disputed.append(reconciled)
    return tuple(disputed)


async def _revocation_disputes(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    evidence_id: str,
) -> tuple[Assertion, ...]:
    disputed: list[Assertion] = []
    for assertion_id in await _dependent_assertion_ids(connection, evidence_id):
        assertion = await _assertion(connection, scope, assertion_id)
        if assertion is not None and assertion.status is AssertionStatus.DISPUTED:
            disputed.append(assertion)
    return tuple(disputed)


async def _dependent_assertion_ids(
    connection: AsyncConnection,
    evidence_id: str,
) -> tuple[str, ...]:
    rows = (
        await connection.execute(
            text(
                "SELECT assertion_id FROM assertion_evidence_snapshots "
                "WHERE evidence_id=:evidence ORDER BY assertion_id"
            ),
            {"evidence": evidence_id},
        )
    ).all()
    return tuple(str(row[0]) for row in rows)


async def _canonical_source(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    reference: AssertionEvidenceReference,
    registered_at: datetime,
) -> ResolvedAssertionEvidence:
    parameters = {
        **_scope_parameters(scope, _micros(registered_at)),
        "event": reference.event_id,
    }
    row = (
        (
            await connection.execute(
                text(
                    "SELECT e.event_id,e.type,e.classification,e.occurred_at,e.payload_ref,"  # noqa: S608  # nosec B608
                    "x.principal_id AS source_principal_id,x.project_id,x.repository_id,"
                    "x.checkout_id,x.canonical_sha256,"
                    "a.id AS artifact_id,a.sha256 AS artifact_sha256,a.byte_length "
                    "FROM agent_events e JOIN agent_event_envelopes x ON x.event_id=e.event_id "
                    "LEFT JOIN artifacts a ON a.id=e.payload_ref AND a.brain_id=e.brain_id "
                    "WHERE e.event_id=:event AND e.brain_id=:brain_id "
                    "AND e.classification IN (SELECT value FROM json_each(:classifications)) "
                    "AND " + _authorized_scope_sql("x") + " LIMIT 1"
                ),
                parameters,
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise GraphAuthorizationError(_ERR_SOURCE)
    if reference.kind is EvidenceKind.USER_STATEMENT and (
        str(row["type"]) != _PROMPT_EVENT
        or str(row["source_principal_id"]) != scope.principal_id.value
    ):
        raise GraphConflictError(_ERR_SOURCE)
    if _time(row["occurred_at"]) > registered_at:
        raise GraphConflictError(_ERR_SOURCE)
    source_id = reference.event_id
    digest = _bytes(row["canonical_sha256"])
    if reference.kind in {EvidenceKind.ARTIFACT, EvidenceKind.SOURCE_SPAN}:
        if row["artifact_id"] is None or str(row["artifact_id"]) != reference.artifact_id:
            raise GraphConflictError(_ERR_SOURCE)
        source_id = _present(reference.artifact_id)
        artifact_digest = _bytes(row["artifact_sha256"])
        if reference.kind is EvidenceKind.ARTIFACT:
            digest = artifact_digest
        else:
            if reference.span_end is None or reference.span_end > int(str(row["byte_length"])):
                raise GraphConflictError(_ERR_SOURCE)
            digest = _span_digest(
                artifact_digest,
                cast("int", reference.span_start),
                reference.span_end,
            )
    return ResolvedAssertionEvidence(
        evidence_id=reference.evidence_id,
        source_id=source_id,
        kind=reference.kind,
        scope=AssertionScope(
            scope.brain_id.value,
            str(row["project_id"]),
            str(row["repository_id"]),
            None if row["checkout_id"] is None else str(row["checkout_id"]),
            str(row["classification"]),
        ),
        source_digest=digest.hex(),
        occurred_at=_time(row["occurred_at"]),
        accessible=True,
        deleted=False,
        immutable=True,
    )


async def _anchor_evidence_revision(
    connection: AsyncConnection,
    source: ResolvedAssertionEvidence,
    anchored_at: datetime,
) -> None:
    """Anchor non-user evidence to the last observed immutable Checkout commit."""
    if source.kind is EvidenceKind.USER_STATEMENT or source.scope.checkout_id is None:
        return
    await connection.execute(
        text(
            "INSERT INTO assertion_evidence_revision_anchors "
            "(evidence_id,brain_id,repository_id,checkout_id,commit_sha,branch_at_capture,"
            "revision_observed_at,anchored_at,schema_version) "
            "SELECT :evidence,:brain,:repository,:checkout,o.head_commit,o.branch,o.observed_at,"
            ":anchored,1 FROM checkout_observations AS o "
            "WHERE o.brain_id=:brain AND o.repository_id=:repository "
            "AND o.checkout_id=:checkout AND o.observed_at<=:occurred "
            "AND o.head_commit IS NOT NULL ORDER BY o.observed_at DESC,o.aggregate_version DESC "
            "LIMIT 1"
        ),
        {
            "evidence": source.evidence_id,
            "brain": source.scope.brain_id,
            "repository": source.scope.repository_id,
            "checkout": source.scope.checkout_id,
            "occurred": _micros(source.occurred_at),
            "anchored": _micros(anchored_at),
        },
    )


async def _require_current_authority(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    coordinates: AssertionScope,
    at: datetime,
) -> None:
    if not _scope_contains(scope, coordinates):
        raise GraphAuthorizationError(_ERR_SCOPE)
    parameters = {
        **_scope_parameters(scope, _micros(at)),
        "project": coordinates.project_id,
        "repository": coordinates.repository_id,
    }
    row = (
        await connection.execute(
            text(
                "SELECT 1 FROM scope_grants g JOIN principals p ON p.id=g.principal_id "
                "JOIN brains b ON b.id=g.brain_id WHERE g.principal_id=:principal_id "
                "AND g.brain_id=:brain_id AND g.role IN ('owner','admin','editor','reader') "
                "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now) "
                "AND (g.project_id IS NULL OR g.project_id=:project) "
                "AND (g.repository_id IS NULL OR g.repository_id=:repository) "
                "AND p.status='active' AND b.status='active' LIMIT 1"
            ),
            parameters,
        )
    ).first()
    if row is None:
        raise GraphAuthorizationError(_ERR_SCOPE)


async def _operation(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM assertion_operations WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _verify_operation(  # noqa: PLR0913 -- Comparison binds the complete operation receipt.
    row: RowMapping,
    scope: AuthorizedScope,
    action: str,
    assertion_id: str,
    request_digest: bytes,
    event_id: str | None,
    status: AssertionStatus,
    version: int,
) -> None:
    if (
        str(row["brain_id"]) != scope.brain_id.value
        or str(row["principal_id"]) != scope.principal_id.value
        or _bytes(row["scope_fingerprint"]).hex() != scope.scope_fingerprint
        or str(row["action"]) != action
        or str(row["assertion_id"]) != assertion_id
        or _bytes(row["request_digest"]) != request_digest
        or (None if row["event_id"] is None else str(row["event_id"])) != event_id
        or str(row["result_status"]) != status.value
        or int(str(row["aggregate_version"])) != version
    ):
        raise GraphConflictError(_ERR_CONFLICT)


async def _insert_operation(  # noqa: PLR0913 -- Persistence binds the complete receipt.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    action: str,
    assertion_id: str,
    request_digest: bytes,
    event_id: str | None,
    status: AssertionStatus,
    version: int,
    occurred_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO assertion_operations "
            "(operation_id,brain_id,principal_id,scope_fingerprint,action,assertion_id,"
            "request_digest,event_id,result_status,aggregate_version,occurred_at,schema_version) "
            "VALUES (:operation,:brain,:principal,:scope,:action,:assertion,:request,:event,"
            ":status,:version,:at,1)"
        ),
        {
            "operation": operation_id,
            "brain": scope.brain_id.value,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "action": action,
            "assertion": assertion_id,
            "request": request_digest,
            "event": event_id,
            "status": status.value,
            "version": version,
            "at": _micros(occurred_at),
        },
    )


async def _insert_candidate(
    connection: AsyncConnection,
    operation_id: str,
    candidate: AssertionCandidate,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO assertion_candidates "
            "(assertion_id,proposal_operation_id,brain_id,project_id,repository_id,checkout_id,"
            "subject_id,predicate,polarity,object_id,classification,valid_from,valid_to,proposed_at,"
            "confidence_evidence_support,confidence_source_reliability,"
            "confidence_extraction_quality,extractor_id,extractor_version,model_id,"
            "model_revision,evidence_ids_json,content_fingerprint,revision_id,status,"
            "schema_version) VALUES (:id,:operation,:brain,:project,:repository,:checkout,"
            ":subject,:predicate,:polarity,:object,:classification,:valid_from,:valid_to,:proposed_at,"
            ":support,:reliability,:quality,:extractor,:extractor_version,:model,"
            ":model_revision,:evidence,:fingerprint,:revision,'candidate',1)"
        ),
        _candidate_parameters(operation_id, candidate),
    )


async def _insert_lifecycle(
    connection: AsyncConnection,
    operation_id: str,
    assertion: Assertion,
    event: AssertionLifecycleEvent,
    version: int,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO assertion_lifecycle "
            "(assertion_id,aggregate_version,operation_id,event_id,status,recorded_from,"
            "recorded_to,event_digest,created_at,schema_version) VALUES "
            "(:assertion,:version,:operation,:event,:status,:recorded_from,:recorded_to,"
            ":digest,:created,1)"
        ),
        {
            "assertion": assertion.id,
            "version": version,
            "operation": operation_id,
            "event": event.event_id,
            "status": assertion.status.value,
            "recorded_from": _micros(assertion.temporal.recorded_from),
            "recorded_to": _optional_micros(assertion.temporal.recorded_to),
            "digest": bytes.fromhex(event.digest),
            "created": _micros(event.occurred_at),
        },
    )


async def _insert_evidence_snapshots(connection: AsyncConnection, assertion: Assertion) -> None:
    for evidence in assertion.evidence:
        await connection.execute(
            text(
                "INSERT INTO assertion_evidence_snapshots "
                "(assertion_id,evidence_id,source_id,kind,brain_id,project_id,repository_id,"
                "checkout_id,classification,source_digest,occurred_at,aggregate_version,"
                "schema_version) VALUES (:assertion,:evidence,:source,:kind,:brain,:project,"
                ":repository,:checkout,:classification,:digest,:occurred,1,1)"
            ),
            {
                "assertion": assertion.id,
                "evidence": evidence.evidence_id,
                "source": evidence.source_id,
                "kind": evidence.kind.value,
                "brain": evidence.scope.brain_id,
                "project": evidence.scope.project_id,
                "repository": evidence.scope.repository_id,
                "checkout": evidence.scope.checkout_id,
                "classification": evidence.scope.classification,
                "digest": bytes.fromhex(evidence.source_digest),
                "occurred": _micros(evidence.occurred_at),
            },
        )


async def _insert_domain_event(
    connection: AsyncConnection,
    assertion: Assertion,
    event: AssertionLifecycleEvent,
    version: int,
) -> None:
    document = {
        "assertion_id": assertion.id,
        "evidence_ids": list(event.evidence_ids),
        "event_digest": event.digest,
        "revision_id": assertion.revision_id,
        "status": assertion.status.value,
    }
    payload = _canonical_json(document)
    await connection.execute(
        text(
            "INSERT INTO domain_events "
            "(event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,"
            "payload_json,payload_hash,source_digest,missing_dependency,occurred_at,recorded_at,"
            "schema_version,aggregate_type,aggregate_id,aggregate_version,event_type,event_json,"
            "correlation_id,causation_id) VALUES (:event,:brain,'graph',:stable,'assertion',"
            ":target,:payload,:payload_hash,:source,NULL,:at,:at,2,'assertion',:assertion,"
            ":version,:event_type,:payload,:correlation,:causation)"
        ),
        {
            "event": event.event_id,
            "brain": assertion.scope.brain_id,
            "stable": assertion.id,
            "target": hashlib.sha256(assertion.id.encode()).digest(),
            "payload": payload.decode(),
            "payload_hash": hashlib.sha256(payload).digest(),
            "source": bytes.fromhex(event.digest),
            "at": _micros(event.occurred_at),
            "assertion": assertion.id,
            "version": version,
            "event_type": event.event_type.value,
            "correlation": event.operation_id,
            "causation": event.evidence_ids[0],
        },
    )
    queued = await connection.execute(
        text(
            "INSERT INTO assertion_edge_projection_jobs "
            "(source_event_id,assertion_id,brain_id,principal_id,scope_fingerprint,project_id,"
            "repository_id,checkout_id,classification,aggregate_version,event_type,event_digest,"
            "state,attempts,not_before,lease_owner,lease_until,last_error_code,created_at,"
            "updated_at,completed_at,schema_version) "
            "SELECT :event,:assertion,:brain,o.principal_id,o.scope_fingerprint,:project,"
            ":repository,:checkout,:classification,:version,:event_type,:digest,'ready',0,:at,"
            "NULL,NULL,NULL,:at,:at,NULL,1 FROM assertion_operations AS o "
            "WHERE o.operation_id=:operation"
        ),
        {
            "event": event.event_id,
            "assertion": assertion.id,
            "brain": assertion.scope.brain_id,
            "project": assertion.scope.project_id,
            "repository": assertion.scope.repository_id,
            "checkout": assertion.scope.checkout_id,
            "classification": assertion.scope.classification,
            "version": version,
            "event_type": event.event_type.value,
            "digest": bytes.fromhex(event.digest),
            "at": _micros(event.occurred_at),
            "operation": event.operation_id,
        },
    )
    if queued.rowcount != 1:
        raise GraphIntegrityError(_ERR_INTEGRITY)


def _candidate_parameters(operation_id: str, candidate: AssertionCandidate) -> dict[str, object]:
    return {
        "id": candidate.id,
        "operation": operation_id,
        "brain": candidate.scope.brain_id,
        "project": candidate.scope.project_id,
        "repository": candidate.scope.repository_id,
        "checkout": candidate.scope.checkout_id,
        "subject": candidate.subject_id,
        "predicate": candidate.predicate.value,
        "polarity": candidate.polarity.value,
        "object": candidate.object_id,
        "classification": candidate.scope.classification,
        "valid_from": _micros(candidate.temporal.valid_from),
        "valid_to": _optional_micros(candidate.temporal.valid_to),
        "proposed_at": _micros(candidate.temporal.recorded_from),
        "support": candidate.confidence.evidence_support,
        "reliability": candidate.confidence.source_reliability,
        "quality": candidate.confidence.extraction_quality,
        "extractor": candidate.extractor.extractor_id,
        "extractor_version": candidate.extractor.extractor_version,
        "model": candidate.extractor.model_id,
        "model_revision": candidate.extractor.model_revision,
        "evidence": json.dumps(candidate.evidence_ids, separators=(",", ":")),
        "fingerprint": bytes.fromhex(candidate.content_fingerprint),
        "revision": bytes.fromhex(candidate.revision_id),
    }


def _decode_candidate(row: RowMapping) -> AssertionCandidate:
    try:
        raw_evidence = _string_list(json.loads(str(row["evidence_ids_json"])))
        candidate = AssertionCandidate.create(
            candidate_id=str(row["assertion_id"]),
            subject_id=str(row["subject_id"]),
            predicate=AssertionPredicate(str(row["predicate"])),
            polarity=AssertionPolarity(str(row["polarity"])),
            object_id=str(row["object_id"]),
            scope=AssertionScope(
                str(row["brain_id"]),
                str(row["project_id"]),
                str(row["repository_id"]),
                None if row["checkout_id"] is None else str(row["checkout_id"]),
                str(row["classification"]),
            ),
            temporal=AssertionTemporal(
                _time(row["valid_from"]),
                None if row["valid_to"] is None else _time(row["valid_to"]),
                _time(row["proposed_at"]),
                None,
            ),
            confidence=AssertionConfidence(
                int(str(row["confidence_evidence_support"])),
                int(str(row["confidence_source_reliability"])),
                int(str(row["confidence_extraction_quality"])),
            ),
            extractor=AssertionExtractor(
                str(row["extractor_id"]),
                str(row["extractor_version"]),
                str(row["model_id"]),
                str(row["model_revision"]),
            ),
            evidence_ids=raw_evidence,
        )
        if (
            _bytes(row["content_fingerprint"]).hex() != candidate.content_fingerprint
            or _bytes(row["revision_id"]).hex() != candidate.revision_id
            or str(row["status"]) != AssertionStatus.CANDIDATE.value
        ):
            raise GraphIntegrityError(_ERR_INTEGRITY)
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error
    else:
        return candidate


def _decode_source(
    row: RowMapping,
    principal_id: str,
    resolved_at: datetime,
    tombstones: set[tuple[str, bytes]],
) -> ResolvedAssertionEvidence:
    try:
        kind = EvidenceKind(str(row["kind"]))
        event_id = str(row["event_id"])
        event_digest = _bytes(row["canonical_sha256"])
        source_id = event_id
        expected = event_digest
        if kind is EvidenceKind.USER_STATEMENT and (
            str(row["event_type"]) != _PROMPT_EVENT
            or str(row["source_principal_id"]) != principal_id
        ):
            raise GraphIntegrityError(_ERR_EVIDENCE)
        if kind in {EvidenceKind.ARTIFACT, EvidenceKind.SOURCE_SPAN}:
            if row["artifact_id"] is None or row["artifact_sha256"] is None:
                raise GraphIntegrityError(_ERR_EVIDENCE)
            source_id = str(row["artifact_id"])
            artifact_digest = _bytes(row["artifact_sha256"])
            if str(row["payload_ref"]) != source_id:
                raise GraphIntegrityError(_ERR_EVIDENCE)
            expected = artifact_digest
            if kind is EvidenceKind.SOURCE_SPAN:
                start = int(str(row["span_start"]))
                end = int(str(row["span_end"]))
                if end > int(str(row["byte_length"])):
                    raise GraphIntegrityError(_ERR_EVIDENCE)
                expected = _span_digest(artifact_digest, start, end)
        if expected != _bytes(row["source_digest"]):
            raise GraphIntegrityError(_ERR_EVIDENCE)
        evidence_id = str(row["evidence_id"])
        revoked_at = row["revoked_at"]
        deleted = (revoked_at is not None and int(str(revoked_at)) <= _micros(resolved_at)) or any(
            (target, hashlib.sha256(identity.encode()).digest()) in tombstones
            for target, identity in (
                ("assertion_evidence", evidence_id),
                ("agent_event", event_id),
                ("artifact", source_id),
            )
        )
        return ResolvedAssertionEvidence(
            evidence_id=evidence_id,
            source_id=source_id,
            kind=kind,
            scope=AssertionScope(
                str(row["brain_id"]),
                str(row["project_id"]),
                str(row["repository_id"]),
                None if row["checkout_id"] is None else str(row["checkout_id"]),
                str(row["classification"]),
            ),
            source_digest=expected.hex(),
            occurred_at=_time(row["occurred_at"]),
            accessible=True,
            deleted=deleted,
            immutable=True,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_EVIDENCE) from error


def _decode_snapshot(row: RowMapping) -> ResolvedAssertionEvidence:
    try:
        return ResolvedAssertionEvidence(
            evidence_id=str(row["evidence_id"]),
            source_id=str(row["source_id"]),
            kind=EvidenceKind(str(row["kind"])),
            scope=AssertionScope(
                str(row["brain_id"]),
                str(row["project_id"]),
                str(row["repository_id"]),
                None if row["checkout_id"] is None else str(row["checkout_id"]),
                str(row["classification"]),
            ),
            source_digest=_bytes(row["source_digest"]).hex(),
            occurred_at=_time(row["occurred_at"]),
            accessible=True,
            deleted=False,
            immutable=True,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GraphIntegrityError(_ERR_INTEGRITY) from error


async def _tombstone_keys(connection: AsyncConnection, brain_id: str) -> set[tuple[str, bytes]]:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT target_type,target_id_hash FROM deletion_tombstones "
                    "WHERE brain_id=:brain AND purge_state IN ('tombstoned','completed')"
                ),
                {"brain": brain_id},
            )
        )
        .mappings()
        .all()
    )
    return {(str(row["target_type"]), _bytes(row["target_id_hash"])) for row in rows}


def _scope_contains(scope: AuthorizedScope, coordinates: AssertionScope) -> bool:
    if coordinates.brain_id != scope.brain_id.value:
        return False
    member = next(
        (item for item in scope.members if item.project_id.value == coordinates.project_id),
        None,
    )
    if member is None or coordinates.repository_id not in {
        item.value for item in member.repository_ids
    }:
        return False
    if (
        coordinates.checkout_id is not None
        and member.checkout_ids
        and coordinates.checkout_id not in {item.value for item in member.checkout_ids}
    ):
        return False
    ceiling = _CLASSIFICATIONS.index(scope.classification_ceiling.value)
    return coordinates.classification in _CLASSIFICATIONS[: ceiling + 1]


def _authorized_scope_sql(alias: str | None = None) -> str:
    prefix = "" if alias is None else f"{alias}."
    return _AUTHORIZED_SCOPE.format(
        project=f"{prefix}project_id",
        repository=f"{prefix}repository_id",
        checkout=f"{prefix}checkout_id",
    )


def _scope_parameters(scope: AuthorizedScope, now: int) -> dict[str, object]:
    ceiling = _CLASSIFICATIONS.index(scope.classification_ceiling.value)
    return {
        "brain_id": scope.brain_id.value,
        "principal_id": scope.principal_id.value,
        "now": now,
        "classifications": json.dumps(_CLASSIFICATIONS[: ceiling + 1]),
        "members": json.dumps(
            [
                {
                    "checkout_ids": [value.value for value in member.checkout_ids],
                    "project_id": member.project_id.value,
                    "repository_ids": [value.value for value in member.repository_ids],
                }
                for member in scope.members
            ],
            separators=(",", ":"),
            sort_keys=True,
        ),
    }


def _request_digest(*parts: str) -> bytes:
    return hashlib.sha256(
        b"assertion-operation.v1\x00" + b"\x00".join(part.encode() for part in parts)
    ).digest()


def _cascade_operation_id(revocation_operation_id: str, assertion_id: str) -> str:
    digest = hashlib.sha256(
        b"assertion-revocation-cascade.v1\x00"
        + revocation_operation_id.encode()
        + b"\x00"
        + assertion_id.encode()
    ).hexdigest()
    return f"assertion-reconcile-{digest[:32]}"


def _span_digest(artifact_digest: bytes, start: int, end: int) -> bytes:
    return hashlib.sha256(
        b"assertion-source-span.v1\x00"
        + artifact_digest
        + b"\x00"
        + str(start).encode()
        + b":"
        + str(end).encode()
    ).digest()


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ValueError
    return round(value.timestamp() * 1_000_000)


def _now_micros() -> int:
    return _micros(datetime.now(UTC))


def _optional_micros(value: datetime | None) -> int | None:
    return None if value is None else _micros(value)


def _time(value: object) -> datetime:
    if isinstance(value, bool):
        raise TypeError
    return datetime.fromtimestamp(int(str(value)) / 1_000_000, tz=UTC)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTES:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return value


def _require_no_conflict(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise GraphConflictError(_ERR_CONFLICT)


def _require_authorized(condition: bool, message: str) -> None:  # noqa: FBT001
    if not condition:
        raise GraphAuthorizationError(message)


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError
    items = cast("list[object]", value)
    if any(not isinstance(item, str) for item in items):
        raise TypeError
    return tuple(cast("str", item) for item in items)


def _present[T](value: T | None) -> T:
    if value is None:
        raise GraphIntegrityError(_ERR_INTEGRITY)
    return value
