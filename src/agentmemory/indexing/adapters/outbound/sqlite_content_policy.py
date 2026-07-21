"""IDX-006 SQLite policy authority, decision ledger, work queue, and projection effects."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyAction,
    PolicyDecision,
    PolicyDisposition,
    PolicyLayer,
    PolicyRule,
    PolicyRuleSource,
    ReconciliationAction,
)
from agentmemory.indexing.domain.content_policy_ports import (
    PolicyChangeResult,
    PolicyReconciliationWork,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_AUTHORIZATION = "content policy storage action is not authorized"
_ERR_CONFLICT = "content policy conflicts with immutable history"
_ERR_INTEGRITY = "content policy storage failed integrity verification"
_ERR_STORAGE = "content policy storage is unavailable"
_DEFAULT_ACTIVATED_AT = datetime(2024, 1, 1, tzinfo=UTC)
_LEASE = timedelta(minutes=5)
_MAX_AFFECTED_PATHS = 250_000
_MAX_DEPENDENCIES = 100_000
_WRITE_ROLES = frozenset({"owner", "admin"})
_READ_ROLES = frozenset({"owner", "admin", "auditor"})


class SqliteIndexContentPolicyAdapter:
    """Implement policy repositories and bounded reconciliation leases in SQLite."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the sole canonical writer and local relational authority."""
        self._store = store
        self._clock = clock

    async def resolve_revision(
        self,
        repository_id: str,
        resolved_at: datetime,
    ) -> IndexPolicyRevision:
        """Resolve exact repository authority and its latest immutable policy."""
        del resolved_at
        try:
            async with self._store.engine.connect() as connection:
                brain_id = await _repository_brain(connection, repository_id)
                row = await _latest_policy_row(connection, repository_id)
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error
        if brain_id is None:
            raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
        return (
            IndexPolicyRevision.production_default(
                brain_id,
                repository_id,
                _DEFAULT_ACTIVATED_AT,
            )
            if row is None
            else _decode_revision(_blob(row["document_json"]))
        )

    async def observe_source(
        self,
        repository_id: str,
        layer: PolicyLayer,
        content: bytes,
        observed_at: datetime,
    ) -> PolicyRuleSource:
        """Assign a stable monotonic source version and retain parsed rules only."""
        source_hash = hashlib.sha256(content).hexdigest()
        try:
            async with _write_transaction(self._store) as connection:
                if await _repository_brain(connection, repository_id) is None:
                    raise IndexingAuthorizationError(_ERR_AUTHORIZATION)  # noqa: TRY301
                existing = await _source_by_hash(connection, repository_id, layer, source_hash)
                if existing is not None:
                    return _decode_source(existing)
                latest = await _latest_source(connection, repository_id, layer)
                version = 1 if latest is None else int(latest["source_version"]) + 1
                source = PolicyRuleSource.from_ignore_bytes(layer, version, content)
                rules_json = _canonical_json([rule.canonical_document for rule in source.rules])
                source_id = _identity(
                    "index-policy-source.v1",
                    repository_id,
                    layer.value,
                    str(version),
                    source.source_hash,
                )
                await connection.execute(
                    text(
                        "INSERT INTO index_policy_rule_sources "
                        "(source_id,repository_id,layer,source_version,source_hash,rules_json,"
                        "observed_at,schema_version) VALUES "
                        "(:id,:repository,:layer,:version,:hash,:rules,:at,1)"
                    ),
                    {
                        "at": _micros(observed_at),
                        "hash": source.source_hash,
                        "id": source_id,
                        "layer": layer.value,
                        "repository": repository_id,
                        "rules": rules_json,
                        "version": version,
                    },
                )
                return source
        except IndexingAuthorizationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def record_decision(self, decision: PolicyDecision) -> None:
        """Append one exact content-free decision or prove an exact replay."""
        try:
            async with _write_transaction(self._store) as connection:
                await connection.execute(
                    text(
                        "INSERT OR IGNORE INTO index_policy_decisions "
                        "(decision_id,repository_id,relative_path,phase,disposition,reason,layer,"
                        "rule_id,rule_version,source_hash,policy_digest,byte_length,content_hash,"
                        "is_binary,is_encrypted,is_private,is_symlink,decided_at,decision_json,"
                        "schema_version) VALUES (:id,:repository,:path,:phase,:disposition,:reason,"
                        ":layer,:rule,:version,:source,:policy,:bytes,:content,:binary,:encrypted,"
                        ":private,:symlink,:at,:document,1)"
                    ),
                    _decision_parameters(decision),
                )
                stored = (
                    await connection.execute(
                        text(
                            "SELECT decision_json FROM index_policy_decisions WHERE decision_id=:id"
                        ),
                        {"id": decision.id},
                    )
                ).scalar_one()
                if _blob(stored) != decision.canonical_bytes:
                    raise IndexingConflictError(_ERR_CONFLICT)  # noqa: TRY301
        except IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def activate(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        revision: IndexPolicyRevision,
        activated_at: datetime,
    ) -> PolicyChangeResult:
        """Activate exactly the next revision and queue all affected paths atomically."""
        project_id, repository_id = _exact_scope(scope)
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(
                    connection,
                    scope,
                    project_id,
                    repository_id,
                    activated_at,
                    write=True,
                )
                replay = await _change_by_operation(connection, operation_id)
                if replay is not None:
                    result = _decode_change(replay)
                    if result.current_policy_digest != revision.digest:
                        raise IndexingConflictError(_ERR_CONFLICT)  # noqa: TRY301
                    return result
                previous_row = await _latest_policy_row(connection, repository_id)
                previous = (
                    IndexPolicyRevision.production_default(
                        scope.brain_id.value,
                        repository_id,
                        _DEFAULT_ACTIVATED_AT,
                    )
                    if previous_row is None
                    else _decode_revision(_blob(previous_row["document_json"]))
                )
                if revision.version != previous.version + 1:
                    raise IndexingConflictError(_ERR_CONFLICT)  # noqa: TRY301
                sources = await _current_sources(connection, repository_id)
                policy = IndexContentPolicy(
                    revision,
                    sources.get(PolicyLayer.AGENTMEMORY_IGNORE),
                    sources.get(PolicyLayer.GITIGNORE),
                )
                decisions = await _latest_decisions(connection, repository_id)
                if len(decisions) > _MAX_AFFECTED_PATHS:
                    raise IndexingUnavailableError(_ERR_STORAGE)  # noqa: TRY301
                work = _reconciliation_work(policy, decisions, activated_at)
                change_id = _identity(
                    "index-policy-change.v1",
                    operation_id,
                    previous.digest,
                    revision.digest,
                )
                result = PolicyChangeResult(
                    change_id,
                    operation_id,
                    scope.brain_id.value,
                    repository_id,
                    previous.digest,
                    revision.digest,
                    sum(action is ReconciliationAction.DELETE for _, action in work),
                    sum(action is ReconciliationAction.REINDEX for _, action in work),
                    activated_at,
                )
                await _insert_policy(connection, scope, operation_id, revision)
                await _insert_change(connection, result)
                await _insert_work(connection, result, work)
                return result
        except IndexingAuthorizationError, IndexingConflictError, IndexingUnavailableError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def get_change(
        self,
        scope: AuthorizedScope,
        change_id: str,
    ) -> PolicyChangeResult | None:
        """Return one change after current authorization is re-established."""
        project_id, repository_id = _exact_scope(scope)
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(
                    connection,
                    scope,
                    project_id,
                    repository_id,
                    self._clock.now(),
                    write=False,
                )
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM index_policy_changes WHERE change_id=:change "
                                "AND brain_id=:brain AND repository_id=:repository"
                            ),
                            {
                                "brain": scope.brain_id.value,
                                "change": change_id,
                                "repository": repository_id,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
        except IndexingAuthorizationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error
        return None if row is None else _decode_change(row)

    async def claim_next(self, claimed_at: datetime) -> PolicyReconciliationWork | None:
        """Claim one queued or expired item with an append-only lease snapshot."""
        try:
            async with _write_transaction(self._store) as connection:
                row = await _next_work(connection, claimed_at)
                if row is None:
                    return None
                snapshot_version = int(row["snapshot_version"]) + 1
                attempt = int(row["attempt"]) + 1
                leased_until = claimed_at + _LEASE
                digest = _snapshot_digest(
                    str(row["item_id"]), snapshot_version, "claimed", attempt, leased_until
                )
                await connection.execute(
                    text(
                        "INSERT INTO index_policy_reconciliation_snapshots "
                        "(item_id,snapshot_version,state,attempt,leased_until,updated_at,"
                        "snapshot_digest,schema_version) VALUES "
                        "(:item,:version,'claimed',:attempt,:lease,:at,:digest,1)"
                    ),
                    {
                        "at": _micros(claimed_at),
                        "attempt": attempt,
                        "digest": digest,
                        "item": str(row["item_id"]),
                        "lease": _micros(leased_until),
                        "version": snapshot_version,
                    },
                )
                return PolicyReconciliationWork(
                    str(row["item_id"]),
                    str(row["change_id"]),
                    str(row["repository_id"]),
                    str(row["relative_path"]),
                    ReconciliationAction(str(row["action"])),
                    str(row["policy_digest"]),
                    claimed_at,
                )
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def complete(self, item_id: str, completed_at: datetime) -> None:
        """Complete only a live claimed item and replay the receipt exactly."""
        try:
            async with _write_transaction(self._store) as connection:
                row = await _latest_work_snapshot(connection, item_id)
                if row is None:
                    raise IndexingValidationError(_ERR_INTEGRITY)  # noqa: TRY301
                if str(row["state"]) == "completed":
                    return
                if str(row["state"]) != "claimed" or int(row["leased_until"]) < _micros(
                    completed_at
                ):
                    raise IndexingConflictError(_ERR_CONFLICT)  # noqa: TRY301
                version = int(row["snapshot_version"]) + 1
                attempt = int(row["attempt"])
                digest = _snapshot_digest(item_id, version, "completed", attempt, None)
                await connection.execute(
                    text(
                        "INSERT INTO index_policy_reconciliation_snapshots "
                        "(item_id,snapshot_version,state,attempt,leased_until,updated_at,"
                        "snapshot_digest,schema_version) VALUES "
                        "(:item,:version,'completed',:attempt,NULL,:at,:digest,1)"
                    ),
                    {
                        "at": _micros(completed_at),
                        "attempt": attempt,
                        "digest": digest,
                        "item": item_id,
                        "version": version,
                    },
                )
        except IndexingValidationError, IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


class SqliteIndexPolicyProjection:
    """Apply policy invalidation and reindex requests without source content."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind projection receipts to the canonical writer lock."""
        self._store = store

    async def apply(self, work: PolicyReconciliationWork) -> None:
        """Invalidate exact derivative closure or append one rebuild request."""
        try:
            async with _write_transaction(self._store) as connection:
                if work.action is ReconciliationAction.DELETE:
                    await _invalidate_derivatives(connection, work)
                elif work.action is ReconciliationAction.REINDEX:
                    await connection.execute(
                        text(
                            "INSERT OR IGNORE INTO index_policy_reindex_requests "
                            "(item_id,repository_id,relative_path,policy_digest,requested_at,"
                            "schema_version) VALUES (:item,:repository,:path,:policy,:at,1)"
                        ),
                        {
                            "at": _micros(work.claimed_at),
                            "item": work.item_id,
                            "path": work.relative_path,
                            "policy": work.policy_digest,
                            "repository": work.repository_id,
                        },
                    )
                else:
                    raise IndexingValidationError(_ERR_INTEGRITY)  # noqa: TRY301
        except IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


def _decision_parameters(decision: PolicyDecision) -> dict[str, object]:
    return {
        "at": _micros(decision.decided_at),
        "binary": decision.binary,
        "bytes": decision.byte_length,
        "content": decision.content_hash,
        "disposition": decision.disposition.value,
        "document": decision.canonical_bytes,
        "encrypted": decision.encrypted,
        "id": decision.id,
        "layer": decision.layer.value,
        "path": decision.relative_path,
        "phase": decision.phase.value,
        "policy": decision.policy_digest,
        "private": decision.private,
        "reason": decision.reason,
        "repository": decision.repository_id,
        "rule": decision.rule_id,
        "source": decision.source_hash,
        "symlink": decision.symlink,
        "version": decision.rule_version,
    }


async def _insert_policy(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    revision: IndexPolicyRevision,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO index_content_policy_versions "
            "(policy_digest,operation_id,policy_id,policy_version,brain_id,repository_id,"
            "principal_id,scope_fingerprint,document_json,activated_at,schema_version) VALUES "
            "(:digest,:operation,:policy_id,:version,:brain,:repository,:principal,:scope,"
            ":document,:at,1)"
        ),
        {
            "at": _micros(revision.activated_at),
            "brain": revision.brain_id,
            "digest": revision.digest,
            "document": revision.canonical_bytes,
            "operation": operation_id,
            "policy_id": revision.policy_id,
            "principal": scope.principal_id.value,
            "repository": revision.repository_id,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "version": revision.version,
        },
    )


async def _insert_change(connection: AsyncConnection, result: PolicyChangeResult) -> None:
    await connection.execute(
        text(
            "INSERT INTO index_policy_changes "
            "(change_id,operation_id,brain_id,repository_id,previous_policy_digest,"
            "current_policy_digest,delete_count,reindex_count,activated_at,schema_version) "
            "VALUES (:change,:operation,:brain,:repository,:previous,:current,:deletes,"
            ":reindexes,:at,1)"
        ),
        {
            "at": _micros(result.activated_at),
            "brain": result.brain_id,
            "change": result.change_id,
            "current": result.current_policy_digest,
            "deletes": result.delete_count,
            "operation": result.operation_id,
            "previous": result.previous_policy_digest,
            "reindexes": result.reindex_count,
            "repository": result.repository_id,
        },
    )


async def _insert_work(
    connection: AsyncConnection,
    change: PolicyChangeResult,
    work: tuple[tuple[str, ReconciliationAction], ...],
) -> None:
    for ordinal, (path, action) in enumerate(work):
        item_id = _identity(
            "index-policy-work.v1", change.change_id, str(ordinal), path, action.value
        )
        await connection.execute(
            text(
                "INSERT INTO index_policy_reconciliation_items "
                "(item_id,change_id,repository_id,ordinal,relative_path,action,policy_digest,"
                "created_at,schema_version) VALUES "
                "(:item,:change,:repository,:ordinal,:path,:action,:policy,:at,1)"
            ),
            {
                "action": action.value,
                "at": _micros(change.activated_at),
                "change": change.change_id,
                "item": item_id,
                "ordinal": ordinal,
                "path": path,
                "policy": change.current_policy_digest,
                "repository": change.repository_id,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO index_policy_reconciliation_snapshots "
                "(item_id,snapshot_version,state,attempt,leased_until,updated_at,snapshot_digest,"
                "schema_version) VALUES (:item,0,'queued',0,NULL,:at,:digest,1)"
            ),
            {
                "at": _micros(change.activated_at),
                "digest": _snapshot_digest(item_id, 0, "queued", 0, None),
                "item": item_id,
            },
        )


def _reconciliation_work(
    policy: IndexContentPolicy,
    decisions: tuple[RowMapping, ...],
    activated_at: datetime,
) -> tuple[tuple[str, ReconciliationAction], ...]:
    result: list[tuple[str, ReconciliationAction]] = []
    for row in decisions:
        path = str(row["relative_path"])
        next_path = policy.evaluate_path(
            path,
            symlink=bool(row["is_symlink"]),
            byte_length=int(row["byte_length"]),
            decided_at=activated_at,
        )
        previous = PolicyDisposition(str(row["disposition"]))
        if previous is PolicyDisposition.INCLUDE:
            result.append((path, ReconciliationAction.DELETE))
        if next_path.included:
            result.append((path, ReconciliationAction.REINDEX))
    return tuple(sorted(result, key=lambda item: (item[0], item[1].value)))


async def _invalidate_derivatives(
    connection: AsyncConnection,
    work: PolicyReconciliationWork,
) -> None:
    semantic_ids = tuple(
        sorted(
            str(value)
            for value in (
                await connection.execute(
                    text(
                        "SELECT file_revision.id FROM file_revisions AS file_revision JOIN "
                        "source_files AS source_file ON source_file.id=file_revision.file_id "
                        "WHERE source_file.repository_id=:repository "
                        "AND source_file.relative_path=:path UNION SELECT revision.id FROM "
                        "symbol_revisions AS revision JOIN "
                        "file_revisions AS file_revision ON "
                        "file_revision.id=revision.file_revision_id "
                        "JOIN source_files AS source_file ON source_file.id=file_revision.file_id "
                        "WHERE source_file.repository_id=:repository "
                        "AND source_file.relative_path=:path"
                    ),
                    {"path": work.relative_path, "repository": work.repository_id},
                )
            ).scalars()
        )
    )
    facts, evidence = await _dependency_closure(connection, semantic_ids)
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO index_policy_derivative_invalidations "
            "(item_id,repository_id,relative_path,semantic_ids_json,dependent_fact_ids_json,"
            "assertion_evidence_ids_json,invalidated_at,schema_version) VALUES "
            "(:item,:repository,:path,:semantics,:facts,:evidence,:at,1)"
        ),
        {
            "at": _micros(work.claimed_at),
            "evidence": _canonical_json(sorted(evidence)),
            "facts": _canonical_json(sorted(facts)),
            "item": work.item_id,
            "path": work.relative_path,
            "repository": work.repository_id,
            "semantics": _canonical_json(semantic_ids),
        },
    )


async def _dependency_closure(
    connection: AsyncConnection,
    semantic_ids: tuple[str, ...],
) -> tuple[set[str], set[str]]:
    frontier = set(semantic_ids)
    visited = set(semantic_ids)
    facts: set[str] = set()
    evidence: set[str] = set()
    while frontier:
        if len(visited) > _MAX_DEPENDENCIES:
            raise IndexingValidationError(_ERR_INTEGRITY)
        batch = tuple(sorted(frontier))
        frontier.clear()
        statement = text(
            "SELECT dependent_fact_id,assertion_evidence_id FROM index_semantic_dependencies "
            "WHERE source_semantic_id IN :ids"
        ).bindparams(bindparam("ids", expanding=True))
        rows = (await connection.execute(statement, {"ids": batch})).mappings().all()
        for row in rows:
            fact = None if row["dependent_fact_id"] is None else str(row["dependent_fact_id"])
            evidence_id = (
                None if row["assertion_evidence_id"] is None else str(row["assertion_evidence_id"])
            )
            if fact is not None:
                facts.add(fact)
                if fact not in visited:
                    visited.add(fact)
                    frontier.add(fact)
            if evidence_id is not None:
                evidence.add(evidence_id)
    return facts, evidence


async def _current_sources(
    connection: AsyncConnection,
    repository_id: str,
) -> dict[PolicyLayer, PolicyRuleSource]:
    result: dict[PolicyLayer, PolicyRuleSource] = {}
    for layer in (PolicyLayer.AGENTMEMORY_IGNORE, PolicyLayer.GITIGNORE):
        row = await _latest_source(connection, repository_id, layer)
        if row is not None:
            result[layer] = _decode_source(row)
    return result


async def _latest_decisions(
    connection: AsyncConnection,
    repository_id: str,
) -> tuple[RowMapping, ...]:
    return tuple(
        (
            await connection.execute(
                text(
                    "WITH ranked AS (SELECT decision.*,ROW_NUMBER() OVER (PARTITION BY "
                    "relative_path ORDER BY decided_at DESC,CASE phase WHEN 'content' "
                    "THEN 1 ELSE 0 "
                    "END DESC,decision_id DESC) AS rank FROM index_policy_decisions AS decision "
                    "WHERE repository_id=:repository) SELECT * FROM ranked WHERE rank=1 "
                    "ORDER BY relative_path LIMIT :limit"
                ),
                {"limit": _MAX_AFFECTED_PATHS + 1, "repository": repository_id},
            )
        )
        .mappings()
        .all()
    )


async def _next_work(connection: AsyncConnection, claimed_at: datetime) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT item.*,snapshot.snapshot_version,snapshot.state,snapshot.attempt,"
                    "snapshot.leased_until FROM index_policy_reconciliation_items AS item JOIN "
                    "index_policy_reconciliation_snapshots AS snapshot ON "
                    "snapshot.item_id=item.item_id "
                    "WHERE snapshot.snapshot_version=(SELECT MAX(latest.snapshot_version) FROM "
                    "index_policy_reconciliation_snapshots AS latest WHERE "
                    "latest.item_id=item.item_id) "
                    "AND (snapshot.state='queued' OR (snapshot.state='claimed' "
                    "AND snapshot.leased_until<:now)) ORDER BY item.created_at,item.ordinal LIMIT 1"
                ),
                {"now": _micros(claimed_at)},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _latest_work_snapshot(connection: AsyncConnection, item_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM index_policy_reconciliation_snapshots WHERE item_id=:item "
                    "ORDER BY snapshot_version DESC LIMIT 1"
                ),
                {"item": item_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _source_by_hash(
    connection: AsyncConnection,
    repository_id: str,
    layer: PolicyLayer,
    source_hash: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM index_policy_rule_sources WHERE repository_id=:repository "
                    "AND layer=:layer AND source_hash=:hash"
                ),
                {"hash": source_hash, "layer": layer.value, "repository": repository_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _latest_source(
    connection: AsyncConnection,
    repository_id: str,
    layer: PolicyLayer,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM index_policy_rule_sources WHERE repository_id=:repository "
                    "AND layer=:layer ORDER BY source_version DESC LIMIT 1"
                ),
                {"layer": layer.value, "repository": repository_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _decode_source(row: RowMapping) -> PolicyRuleSource:
    layer = PolicyLayer(str(row["layer"]))
    version = int(row["source_version"])
    document = _json_array(_blob(row["rules_json"]))
    rules = tuple(
        PolicyRule(
            layer,
            str(item["rule_id"]),
            version,
            str(item["pattern"]),
            PolicyAction(str(item["action"])),
        )
        for item in document
    )
    return PolicyRuleSource(layer, version, str(row["source_hash"]), rules)


def _decode_revision(value: bytes) -> IndexPolicyRevision:
    try:
        document = cast("dict[str, Any]", json.loads(value))
        version = int(document["version"])
        rules = tuple(
            PolicyRule(
                PolicyLayer.BRAIN,
                str(item["rule_id"]),
                version,
                str(item["pattern"]),
                PolicyAction(str(item["action"])),
            )
            for item in cast("list[dict[str, Any]]", document["brain_rules"])
        )
        return IndexPolicyRevision(
            policy_id=str(document["policy_id"]),
            version=version,
            brain_id=str(document["brain_id"]),
            repository_id=(
                None if document["repository_id"] is None else str(document["repository_id"])
            ),
            brain_rules=PolicyRuleSource(
                PolicyLayer.BRAIN,
                version,
                str(document["brain_source_hash"]),
                rules,
            ),
            max_file_bytes=int(document["max_file_bytes"]),
            private_block_pairs=tuple(
                (str(pair[0]), str(pair[1]))
                for pair in cast("list[list[str]]", document["private_block_pairs"])
            ),
            exclude_binary=bool(document["exclude_binary"]),
            exclude_generated=bool(document["exclude_generated"]),
            exclude_encrypted=bool(document["exclude_encrypted"]),
            activated_at=datetime.fromtimestamp(int(document["activated_at"]) / 1_000_000, tz=UTC),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise IndexingValidationError(_ERR_INTEGRITY) from error


async def _latest_policy_row(
    connection: AsyncConnection,
    repository_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM index_content_policy_versions WHERE repository_id=:repository "
                    "ORDER BY policy_version DESC LIMIT 1"
                ),
                {"repository": repository_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _change_by_operation(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM index_policy_changes WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _decode_change(row: RowMapping) -> PolicyChangeResult:
    return PolicyChangeResult(
        str(row["change_id"]),
        str(row["operation_id"]),
        str(row["brain_id"]),
        str(row["repository_id"]),
        (None if row["previous_policy_digest"] is None else str(row["previous_policy_digest"])),
        str(row["current_policy_digest"]),
        int(row["delete_count"]),
        int(row["reindex_count"]),
        datetime.fromtimestamp(int(row["activated_at"]) / 1_000_000, tz=UTC),
    )


async def _repository_brain(connection: AsyncConnection, repository_id: str) -> str | None:
    value = (
        (
            await connection.execute(
                text(
                    "SELECT DISTINCT project.brain_id FROM repositories AS repository JOIN "
                    "project_repositories AS binding ON binding.repository_id=repository.id JOIN "
                    "projects AS project ON project.id=binding.project_id WHERE "
                    "repository.id=:repository AND repository.status='active' "
                    "AND project.status='active' LIMIT 2"
                ),
                {"repository": repository_id},
            )
        )
        .scalars()
        .all()
    )
    if len(value) != 1:
        return None
    return str(value[0])


async def _authorize(  # noqa: PLR0913 -- Exact current authority inputs are explicit.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    project_id: str,
    repository_id: str,
    now: datetime,
    *,
    write: bool,
) -> None:
    allowed = _WRITE_ROLES if write else _READ_ROLES
    if scope.role.value not in allowed:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    value = (
        await connection.execute(
            text(
                "SELECT EXISTS(SELECT 1 FROM repositories AS repository JOIN "
                "project_repositories AS binding ON binding.repository_id=repository.id JOIN "
                "projects AS project ON project.id=binding.project_id WHERE "
                "repository.id=:repository AND project.id=:project AND repository.status='active' "
                "AND project.status='active' AND project.brain_id=:brain AND EXISTS(SELECT 1 FROM "
                "scope_grants AS grant_row WHERE grant_row.principal_id=:principal AND "
                "grant_row.brain_id=:brain AND grant_row.role=:role AND grant_row.valid_from<=:now "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) AND "
                "(grant_row.project_id IS NULL OR grant_row.project_id=project.id) AND "
                "(grant_row.repository_id IS NULL OR grant_row.repository_id=repository.id)))"
            ),
            {
                "brain": scope.brain_id.value,
                "now": _micros(now),
                "principal": scope.principal_id.value,
                "project": project_id,
                "repository": repository_id,
                "role": scope.role.value,
            },
        )
    ).scalar_one()
    if not value:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _exact_scope(scope: AuthorizedScope) -> tuple[str, str]:
    if len(scope.project_ids) != 1 or len(scope.repository_ids) != 1:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    return scope.project_ids[0].value, scope.repository_ids[0].value


def _json_array(value: bytes) -> list[dict[str, Any]]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise IndexingValidationError(_ERR_INTEGRITY) from error
    if not isinstance(decoded, list):
        raise IndexingValidationError(_ERR_INTEGRITY)
    items = cast("list[object]", decoded)
    if not all(isinstance(item, dict) for item in items):
        raise IndexingValidationError(_ERR_INTEGRITY)
    return cast("list[dict[str, Any]]", items)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _identity(namespace: str, *values: str) -> str:
    digest = hashlib.sha256()
    digest.update(namespace.encode())
    for value in values:
        encoded = value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _snapshot_digest(
    item_id: str,
    version: int,
    state: str,
    attempt: int,
    leased_until: datetime | None,
) -> bytes:
    return hashlib.sha256(
        _canonical_json(
            {
                "attempt": attempt,
                "item_id": item_id,
                "leased_until": None if leased_until is None else _micros(leased_until),
                "state": state,
                "version": version,
            }
        )
    ).digest()


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise IndexingValidationError(_ERR_INTEGRITY)


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise IndexingValidationError(_ERR_INTEGRITY)
    return round(value.timestamp() * 1_000_000)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    await store.write_lock.acquire()
    try:
        async with store.engine.connect() as connection:
            await connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise
    finally:
        store.write_lock.release()
