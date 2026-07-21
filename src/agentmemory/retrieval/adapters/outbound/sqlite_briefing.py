"""MEM-006 authorized memory/revision reads and ContextInjected event persistence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.retrieval.domain.continuity import (
    CodeRevision,
    ContextInjectedEvent,
    ContinuityItem,
    ContinuityKind,
    ItemProvenance,
)
from agentmemory.retrieval.domain.errors import (
    RetrievalAuthorizationError,
    RetrievalConflictError,
    RetrievalDependencyError,
    RetrievalIntegrityError,
    RetrievalValidationError,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.shared.clock import Clock

_MAX_CANDIDATES = 200
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_MEMORY_CLASS_KIND = {
    "constraint": ContinuityKind.FACT,
    "decision": ContinuityKind.DECISION,
    "episode": ContinuityKind.FACT,
    "lesson": ContinuityKind.FACT,
    "unresolved_work": ContinuityKind.NEXT_STEP,
}
_ERR_LIMIT = "memory briefing candidate limit is invalid"
_ERR_STORAGE = "briefing storage is unavailable"
_ERR_MEMORY = "briefing memory projection was malformed"
_ERR_AUTHORIZATION = "briefing event authorization is no longer active"
_ERR_CONFLICT = "briefing operation identity was reused with different input or selection"
_ERR_CLOCK = "briefing clock is not UTC"
_DIGEST_BYTES = 32

_MEMORY_QUERY = """
SELECT m.id,m.brain_id,m.memory_class,m.project_id,m.repository_id,m.checkout_id,m.valid_from,
       m.recorded_from,m.classification,m.source_task_id,m.current_revision,
       r.content_json,r.provenance_json,
       (SELECT json_group_array(event_id) FROM (
          SELECT event_id FROM memory_evidence me WHERE me.memory_id=m.id ORDER BY event_id
       )) AS evidence_json
FROM memories m
JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision
JOIN memory_lifecycle l ON l.memory_id=m.id AND l.brain_id=m.brain_id
WHERE m.brain_id=:brain AND m.status='active'
  AND m.memory_class IN ('constraint','decision','episode','lesson','unresolved_work')
  AND l.recall_state='active' AND (l.expires_at IS NULL OR l.expires_at>:now)
  AND m.valid_from<=:now AND (m.valid_to IS NULL OR m.valid_to>:now)
  AND (m.recorded_to IS NULL OR m.recorded_to>:now)
  AND m.classification IN (SELECT value FROM json_each(:classifications))
  AND EXISTS (
    SELECT 1 FROM scope_grants g
    JOIN principals p ON p.id=g.principal_id AND p.status='active'
    JOIN brains b ON b.id=g.brain_id AND b.status='active'
    WHERE g.principal_id=:principal AND g.brain_id=m.brain_id
      AND g.role IN ('owner','admin','editor','reader','auditor')
      AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now)
      AND (g.project_id IS NULL OR g.project_id=m.project_id)
      AND (g.repository_id IS NULL OR g.repository_id=m.repository_id)
  )
  AND EXISTS (
    SELECT 1 FROM json_each(:members) member
    WHERE json_extract(member.value,'$.project_id')=m.project_id
      AND m.repository_id IN (
        SELECT value FROM json_each(json_extract(member.value,'$.repository_ids'))
      )
      AND (
        json_array_length(json_extract(member.value,'$.checkout_ids'))=0
        OR m.checkout_id IN (
          SELECT value FROM json_each(json_extract(member.value,'$.checkout_ids'))
        )
      )
  )
ORDER BY m.recorded_from DESC,m.id
LIMIT :limit
"""


@dataclass(frozen=True, slots=True)
class SqliteMemoryBriefingRepository:
    """Read authorized active evidence-backed memories for MEM-006."""

    engine: AsyncEngine
    clock: Clock

    async def list_items(
        self,
        authorized_scope: AuthorizedScope,
        candidate_limit: int,
    ) -> tuple[ContinuityItem, ...]:
        """Return memories after SQL authorization, lifecycle, time, and deletion filters."""
        if not 1 <= candidate_limit <= _MAX_CANDIDATES:
            raise RetrievalValidationError(_ERR_LIMIT)
        now = _micros(self.clock.now())
        parameters = _scope_parameters(authorized_scope, now)
        parameters["limit"] = candidate_limit + 1
        try:
            async with self.engine.connect() as connection:
                rows = list((await connection.execute(text(_MEMORY_QUERY), parameters)).mappings())
        except SQLAlchemyError as error:
            raise RetrievalDependencyError(_ERR_STORAGE) from error
        if len(rows) > candidate_limit:
            rows = rows[:candidate_limit]
        return tuple(_memory_item(row) for row in rows)


@dataclass(frozen=True, slots=True)
class SqliteCodeRevisionQuery:
    """Read latest revision observations only for authorized current Checkouts."""

    engine: AsyncEngine
    clock: Clock

    async def current_revisions(
        self,
        authorized_scope: AuthorizedScope,
    ) -> tuple[CodeRevision, ...]:
        """Return deterministic current Checkout revision coordinates."""
        checkout_ids = sorted(
            {value.value for member in authorized_scope.members for value in member.checkout_ids}
        )
        if not checkout_ids:
            return ()
        now = _micros(self.clock.now())
        try:
            async with self.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT o.repository_id,o.checkout_id,o.branch,o.head_commit,"
                                "o.observed_at FROM checkout_observations o "
                                "JOIN principals p ON p.id=:principal AND p.status='active' "
                                "JOIN brains b ON b.id=o.brain_id AND b.status='active' "
                                "WHERE o.brain_id=:brain AND o.checkout_id IN "
                                "(SELECT value FROM json_each(:checkouts)) "
                                "AND EXISTS (SELECT 1 FROM scope_grants g "
                                "WHERE g.principal_id=:principal AND g.brain_id=o.brain_id "
                                "AND g.role IN ('owner','admin','editor','reader','auditor') "
                                "AND g.valid_from<=:now AND "
                                "(g.valid_to IS NULL OR g.valid_to>:now) "
                                "AND (g.repository_id IS NULL OR g.repository_id=o.repository_id)) "
                                "AND o.aggregate_version=(SELECT MAX(latest.aggregate_version) "
                                "FROM checkout_observations latest "
                                "WHERE latest.brain_id=o.brain_id "
                                "AND latest.checkout_id=o.checkout_id) "
                                "ORDER BY o.repository_id,o.checkout_id"
                            ),
                            {
                                "brain": authorized_scope.brain_id.value,
                                "checkouts": json.dumps(checkout_ids),
                                "now": now,
                                "principal": authorized_scope.principal_id.value,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise RetrievalDependencyError(_ERR_STORAGE) from error
        return tuple(
            CodeRevision(
                str(row["repository_id"]),
                str(row["checkout_id"]),
                None if row["branch"] is None else str(row["branch"]),
                None if row["head_commit"] is None else str(row["head_commit"]),
                _time(row["observed_at"]),
            )
            for row in rows
        )


@dataclass(frozen=True, slots=True)
class SqliteContextInjectionRepository:
    """Reauthorize and atomically append a content-free ContextInjected event and receipt."""

    engine: AsyncEngine

    async def record(
        self,
        authorized_scope: AuthorizedScope,
        event: ContextInjectedEvent,
    ) -> str:
        """Persist once and return the first event ID for every exact retry."""
        if (
            event.brain_id != authorized_scope.brain_id.value
            or event.principal_id != authorized_scope.principal_id.value
            or event.scope_fingerprint != authorized_scope.scope_fingerprint
        ):
            raise RetrievalAuthorizationError(_ERR_AUTHORIZATION)
        members = [
            {"project_id": member.project_id.value, "repository_id": repository.value}
            for member in authorized_scope.members
            for repository in member.repository_ids
        ]
        parameters = {
            "brain": event.brain_id,
            "members": json.dumps(members, separators=(",", ":"), sort_keys=True),
            "now": _micros(event.occurred_at),
            "principal": event.principal_id,
        }
        try:
            async with self.engine.begin() as connection:
                authorized = (
                    await connection.execute(
                        text(
                            "SELECT CASE WHEN EXISTS (SELECT 1 FROM principals p "
                            "JOIN brains b ON b.id=:brain AND b.status='active' "
                            "WHERE p.id=:principal AND p.status='active') AND NOT EXISTS ("
                            "SELECT 1 FROM json_each(:members) member WHERE NOT EXISTS ("
                            "SELECT 1 FROM scope_grants g WHERE g.principal_id=:principal "
                            "AND g.brain_id=:brain AND g.role IN "
                            "('owner','admin','editor','reader','auditor') "
                            "AND g.valid_from<=:now AND (g.valid_to IS NULL OR g.valid_to>:now) "
                            "AND (g.project_id IS NULL OR g.project_id="
                            "json_extract(member.value,'$.project_id')) "
                            "AND (g.repository_id IS NULL OR g.repository_id="
                            "json_extract(member.value,'$.repository_id')))) THEN 1 ELSE 0 END"
                        ),
                        parameters,
                    )
                ).scalar_one()
                _require_authorized(authorized)
                existing = await _existing_receipt(connection, event.operation_id)
                if existing is not None:
                    return _canonical_retry_event_id(existing, event)
                await _insert_context_event(connection, event)
                return event.event_id
        except RetrievalAuthorizationError, RetrievalConflictError:
            raise
        except IntegrityError as error:
            try:
                async with self.engine.connect() as connection:
                    existing = await _existing_receipt(connection, event.operation_id)
            except SQLAlchemyError as read_error:
                raise RetrievalDependencyError(_ERR_STORAGE) from read_error
            if existing is not None and _receipt_matches(existing, event):
                return str(existing["event_id"])
            raise RetrievalConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise RetrievalDependencyError(_ERR_STORAGE) from error


async def _existing_receipt(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT operation_id,event_id,brain_id,principal_id,scope_fingerprint,"
                    "request_sha256,selected_json,budget_json,used_tokens,used_items,used_bytes,"
                    "truncated,status,policy_version,occurred_at FROM session_briefing_receipts "
                    "WHERE operation_id=:operation"
                ),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _receipt_matches(existing: RowMapping, event: ContextInjectedEvent) -> bool:
    return (
        str(existing["brain_id"]) == event.brain_id
        and str(existing["principal_id"]) == event.principal_id
        and _bytes(existing["scope_fingerprint"]).hex() == event.scope_fingerprint
        and _bytes(existing["request_sha256"]).hex() == event.request_sha256
        and str(existing["selected_json"]) == _selected_json(event)
        and str(existing["budget_json"]) == _budget_json(event)
        and int(str(existing["used_tokens"])) == event.used_tokens
        and int(str(existing["used_items"])) == event.used_items
        and int(str(existing["used_bytes"])) == event.used_bytes
        and bool(existing["truncated"]) is event.truncated
        and str(existing["status"]) == event.status.value
        and str(existing["policy_version"]) == event.policy_version
        and int(str(existing["occurred_at"])) == _micros(event.occurred_at)
    )


def _require_authorized(value: object) -> None:
    if int(str(value)) != 1:
        raise RetrievalAuthorizationError(_ERR_AUTHORIZATION)


def _canonical_retry_event_id(existing: RowMapping, event: ContextInjectedEvent) -> str:
    if not _receipt_matches(existing, event):
        raise RetrievalConflictError(_ERR_CONFLICT)
    return str(existing["event_id"])


async def _insert_context_event(
    connection: AsyncConnection,
    event: ContextInjectedEvent,
) -> None:
    now = _micros(event.occurred_at)
    selected_json = _selected_json(event)
    budget_json = _budget_json(event)
    await connection.execute(
        text(
            "INSERT INTO domain_events "
            "(event_id,brain_id,projection_type,stable_id,target_type,target_id_hash,payload_json,"
            "payload_hash,source_digest,missing_dependency,occurred_at,recorded_at,schema_version,"
            "aggregate_type,aggregate_id,aggregate_version,event_type,event_json,correlation_id,"
            "causation_id) VALUES (:event,:brain,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,:now,:now,"
            "1,'session_briefing',:operation,1,'ContextInjected',:event_json,:operation,NULL)"
        ),
        {
            "event": event.event_id,
            "brain": event.brain_id,
            "now": now,
            "operation": event.operation_id,
            "event_json": event.event_json,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO session_briefing_receipts "
            "(operation_id,event_id,brain_id,principal_id,scope_fingerprint,request_sha256,"
            "selected_json,event_sha256,budget_json,used_tokens,used_items,used_bytes,truncated,"
            "status,policy_version,occurred_at,schema_version) VALUES "
            "(:operation,:event,:brain,:principal,:scope,:request,:selected,:event_sha,:budget,"
            ":tokens,:items,:bytes,:truncated,:status,:policy,:now,1)"
        ),
        {
            "operation": event.operation_id,
            "event": event.event_id,
            "brain": event.brain_id,
            "principal": event.principal_id,
            "scope": bytes.fromhex(event.scope_fingerprint),
            "request": bytes.fromhex(event.request_sha256),
            "selected": selected_json,
            "event_sha": bytes.fromhex(event.event_sha256),
            "budget": budget_json,
            "tokens": event.used_tokens,
            "items": event.used_items,
            "bytes": event.used_bytes,
            "truncated": event.truncated,
            "status": event.status.value,
            "policy": event.policy_version,
            "now": now,
        },
    )


def _selected_json(event: ContextInjectedEvent) -> str:
    return json.dumps(
        [selection.document() for selection in event.selections],
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _budget_json(event: ContextInjectedEvent) -> str:
    return json.dumps(
        {
            "max_bytes": event.budget.max_bytes,
            "max_items": event.budget.max_items,
            "max_tokens": event.budget.max_tokens,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _memory_item(row: RowMapping) -> ContinuityItem:
    try:
        raw_content = cast("object", json.loads(str(row["content_json"])))
        raw_provenance = cast("object", json.loads(str(row["provenance_json"])))
        raw_evidence = cast("object", json.loads(str(row["evidence_json"])))
        if not isinstance(raw_content, dict):
            raise RetrievalIntegrityError(_ERR_MEMORY)
        content = cast("dict[object, object]", raw_content)
        if set(content) != {"statement"}:
            raise RetrievalIntegrityError(_ERR_MEMORY)
        statement = _string(content, "statement")
        if not isinstance(raw_provenance, dict):
            raise RetrievalIntegrityError(_ERR_MEMORY)
        provenance = cast("dict[object, object]", raw_provenance)
        raw_extractor = provenance.get("extractor")
        if not isinstance(raw_extractor, dict):
            raise RetrievalIntegrityError(_ERR_MEMORY)
        extractor = cast("dict[object, object]", raw_extractor)
        if not isinstance(raw_evidence, list):
            raise RetrievalIntegrityError(_ERR_MEMORY)
        evidence_values = cast("list[object]", raw_evidence)
        if not evidence_values or not all(isinstance(item, str) for item in evidence_values):
            raise RetrievalIntegrityError(_ERR_MEMORY)
        evidence_ids = cast("list[str]", evidence_values)
        memory_class = str(row["memory_class"])
        memory_id = str(row["id"])
        return ContinuityItem(
            item_id=f"memory:{memory_id}:revision:{int(str(row['current_revision']))}",
            semantic_id=f"memory:{memory_id}",
            kind=_MEMORY_CLASS_KIND[memory_class],
            content=statement,
            brain_id=str(row["brain_id"]),
            project_id=str(row["project_id"]),
            repository_id=str(row["repository_id"]),
            checkout_id=None if row["checkout_id"] is None else str(row["checkout_id"]),
            branch_name=None,
            commit_sha=None,
            occurred_at=_time(row["valid_from"]),
            ingested_at=_time(row["recorded_from"]),
            classification=str(row["classification"]),
            evidence_event_id=evidence_ids[0],
            provenance=ItemProvenance(
                "memory_consolidation",
                _string(extractor, "model_id"),
                _string(extractor, "extractor_id"),
                _string(extractor, "extractor_version"),
                "inferred",
            ),
            source_event_type="agentmemory.memory.consolidated.v1",
            source_task_id=str(row["source_task_id"]),
            source_memory_class=memory_class,
            source_memory_id=memory_id,
        )
    except (KeyError, TypeError, ValueError, RetrievalValidationError) as error:
        raise RetrievalIntegrityError(_ERR_MEMORY) from error


def _scope_parameters(scope: AuthorizedScope, now: int) -> dict[str, object]:
    ceiling = _CLASSIFICATIONS.index(scope.classification_ceiling.value)
    return {
        "brain": scope.brain_id.value,
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
        "now": now,
        "principal": scope.principal_id.value,
    }


def _string(document: dict[object, object], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str):
        raise RetrievalIntegrityError(_ERR_MEMORY)
    return value


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise RetrievalValidationError(_ERR_CLOCK)
    return round(value.timestamp() * 1_000_000)


def _time(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            value = int(str(value))
        except ValueError as error:
            raise RetrievalIntegrityError(_ERR_MEMORY) from error
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTES:
        raise RetrievalIntegrityError(_ERR_MEMORY)
    return value
