"""SQLite MEM-002 canonical memory repository and authorized explanation query."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, cast

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.memory.domain.consolidation import (
    ConfidenceDimensions,
    ExtractorIdentity,
    Memory,
    MemoryClass,
    MemoryProvenance,
    MemoryScope,
    MemoryStatus,
)
from agentmemory.memory.domain.errors import (
    MemoryDependencyError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from agentmemory.memory.domain.explanation import (
    EvidenceAvailability,
    MemoryEvidenceReference,
    MemoryExplanation,
    MemoryExplanationAccess,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
_DIGEST_BYTES = 32

_MEMORY_QUERY = """
SELECT
  m.*, r.content_json, r.provenance_json, r.created_by_event,
  c.actor_id AS provenance_actor_id,
  c.task_id AS provenance_task_id,
  c.source_terminal_event_id AS provenance_created_by_event,
  c.evidence_watermark_sha256 AS provenance_watermark,
  c.extractor_input_sha256 AS provenance_input,
  c.extractor_id AS provenance_extractor_id,
  c.extractor_version AS provenance_extractor_version,
  c.model_id AS provenance_model_id,
  c.model_revision AS provenance_model_revision,
  c.output_schema AS provenance_output_schema,
  c.extractor_fingerprint AS provenance_extractor_fingerprint,
  c.promotion_policy_version AS provenance_policy_version,
  c.classification AS provenance_classification,
  c.retention_policy_id AS provenance_retention
FROM memories AS m
JOIN memory_revisions AS r
  ON r.memory_id=m.id AND r.revision=m.current_revision
JOIN memory_consolidations AS c
  ON c.idempotency_key=m.consolidation_key
JOIN scope_grants AS g
  ON g.id=:grant AND g.principal_id=:actor AND g.brain_id=m.brain_id
 AND (g.project_id IS NULL OR g.project_id=m.project_id)
 AND (g.repository_id IS NULL OR g.repository_id=m.repository_id)
JOIN principals AS p ON p.id=g.principal_id AND p.status='active'
JOIN brains AS b ON b.id=g.brain_id AND b.status='active'
WHERE m.id=:memory AND m.brain_id=:brain
  AND g.role IN ('owner','admin','editor','reader','auditor','worker')
  AND g.valid_from<=:authorized_at
  AND (g.valid_to IS NULL OR g.valid_to>:authorized_at)
LIMIT 1
"""

_EVIDENCE_QUERY = """
SELECT me.event_id,me.canonical_event_sha256,
       e.event_id AS canonical_event_id,
       l.event_type,l.occurred_at,l.canonical_event_sha256 AS lineage_sha256
FROM memory_evidence AS me
LEFT JOIN agent_events AS e ON e.event_id=me.event_id
LEFT JOIN event_task_lineage AS l ON l.event_id=me.event_id
WHERE me.memory_id=:memory AND me.relation='supports'
ORDER BY me.event_id
"""


class SqliteMemoryRepository:
    """Reconstruct complete provenance only after one exact SQL authorization join."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local relational authority."""
        self._store = store

    async def explain_authorized(
        self,
        access: MemoryExplanationAccess,
    ) -> MemoryExplanation | None:
        """Hide unauthorized existence and authenticate every joined provenance coordinate."""
        parameters = {
            "memory": access.memory_id,
            "brain": access.brain_id,
            "actor": access.actor_id,
            "grant": access.grant_id,
            "authorized_at": _micros(access.authorized_at),
        }
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (await connection.execute(text(_MEMORY_QUERY), parameters))
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return None
                evidence_rows = list(
                    (
                        await connection.execute(
                            text(_EVIDENCE_QUERY),
                            {"memory": access.memory_id},
                        )
                    )
                    .mappings()
                    .all()
                )
                tombstones = await _tombstone_hashes(connection, access.brain_id)
        except SQLAlchemyError as error:
            raise MemoryDependencyError from error
        try:
            memory = _memory(row)
            evidence = _evidence(evidence_rows, tombstones)
            return MemoryExplanation.create(memory, evidence, access.valid_at, access.recorded_at)
        except (KeyError, TypeError, ValueError, MemoryValidationError) as error:
            raise MemoryIntegrityError from error


async def _tombstone_hashes(connection: AsyncConnection, brain_id: str) -> frozenset[bytes]:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT target_id_hash FROM deletion_tombstones "
                    "WHERE brain_id=:brain AND target_type='agent_event' "
                    "AND purge_state IN ('tombstoned','completed')"
                ),
                {"brain": brain_id},
            )
        )
        .scalars()
        .all()
    )
    return frozenset(_bytes(item) for item in rows)


def _memory(row: RowMapping) -> Memory:
    scope_document = _object(str(row["scope_json"]), "scope_json")
    brain_id = str(row["brain_id"])
    project_id = str(row["project_id"])
    repository_id = str(row["repository_id"])
    checkout_id = None if row["checkout_id"] is None else str(row["checkout_id"])
    expected_scope = {
        "brain_id": brain_id,
        "checkout_id": checkout_id,
        "project_id": project_id,
        "repository_id": repository_id,
    }
    if scope_document != expected_scope:
        raise MemoryIntegrityError
    confidence_document = _object(str(row["confidence_json"]), "confidence_json")
    _exact(
        confidence_document,
        {"evidence_support", "extraction_quality", "source_reliability"},
    )
    content_document = _object(str(row["content_json"]), "content_json")
    _exact(content_document, {"statement"})
    statement = _string(content_document, "statement")
    provenance = _provenance(row)
    memory = Memory.create(
        memory_id=str(row["id"]),
        memory_class=MemoryClass(str(row["memory_class"])),
        scope=MemoryScope(brain_id, project_id, repository_id, checkout_id),
        status=MemoryStatus(str(row["status"])),
        statement=statement,
        confidence=ConfidenceDimensions(
            _integer(confidence_document, "evidence_support"),
            _integer(confidence_document, "source_reliability"),
            _integer(confidence_document, "extraction_quality"),
        ),
        valid_from=_time(row["valid_from"]),
        valid_to=None if row["valid_to"] is None else _time(row["valid_to"]),
        recorded_from=_time(row["recorded_from"]),
        recorded_to=None if row["recorded_to"] is None else _time(row["recorded_to"]),
        provenance=provenance,
        classification=str(row["classification"]),
        retention_policy_id=str(row["retention_policy_id"]),
        aggregate_version=_row_integer(row, "aggregate_version"),
    )
    _cross_check(row, memory)
    return memory


def _provenance(row: RowMapping) -> MemoryProvenance:
    document = _object(str(row["provenance_json"]), "provenance_json")
    _exact(
        document,
        {
            "actor_id",
            "agent_id",
            "content_sha256",
            "created_by_event",
            "evidence_ids",
            "evidence_watermark_sha256",
            "extractor",
            "extractor_input_sha256",
            "promotion_policy_version",
            "source_task_id",
        },
    )
    extractor_document = document["extractor"]
    if not isinstance(extractor_document, dict):
        _invalid_json()
    extractor = extractor_document
    _exact(
        extractor,
        {
            "extractor_id",
            "extractor_version",
            "fingerprint",
            "model_id",
            "model_revision",
            "output_schema",
        },
    )
    identity = ExtractorIdentity(
        _string(extractor, "extractor_id"),
        _string(extractor, "extractor_version"),
        _string(extractor, "model_id"),
        _string(extractor, "model_revision"),
        _string(extractor, "output_schema"),
    )
    if _string(extractor, "fingerprint") != identity.fingerprint:
        raise MemoryIntegrityError
    evidence = document["evidence_ids"]
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        _invalid_json()
    provenance = MemoryProvenance(
        _string(document, "actor_id"),
        _string(document, "agent_id"),
        _string(document, "source_task_id"),
        _string(document, "created_by_event"),
        identity,
        tuple(cast("list[str]", evidence)),
        _string(document, "evidence_watermark_sha256"),
        _string(document, "extractor_input_sha256"),
        _string(document, "content_sha256"),
        _string(document, "promotion_policy_version"),
    )
    if _canonical_json(dict(provenance.canonical)).decode() != str(row["provenance_json"]):
        raise MemoryIntegrityError
    return provenance


def _cross_check(row: RowMapping, memory: Memory) -> None:
    provenance = memory.provenance
    comparisons = (
        (provenance.actor_id, str(row["provenance_actor_id"])),
        (provenance.source_task_id, str(row["source_task_id"])),
        (provenance.source_task_id, str(row["provenance_task_id"])),
        (provenance.created_by_event, str(row["created_by_event"])),
        (provenance.created_by_event, str(row["provenance_created_by_event"])),
        (provenance.extractor.extractor_id, str(row["provenance_extractor_id"])),
        (provenance.extractor.extractor_version, str(row["provenance_extractor_version"])),
        (provenance.extractor.model_id, str(row["provenance_model_id"])),
        (provenance.extractor.model_revision, str(row["provenance_model_revision"])),
        (provenance.extractor.output_schema, str(row["provenance_output_schema"])),
        (provenance.promotion_policy_version, str(row["provenance_policy_version"])),
        (memory.classification, str(row["provenance_classification"])),
        (memory.retention_policy_id, str(row["provenance_retention"])),
    )
    if any(left != right for left, right in comparisons):
        raise MemoryIntegrityError
    digest_comparisons = (
        (memory.content_sha256, row["content_hash"]),
        (provenance.evidence_watermark_sha256, row["provenance_watermark"]),
        (provenance.extractor_input_sha256, row["provenance_input"]),
        (provenance.extractor.fingerprint, row["extractor_fingerprint"]),
        (provenance.extractor.fingerprint, row["provenance_extractor_fingerprint"]),
    )
    if any(_bytes(value).hex() != expected for expected, value in digest_comparisons):
        raise MemoryIntegrityError


def _evidence(
    rows: Sequence[RowMapping],
    tombstones: frozenset[bytes],
) -> tuple[MemoryEvidenceReference, ...]:
    result: list[MemoryEvidenceReference] = []
    for row in rows:
        event_id = str(row["event_id"])
        digest = _bytes(row["canonical_event_sha256"])
        purged = hashlib.sha256(event_id.encode()).digest() in tombstones
        missing = row["canonical_event_id"] is None or row["event_type"] is None
        if purged:
            availability = EvidenceAvailability.PURGED
        elif missing:
            availability = EvidenceAvailability.MISSING
        else:
            availability = EvidenceAvailability.AVAILABLE
            if digest != _bytes(row["lineage_sha256"]):
                raise MemoryIntegrityError
        available = availability is EvidenceAvailability.AVAILABLE
        result.append(
            MemoryEvidenceReference(
                event_id,
                digest.hex(),
                availability,
                str(row["event_type"]) if available else None,
                _time(row["occurred_at"]) if available else None,
                f"memory://evidence/{event_id}" if available else None,
            )
        )
    return tuple(result)


def _object(value: str, _field: str) -> dict[str, JsonValue]:
    def pairs(items: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        document: dict[str, JsonValue] = {}
        for key, item in items:
            if key in document:
                raise MemoryIntegrityError
            document[key] = item
        return document

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda _value: _invalid_json(),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MemoryIntegrityError from error
    if not isinstance(parsed, dict):
        raise MemoryIntegrityError
    document = cast("dict[str, JsonValue]", parsed)
    if _canonical_json(document).decode() != value:
        raise MemoryIntegrityError
    return document


def _canonical_json(value: JsonValue) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _exact(document: Mapping[str, JsonValue], expected: set[str]) -> None:
    if set(document) != expected:
        _invalid_json()


def _string(document: Mapping[str, JsonValue], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        _invalid_json()
    return value


def _integer(document: Mapping[str, JsonValue], field: str) -> int:
    value = document[field]
    if not isinstance(value, int) or isinstance(value, bool):
        _invalid_json()
    return value


def _row_integer(row: RowMapping, field: str) -> int:
    value = row[field]
    if not isinstance(value, int) or isinstance(value, bool):
        raise MemoryIntegrityError
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MemoryIntegrityError
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        field = "authorized_at"
        raise MemoryValidationError.single(field, "not_utc")
    return round(value.timestamp() * 1_000_000)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTES:
        raise MemoryIntegrityError
    return value


def _invalid_json() -> Never:
    raise MemoryIntegrityError
