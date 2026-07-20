"""MEM-002 canonical provenance and replayable MemoryProjected sources.

Revision ID: 0016_mem002_memory_provenance
Revises: 0015_mem001_memory_consolidation
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Never, cast

import sqlalchemy as sa
from alembic import op

revision = "0016_mem002_memory_provenance"
down_revision = "0015_mem001_memory_consolidation"
branch_labels = None
depends_on = None

_OLD_FIELDS = {
    "created_by_event",
    "evidence_ids",
    "extractor",
    "promotion_policy_version",
    "source_task_id",
    "evidence_watermark_sha256",
}
_NEW_FIELDS = {
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
}
_EXTRACTOR_FIELDS = {
    "extractor_id",
    "extractor_version",
    "fingerprint",
    "model_id",
    "model_revision",
    "output_schema",
}
_DIGEST_BYTES = 32


def upgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            "SELECT r.memory_id,r.provenance_json,r.content_hash,c.actor_id,c.task_id,"
            "c.source_terminal_event_id,c.evidence_watermark_sha256,c.extractor_input_sha256,"
            "c.extractor_id,c.extractor_version,c.model_id,c.model_revision,c.output_schema,"
            "c.extractor_fingerprint,c.promotion_policy_version "
            "FROM memory_revisions r JOIN memories m ON m.id=r.memory_id "
            "JOIN memory_consolidations c ON c.idempotency_key=m.consolidation_key"
        )
    ).mappings()
    provenance_by_memory: dict[str, dict[str, Any]] = {}
    for row in rows:
        memory_id = str(row["memory_id"])
        provenance = _upgrade_provenance(dict(row))
        provenance_by_memory[memory_id] = provenance
        connection.execute(
            sa.text(
                "UPDATE memory_revisions SET provenance_json=:provenance,schema_version=2 "
                "WHERE memory_id=:memory"
            ),
            {"provenance": _canonical(provenance), "memory": memory_id},
        )

    events = connection.execute(
        sa.text(
            "SELECT event_id,aggregate_id,event_json FROM domain_events "
            "WHERE aggregate_type='memory'"
        )
    ).mappings()
    for event in events:
        _upgrade_projection_event(connection, dict(event), provenance_by_memory)

    op.create_index(
        "ix_memory_evidence_explain",
        "memory_evidence",
        ["memory_id", "relation", "event_id"],
    )
    op.execute(
        "CREATE TRIGGER memory_revision_provenance_no_update "
        "BEFORE UPDATE OF provenance_json ON memory_revisions BEGIN "
        "SELECT RAISE(ABORT, 'memory provenance is immutable'); END"
    )


def downgrade() -> None:
    connection = op.get_bind()
    count = connection.execute(sa.text("SELECT COUNT(*) FROM memory_revisions")).scalar_one()
    if count:
        msg = "MEM-002 downgrade refused while canonical memory provenance exists"
        raise RuntimeError(msg)
    op.execute("DROP TRIGGER memory_revision_provenance_no_update")
    op.drop_index("ix_memory_evidence_explain", table_name="memory_evidence")


def _upgrade_provenance(row: dict[str, Any]) -> dict[str, Any]:
    existing = _strict_object(str(row["provenance_json"]))
    extractor = _extractor(row)
    expected_old = {
        "created_by_event": str(row["source_terminal_event_id"]),
        "evidence_ids": existing.get("evidence_ids"),
        "extractor": extractor,
        "promotion_policy_version": str(row["promotion_policy_version"]),
        "source_task_id": str(row["task_id"]),
        "evidence_watermark_sha256": _digest(row["evidence_watermark_sha256"]),
    }
    if set(existing) == _OLD_FIELDS:
        if existing != expected_old:
            _fail("legacy memory provenance diverged during MEM-002 upgrade")
    elif set(existing) == _NEW_FIELDS:
        expected_new = _new_provenance(row, extractor, existing.get("evidence_ids"))
        if existing != expected_new:
            _fail("current memory provenance diverged during MEM-002 upgrade")
    else:
        _fail("memory provenance schema is unsupported during MEM-002 upgrade")
    return _new_provenance(row, extractor, existing.get("evidence_ids"))


def _extractor(row: dict[str, Any]) -> dict[str, Any]:
    result = {
        "extractor_id": str(row["extractor_id"]),
        "extractor_version": str(row["extractor_version"]),
        "fingerprint": _digest(row["extractor_fingerprint"]),
        "model_id": str(row["model_id"]),
        "model_revision": str(row["model_revision"]),
        "output_schema": str(row["output_schema"]),
    }
    if set(result) != _EXTRACTOR_FIELDS:
        _fail("extractor provenance is incomplete")
    return result


def _new_provenance(
    row: dict[str, Any],
    extractor: dict[str, Any],
    evidence: object,
) -> dict[str, Any]:
    if (
        not isinstance(evidence, list)
        or not evidence
        or not all(isinstance(item, str) for item in evidence)
    ):
        _fail("memory evidence provenance is invalid")
    return {
        "actor_id": str(row["actor_id"]),
        "agent_id": str(row["extractor_id"]),
        "content_sha256": _digest(row["content_hash"]),
        "created_by_event": str(row["source_terminal_event_id"]),
        "evidence_ids": cast("list[str]", evidence),
        "evidence_watermark_sha256": _digest(row["evidence_watermark_sha256"]),
        "extractor": extractor,
        "extractor_input_sha256": _digest(row["extractor_input_sha256"]),
        "promotion_policy_version": str(row["promotion_policy_version"]),
        "source_task_id": str(row["task_id"]),
    }


def _upgrade_projection_event(
    connection: sa.Connection,
    event: dict[str, Any],
    provenance_by_memory: dict[str, dict[str, Any]],
) -> None:
    memory_id = str(event["aggregate_id"])
    provenance = provenance_by_memory.get(memory_id)
    if provenance is None:
        _fail("memory projection has no canonical provenance")
    document = _strict_object(str(event["event_json"]))
    if document.get("memory_id") != memory_id:
        _fail("memory projection identity diverged")
    document["provenance"] = provenance
    payload = _canonical(document)
    content_sha256 = document.get("content_sha256")
    if not isinstance(content_sha256, str):
        _fail("memory projection content hash is missing")
    source = _canonical(
        {
            "content_sha256": content_sha256,
            "created_by_event": provenance["created_by_event"],
            "memory_id": memory_id,
            "provenance_sha256": hashlib.sha256(_canonical(provenance).encode()).hexdigest(),
        }
    )
    connection.execute(
        sa.text(
            "UPDATE domain_events SET projection_type='graph',stable_id=:stable,"
            "target_type='memory',target_id_hash=:target,payload_json=:payload,"
            "payload_hash=:payload_hash,source_digest=:source,event_type='MemoryProjected',"
            "event_json=:payload,schema_version=2 WHERE event_id=:event"
        ),
        {
            "stable": memory_id,
            "target": hashlib.sha256(memory_id.encode()).digest(),
            "payload": payload,
            "payload_hash": hashlib.sha256(payload.encode()).digest(),
            "source": hashlib.sha256(source.encode()).digest(),
            "event": str(event["event_id"]),
        },
    )


def _strict_object(value: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                _fail("duplicate key in memory provenance")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda _value: _fail("nonfinite memory provenance"),
        )
    except json.JSONDecodeError:
        _fail("invalid memory provenance JSON")
    if not isinstance(parsed, dict) or _canonical(parsed) != value:
        _fail("memory provenance is not canonical JSON")
    return cast("dict[str, Any]", parsed)


def _digest(value: object) -> str:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTES:
        _fail("memory provenance digest is invalid")
    return value.hex()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _fail(message: str) -> Never:
    raise RuntimeError(message)
