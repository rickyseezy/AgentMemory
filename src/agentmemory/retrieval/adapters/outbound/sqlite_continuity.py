"""Authorized decryption and projection of ADP-006 canonical continuity events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.ingestion.adapters.inbound.agent_event_schema import parse_agent_event_json
from agentmemory.ingestion.adapters.outbound.envelope_crypto import decrypt_agent_event
from agentmemory.ingestion.domain.capture import EncryptedAgentEvent
from agentmemory.ingestion.domain.errors import IngestionDependencyError, IngestionValidationError
from agentmemory.retrieval.domain.continuity import (
    ContinuityItem,
    ContinuityKind,
    ItemProvenance,
)
from agentmemory.retrieval.domain.errors import (
    RetrievalDependencyError,
    RetrievalIntegrityError,
    RetrievalValidationError,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncEngine

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.ingestion.adapters.outbound.envelope_crypto import BrainKeyProvider
    from agentmemory.ingestion.domain.agent_event import AgentEvent, JsonValue
    from agentmemory.retrieval.domain.continuity import ProcedureCandidate
    from agentmemory.shared.clock import Clock

_MAX_CANDIDATES = 200
_MAX_EVENT_ITEMS = 32
_CONTINUITY_KEYS = frozenset({"schema_version", "items"})
_ITEM_KEYS = frozenset({"semantic_id", "kind", "content"})
_ERR_CANDIDATE_LIMIT = "continuity candidate limit is invalid"
_ERR_PROCEDURE_LIMIT = "procedure candidate limit is invalid"
_ERR_STORAGE = "continuity storage is unavailable"
_ERR_KEY_ACCESS = "continuity key access is unavailable"
_ERR_KEY_RESULT = "continuity key result was invalid"
_ERR_KEY_IDENTITY = "continuity Brain key identity diverged"
_ERR_EVENT_VERIFICATION = "continuity canonical event failed verification"
_ERR_INDEX_DIVERGED = "continuity canonical index diverged"
_ERR_PAYLOAD = "continuity payload was invalid"
_ERR_PROJECTION = "continuity event projection was malformed"
_ERR_ITEM_MALFORMED = "continuity event item was malformed"
_ERR_ITEM_INVALID = "continuity event item was invalid"
_ERR_SEMANTIC_DUPLICATE = "continuity event semantic identity was duplicated"
_ERR_BINARY = "continuity binary storage was malformed"
_ALLOWED_EVENT_TYPES = frozenset(
    {
        "agentmemory.session.completed.v1",
        "agentmemory.task.started.v1",
        "agentmemory.task.checkpointed.v1",
        "agentmemory.task.completed.v1",
        "agentmemory.tool.failed.v1",
        "agentmemory.file.changed.v1",
        "agentmemory.command.completed.v1",
        "agentmemory.test.completed.v1",
    }
)

_AUTHORIZED_EVENTS = """
SELECT e.event_id, e.brain_id, e.type, e.classification, e.occurred_at, e.ingested_at,
       x.project_id, x.repository_id, x.checkout_id, x.envelope_version, x.algorithm,
       x.brain_key_id, x.data_key_id, x.payload_nonce, x.ciphertext,
       x.wrapped_data_key_nonce, x.wrapped_data_key, x.aad_sha256, x.canonical_sha256
FROM agent_events AS e
JOIN agent_event_envelopes AS x ON x.event_id = e.event_id
WHERE e.brain_id = :brain_id
  AND e.type IN (SELECT value FROM json_each(:event_types))
  AND e.classification IN (SELECT value FROM json_each(:classifications))
  AND (:temporal_from IS NULL OR e.occurred_at >= :temporal_from)
  AND (:temporal_to IS NULL OR e.occurred_at < :temporal_to)
  AND EXISTS (
    SELECT 1 FROM scope_grants AS active_grant
    JOIN principals AS principal ON principal.id = active_grant.principal_id
    JOIN brains AS brain ON brain.id = active_grant.brain_id
    WHERE active_grant.principal_id = :principal_id
      AND active_grant.brain_id = e.brain_id
      AND active_grant.role IN ('owner','admin','editor','reader')
      AND active_grant.valid_from <= :now
      AND (active_grant.valid_to IS NULL OR active_grant.valid_to > :now)
      AND (active_grant.project_id IS NULL OR active_grant.project_id = x.project_id)
      AND (active_grant.repository_id IS NULL OR active_grant.repository_id = x.repository_id)
      AND principal.status = 'active' AND brain.status = 'active'
  )
  AND EXISTS (
    SELECT 1 FROM json_each(:members) AS member
    WHERE json_extract(member.value, '$.project_id') = x.project_id
      AND x.repository_id IN (
        SELECT value FROM json_each(json_extract(member.value, '$.repository_ids'))
      )
      AND (
        json_array_length(json_extract(member.value, '$.checkout_ids')) = 0
        OR x.checkout_id IN (
          SELECT value FROM json_each(json_extract(member.value, '$.checkout_ids'))
        )
      )
  )
ORDER BY e.occurred_at DESC, e.event_id
LIMIT :candidate_limit
"""

_CLASSIFICATIONS = (
    "public",
    "internal",
    "confidential",
    "restricted",
    "local_only",
)


@dataclass(frozen=True, slots=True)
class SqliteContinuityReadRepository:
    """Read scoped canonical events and expose authenticated continuity atoms."""

    engine: AsyncEngine
    keys: BrainKeyProvider
    clock: Clock

    async def list_items(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ContinuityItem, ...]:
        """Authorize in SQL, exclude tombstones, decrypt, validate, and map events."""
        if not 1 <= candidate_limit <= _MAX_CANDIDATES:
            raise RetrievalValidationError(_ERR_CANDIDATE_LIMIT)
        try:
            async with self.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(_AUTHORIZED_EVENTS),
                            _query_parameters(
                                authorized_scope,
                                candidate_limit,
                                round(self.clock.now().timestamp() * 1_000_000),
                            ),
                        )
                    )
                    .mappings()
                    .all()
                )
                tombstones = (
                    (
                        await connection.execute(
                            text(
                                "SELECT target_type,target_id_hash FROM deletion_tombstones "
                                "WHERE brain_id=:brain_id AND target_type IN "
                                "('agent_event','continuity_item')"
                            ),
                            {"brain_id": authorized_scope.brain_id.value},
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise RetrievalDependencyError(_ERR_STORAGE) from error
        try:
            brain_key = await self.keys.current(authorized_scope.brain_id.value)
        except IngestionDependencyError as error:
            raise RetrievalDependencyError(_ERR_KEY_ACCESS) from error
        deleted = {(str(row["target_type"]), _bytes(row["target_id_hash"])) for row in tombstones}
        result: list[ContinuityItem] = []
        for row in rows:
            event_id = str(row["event_id"])
            if ("agent_event", hashlib.sha256(event_id.encode()).digest()) in deleted:
                continue
            event = _decrypt_event(row, brain_key)
            mapped = project_continuity_event(event, int(str(row["ingested_at"])))
            result.extend(
                item
                for item in mapped
                if (
                    "continuity_item",
                    hashlib.sha256(item.item_id.encode()).digest(),
                )
                not in deleted
            )
        return tuple(result)


@dataclass(frozen=True, slots=True)
class EmptyProcedureReadRepository:
    """Explicit empty adapter until governed procedure projection stories are active."""

    async def list_candidates(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ProcedureCandidate, ...]:
        """Return no procedure without weakening or changing memory authorization."""
        del authorized_scope
        if not 1 <= candidate_limit <= _MAX_CANDIDATES:
            raise RetrievalValidationError(_ERR_PROCEDURE_LIMIT)
        return ()


def _query_parameters(scope: AuthorizedScope, candidate_limit: int, now: int) -> dict[str, object]:
    ceiling = _CLASSIFICATIONS.index(scope.classification_ceiling.value)
    members = [
        {
            "checkout_ids": [value.value for value in member.checkout_ids],
            "project_id": member.project_id.value,
            "repository_ids": [value.value for value in member.repository_ids],
        }
        for member in scope.members
    ]
    return {
        "brain_id": scope.brain_id.value,
        "candidate_limit": candidate_limit,
        "classifications": json.dumps(_CLASSIFICATIONS[: ceiling + 1]),
        "event_types": json.dumps(sorted(_ALLOWED_EVENT_TYPES)),
        "members": json.dumps(members, separators=(",", ":"), sort_keys=True),
        "now": now,
        "principal_id": scope.principal_id.value,
        "temporal_from": scope.temporal_scope.valid_from,
        "temporal_to": scope.temporal_scope.valid_to,
    }


def _decrypt_event(row: RowMapping, brain_key: object) -> AgentEvent:
    from agentmemory.ingestion.adapters.outbound.envelope_crypto import (  # noqa: PLC0415
        BrainEncryptionKey,
    )

    if not isinstance(brain_key, BrainEncryptionKey):
        raise RetrievalIntegrityError(_ERR_KEY_RESULT)
    event_id = str(row["event_id"])
    brain_id = str(row["brain_id"])
    classification = str(row["classification"])
    encrypted = EncryptedAgentEvent(
        int(str(row["envelope_version"])),
        str(row["algorithm"]),
        str(row["brain_key_id"]),
        str(row["data_key_id"]),
        _bytes(row["payload_nonce"]),
        _bytes(row["ciphertext"]),
        _bytes(row["wrapped_data_key_nonce"]),
        _bytes(row["wrapped_data_key"]),
        _bytes(row["aad_sha256"]).hex(),
        _bytes(row["canonical_sha256"]).hex(),
    )
    if brain_key.key_id != encrypted.brain_key_id:
        raise RetrievalIntegrityError(_ERR_KEY_IDENTITY)
    try:
        raw = decrypt_agent_event(
            encrypted,
            brain_key,
            event_id=event_id,
            brain_id=brain_id,
            classification=classification,
        )
        event = parse_agent_event_json(raw)
    except (IngestionDependencyError, IngestionValidationError) as error:
        raise RetrievalIntegrityError(_ERR_EVENT_VERIFICATION) from error
    if (
        event.event_id != event_id
        or event.identity.brain_id != brain_id
        or event.identity.project_id != str(row["project_id"])
        or event.identity.repository_id != str(row["repository_id"])
        or event.identity.checkout_id
        != (None if row["checkout_id"] is None else str(row["checkout_id"]))
        or event.event_type.value != str(row["type"])
        or event.classification.value != classification
        or round(event.occurred_at.timestamp() * 1_000_000) != int(str(row["occurred_at"]))
    ):
        raise RetrievalIntegrityError(_ERR_INDEX_DIVERGED)
    return event


def project_continuity_event(
    event: AgentEvent, ingested_at_microseconds: int
) -> tuple[ContinuityItem, ...]:
    """Map one verified canonical event into deterministic atomic continuity items."""
    if event.payload is None:
        return ()
    try:
        payload = cast("JsonValue", json.loads(event.payload.value))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RetrievalIntegrityError(_ERR_PAYLOAD) from error
    if not isinstance(payload, dict) or "continuity" not in payload:
        return ()
    continuity = payload["continuity"]
    continuity_items = continuity.get("items") if isinstance(continuity, dict) else None
    if (
        not isinstance(continuity, dict)
        or frozenset(continuity) != _CONTINUITY_KEYS
        or continuity.get("schema_version") != 1
        or not isinstance(continuity_items, list)
        or not 1 <= len(continuity_items) <= _MAX_EVENT_ITEMS
    ):
        raise RetrievalIntegrityError(_ERR_PROJECTION)
    raw_items = cast("list[object]", continuity_items)
    result: list[ContinuityItem] = []
    semantic_ids: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, dict):
            raise RetrievalIntegrityError(_ERR_ITEM_MALFORMED)
        item_document = cast("dict[str, JsonValue]", raw_item)
        if frozenset(item_document) != _ITEM_KEYS:
            raise RetrievalIntegrityError(_ERR_ITEM_MALFORMED)
        try:
            semantic_id = cast("str", item_document["semantic_id"])
            item = ContinuityItem(
                item_id=f"{event.event_id}:{index}",
                semantic_id=semantic_id,
                kind=ContinuityKind(cast("str", item_document["kind"])),
                content=cast("str", item_document["content"]),
                brain_id=event.identity.brain_id,
                project_id=event.identity.project_id,
                repository_id=event.identity.repository_id,
                checkout_id=event.identity.checkout_id,
                branch_name=event.identity.branch_name,
                commit_sha=event.identity.commit_sha,
                occurred_at=event.occurred_at,
                ingested_at=datetime.fromtimestamp(ingested_at_microseconds / 1_000_000, tz=UTC),
                classification=event.classification.value,
                evidence_event_id=event.event_id,
                provenance=ItemProvenance(
                    event.provenance.agent_host,
                    event.provenance.model_id,
                    event.provenance.adapter_id,
                    event.provenance.adapter_version,
                    event.provenance.capture_method.value,
                ),
                source_event_type=event.event_type.value,
                source_session_id=event.provenance.session_id,
                source_task_id=event.provenance.task_id,
            )
        except (KeyError, TypeError, ValueError, RetrievalValidationError) as error:
            raise RetrievalIntegrityError(_ERR_ITEM_INVALID) from error
        if semantic_id in semantic_ids:
            raise RetrievalIntegrityError(_ERR_SEMANTIC_DUPLICATE)
        semantic_ids.add(semantic_id)
        result.append(item)
    return tuple(result)


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise RetrievalIntegrityError(_ERR_BINARY)
    return value
