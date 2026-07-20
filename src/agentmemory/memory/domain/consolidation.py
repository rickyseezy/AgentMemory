"""MEM-001 bounded evidence, strict candidates, promotion, and active memory."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Never, cast
from uuid import UUID

from agentmemory.memory.domain.errors import MemoryValidationError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_EVENT_TYPE = re.compile(r"^agentmemory\.[a-z0-9._-]{1,180}\.v[1-9][0-9]*$")
_MAX_EVIDENCE_ITEMS = 256
_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_EVENT_BYTES = 65_536
_MAX_CANDIDATE_DOCUMENT_BYTES = 256 * 1024
_MAX_CANDIDATES = 32
_MAX_STATEMENT_CHARACTERS = 8_192
_MAX_EVIDENCE_PER_CANDIDATE = 64
_MAX_MODEL_TEXT = 256
_MAX_CONFIDENCE = 10_000
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL = 127
_TERMINAL_EVENTS = frozenset(
    {
        "agentmemory.task.checkpointed.v1",
        "agentmemory.task.completed.v1",
    }
)
_EXPLICIT_PREFERENCE_EVENTS = frozenset(
    {
        "agentmemory.prompt.received.v1",
        "agentmemory.feedback.recorded.v1",
        "agentmemory.memory.feedback.recorded.v1",
    }
)
_LESSON_EVIDENCE_EVENTS = frozenset(
    {
        "agentmemory.outcome.observed.v1",
        "agentmemory.test.completed.v1",
        "agentmemory.tool.failed.v1",
        "agentmemory.incident.recorded.v1",
    }
)
_CLASSIFICATION_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "local_only": 4,
}

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class MemoryClass(StrEnum):
    """Closed useful long-term memory taxonomy."""

    DECISION = "decision"
    CONSTRAINT = "constraint"
    PROCEDURE = "procedure"
    PREFERENCE = "preference"
    LESSON = "lesson"
    EPISODE = "episode"
    UNRESOLVED_WORK = "unresolved_work"


class MemoryStatus(StrEnum):
    """MEM-001 reachable states from the normative Memory lifecycle."""

    ACTIVE = "active"


class PromotionDisposition(StrEnum):
    """Closed outcome of policy evaluation outside the extractor model."""

    PROMOTE = "promote"
    REJECT = "reject"


@dataclass(frozen=True, slots=True, order=True)
class MemoryScope:
    """Exact Brain/project/repository/checkout authority for one memory."""

    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None

    def __post_init__(self) -> None:
        """Require canonical UUIDv7 identities at every declared level."""
        _require_uuid7(self.brain_id, "scope.brain_id")
        _require_uuid7(self.project_id, "scope.project_id")
        _require_uuid7(self.repository_id, "scope.repository_id")
        if self.checkout_id is not None:
            _require_uuid7(self.checkout_id, "scope.checkout_id")

    @property
    def canonical(self) -> Mapping[str, JsonValue]:
        """Return the closed deterministic scope document."""
        return MappingProxyType(
            {
                "brain_id": self.brain_id,
                "checkout_id": self.checkout_id,
                "project_id": self.project_id,
                "repository_id": self.repository_id,
            }
        )


@dataclass(frozen=True, slots=True)
class ConfidenceDimensions:
    """Integer basis-point confidence components with no floating ambiguity."""

    evidence_support: int
    source_reliability: int
    extraction_quality: int

    def __post_init__(self) -> None:
        """Keep every dimension within inclusive 0..10000 basis points."""
        for value, field in (
            (self.evidence_support, "confidence.evidence_support"),
            (self.source_reliability, "confidence.source_reliability"),
            (self.extraction_quality, "confidence.extraction_quality"),
        ):
            if isinstance(value, bool) or not 0 <= value <= _MAX_CONFIDENCE:
                _invalid(field, "out_of_range")

    @property
    def canonical(self) -> Mapping[str, JsonValue]:
        """Return stable structured confidence evidence."""
        return MappingProxyType(
            {
                "evidence_support": self.evidence_support,
                "extraction_quality": self.extraction_quality,
                "source_reliability": self.source_reliability,
            }
        )


@dataclass(frozen=True, slots=True)
class ExtractorIdentity:
    """Exact extractor, model revision, and output contract identity."""

    extractor_id: str
    extractor_version: str
    model_id: str
    model_revision: str
    output_schema: str

    def __post_init__(self) -> None:
        """Reject mutable/latest model identities and ambiguous versions."""
        _require_token(self.extractor_id, "extractor.extractor_id")
        if _SEMVER.fullmatch(self.extractor_version) is None:
            _invalid("extractor.extractor_version", "invalid_semver")
        _require_bounded_text(self.model_id, "extractor.model_id", _MAX_MODEL_TEXT)
        _require_token(self.model_revision, "extractor.model_revision")
        if self.output_schema != "memory-candidates.v1":
            _invalid("extractor.output_schema", "unsupported")

    @property
    def fingerprint(self) -> str:
        """Bind every implementation/model/schema coordinate for idempotency."""
        return hashlib.sha256(
            _canonical_json(
                {
                    "extractor_id": self.extractor_id,
                    "extractor_version": self.extractor_version,
                    "model_id": self.model_id,
                    "model_revision": self.model_revision,
                    "output_schema": self.output_schema,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class TaskEvidence:
    """One sanitized canonical event projection supplied to extraction."""

    event_id: str
    task_id: str
    scope: MemoryScope
    event_type: str
    occurred_at: datetime
    classification: str
    retention_policy_id: str
    payload: bytes
    payload_sha256: str
    canonical_event_sha256: str

    def __post_init__(self) -> None:
        """Authenticate bounded canonical JSON and immutable event lineage."""
        _require_uuid7(self.event_id, "evidence.event_id")
        _require_uuid7(self.task_id, "evidence.task_id")
        if _EVENT_TYPE.fullmatch(self.event_type) is None:
            _invalid("evidence.event_type", "invalid")
        _require_utc(self.occurred_at, "evidence.occurred_at")
        if self.classification not in _CLASSIFICATION_ORDER:
            _invalid("evidence.classification", "unsupported")
        _require_token(self.retention_policy_id, "evidence.retention_policy_id")
        _require_digest(self.payload_sha256, "evidence.payload_sha256")
        _require_digest(self.canonical_event_sha256, "evidence.canonical_event_sha256")
        if not self.payload or len(self.payload) > _MAX_EVENT_BYTES:
            _invalid("evidence.payload", "size_invalid")
        if hashlib.sha256(self.payload).hexdigest() != self.payload_sha256:
            _invalid("evidence.payload_sha256", "mismatch")
        parsed = _decode_json(self.payload, "evidence.payload", _MAX_EVENT_BYTES)
        if _canonical_json(parsed) != self.payload:
            _invalid("evidence.payload", "non_canonical")

    @property
    def extractor_record(self) -> Mapping[str, JsonValue]:
        """Expose minimum sanitized model input while retaining source identity."""
        return MappingProxyType(
            {
                "event_id": self.event_id,
                "event_type": self.event_type,
                "occurred_at": _format_time(self.occurred_at),
                "payload": _decode_json(self.payload, "evidence.payload", _MAX_EVENT_BYTES),
                "payload_sha256": self.payload_sha256,
            }
        )


@dataclass(frozen=True, slots=True)
class TaskEvidenceBundle:
    """One bounded ordered terminal task evidence snapshot."""

    task_id: str
    scope: MemoryScope
    evidence: tuple[TaskEvidence, ...]
    terminal_event_id: str
    terminal_occurred_at: datetime
    watermark_sha256: str
    extractor_input_bytes: bytes
    extractor_input_sha256: str
    classification: str
    retention_policy_id: str

    @classmethod
    def create(
        cls,
        task_id: str,
        scope: MemoryScope,
        evidence: Sequence[TaskEvidence],
    ) -> TaskEvidenceBundle:
        """Validate and snapshot a completed/checkpointed task deterministically."""
        _require_uuid7(task_id, "task_id")
        items = tuple(evidence)
        if not items or len(items) > _MAX_EVIDENCE_ITEMS:
            _invalid("evidence", "count_invalid")
        if sum(len(item.payload) for item in items) > _MAX_EVIDENCE_BYTES:
            _invalid("evidence", "bytes_exceeded")
        if any(item.task_id != task_id or item.scope != scope for item in items):
            _invalid("evidence", "scope_mismatch")
        ordered = tuple(sorted(items, key=lambda item: (item.occurred_at, item.event_id)))
        if ordered != items or len({item.event_id for item in items}) != len(items):
            _invalid("evidence", "not_canonical")
        terminal = items[-1]
        if terminal.event_type not in _TERMINAL_EVENTS:
            _invalid("evidence", "terminal_required")
        retentions = {item.retention_policy_id for item in items}
        if len(retentions) != 1:
            _invalid("evidence", "retention_mismatch")
        classification = max(
            (item.classification for item in items),
            key=_CLASSIFICATION_ORDER.__getitem__,
        )
        watermark = derive_evidence_watermark(
            tuple((item.event_id, item.event_type, item.canonical_event_sha256) for item in items)
        )
        extractor_input = _canonical_json(
            {
                "evidence": [dict(item.extractor_record) for item in items],
                "scope": dict(scope.canonical),
                "task_id": task_id,
                "terminal_event_id": terminal.event_id,
                "watermark_sha256": watermark,
            }
        )
        return cls(
            task_id,
            scope,
            items,
            terminal.event_id,
            terminal.occurred_at,
            watermark,
            extractor_input,
            hashlib.sha256(extractor_input).hexdigest(),
            classification,
            next(iter(retentions)),
        )

    @property
    def evidence_by_id(self) -> Mapping[str, TaskEvidence]:
        """Return immutable exact evidence lookup for policy decisions."""
        return MappingProxyType({item.event_id: item for item in self.evidence})


@dataclass(frozen=True, slots=True)
class MemoryCandidate:
    """One schema-valid model proposal that has no write authority."""

    candidate_key: str
    memory_class: MemoryClass
    statement: str
    scope: MemoryScope
    confidence: ConfidenceDimensions
    valid_from: datetime
    valid_to: datetime | None
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require canonical useful content, temporal bounds, and source references."""
        _require_token(self.candidate_key, "candidate.candidate_key")
        _require_bounded_text(
            self.statement,
            "candidate.statement",
            _MAX_STATEMENT_CHARACTERS,
        )
        if self.statement != unicodedata.normalize("NFC", self.statement).strip():
            _invalid("candidate.statement", "non_canonical")
        _require_utc(self.valid_from, "candidate.valid_from")
        if self.valid_to is not None:
            _require_utc(self.valid_to, "candidate.valid_to")
            if self.valid_to <= self.valid_from:
                _invalid("candidate.valid_to", "not_after_start")
        if (
            not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE_PER_CANDIDATE
            or tuple(sorted(set(self.evidence_ids))) != self.evidence_ids
        ):
            _invalid("candidate.evidence_ids", "not_canonical")
        for event_id in self.evidence_ids:
            _require_uuid7(event_id, "candidate.evidence_ids")

    @property
    def canonical_content(self) -> bytes:
        """Return content identity independent of evidence/confidence metadata."""
        return _canonical_json(
            {
                "memory_class": self.memory_class.value,
                "scope": dict(self.scope.canonical),
                "statement": self.statement,
                "valid_from": _format_time(self.valid_from),
                "valid_to": None if self.valid_to is None else _format_time(self.valid_to),
            }
        )

    @property
    def content_sha256(self) -> str:
        """Fingerprint exact semantic candidate content."""
        return hashlib.sha256(self.canonical_content).hexdigest()

    def activate(
        self,
        decision: PromotionDecision,
        source: TaskEvidenceBundle,
        extractor: ExtractorIdentity,
        actor_id: str,
        recorded_at: datetime,
    ) -> Memory:
        """Create active memory only from a policy receipt bound to source and candidate."""
        _require_utc(recorded_at, "recorded_at")
        if (
            decision.disposition is not PromotionDisposition.PROMOTE
            or decision.candidate_sha256 != self.content_sha256
            or decision.evidence_watermark_sha256 != source.watermark_sha256
            or self.scope != source.scope
        ):
            _invalid("promotion", "receipt_mismatch")
        # The extractor saw the complete bundle. Derived data therefore inherits the
        # maximum classification of every input, not only the evidence subset selected
        # by the untrusted model.
        for event_id in self.evidence_ids:
            if event_id not in source.evidence_by_id:
                _invalid("promotion", "unsupported_evidence")
        memory_id = _memory_id(
            source,
            extractor,
            self.candidate_key,
            self.content_sha256,
        )
        return Memory.create(
            memory_id=memory_id,
            memory_class=self.memory_class,
            scope=self.scope,
            status=MemoryStatus.ACTIVE,
            statement=self.statement,
            confidence=self.confidence,
            valid_from=self.valid_from,
            valid_to=self.valid_to,
            recorded_from=recorded_at,
            recorded_to=None,
            provenance=MemoryProvenance(
                actor_id=actor_id,
                agent_id=extractor.extractor_id,
                source_task_id=source.task_id,
                created_by_event=source.terminal_event_id,
                extractor=extractor,
                evidence_ids=self.evidence_ids,
                evidence_watermark_sha256=source.watermark_sha256,
                extractor_input_sha256=source.extractor_input_sha256,
                content_sha256=self.content_sha256,
                promotion_policy_version=decision.policy_version,
            ),
            classification=source.classification,
            retention_policy_id=source.retention_policy_id,
            aggregate_version=1,
        )


@dataclass(frozen=True, slots=True)
class MemoryCandidateBatch:
    """Strict closed extractor output validated before policy evaluation."""

    schema: str
    input_sha256: str
    candidates: tuple[MemoryCandidate, ...]

    @classmethod
    def decode(cls, raw: bytes, expected_input_sha256: str) -> MemoryCandidateBatch:
        """Decode duplicate-free finite JSON with no ignored model fields."""
        _require_digest(expected_input_sha256, "expected_input_sha256")
        document = _require_object(
            _decode_json(raw, "candidate_batch", _MAX_CANDIDATE_DOCUMENT_BYTES),
            "candidate_batch",
        )
        _require_exact_fields(document, {"schema", "input_sha256", "candidates"}, "batch")
        if document["schema"] != "agentmemory.memory-candidates.v1":
            _invalid("batch.schema", "unsupported")
        input_sha = _require_string(document["input_sha256"], "batch.input_sha256")
        _require_digest(input_sha, "batch.input_sha256")
        if input_sha != expected_input_sha256:
            _invalid("batch.input_sha256", "mismatch")
        raw_candidates = document["candidates"]
        if not isinstance(raw_candidates, list) or len(raw_candidates) > _MAX_CANDIDATES:
            _invalid("batch.candidates", "count_invalid")
        candidates = tuple(_candidate(item, index) for index, item in enumerate(raw_candidates))
        keys = tuple(item.candidate_key for item in candidates)
        if len(set(keys)) != len(keys):
            _invalid("batch.candidates", "duplicate_key")
        if _canonical_json(document) != raw:
            _invalid("candidate_batch", "non_canonical")
        return cls("agentmemory.memory-candidates.v1", input_sha, candidates)


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    """Content-free deterministic policy receipt required for activation."""

    disposition: PromotionDisposition
    reason_code: str
    policy_version: str
    candidate_sha256: str
    evidence_watermark_sha256: str


@dataclass(frozen=True, slots=True)
class _PromotionThreshold:
    support: int
    reliability: int
    extraction: int
    evidence_count: int


@dataclass(frozen=True, slots=True)
class MemoryPromotionPolicy:
    """Class-aware deterministic authority outside the extractor model."""

    policy_version: str
    thresholds: Mapping[MemoryClass, _PromotionThreshold]

    @classmethod
    def production(cls) -> MemoryPromotionPolicy:
        """Return the immutable secure default promotion policy."""
        return cls(
            "memory-promotion.v1",
            MappingProxyType(
                {
                    MemoryClass.DECISION: _PromotionThreshold(8000, 7000, 7000, 2),
                    MemoryClass.CONSTRAINT: _PromotionThreshold(8500, 8000, 7500, 2),
                    MemoryClass.PROCEDURE: _PromotionThreshold(8500, 7500, 8000, 2),
                    MemoryClass.PREFERENCE: _PromotionThreshold(9000, 8500, 8000, 1),
                    MemoryClass.LESSON: _PromotionThreshold(8000, 7500, 7500, 2),
                    MemoryClass.EPISODE: _PromotionThreshold(7000, 7000, 7000, 1),
                    MemoryClass.UNRESOLVED_WORK: _PromotionThreshold(7500, 7000, 7000, 1),
                }
            ),
        )

    def evaluate(
        self,
        candidate: MemoryCandidate,
        source: TaskEvidenceBundle,
    ) -> PromotionDecision:
        """Promote only exact-scope candidates supported by source evidence and policy."""
        reason = self._rejection_reason(candidate, source)
        disposition = (
            PromotionDisposition.PROMOTE if reason is None else PromotionDisposition.REJECT
        )
        return PromotionDecision(
            disposition,
            "promoted" if reason is None else reason,
            self.policy_version,
            candidate.content_sha256,
            source.watermark_sha256,
        )

    def _rejection_reason(
        self,
        candidate: MemoryCandidate,
        source: TaskEvidenceBundle,
    ) -> str | None:
        reason = "scope_mismatch" if candidate.scope != source.scope else None
        available = source.evidence_by_id
        if reason is None and any(event_id not in available for event_id in candidate.evidence_ids):
            reason = "unsupported_evidence"
        threshold = self.thresholds[candidate.memory_class]
        if reason is None and len(candidate.evidence_ids) < threshold.evidence_count:
            reason = "insufficient_evidence"
        confidence = candidate.confidence
        if reason is None and (
            confidence.evidence_support < threshold.support
            or confidence.source_reliability < threshold.reliability
            or confidence.extraction_quality < threshold.extraction
        ):
            reason = "below_class_threshold"
        selected_types = {
            available[item].event_type for item in candidate.evidence_ids if item in available
        }
        if (
            reason is None
            and candidate.memory_class is MemoryClass.PREFERENCE
            and selected_types.isdisjoint(_EXPLICIT_PREFERENCE_EVENTS)
        ):
            reason = "missing_explicit_preference_evidence"
        if (
            reason is None
            and candidate.memory_class is MemoryClass.LESSON
            and selected_types.isdisjoint(_LESSON_EVIDENCE_EVENTS)
        ):
            reason = "missing_outcome_evidence"
        if (
            reason is None
            and candidate.memory_class is MemoryClass.UNRESOLVED_WORK
            and source.evidence[-1].event_type != "agentmemory.task.checkpointed.v1"
        ):
            reason = "completed_task_cannot_be_unresolved"
        return reason


@dataclass(frozen=True, slots=True)
class MemoryProvenance:
    """Immutable complete authority and derivation coordinates for one memory."""

    actor_id: str
    agent_id: str
    source_task_id: str
    created_by_event: str
    extractor: ExtractorIdentity
    evidence_ids: tuple[str, ...]
    evidence_watermark_sha256: str
    extractor_input_sha256: str
    content_sha256: str
    promotion_policy_version: str

    def __post_init__(self) -> None:
        """Reject absent, mutable, ambiguous, or unbound provenance."""
        _require_uuid7(self.actor_id, "provenance.actor_id")
        _require_token(self.agent_id, "provenance.agent_id")
        if self.agent_id != self.extractor.extractor_id:
            _invalid("provenance.agent_id", "extractor_mismatch")
        _require_uuid7(self.source_task_id, "provenance.source_task_id")
        _require_uuid7(self.created_by_event, "provenance.created_by_event")
        if (
            not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE_PER_CANDIDATE
            or tuple(sorted(set(self.evidence_ids))) != self.evidence_ids
        ):
            _invalid("provenance.evidence_ids", "not_canonical")
        for event_id in self.evidence_ids:
            _require_uuid7(event_id, "provenance.evidence_ids")
        _require_digest(
            self.evidence_watermark_sha256,
            "provenance.evidence_watermark_sha256",
        )
        _require_digest(
            self.extractor_input_sha256,
            "provenance.extractor_input_sha256",
        )
        _require_digest(self.content_sha256, "provenance.content_sha256")
        _require_token(
            self.promotion_policy_version,
            "provenance.promotion_policy_version",
        )

    @property
    def canonical(self) -> Mapping[str, JsonValue]:
        """Return the closed language-neutral provenance document."""
        return MappingProxyType(
            {
                "actor_id": self.actor_id,
                "agent_id": self.agent_id,
                "content_sha256": self.content_sha256,
                "created_by_event": self.created_by_event,
                "evidence_ids": list(self.evidence_ids),
                "evidence_watermark_sha256": self.evidence_watermark_sha256,
                "extractor": {
                    "extractor_id": self.extractor.extractor_id,
                    "extractor_version": self.extractor.extractor_version,
                    "fingerprint": self.extractor.fingerprint,
                    "model_id": self.extractor.model_id,
                    "model_revision": self.extractor.model_revision,
                    "output_schema": self.extractor.output_schema,
                },
                "extractor_input_sha256": self.extractor_input_sha256,
                "promotion_policy_version": self.promotion_policy_version,
                "source_task_id": self.source_task_id,
            }
        )

    @property
    def provenance_sha256(self) -> str:
        """Fingerprint the complete immutable provenance document."""
        return hashlib.sha256(_canonical_json(dict(self.canonical))).hexdigest()


@dataclass(frozen=True, slots=True)
class Memory:
    """One evidence-backed active long-term memory aggregate snapshot."""

    memory_id: str
    memory_class: MemoryClass
    scope: MemoryScope
    status: MemoryStatus
    statement: str
    content_sha256: str
    confidence: ConfidenceDimensions
    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None
    provenance: MemoryProvenance
    classification: str
    retention_policy_id: str
    aggregate_version: int

    @classmethod
    def create(  # noqa: PLR0913 -- Factory names every mandatory aggregate coordinate.
        cls,
        *,
        memory_id: str,
        memory_class: MemoryClass,
        scope: MemoryScope,
        status: MemoryStatus,
        statement: str,
        confidence: ConfidenceDimensions,
        valid_from: datetime,
        valid_to: datetime | None,
        recorded_from: datetime,
        recorded_to: datetime | None,
        provenance: MemoryProvenance | None,
        classification: str,
        retention_policy_id: str,
        aggregate_version: int,
    ) -> Memory:
        """Activate only a memory carrying complete immutable provenance."""
        if provenance is None:
            _invalid("provenance", "required")
        return cls(
            memory_id,
            memory_class,
            scope,
            status,
            statement,
            provenance.content_sha256,
            confidence,
            valid_from,
            valid_to,
            recorded_from,
            recorded_to,
            provenance,
            classification,
            retention_policy_id,
            aggregate_version,
        )

    def __post_init__(self) -> None:
        """Defend active snapshots against forged identity or missing provenance."""
        self._validate_content_and_time()
        self._validate_provenance()

    def _validate_content_and_time(self) -> None:
        """Validate identity, lifecycle, content digest, and bitemporal shape."""
        _require_uuid7(self.memory_id, "memory_id")
        if self.status is not MemoryStatus.ACTIVE:
            _invalid("status", "unsupported")
        _require_bounded_text(self.statement, "statement", _MAX_STATEMENT_CHARACTERS)
        if self.statement != unicodedata.normalize("NFC", self.statement).strip():
            _invalid("statement", "non_canonical")
        _require_utc(self.valid_from, "valid_from")
        if self.valid_to is not None:
            _require_utc(self.valid_to, "valid_to")
            if self.valid_to <= self.valid_from:
                _invalid("valid_to", "not_after_start")
        _require_digest(self.content_sha256, "content_sha256")
        if (
            hashlib.sha256(
                _canonical_json(
                    {
                        "memory_class": self.memory_class.value,
                        "scope": dict(self.scope.canonical),
                        "statement": self.statement,
                        "valid_from": _format_time(self.valid_from),
                        "valid_to": None if self.valid_to is None else _format_time(self.valid_to),
                    }
                )
            ).hexdigest()
            != self.content_sha256
        ):
            _invalid("content_sha256", "mismatch")
        _require_utc(self.recorded_from, "recorded_from")
        if self.recorded_to is not None:
            _require_utc(self.recorded_to, "recorded_to")
            if self.recorded_to <= self.recorded_from:
                _invalid("recorded_to", "not_after_start")

    def _validate_provenance(self) -> None:
        """Validate every mandatory source, policy, and aggregate coordinate."""
        if self.content_sha256 != self.provenance.content_sha256:
            _invalid("content_sha256", "provenance_mismatch")
        if self.classification not in _CLASSIFICATION_ORDER:
            _invalid("classification", "unsupported")
        _require_token(self.retention_policy_id, "retention_policy_id")
        if self.aggregate_version != 1:
            _invalid("aggregate_version", "unsupported")

    @property
    def extractor(self) -> ExtractorIdentity:
        """Expose the immutable extractor coordinate for existing consumers."""
        return self.provenance.extractor

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Expose exact evidence lineage without duplicating mutable state."""
        return self.provenance.evidence_ids

    @property
    def source_task_id(self) -> str:
        """Expose the canonical source task coordinate."""
        return self.provenance.source_task_id

    @property
    def created_by_event(self) -> str:
        """Expose the canonical creation event coordinate."""
        return self.provenance.created_by_event

    @property
    def promotion_policy_version(self) -> str:
        """Expose the immutable deterministic promotion policy coordinate."""
        return self.provenance.promotion_policy_version


@dataclass(frozen=True, slots=True)
class ExtractorRequest:
    """Bounded operation-scoped input supplied to one exact extractor."""

    operation_id: str
    idempotency_key: str
    task_id: str
    input_bytes: bytes
    input_sha256: str
    classification: str
    purpose: str
    deadline: datetime
    extractor: ExtractorIdentity

    def __post_init__(self) -> None:
        """Bind operation, input, policy purpose, deadline, and extractor identity."""
        _require_token(self.operation_id, "operation_id")
        _require_digest(self.idempotency_key, "idempotency_key")
        _require_uuid7(self.task_id, "task_id")
        _require_digest(self.input_sha256, "input_sha256")
        if (
            not self.input_bytes
            or len(self.input_bytes) > _MAX_EVIDENCE_BYTES
            or hashlib.sha256(self.input_bytes).hexdigest() != self.input_sha256
        ):
            _invalid("input_bytes", "digest_mismatch")
        if self.classification not in _CLASSIFICATION_ORDER:
            _invalid("classification", "unsupported")
        if self.purpose != "memory_consolidation":
            _invalid("purpose", "unsupported")
        _require_utc(self.deadline, "deadline")


@dataclass(frozen=True, slots=True)
class ExtractorResponse:
    """Untrusted extractor response envelope authenticated before output parsing."""

    operation_id: str
    idempotency_key: str
    task_id: str
    input_sha256: str
    extractor: ExtractorIdentity
    output_bytes: bytes
    output_sha256: str

    def __post_init__(self) -> None:
        """Require bounded hash-bound bytes and canonical operation coordinates."""
        _require_token(self.operation_id, "operation_id")
        _require_digest(self.idempotency_key, "idempotency_key")
        _require_uuid7(self.task_id, "task_id")
        _require_digest(self.input_sha256, "input_sha256")
        _require_digest(self.output_sha256, "output_sha256")
        if (
            not self.output_bytes
            or len(self.output_bytes) > _MAX_CANDIDATE_DOCUMENT_BYTES
            or hashlib.sha256(self.output_bytes).hexdigest() != self.output_sha256
        ):
            _invalid("output_bytes", "digest_mismatch")

    def matches(self, request: ExtractorRequest) -> bool:
        """Verify exact request echo and immutable extractor revision."""
        return (
            self.operation_id == request.operation_id
            and self.idempotency_key == request.idempotency_key
            and self.task_id == request.task_id
            and self.input_sha256 == request.input_sha256
            and self.extractor == request.extractor
        )


@dataclass(frozen=True, slots=True, order=True)
class CandidateRejection:
    """Content-free evidence that policy denied one schema-valid candidate."""

    candidate_key_sha256: str
    memory_class: MemoryClass
    content_sha256: str
    reason_code: str

    def __post_init__(self) -> None:
        """Allow only stable identifiers and hashes in durable rejection evidence."""
        _require_digest(self.candidate_key_sha256, "rejection.candidate_key_sha256")
        _require_digest(self.content_sha256, "rejection.content_sha256")
        _require_token(self.reason_code, "rejection.reason_code")


@dataclass(frozen=True, slots=True)
class ConsolidationResult:
    """Content-free idempotent result returned by task consolidation."""

    idempotency_key: str
    task_id: str
    evidence_watermark_sha256: str
    extractor_fingerprint: str
    memory_ids: tuple[str, ...]
    promoted: int
    rejected: int
    result_sha256: str

    def __post_init__(self) -> None:
        """Reject count, identity, or result-digest divergence."""
        _require_digest(self.idempotency_key, "idempotency_key")
        _require_uuid7(self.task_id, "task_id")
        _require_digest(self.evidence_watermark_sha256, "evidence_watermark_sha256")
        _require_digest(self.extractor_fingerprint, "extractor_fingerprint")
        for memory_id in self.memory_ids:
            _require_uuid7(memory_id, "memory_ids")
        if tuple(sorted(set(self.memory_ids))) != self.memory_ids:
            _invalid("memory_ids", "not_canonical")
        if self.promoted != len(self.memory_ids) or self.rejected < 0:
            _invalid("result_counts", "mismatch")
        _require_digest(self.result_sha256, "result_sha256")
        if self.result_sha256 != _result_digest(
            (
                self.idempotency_key,
                self.task_id,
                self.evidence_watermark_sha256,
                self.extractor_fingerprint,
            ),
            self.memory_ids,
            self.rejected,
        ):
            _invalid("result_sha256", "mismatch")


@dataclass(frozen=True, slots=True)
class ConsolidationCommit:
    """Atomic canonical memory, rejection, event, outbox, and audit intent."""

    operation_id: str
    actor_id: str
    grant_id: str
    correlation_id: str
    causation_id: str
    idempotency_key: str
    task_id: str
    scope: MemoryScope
    evidence_watermark_sha256: str
    extractor_input_sha256: str
    extractor: ExtractorIdentity
    source_terminal_event_id: str
    promotion_policy_version: str
    classification: str
    retention_policy_id: str
    memories: tuple[Memory, ...]
    rejections: tuple[CandidateRejection, ...]
    requested_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        """Require every committed artifact to bind the same task snapshot and policy."""
        _require_token(self.operation_id, "operation_id")
        _require_uuid7(self.actor_id, "actor_id")
        _require_uuid7(self.grant_id, "grant_id")
        _require_uuid7(self.correlation_id, "correlation_id")
        _require_uuid7(self.causation_id, "causation_id")
        expected = consolidation_idempotency_key(
            self.task_id,
            self.evidence_watermark_sha256,
            self.extractor.fingerprint,
        )
        if self.idempotency_key != expected:
            _invalid("idempotency_key", "mismatch")
        _require_digest(self.extractor_input_sha256, "extractor_input_sha256")
        _require_uuid7(self.source_terminal_event_id, "source_terminal_event_id")
        _require_token(self.promotion_policy_version, "promotion_policy_version")
        if self.classification not in _CLASSIFICATION_ORDER:
            _invalid("classification", "unsupported")
        _require_token(self.retention_policy_id, "retention_policy_id")
        _require_utc(self.requested_at, "requested_at")
        _require_utc(self.completed_at, "completed_at")
        if self.completed_at < self.requested_at:
            _invalid("completed_at", "before_request")
        if len(self.memories) + len(self.rejections) > _MAX_CANDIDATES:
            _invalid("consolidation", "candidate_count_exceeded")
        if any(
            memory.source_task_id != self.task_id
            or memory.scope != self.scope
            or memory.extractor != self.extractor
            or memory.provenance.actor_id != self.actor_id
            or memory.created_by_event != self.source_terminal_event_id
            or memory.provenance.evidence_watermark_sha256 != self.evidence_watermark_sha256
            or memory.provenance.extractor_input_sha256 != self.extractor_input_sha256
            or memory.classification != self.classification
            or memory.retention_policy_id != self.retention_policy_id
            or memory.promotion_policy_version != self.promotion_policy_version
            for memory in self.memories
        ):
            _invalid("memories", "lineage_mismatch")
        ids = tuple(sorted(memory.memory_id for memory in self.memories))
        if len(set(ids)) != len(ids):
            _invalid("memories", "duplicate_identity")
        rejection_keys = tuple(item.candidate_key_sha256 for item in self.rejections)
        if len(set(rejection_keys)) != len(rejection_keys):
            _invalid("rejections", "duplicate_identity")

    @property
    def result(self) -> ConsolidationResult:
        """Return the deterministic content-free commit receipt."""
        memory_ids = tuple(sorted(item.memory_id for item in self.memories))
        digest = _result_digest(
            (
                self.idempotency_key,
                self.task_id,
                self.evidence_watermark_sha256,
                self.extractor.fingerprint,
            ),
            memory_ids,
            len(self.rejections),
        )
        return ConsolidationResult(
            self.idempotency_key,
            self.task_id,
            self.evidence_watermark_sha256,
            self.extractor.fingerprint,
            memory_ids,
            len(memory_ids),
            len(self.rejections),
            digest,
        )


def consolidation_idempotency_key(
    task_id: str,
    evidence_watermark_sha256: str,
    extractor_fingerprint: str,
) -> str:
    """Bind one task snapshot to one exact extractor implementation."""
    _require_uuid7(task_id, "task_id")
    _require_digest(evidence_watermark_sha256, "evidence_watermark_sha256")
    _require_digest(extractor_fingerprint, "extractor_fingerprint")
    return hashlib.sha256(
        _length_framed((task_id, evidence_watermark_sha256, extractor_fingerprint))
    ).hexdigest()


def derive_evidence_watermark(records: Sequence[tuple[str, str, str]]) -> str:
    """Hash one already-ordered exact event-ID/type/canonical-digest sequence."""
    if not records:
        _invalid("evidence_watermark", "empty")
    document: list[dict[str, JsonValue]] = []
    prior: tuple[str, str, str] | None = None
    for event_id, event_type, canonical_sha256 in records:
        _require_uuid7(event_id, "evidence_watermark.event_id")
        if _EVENT_TYPE.fullmatch(event_type) is None:
            _invalid("evidence_watermark.event_type", "invalid")
        _require_digest(canonical_sha256, "evidence_watermark.canonical_sha256")
        current = (event_id, event_type, canonical_sha256)
        if prior == current:
            _invalid("evidence_watermark", "duplicate")
        prior = current
        document.append(
            {
                "canonical_event_sha256": canonical_sha256,
                "event_id": event_id,
                "event_type": event_type,
            }
        )
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def validate_consolidation_command_actor(
    operation_id: str,
    actor_id: str,
    grant_id: str,
) -> None:
    """Validate idempotency and current-authorization coordinates."""
    _require_token(operation_id, "operation_id")
    _require_uuid7(actor_id, "actor_id")
    _require_uuid7(grant_id, "grant_id")


def validate_consolidation_command_trace(
    correlation_id: str,
    causation_id: str,
    task_id: str,
    terminal_event_id: str,
) -> None:
    """Validate immutable task and trace coordinates."""
    _require_uuid7(correlation_id, "correlation_id")
    _require_uuid7(causation_id, "causation_id")
    _require_uuid7(task_id, "task_id")
    _require_uuid7(terminal_event_id, "terminal_event_id")


def validate_consolidation_command_time(
    requested_at: datetime,
    deadline: datetime,
) -> None:
    """Validate immutable request/deadline ordering."""
    _require_utc(requested_at, "requested_at")
    _require_utc(deadline, "deadline")
    if deadline <= requested_at:
        _invalid("deadline", "not_after_request")


def _result_digest(
    coordinates: tuple[str, str, str, str],
    memory_ids: tuple[str, ...],
    rejected: int,
) -> str:
    idempotency_key, task_id, watermark_sha256, extractor_fingerprint = coordinates
    return hashlib.sha256(
        _canonical_json(
            {
                "evidence_watermark_sha256": watermark_sha256,
                "extractor_fingerprint": extractor_fingerprint,
                "idempotency_key": idempotency_key,
                "memory_ids": list(memory_ids),
                "rejected": rejected,
                "task_id": task_id,
            }
        )
    ).hexdigest()


def _candidate(value: JsonValue, index: int) -> MemoryCandidate:
    field = f"batch.candidates[{index}]"
    document = _require_object(value, field)
    _require_exact_fields(
        document,
        {
            "candidate_key",
            "confidence",
            "evidence_ids",
            "memory_class",
            "scope",
            "statement",
            "valid_from",
            "valid_to",
        },
        field,
    )
    confidence = _confidence(document["confidence"], field)
    evidence_values = document["evidence_ids"]
    if not isinstance(evidence_values, list) or not all(
        isinstance(item, str) for item in evidence_values
    ):
        _invalid(f"{field}.evidence_ids", "array_required")
    try:
        memory_class = MemoryClass(_require_string(document["memory_class"], field))
    except ValueError as error:
        class_field = f"{field}.memory_class"
        raise MemoryValidationError.single(class_field, "unsupported") from error
    return MemoryCandidate(
        _require_string(document["candidate_key"], f"{field}.candidate_key"),
        memory_class,
        _require_string(document["statement"], f"{field}.statement"),
        _scope(document["scope"], field),
        confidence,
        _parse_time(document["valid_from"], f"{field}.valid_from"),
        None
        if document["valid_to"] is None
        else _parse_time(document["valid_to"], f"{field}.valid_to"),
        tuple(cast("list[str]", evidence_values)),
    )


def _scope(value: JsonValue, parent: str) -> MemoryScope:
    document = _require_object(value, f"{parent}.scope")
    _require_exact_fields(
        document,
        {"brain_id", "checkout_id", "project_id", "repository_id"},
        f"{parent}.scope",
    )
    checkout = document["checkout_id"]
    if checkout is not None and not isinstance(checkout, str):
        _invalid(f"{parent}.scope.checkout_id", "string_or_null_required")
    return MemoryScope(
        _require_string(document["brain_id"], f"{parent}.scope.brain_id"),
        _require_string(document["project_id"], f"{parent}.scope.project_id"),
        _require_string(document["repository_id"], f"{parent}.scope.repository_id"),
        checkout,
    )


def _confidence(value: JsonValue, parent: str) -> ConfidenceDimensions:
    document = _require_object(value, f"{parent}.confidence")
    _require_exact_fields(
        document,
        {"evidence_support", "extraction_quality", "source_reliability"},
        f"{parent}.confidence",
    )
    values: list[int] = []
    for name in ("evidence_support", "source_reliability", "extraction_quality"):
        item = document[name]
        if not isinstance(item, int) or isinstance(item, bool):
            _invalid(f"{parent}.confidence.{name}", "integer_required")
        values.append(item)
    return ConfidenceDimensions(*values)


def _memory_id(
    source: TaskEvidenceBundle,
    extractor: ExtractorIdentity,
    candidate_key: str,
    content_sha256: str,
) -> str:
    seed = _length_framed(
        (
            source.task_id,
            source.watermark_sha256,
            extractor.fingerprint,
            candidate_key,
            content_sha256,
        )
    )
    entropy = int.from_bytes(hashlib.sha256(seed).digest(), "big")
    milliseconds = int(source.terminal_occurred_at.timestamp() * 1000) & ((1 << 48) - 1)
    random_a = (entropy >> 62) & ((1 << 12) - 1)
    random_b = entropy & ((1 << 62) - 1)
    integer = (milliseconds << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    return str(UUID(int=integer))


def _length_framed(values: Sequence[str]) -> bytes:
    result = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        result.extend(len(encoded).to_bytes(4, "big"))
        result.extend(encoded)
    return bytes(result)


def _decode_json(raw: bytes, field: str, maximum_bytes: int) -> JsonValue:
    if not raw or len(raw) > maximum_bytes:
        _invalid(field, "size_invalid")

    def unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                _invalid(field, "duplicate_key")
            result[key] = value
        return result

    def reject_constant(_: str) -> Never:
        _invalid(field, "non_finite")

    try:
        return cast(
            "JsonValue",
            json.loads(
                raw,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            ),
        )
    except UnicodeDecodeError, json.JSONDecodeError:
        _invalid(field, "invalid_json")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except TypeError, ValueError, OverflowError:
        _invalid("json", "invalid_value")


def _require_object(value: JsonValue, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        _invalid(field, "object_required")
    return value


def _require_exact_fields(
    value: Mapping[str, JsonValue],
    expected: set[str],
    field: str,
) -> None:
    if set(value) != expected:
        _invalid(field, "fields_invalid")


def _require_string(value: JsonValue, field: str) -> str:
    if not isinstance(value, str):
        _invalid(field, "string_required")
    return value


def _parse_time(value: JsonValue, field: str) -> datetime:
    text = _require_string(value, field)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_timestamp") from error
    if _format_time(parsed) != text:
        _invalid(field, "non_canonical")
    return parsed


def _format_time(value: datetime) -> str:
    _require_utc(value, "timestamp")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        _invalid(field, "invalid_uuid7")


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        _invalid(field, "invalid_digest")


def _require_token(value: str, field: str) -> None:
    if _TOKEN.fullmatch(value) is None:
        _invalid(field, "invalid_token")


def _require_bounded_text(value: str, field: str, maximum: int) -> None:
    if (
        not value
        or len(value) > maximum
        or any(
            ord(character) < _C0_CONTROL_LIMIT or ord(character) == _DELETE_CONTROL
            for character in value
        )
    ):
        _invalid(field, "invalid_text")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
