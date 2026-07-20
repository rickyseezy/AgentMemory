"""MEM-003 deterministic memory compatibility and lossless merge planning."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.memory.domain.errors import MemoryValidationError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from agentmemory.memory.domain.consolidation import Memory, MemoryClass, MemoryScope

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_WORD = re.compile(r"[a-z0-9]+")
_MAX_CANDIDATES = 256
_MAX_BASIS_POINTS = 10_000
_MAX_EMBEDDING_DIMENSION = 65_536
_MIN_MERGE_MEMORIES = 2
_MIN_SEMANTIC_SIMILARITY = 9000
_POLICY_VERSION = "memory-compatibility.v1"
_NEGATIONS = frozenset(
    {"avoid", "cannot", "deny", "denied", "disable", "forbid", "never", "no", "not", "without"}
)
_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "do",
        "for",
        "from",
        "has",
        "have",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "should",
        "that",
        "the",
        "this",
        "to",
        "use",
        "used",
        "uses",
        "using",
        "was",
        "were",
        "will",
        "with",
    }
)
_SYNONYMS: dict[str, str] = {
    "postgres": "postgresql",
    "utilise": "use",
    "utilised": "use",
    "utilize": "use",
    "utilized": "use",
}


class MemoryPolarity(StrEnum):
    """Closed assertion polarity used to prevent contradiction merges."""

    AFFIRMED = "affirmed"
    NEGATED = "negated"


class DeduplicationMode(StrEnum):
    """Ordered matching stages; exact always precedes semantic."""

    EXACT = "exact"
    SEMANTIC = "semantic"


@dataclass(frozen=True, slots=True)
class MemoryDeduplicationProfile:
    """Canonical compatibility coordinates derived without model write authority."""

    memory_id: str
    memory_class: MemoryClass
    subject_key: str
    scope: MemoryScope
    valid_from: datetime
    valid_to: datetime | None
    polarity: MemoryPolarity
    promotion_policy_version: str
    compatibility_policy_version: str
    content_sha256: str
    classification: str
    retention_policy_id: str
    evidence_ids: tuple[str, ...]
    recorded_from: datetime
    aggregate_version: int

    @classmethod
    def from_memory(cls, memory: Memory) -> MemoryDeduplicationProfile:
        """Derive a conservative subject and polarity from canonical memory text."""
        subject_key, polarity = canonical_subject(memory.statement)
        return cls(
            memory.memory_id,
            memory.memory_class,
            subject_key,
            memory.scope,
            memory.valid_from,
            memory.valid_to,
            polarity,
            memory.promotion_policy_version,
            _POLICY_VERSION,
            memory.content_sha256,
            memory.classification,
            memory.retention_policy_id,
            memory.evidence_ids,
            memory.recorded_from,
            memory.aggregate_version,
        )

    def __post_init__(self) -> None:
        """Reject incomplete or ambiguous persisted/search coordinates."""
        _require_uuid7(self.memory_id, "memory_id")
        _require_digest(self.subject_key, "subject_key")
        _require_digest(self.content_sha256, "content_sha256")
        _require_token(self.promotion_policy_version, "promotion_policy_version")
        if self.compatibility_policy_version != _POLICY_VERSION:
            _invalid("compatibility_policy_version", "unsupported")
        _require_token(self.retention_policy_id, "retention_policy_id")
        if self.classification not in {
            "public",
            "internal",
            "confidential",
            "restricted",
            "local_only",
        }:
            _invalid("classification", "unsupported")
        if not self.evidence_ids or tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            _invalid("evidence_ids", "not_canonical")
        for event_id in self.evidence_ids:
            _require_uuid7(event_id, "evidence_ids")
        _require_utc(self.valid_from, "valid_from")
        if self.valid_to is not None:
            _require_utc(self.valid_to, "valid_to")
            if self.valid_to <= self.valid_from:
                _invalid("valid_to", "not_after_start")
        _require_utc(self.recorded_from, "recorded_from")
        if self.aggregate_version < 1:
            _invalid("aggregate_version", "out_of_range")

    @property
    def exact_fingerprint(self) -> str:
        """Bind all security-sensitive metadata around exact canonical content."""
        return _digest_document(
            {
                "classification": self.classification,
                "content_sha256": self.content_sha256,
                "retention_policy_id": self.retention_policy_id,
            }
        )


@dataclass(frozen=True, slots=True)
class SemanticMemoryCandidate:
    """One bounded embedding-retrieval result with deterministic profile metadata."""

    profile: MemoryDeduplicationProfile
    similarity_basis_points: int

    def __post_init__(self) -> None:
        """Require an exact finite integer score in basis-point range."""
        if (
            isinstance(self.similarity_basis_points, bool)
            or not 0 <= self.similarity_basis_points <= _MAX_BASIS_POINTS
        ):
            _invalid("similarity_basis_points", "out_of_range")


@dataclass(frozen=True, slots=True)
class CompatibilityDecision:
    """Content-free deterministic merge-policy result."""

    compatible: bool
    mode: DeduplicationMode
    reason_code: str


@dataclass(frozen=True, slots=True)
class MemoryCompatibilityPolicy:
    """Authorize merges only after every non-semantic invariant matches."""

    policy_version: str = _POLICY_VERSION
    semantic_threshold_basis_points: int = _MIN_SEMANTIC_SIMILARITY

    def __post_init__(self) -> None:
        """Prevent runtime policy weakening or unversioned behavior drift."""
        if self.policy_version != _POLICY_VERSION:
            _invalid("policy_version", "unsupported")
        if (
            isinstance(self.semantic_threshold_basis_points, bool)
            or not _MIN_SEMANTIC_SIMILARITY
            <= self.semantic_threshold_basis_points
            <= _MAX_BASIS_POINTS
        ):
            _invalid("semantic_threshold_basis_points", "out_of_range")

    def evaluate(
        self,
        target: MemoryDeduplicationProfile,
        candidate: SemanticMemoryCandidate,
        mode: DeduplicationMode,
    ) -> CompatibilityDecision:
        """Return the first stable incompatibility reason in closed policy order."""
        other = candidate.profile
        checks = (
            (target.memory_id == other.memory_id, "same_identity"),
            (target.memory_class != other.memory_class, "class_mismatch"),
            (target.subject_key != other.subject_key, "subject_mismatch"),
            (target.scope != other.scope, "scope_mismatch"),
            (
                (target.valid_from, target.valid_to) != (other.valid_from, other.valid_to),
                "temporal_mismatch",
            ),
            (target.polarity is not other.polarity, "polarity_mismatch"),
            (
                target.promotion_policy_version != other.promotion_policy_version,
                "promotion_policy_mismatch",
            ),
            (
                target.compatibility_policy_version != self.policy_version
                or other.compatibility_policy_version != self.policy_version,
                "compatibility_policy_mismatch",
            ),
            (target.classification != other.classification, "classification_mismatch"),
            (target.retention_policy_id != other.retention_policy_id, "retention_mismatch"),
        )
        for failed, reason in checks:
            if failed:
                return CompatibilityDecision(compatible=False, mode=mode, reason_code=reason)
        if mode is DeduplicationMode.EXACT:
            if target.exact_fingerprint != other.exact_fingerprint:
                return CompatibilityDecision(
                    compatible=False,
                    mode=mode,
                    reason_code="exact_fingerprint_mismatch",
                )
        elif candidate.similarity_basis_points < self.semantic_threshold_basis_points:
            return CompatibilityDecision(
                compatible=False,
                mode=mode,
                reason_code="similarity_below_threshold",
            )
        return CompatibilityDecision(compatible=True, mode=mode, reason_code="compatible")


@dataclass(frozen=True, slots=True)
class MemoryMergePlan:
    """Deterministic atomic merge plan retaining every source and evidence identity."""

    survivor: MemoryDeduplicationProfile
    merged: tuple[MemoryDeduplicationProfile, ...]
    evidence_ids: tuple[str, ...]
    mode: DeduplicationMode
    policy_version: str

    def __post_init__(self) -> None:
        """Require complete distinct source lineage and its exact evidence union."""
        if not self.merged or self.policy_version != _POLICY_VERSION:
            _invalid("merge_plan", "invalid")
        source_ids = tuple(item.memory_id for item in self.merged)
        if tuple(sorted(set(source_ids))) != source_ids or self.survivor.memory_id in source_ids:
            _invalid("merge_plan.source_ids", "not_canonical")
        expected_evidence = tuple(
            sorted(
                {
                    event_id
                    for profile in (self.survivor, *self.merged)
                    for event_id in profile.evidence_ids
                }
            )
        )
        if self.evidence_ids != expected_evidence:
            _invalid("merge_plan.evidence_ids", "lineage_mismatch")

    @classmethod
    def create(
        cls,
        target: MemoryDeduplicationProfile,
        exact: Iterable[MemoryDeduplicationProfile],
        semantic: Iterable[SemanticMemoryCandidate],
        policy: MemoryCompatibilityPolicy,
    ) -> MemoryMergePlan | None:
        """Choose exact compatible candidates first and one stable oldest survivor."""
        exact_items = tuple(exact)
        semantic_items = tuple(semantic)
        if len(exact_items) > _MAX_CANDIDATES or len(semantic_items) > _MAX_CANDIDATES:
            _invalid("candidates", "count_exceeded")
        compatible_exact = tuple(
            item
            for item in exact_items
            if policy.evaluate(
                target, SemanticMemoryCandidate(item, 10_000), DeduplicationMode.EXACT
            ).compatible
        )
        mode = DeduplicationMode.EXACT
        compatible = compatible_exact
        if not compatible:
            mode = DeduplicationMode.SEMANTIC
            compatible = tuple(
                item.profile
                for item in semantic_items
                if policy.evaluate(target, item, mode).compatible
            )
        unique = {item.memory_id: item for item in (target, *compatible)}
        if len(unique) < _MIN_MERGE_MEMORIES:
            return None
        ordered = tuple(
            sorted(unique.values(), key=lambda item: (item.recorded_from, item.memory_id))
        )
        survivor = ordered[0]
        merged = tuple(
            sorted(
                (item for item in ordered if item.memory_id != survivor.memory_id),
                key=lambda item: item.memory_id,
            )
        )
        evidence = tuple(sorted({event for item in ordered for event in item.evidence_ids}))
        return cls(survivor, merged, evidence, mode, policy.policy_version)

    @property
    def source_ids(self) -> tuple[str, ...]:
        """Return every redirected identity in deterministic order."""
        return tuple(item.memory_id for item in self.merged)

    @property
    def result_sha256(self) -> str:
        """Authenticate the complete content-free merge outcome."""
        return _digest_document(
            {
                "evidence_ids": list(self.evidence_ids),
                "mode": self.mode.value,
                "policy_version": self.policy_version,
                "source_ids": list(self.source_ids),
                "survivor_id": self.survivor.memory_id,
            }
        )


@dataclass(frozen=True, slots=True)
class DeduplicationResult:
    """Stable content-free receipt for a committed merge or no-op scan."""

    idempotency_key: str
    requested_memory_id: str
    survivor_memory_id: str
    merged_memory_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    mode: DeduplicationMode | None
    policy_version: str
    result_sha256: str

    @classmethod
    def create(
        cls,
        idempotency_key: str,
        target: MemoryDeduplicationProfile,
        plan: MemoryMergePlan | None,
        policy_version: str,
    ) -> DeduplicationResult:
        """Create one authenticated result without leaking statements or similarity."""
        _require_digest(idempotency_key, "idempotency_key")
        survivor = target.memory_id if plan is None else plan.survivor.memory_id
        merged = () if plan is None else plan.source_ids
        evidence = target.evidence_ids if plan is None else plan.evidence_ids
        mode = None if plan is None else plan.mode
        digest = _digest_document(
            {
                "evidence_ids": list(evidence),
                "idempotency_key": idempotency_key,
                "merged_memory_ids": list(merged),
                "mode": None if mode is None else mode.value,
                "policy_version": policy_version,
                "requested_memory_id": target.memory_id,
                "survivor_memory_id": survivor,
            }
        )
        return cls(
            idempotency_key,
            target.memory_id,
            survivor,
            merged,
            evidence,
            mode,
            policy_version,
            digest,
        )

    def __post_init__(self) -> None:
        """Require canonical distinct identities and a self-authenticating digest."""
        _require_digest(self.idempotency_key, "idempotency_key")
        _require_uuid7(self.requested_memory_id, "requested_memory_id")
        _require_uuid7(self.survivor_memory_id, "survivor_memory_id")
        if tuple(sorted(set(self.merged_memory_ids))) != self.merged_memory_ids:
            _invalid("merged_memory_ids", "not_canonical")
        if self.survivor_memory_id in self.merged_memory_ids:
            _invalid("merged_memory_ids", "contains_survivor")
        for memory_id in self.merged_memory_ids:
            _require_uuid7(memory_id, "merged_memory_ids")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            _invalid("evidence_ids", "not_canonical")
        for event_id in self.evidence_ids:
            _require_uuid7(event_id, "evidence_ids")
        _require_token(self.policy_version, "policy_version")
        _require_digest(self.result_sha256, "result_sha256")


@dataclass(frozen=True, slots=True)
class DeduplicationCommit:
    """Complete authorized atomic write intent for one deduplication operation."""

    operation_id: str
    actor_id: str
    grant_id: str
    brain_id: str
    correlation_id: str
    causation_id: str
    target: MemoryDeduplicationProfile
    plan: MemoryMergePlan | None
    result: DeduplicationResult
    requested_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        """Bind authority, trace, result, profile versions, and completion time."""
        for value, field in (
            (self.operation_id, "operation_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
            (self.brain_id, "brain_id"),
            (self.correlation_id, "correlation_id"),
            (self.causation_id, "causation_id"),
        ):
            _require_uuid7(value, field)
        _require_utc(self.requested_at, "requested_at")
        _require_utc(self.completed_at, "completed_at")
        if self.completed_at < self.requested_at:
            _invalid("completed_at", "before_request")
        if self.target.scope.brain_id != self.brain_id:
            _invalid("brain_id", "scope_mismatch")
        if self.plan is not None and self.plan.policy_version != self.result.policy_version:
            _invalid("result", "policy_mismatch")
        expected = DeduplicationResult.create(
            self.result.idempotency_key,
            self.target,
            self.plan,
            self.result.policy_version,
        )
        if expected != self.result:
            _invalid("result", "plan_mismatch")


def deduplication_idempotency_key(operation_id: str, memory_id: str, brain_id: str) -> str:
    """Bind a caller UUID to the exact requested memory and Brain."""
    _require_uuid7(operation_id, "operation_id")
    _require_uuid7(memory_id, "memory_id")
    _require_uuid7(brain_id, "brain_id")
    return _digest_document(
        {"brain_id": brain_id, "memory_id": memory_id, "operation_id": operation_id}
    )


def validate_deduplication_coordinate(value: str, field: str) -> None:
    """Validate one externally supplied UUIDv7 coordinate with a stable field name."""
    _require_uuid7(value, field)


def canonical_subject(statement: str) -> tuple[str, MemoryPolarity]:
    """Derive a conservative language-stable subject signature and polarity."""
    normalized = unicodedata.normalize("NFKC", statement).casefold()
    raw_words: list[str] = _WORD.findall(normalized)
    words: tuple[str, ...] = tuple(_SYNONYMS.get(word, word) for word in raw_words)
    negated = sum(word in _NEGATIONS for word in words) % 2 == 1
    subject_words: set[str] = {
        word for word in words if word not in _STOP_WORDS and word not in _NEGATIONS
    }
    subject: tuple[str, ...] = tuple(sorted(subject_words))
    if not subject:
        _invalid("statement", "subject_unavailable")
    return _digest_document(list(subject)), (
        MemoryPolarity.NEGATED if negated else MemoryPolarity.AFFIRMED
    )


def cosine_similarity_basis_points(left: tuple[float, ...], right: tuple[float, ...]) -> int:
    """Return deterministic bounded cosine similarity without accepting non-finite vectors."""
    if not left or len(left) != len(right) or len(left) > _MAX_EMBEDDING_DIMENSION:
        _invalid("embedding", "dimension_mismatch")
    if any(not math.isfinite(value) for value in (*left, *right)):
        _invalid("embedding", "non_finite")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0 or right_norm == 0:
        _invalid("embedding", "zero_norm")
    cosine = max(
        -1.0,
        min(1.0, sum(a * b for a, b in zip(left, right, strict=True)) / (left_norm * right_norm)),
    )
    return max(0, min(10_000, int((cosine + 1e-12) * 10_000)))


def _digest_document(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode()
    ).hexdigest()


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


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
