"""MEM-004 immutable correction assertions and scope-safe precedence policy."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Never
from uuid import UUID

from agentmemory.memory.domain.consolidation import MemoryClass, MemoryScope, MemoryStatus
from agentmemory.memory.domain.deduplication import canonical_subject
from agentmemory.memory.domain.errors import MemoryConflictError, MemoryValidationError

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MAX_STATEMENT_CHARACTERS = 8_192
_MAX_EVIDENCE = 64
_MIN_CORRECTED_SOURCE_VERSION = 2
_POLICY_VERSION = "memory-precedence.v1"
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL = 127
_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted", "local_only"})


class CorrectionRelation(StrEnum):
    """Closed graph relationship emitted by an explicit correction."""

    SUPERSEDES = "supersedes"
    CONTRADICTS = "contradicts"

    @property
    def graph_type(self) -> str:
        """Return the closed Neo4j relationship type, never caller-controlled text."""
        return "SUPERSEDES" if self is CorrectionRelation.SUPERSEDES else "CONTRADICTS"


@dataclass(frozen=True, slots=True, order=True)
class CorrectionEvidence:
    """One optional immutable canonical evidence link for a user correction."""

    event_id: str
    canonical_event_sha256: str

    def __post_init__(self) -> None:
        """Require a UUIDv7 source and a nonzero canonical digest."""
        _require_uuid7(self.event_id, "evidence.event_id")
        _require_digest(self.canonical_event_sha256, "evidence.canonical_event_sha256")


@dataclass(frozen=True, slots=True)
class CorrectionTarget:
    """Canonical correctable assertion snapshot loaded behind current authority."""

    assertion_id: str
    root_memory_id: str
    memory_class: MemoryClass
    statement: str
    content_sha256: str
    scope: MemoryScope
    status: MemoryStatus
    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None
    classification: str
    retention_policy_id: str
    evidence_ids: tuple[str, ...]
    aggregate_version: int

    def __post_init__(self) -> None:
        """Reject inactive, forged, temporally invalid, or incomplete targets."""
        _require_uuid7(self.assertion_id, "assertion_id")
        _require_uuid7(self.root_memory_id, "root_memory_id")
        _require_statement(self.statement)
        _require_digest(self.content_sha256, "content_sha256")
        if self.content_sha256 != _content_digest(
            self.memory_class,
            self.statement,
            self.scope,
            self.valid_from,
            self.valid_to,
        ):
            _invalid("content_sha256", "mismatch")
        if self.status not in {
            MemoryStatus.ACTIVE,
            MemoryStatus.MERGED,
            MemoryStatus.DISPUTED,
            MemoryStatus.SUPERSEDED,
        }:
            _invalid("status", "unsupported")
        _require_range(self.valid_from, self.valid_to, "valid")
        _require_range(self.recorded_from, self.recorded_to, "recorded")
        if self.classification not in _CLASSIFICATIONS:
            _invalid("classification", "unsupported")
        _require_token(self.retention_policy_id, "retention_policy_id")
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            _invalid("evidence_ids", "not_canonical")
        for event_id in self.evidence_ids:
            _require_uuid7(event_id, "evidence_ids")
        if self.aggregate_version < 1:
            _invalid("aggregate_version", "out_of_range")


@dataclass(frozen=True, slots=True)
class MemoryCorrectionAssertion:
    """One immutable explicit-user assertion linked to its exact prior assertion."""

    assertion_id: str
    root_memory_id: str
    source_assertion_id: str
    memory_class: MemoryClass
    statement: str
    content_sha256: str
    scope: MemoryScope
    relation: CorrectionRelation
    reason: str
    evidence: tuple[CorrectionEvidence, ...]
    actor_id: str
    grant_id: str
    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None
    status: MemoryStatus
    classification: str
    retention_policy_id: str
    policy_version: str
    aggregate_version: int

    def __post_init__(self) -> None:
        """Authenticate content, lineage, authority, scope, time, and lifecycle."""
        for value, field in (
            (self.assertion_id, "assertion_id"),
            (self.root_memory_id, "root_memory_id"),
            (self.source_assertion_id, "source_assertion_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field)
        if self.assertion_id in {self.root_memory_id, self.source_assertion_id}:
            _invalid("assertion_id", "lineage_cycle")
        _require_statement(self.statement)
        _require_digest(self.content_sha256, "content_sha256")
        if self.content_sha256 != _content_digest(
            self.memory_class,
            self.statement,
            self.scope,
            self.valid_from,
            self.valid_to,
        ):
            _invalid("content_sha256", "mismatch")
        _require_token(self.reason, "reason")
        if len(self.evidence) > _MAX_EVIDENCE or tuple(sorted(set(self.evidence))) != self.evidence:
            _invalid("evidence", "not_canonical")
        _require_range(self.valid_from, self.valid_to, "valid")
        _require_range(self.recorded_from, self.recorded_to, "recorded")
        if self.status not in {
            MemoryStatus.ACTIVE,
            MemoryStatus.DISPUTED,
            MemoryStatus.SUPERSEDED,
        }:
            _invalid("status", "unsupported")
        if self.classification not in _CLASSIFICATIONS:
            _invalid("classification", "unsupported")
        _require_token(self.retention_policy_id, "retention_policy_id")
        if self.policy_version != _POLICY_VERSION:
            _invalid("policy_version", "unsupported")
        if self.aggregate_version < 1:
            _invalid("aggregate_version", "out_of_range")

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """Return canonical optional evidence identities."""
        return tuple(item.event_id for item in self.evidence)

    @property
    def version(self) -> int:
        """Expose the assertion aggregate version for optimistic callers."""
        return self.aggregate_version


@dataclass(frozen=True, slots=True)
class MemoryAssertionSelection:
    """Current assertion chosen by deterministic scope and bitemporal precedence."""

    assertion_id: str
    root_memory_id: str
    statement: str
    scope: MemoryScope
    relation: CorrectionRelation | None
    policy_version: str


@dataclass(frozen=True, slots=True)
class MemoryCorrectionHistory:
    """One root memory and its complete immutable correction assertion chain."""

    root: CorrectionTarget
    corrections: tuple[MemoryCorrectionAssertion, ...]

    def __post_init__(self) -> None:
        """Require one ordered, connected, duplicate-free correction chain."""
        if self.root.assertion_id != self.root.root_memory_id:
            _invalid("history.root", "not_root")
        if (
            tuple(
                sorted(self.corrections, key=lambda item: (item.recorded_from, item.assertion_id))
            )
            != self.corrections
        ):
            _invalid("history.corrections", "not_canonical")
        known = {self.root.assertion_id}
        for correction in self.corrections:
            if (
                correction.root_memory_id != self.root.root_memory_id
                or correction.source_assertion_id not in known
                or correction.assertion_id in known
            ):
                _invalid("history.corrections", "lineage_mismatch")
            known.add(correction.assertion_id)


@dataclass(frozen=True, slots=True)
class MemoryPrecedencePolicy:
    """Give explicit corrections precedence only inside their declared scope and time."""

    policy_version: str = _POLICY_VERSION

    def __post_init__(self) -> None:
        """Reject silent policy drift."""
        if self.policy_version != _POLICY_VERSION:
            _invalid("policy_version", "unsupported")

    def require_correction_scope(self, source: MemoryScope, correction: MemoryScope) -> None:
        """Allow exact or checkout-narrower scope and reject every broadening/rebinding."""
        if (
            source.brain_id != correction.brain_id
            or source.project_id != correction.project_id
            or source.repository_id != correction.repository_id
            or (source.checkout_id is not None and source.checkout_id != correction.checkout_id)
        ):
            _invalid("scope", "not_same_or_narrower")

    def resolve(
        self,
        source: CorrectionTarget,
        corrections: tuple[MemoryCorrectionAssertion, ...],
        query_scope: MemoryScope,
        *,
        valid_at: datetime,
        recorded_at: datetime,
    ) -> MemoryAssertionSelection:
        """Choose the most-specific latest applicable explicit assertion deterministically."""
        _require_utc(valid_at, "valid_at")
        _require_utc(recorded_at, "recorded_at")
        if not _query_within(source.scope, query_scope):
            _invalid("query_scope", "outside_source")
        applicable = tuple(
            item
            for item in corrections
            if item.root_memory_id == source.root_memory_id
            and _query_within(item.scope, query_scope)
            and _contains(item.valid_from, item.valid_to, valid_at)
            and _contains(item.recorded_from, item.recorded_to, recorded_at)
        )
        if applicable:
            selected = max(
                applicable,
                key=lambda item: (
                    item.scope.checkout_id is not None,
                    item.recorded_from,
                    item.assertion_id,
                ),
            )
            return MemoryAssertionSelection(
                selected.assertion_id,
                selected.root_memory_id,
                selected.statement,
                selected.scope,
                selected.relation,
                self.policy_version,
            )
        if not _contains(source.valid_from, source.valid_to, valid_at) or not _contains(
            source.recorded_from, source.recorded_to, recorded_at
        ):
            _invalid("query_time", "no_effective_assertion")
        return MemoryAssertionSelection(
            source.assertion_id,
            source.root_memory_id,
            source.statement,
            source.scope,
            None,
            self.policy_version,
        )


@dataclass(frozen=True, slots=True)
class MemoryCorrectionPlan:
    """Atomic source transition and new correction assertion."""

    target: CorrectionTarget
    assertion: MemoryCorrectionAssertion
    relation: CorrectionRelation
    source_status: MemoryStatus
    source_recorded_to: datetime | None
    source_version: int
    policy_version: str

    @classmethod
    def create(  # noqa: PLR0913 -- every correction coordinate is security-sensitive.
        cls,
        *,
        correction_id: str,
        target: CorrectionTarget,
        expected_version: int,
        statement: str,
        scope: MemoryScope,
        valid_from: datetime,
        valid_to: datetime | None,
        reason: str,
        evidence: tuple[CorrectionEvidence, ...],
        actor_id: str,
        grant_id: str,
        recorded_at: datetime,
        policy: MemoryPrecedencePolicy,
    ) -> MemoryCorrectionPlan:
        """Create a correction only against the exact authorized aggregate version."""
        if expected_version != target.aggregate_version:
            raise MemoryConflictError
        if target.status is not MemoryStatus.ACTIVE and target.recorded_to is not None:
            raise MemoryConflictError
        policy.require_correction_scope(target.scope, scope)
        _require_utc(recorded_at, "recorded_at")
        if recorded_at <= target.recorded_from:
            _invalid("recorded_at", "not_after_source")
        target_subject, target_polarity = canonical_subject(target.statement)
        corrected_subject, corrected_polarity = canonical_subject(statement)
        relation = (
            CorrectionRelation.CONTRADICTS
            if target_subject == corrected_subject and target_polarity is not corrected_polarity
            else CorrectionRelation.SUPERSEDES
        )
        assertion = MemoryCorrectionAssertion(
            correction_id,
            target.root_memory_id,
            target.assertion_id,
            target.memory_class,
            statement,
            _content_digest(target.memory_class, statement, scope, valid_from, valid_to),
            scope,
            relation,
            reason,
            evidence,
            actor_id,
            grant_id,
            valid_from,
            valid_to,
            recorded_at,
            None,
            MemoryStatus.ACTIVE,
            target.classification,
            target.retention_policy_id,
            policy.policy_version,
            1,
        )
        source_status = (
            MemoryStatus.DISPUTED
            if relation is CorrectionRelation.CONTRADICTS
            else MemoryStatus.SUPERSEDED
        )
        return cls(
            target,
            assertion,
            relation,
            source_status,
            recorded_at if scope == target.scope else target.recorded_to,
            target.aggregate_version + 1,
            policy.policy_version,
        )

    def __post_init__(self) -> None:
        """Bind source, result, relationship, lifecycle, and policy exactly."""
        if self.assertion.source_assertion_id != self.target.assertion_id:
            _invalid("assertion.source_assertion_id", "mismatch")
        if self.assertion.root_memory_id != self.target.root_memory_id:
            _invalid("assertion.root_memory_id", "mismatch")
        if self.assertion.relation is not self.relation:
            _invalid("relation", "mismatch")
        expected_status = (
            MemoryStatus.DISPUTED
            if self.relation is CorrectionRelation.CONTRADICTS
            else MemoryStatus.SUPERSEDED
        )
        if self.source_status is not expected_status:
            _invalid("source_status", "mismatch")
        if self.source_version != self.target.aggregate_version + 1:
            _invalid("source_version", "mismatch")
        if self.policy_version != self.assertion.policy_version:
            _invalid("policy_version", "mismatch")

    @property
    def result_sha256(self) -> str:
        """Authenticate the complete content-free correction outcome."""
        return _digest_document(
            {
                "assertion_id": self.assertion.assertion_id,
                "content_sha256": self.assertion.content_sha256,
                "evidence_ids": list(self.assertion.evidence_ids),
                "policy_version": self.policy_version,
                "relation": self.relation.value,
                "root_memory_id": self.target.root_memory_id,
                "source_assertion_id": self.target.assertion_id,
                "source_status": self.source_status.value,
                "source_version": self.source_version,
            }
        )


@dataclass(frozen=True, slots=True)
class MemoryCorrectionResult:
    """Authenticated idempotent receipt for one explicit correction."""

    idempotency_key: str
    request_sha256: str
    plan_sha256: str
    correction_id: str
    root_memory_id: str
    source_assertion_id: str
    relation: CorrectionRelation
    source_status: MemoryStatus
    source_version: int
    policy_version: str
    result_sha256: str

    @classmethod
    def create(
        cls,
        idempotency_key: str,
        request_sha256: str,
        plan: MemoryCorrectionPlan,
    ) -> MemoryCorrectionResult:
        """Build the stable result from the complete policy-approved plan."""
        document = {
            "correction_id": plan.assertion.assertion_id,
            "idempotency_key": idempotency_key,
            "plan_sha256": plan.result_sha256,
            "policy_version": plan.policy_version,
            "relation": plan.relation.value,
            "request_sha256": request_sha256,
            "root_memory_id": plan.target.root_memory_id,
            "source_assertion_id": plan.target.assertion_id,
            "source_status": plan.source_status.value,
            "source_version": plan.source_version,
        }
        return cls(
            idempotency_key,
            request_sha256,
            plan.result_sha256,
            plan.assertion.assertion_id,
            plan.target.root_memory_id,
            plan.target.assertion_id,
            plan.relation,
            plan.source_status,
            plan.source_version,
            plan.policy_version,
            _digest_document(document),
        )

    def __post_init__(self) -> None:
        """Reject replay receipts whose identities, lifecycle, or digest diverge."""
        _require_digest(self.idempotency_key, "idempotency_key")
        _require_digest(self.request_sha256, "request_sha256")
        _require_digest(self.plan_sha256, "plan_sha256")
        for value, field in (
            (self.correction_id, "correction_id"),
            (self.root_memory_id, "root_memory_id"),
            (self.source_assertion_id, "source_assertion_id"),
        ):
            _require_uuid7(value, field)
        if self.source_status not in {MemoryStatus.DISPUTED, MemoryStatus.SUPERSEDED}:
            _invalid("source_status", "unsupported")
        if self.source_version < _MIN_CORRECTED_SOURCE_VERSION:
            _invalid("source_version", "out_of_range")
        if self.policy_version != _POLICY_VERSION:
            _invalid("policy_version", "unsupported")
        _require_digest(self.result_sha256, "result_sha256")
        canonical = _digest_document(
            {
                "correction_id": self.correction_id,
                "idempotency_key": self.idempotency_key,
                "plan_sha256": self.plan_sha256,
                "policy_version": self.policy_version,
                "relation": self.relation.value,
                "request_sha256": self.request_sha256,
                "root_memory_id": self.root_memory_id,
                "source_assertion_id": self.source_assertion_id,
                "source_status": self.source_status.value,
                "source_version": self.source_version,
            }
        )
        if self.result_sha256 != canonical:
            _invalid("result_sha256", "mismatch")


@dataclass(frozen=True, slots=True)
class MemoryCorrectionCommit:
    """Complete authorized atomic write intent for a correction assertion."""

    operation_id: str
    actor_id: str
    grant_id: str
    brain_id: str
    correlation_id: str
    causation_id: str
    target: CorrectionTarget
    plan: MemoryCorrectionPlan
    result: MemoryCorrectionResult
    requested_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        """Bind operation, authority, Brain, plan, result, and completion time."""
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
        if self.plan.target != self.target:
            _invalid("plan", "target_mismatch")
        if (
            self.plan.assertion.assertion_id != self.operation_id
            or self.plan.assertion.actor_id != self.actor_id
            or self.plan.assertion.grant_id != self.grant_id
        ):
            _invalid("plan", "authority_mismatch")
        expected = MemoryCorrectionResult.create(
            self.result.idempotency_key,
            self.result.request_sha256,
            self.plan,
        )
        if expected != self.result:
            _invalid("result", "plan_mismatch")


def correction_idempotency_key(operation_id: str, assertion_id: str, brain_id: str) -> str:
    """Bind an explicit operation to one exact target assertion and Brain."""
    for value, field in (
        (operation_id, "operation_id"),
        (assertion_id, "assertion_id"),
        (brain_id, "brain_id"),
    ):
        _require_uuid7(value, field)
    return _digest_document(
        {"assertion_id": assertion_id, "brain_id": brain_id, "operation_id": operation_id}
    )


def _query_within(declared: MemoryScope, query: MemoryScope) -> bool:
    return (
        declared.brain_id == query.brain_id
        and declared.project_id == query.project_id
        and declared.repository_id == query.repository_id
        and (declared.checkout_id is None or declared.checkout_id == query.checkout_id)
    )


def _contains(start: datetime, end: datetime | None, value: datetime) -> bool:
    return start <= value and (end is None or value < end)


def _content_digest(
    memory_class: MemoryClass,
    statement: str,
    scope: MemoryScope,
    valid_from: datetime,
    valid_to: datetime | None,
) -> str:
    _require_statement(statement)
    _require_range(valid_from, valid_to, "valid")
    return _digest_document(
        {
            "memory_class": memory_class.value,
            "scope": dict(scope.canonical),
            "statement": statement,
            "valid_from": _format_time(valid_from),
            "valid_to": None if valid_to is None else _format_time(valid_to),
        }
    )


def _digest_document(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _require_statement(value: str) -> None:
    if (
        not value
        or len(value) > _MAX_STATEMENT_CHARACTERS
        or value != unicodedata.normalize("NFC", value).strip()
        or any(
            ord(character) < _C0_CONTROL_LIMIT or ord(character) == _DELETE_CONTROL
            for character in value
        )
    ):
        _invalid("statement", "invalid")


def _require_range(start: datetime, end: datetime | None, field: str) -> None:
    _require_utc(start, f"{field}_from")
    if end is not None:
        _require_utc(end, f"{field}_to")
        if end <= start:
            _invalid(f"{field}_to", "not_after_start")


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


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
