"""MEM-005 explicit memory lifecycle state machine and recall participation policy."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.memory.domain.errors import MemoryConflictError, MemoryValidationError

if TYPE_CHECKING:
    from agentmemory.memory.domain.consolidation import MemoryScope

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_POLICY_VERSION = "memory-lifecycle.v1"
_FORGET_CONFIRMATION = "forget-memory"
_FIRST_MUTATED_VERSION = 2


class MemoryRecallState(StrEnum):
    """Closed lifecycle overlay controlling recall without rewriting memory truth."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    EXPIRED = "expired"
    FORGOTTEN = "forgotten"


class MemoryLifecycleAction(StrEnum):
    """Closed explicit and scheduler-owned lifecycle transitions."""

    PIN = "pin"
    ARCHIVE = "archive"
    SET_EXPIRY = "set_expiry"
    EXPIRE = "expire"
    FORGET = "forget"


@dataclass(frozen=True, slots=True)
class MemoryLifecycleSnapshot:
    """Current root-memory participation state loaded under exact authority."""

    memory_id: str
    scope: MemoryScope
    recall_state: MemoryRecallState
    pinned: bool
    expires_at: datetime | None
    version: int
    updated_at: datetime

    def __post_init__(self) -> None:
        """Reject impossible or noncanonical lifecycle snapshots."""
        _require_uuid7(self.memory_id, "memory_id")
        if isinstance(self.version, bool) or self.version < 1:
            _invalid("version", "out_of_range")
        _require_utc(self.updated_at, "updated_at")
        if self.expires_at is not None:
            _require_utc(self.expires_at, "expires_at")
        if self.recall_state is not MemoryRecallState.ACTIVE and self.pinned:
            _invalid("pinned", "inactive_memory")
        if self.recall_state is MemoryRecallState.EXPIRED and self.expires_at is None:
            _invalid("expires_at", "required_for_expired")
        if self.recall_state is MemoryRecallState.FORGOTTEN and self.expires_at is not None:
            _invalid("expires_at", "forbidden_for_forgotten")


@dataclass(frozen=True, slots=True)
class MemoryLifecyclePlan:
    """One validated compare-and-swap transition over a logical root memory."""

    source: MemoryLifecycleSnapshot
    result: MemoryLifecycleSnapshot
    action: MemoryLifecycleAction
    policy_version: str = _POLICY_VERSION

    @classmethod
    def create(
        cls,
        source: MemoryLifecycleSnapshot,
        action: MemoryLifecycleAction,
        *,
        expected_version: int,
        occurred_at: datetime,
        expires_at: datetime | None = None,
    ) -> MemoryLifecyclePlan:
        """Apply the closed transition table against the exact observed version."""
        if isinstance(expected_version, bool) or expected_version != source.version:
            raise MemoryConflictError
        _require_utc(occurred_at, "occurred_at")
        if occurred_at < source.updated_at:
            raise MemoryConflictError
        state, pinned, result_expiry = _apply_transition(
            source,
            action,
            occurred_at=occurred_at,
            expires_at=expires_at,
        )
        return cls(
            source,
            MemoryLifecycleSnapshot(
                source.memory_id,
                source.scope,
                state,
                pinned,
                result_expiry,
                source.version + 1,
                occurred_at,
            ),
            action,
        )

    def __post_init__(self) -> None:
        """Bind identity, scope, version, time, action, and policy."""
        if self.source.memory_id != self.result.memory_id or self.source.scope != self.result.scope:
            _invalid("result", "identity_mismatch")
        if self.result.version != self.source.version + 1:
            _invalid("result.version", "mismatch")
        if self.result.updated_at < self.source.updated_at:
            _invalid("result.updated_at", "before_source")
        if self.policy_version != _POLICY_VERSION:
            _invalid("policy_version", "unsupported")
        try:
            state, pinned, expires_at = _apply_transition(
                self.source,
                self.action,
                occurred_at=self.result.updated_at,
                expires_at=(
                    self.result.expires_at
                    if self.action is MemoryLifecycleAction.SET_EXPIRY
                    else None
                ),
            )
        except (MemoryConflictError, MemoryValidationError) as error:
            field = "result"
            raise MemoryValidationError.single(field, "invalid_transition") from error
        if (state, pinned, expires_at) != (
            self.result.recall_state,
            self.result.pinned,
            self.result.expires_at,
        ):
            _invalid("result", "invalid_transition")

    @property
    def requires_deletion_tombstone(self) -> bool:
        """Return whether this transition must start the governance deletion saga."""
        return self.action is MemoryLifecycleAction.FORGET

    @property
    def event_type(self) -> str:
        """Return the closed integration event name for this transition."""
        return {
            MemoryLifecycleAction.PIN: "MemoryPinned",
            MemoryLifecycleAction.ARCHIVE: "MemoryArchived",
            MemoryLifecycleAction.SET_EXPIRY: "MemoryExpirySet",
            MemoryLifecycleAction.EXPIRE: "MemoryExpired",
            MemoryLifecycleAction.FORGET: "MemoryForgotten",
        }[self.action]

    @property
    def result_sha256(self) -> str:
        """Authenticate the complete content-free transition result."""
        return _digest_document(
            {
                "action": self.action.value,
                "expires_at": _optional_time(self.result.expires_at),
                "memory_id": self.result.memory_id,
                "pinned": self.result.pinned,
                "policy_version": self.policy_version,
                "recall_state": self.result.recall_state.value,
                "updated_at": _format_time(self.result.updated_at),
                "version": self.result.version,
            }
        )


@dataclass(frozen=True, slots=True)
class MemoryLifecycleResult:
    """Stable content-free receipt for one lifecycle operation."""

    idempotency_key: str
    request_sha256: str
    plan_sha256: str
    operation_id: str
    memory_id: str
    action: MemoryLifecycleAction
    recall_state: MemoryRecallState
    pinned: bool
    expires_at: datetime | None
    version: int
    policy_version: str
    result_sha256: str

    @classmethod
    def create(
        cls,
        idempotency_key: str,
        request_sha256: str,
        operation_id: str,
        plan: MemoryLifecyclePlan,
    ) -> MemoryLifecycleResult:
        """Create a canonical receipt from one validated plan."""
        document = {
            "action": plan.action.value,
            "expires_at": _optional_time(plan.result.expires_at),
            "idempotency_key": idempotency_key,
            "memory_id": plan.result.memory_id,
            "operation_id": operation_id,
            "pinned": plan.result.pinned,
            "plan_sha256": plan.result_sha256,
            "policy_version": plan.policy_version,
            "recall_state": plan.result.recall_state.value,
            "request_sha256": request_sha256,
            "version": plan.result.version,
        }
        return cls(
            idempotency_key,
            request_sha256,
            plan.result_sha256,
            operation_id,
            plan.result.memory_id,
            plan.action,
            plan.result.recall_state,
            plan.result.pinned,
            plan.result.expires_at,
            plan.result.version,
            plan.policy_version,
            _digest_document(document),
        )

    def __post_init__(self) -> None:
        """Reject forged identities, digests, versions, and state combinations."""
        for value, field in (
            (self.operation_id, "operation_id"),
            (self.memory_id, "memory_id"),
        ):
            _require_uuid7(value, field)
        for value, field in (
            (self.idempotency_key, "idempotency_key"),
            (self.request_sha256, "request_sha256"),
            (self.plan_sha256, "plan_sha256"),
            (self.result_sha256, "result_sha256"),
        ):
            _require_digest(value, field)
        if isinstance(self.version, bool) or self.version < _FIRST_MUTATED_VERSION:
            _invalid("version", "out_of_range")
        if self.policy_version != _POLICY_VERSION:
            _invalid("policy_version", "unsupported")
        if self.expires_at is not None:
            _require_utc(self.expires_at, "expires_at")
        if self.recall_state is not MemoryRecallState.ACTIVE and self.pinned:
            _invalid("pinned", "inactive_memory")
        if self.recall_state is MemoryRecallState.EXPIRED and self.expires_at is None:
            _invalid("expires_at", "required_for_expired")
        if self.recall_state is MemoryRecallState.FORGOTTEN and self.expires_at is not None:
            _invalid("expires_at", "forbidden_for_forgotten")
        expected_digest = _digest_document(
            {
                "action": self.action.value,
                "expires_at": _optional_time(self.expires_at),
                "idempotency_key": self.idempotency_key,
                "memory_id": self.memory_id,
                "operation_id": self.operation_id,
                "pinned": self.pinned,
                "plan_sha256": self.plan_sha256,
                "policy_version": self.policy_version,
                "recall_state": self.recall_state.value,
                "request_sha256": self.request_sha256,
                "version": self.version,
            }
        )
        if self.result_sha256 != expected_digest:
            _invalid("result_sha256", "mismatch")


@dataclass(frozen=True, slots=True)
class MemoryLifecycleCommit:
    """Complete authorized atomic lifecycle write intent."""

    operation_id: str
    actor_id: str
    grant_id: str | None
    brain_id: str
    correlation_id: str
    causation_id: str
    source: MemoryLifecycleSnapshot
    plan: MemoryLifecyclePlan
    result: MemoryLifecycleResult
    requested_at: datetime
    completed_at: datetime
    event_type: str

    def __post_init__(self) -> None:
        """Bind authority, source, result, event, and timestamps."""
        for value, field in (
            (self.operation_id, "operation_id"),
            (self.actor_id, "actor_id"),
            (self.brain_id, "brain_id"),
            (self.correlation_id, "correlation_id"),
            (self.causation_id, "causation_id"),
        ):
            _require_uuid7(value, field)
        if self.grant_id is not None:
            _require_uuid7(self.grant_id, "grant_id")
        _require_utc(self.requested_at, "requested_at")
        _require_utc(self.completed_at, "completed_at")
        if self.completed_at < self.requested_at:
            _invalid("completed_at", "before_request")
        if self.source != self.plan.source:
            _invalid("plan", "source_mismatch")
        if self.source.scope.brain_id != self.brain_id:
            _invalid("brain_id", "scope_mismatch")
        if self.result.operation_id != self.operation_id:
            _invalid("result.operation_id", "mismatch")
        if self.event_type != self.plan.event_type:
            _invalid("event_type", "mismatch")
        if self.plan.action is not MemoryLifecycleAction.EXPIRE and self.grant_id is None:
            _invalid("grant_id", "required")


@dataclass(frozen=True, slots=True)
class MemoryRecallCandidate:
    """Already-authorized candidate with temporal coordinates for final ranking."""

    lifecycle: MemoryLifecycleSnapshot
    semantic_score: float
    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None

    def __post_init__(self) -> None:
        """Require finite score and canonical half-open temporal ranges."""
        if not math.isfinite(self.semantic_score) or not 0 <= self.semantic_score <= 1:
            _invalid("semantic_score", "out_of_range")
        _require_range(self.valid_from, self.valid_to, "valid")
        _require_range(self.recorded_from, self.recorded_to, "recorded")


def rank_recallable_memories(
    candidates: tuple[MemoryRecallCandidate, ...],
    query_scope: MemoryScope,
    *,
    valid_at: datetime,
    recorded_at: datetime,
    now: datetime,
) -> tuple[MemoryRecallCandidate, ...]:
    """Filter scope/time/lifecycle first, then apply pin as a ranking boost only."""
    for value, field in ((valid_at, "valid_at"), (recorded_at, "recorded_at"), (now, "now")):
        _require_utc(value, field)
    eligible = (
        candidate
        for candidate in candidates
        if candidate.lifecycle.recall_state is MemoryRecallState.ACTIVE
        and not _is_due(candidate.lifecycle, now)
        and _scope_contains(candidate.lifecycle.scope, query_scope)
        and _contains(candidate.valid_from, candidate.valid_to, valid_at)
        and _contains(candidate.recorded_from, candidate.recorded_to, recorded_at)
    )
    return tuple(
        sorted(
            eligible,
            key=lambda item: (
                not item.lifecycle.pinned,
                -item.semantic_score,
                -round(item.lifecycle.updated_at.timestamp() * 1_000_000),
                item.lifecycle.memory_id,
            ),
        )
    )


def lifecycle_idempotency_key(operation_id: str, memory_id: str, action: str) -> str:
    """Bind one operation identity to an exact root memory and closed action."""
    _require_uuid7(operation_id, "operation_id")
    _require_uuid7(memory_id, "memory_id")
    try:
        normalized = MemoryLifecycleAction(action)
    except ValueError as error:
        field = "action"
        raise MemoryValidationError.single(field, "unsupported") from error
    return _digest_document(
        {"action": normalized.value, "memory_id": memory_id, "operation_id": operation_id}
    )


def require_forget_confirmation(value: str) -> None:
    """Require the closed destructive-action confirmation without free-form interpretation."""
    if value != _FORGET_CONFIRMATION:
        _invalid("confirmation", "mismatch")


def _apply_transition(
    source: MemoryLifecycleSnapshot,
    action: MemoryLifecycleAction,
    *,
    occurred_at: datetime,
    expires_at: datetime | None,
) -> tuple[MemoryRecallState, bool, datetime | None]:
    transitions = {
        MemoryLifecycleAction.PIN: _pin_transition,
        MemoryLifecycleAction.ARCHIVE: _archive_transition,
        MemoryLifecycleAction.SET_EXPIRY: _set_expiry_transition,
        MemoryLifecycleAction.EXPIRE: _expire_transition,
        MemoryLifecycleAction.FORGET: _forget_transition,
    }
    try:
        transition = transitions[action]
    except (KeyError, TypeError) as error:
        field = "action"
        raise MemoryValidationError.single(field, "unsupported") from error
    return transition(source, occurred_at, expires_at)


def _pin_transition(
    source: MemoryLifecycleSnapshot,
    occurred_at: datetime,
    expires_at: datetime | None,
) -> tuple[MemoryRecallState, bool, datetime | None]:
    del expires_at
    if (
        source.recall_state is not MemoryRecallState.ACTIVE
        or source.pinned
        or _is_due(source, occurred_at)
    ):
        raise MemoryConflictError
    return source.recall_state, True, source.expires_at


def _archive_transition(
    source: MemoryLifecycleSnapshot,
    occurred_at: datetime,
    expires_at: datetime | None,
) -> tuple[MemoryRecallState, bool, datetime | None]:
    del expires_at
    if source.recall_state is not MemoryRecallState.ACTIVE or _is_due(source, occurred_at):
        raise MemoryConflictError
    return MemoryRecallState.ARCHIVED, False, source.expires_at


def _set_expiry_transition(
    source: MemoryLifecycleSnapshot,
    occurred_at: datetime,
    expires_at: datetime | None,
) -> tuple[MemoryRecallState, bool, datetime | None]:
    if source.recall_state not in {MemoryRecallState.ACTIVE, MemoryRecallState.ARCHIVED}:
        raise MemoryConflictError
    if expires_at is None:
        _invalid("expires_at", "required")
    _require_utc(expires_at, "expires_at")
    if expires_at <= occurred_at:
        _invalid("expires_at", "not_after_request")
    return source.recall_state, source.pinned, expires_at


def _expire_transition(
    source: MemoryLifecycleSnapshot,
    occurred_at: datetime,
    expires_at: datetime | None,
) -> tuple[MemoryRecallState, bool, datetime | None]:
    del expires_at
    if (
        source.recall_state not in {MemoryRecallState.ACTIVE, MemoryRecallState.ARCHIVED}
        or source.expires_at is None
        or source.expires_at > occurred_at
    ):
        raise MemoryConflictError
    return MemoryRecallState.EXPIRED, False, source.expires_at


def _forget_transition(
    source: MemoryLifecycleSnapshot,
    occurred_at: datetime,
    expires_at: datetime | None,
) -> tuple[MemoryRecallState, bool, datetime | None]:
    del occurred_at, expires_at
    if source.recall_state is MemoryRecallState.FORGOTTEN:
        raise MemoryConflictError
    return MemoryRecallState.FORGOTTEN, False, None


def _scope_contains(declared: MemoryScope, query: MemoryScope) -> bool:
    return (
        declared.brain_id == query.brain_id
        and declared.project_id == query.project_id
        and declared.repository_id == query.repository_id
        and (declared.checkout_id is None or declared.checkout_id == query.checkout_id)
    )


def _is_due(source: MemoryLifecycleSnapshot, at: datetime) -> bool:
    return source.expires_at is not None and source.expires_at <= at


def _contains(start: datetime, end: datetime | None, value: datetime) -> bool:
    return start <= value and (end is None or value < end)


def _require_range(start: datetime, end: datetime | None, field: str) -> None:
    _require_utc(start, f"{field}_from")
    if end is not None:
        _require_utc(end, f"{field}_to")
        if end <= start:
            _invalid(f"{field}_to", "not_after_start")


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


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise MemoryValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        _invalid(field, "invalid_uuid7")


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        _invalid(field, "invalid_digest")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _optional_time(value: datetime | None) -> str | None:
    return None if value is None else _format_time(value)


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
