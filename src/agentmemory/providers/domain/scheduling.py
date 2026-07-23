"""PRO-006 pure provider batching, fairness, rate, and result contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.providers.domain.errors import ProviderSchedulingValidationError
from agentmemory.providers.domain.routing import ProviderWorkload

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import Classification
    from agentmemory.providers.domain.profiles import CanonicalPurpose

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PAYLOAD_REF = re.compile(r"^(?:artifact|cas|local-object)://[A-Za-z0-9._:/-]{1,480}$")
_UUID_VERSION = 7
_MAX_ITEMS = 1_000
_MAX_ITEM_TOKENS = 1_000_000
_MAX_REQUEST_TOKENS = 1_000_000
_MAX_INPUT_BYTES = 8 * 1024 * 1024
_MAX_COST_MICROS = 10**15
_MAX_CONCURRENCY = 10_000
_MAX_REQUEST_RATE = 1_000_000
_MAX_TOKEN_RATE = 1_000_000_000
_MINUTE_MICROSECONDS = 60_000_000
_MICRO_UNITS = 1_000_000
_ERR_INPUT = "provider scheduling input is invalid"
_ERR_HOMOGENEOUS = "provider batch must be homogeneous"
_ERR_LIMIT = "provider item exceeds a scheduling limit"
_ERR_DEADLINE = "provider workload and deadline class are incompatible"
_ERR_RESULT = "provider batch result is invalid"


class ProviderDeadlineClass(StrEnum):
    """Closed deadline contracts kept in independent provider batches."""

    INTERACTIVE = "interactive"
    ONLINE = "online"
    BACKGROUND = "background"


class ProviderWorkState(StrEnum):
    """Durable work lifecycle with retry and cancellation states."""

    QUEUED = "queued"
    LEASED = "leased"
    RETRY_SCHEDULED = "retry_scheduled"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ProviderItemResultStatus(StrEnum):
    """Closed child outcomes used to drive exact partial retries."""

    SUCCEEDED = "succeeded"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderBatchKey:
    """Every privacy and semantic coordinate that must be identical in one batch."""

    brain_id: str
    project_id: str | None
    repository_id: str | None
    classification: Classification
    profile_id: str
    profile_version: int
    space_id: str
    space_fingerprint: str
    purpose: CanonicalPurpose
    retention_policy_digest: str
    preprocessing_digest: str
    deadline_class: ProviderDeadlineClass
    workload: ProviderWorkload

    def __post_init__(self) -> None:
        """Reject ambiguous identities and interactive/background mixing."""
        for required_id in (self.brain_id, self.profile_id, self.space_id):
            _uuid7(required_id)
        for optional_id in (self.project_id, self.repository_id):
            if optional_id is not None:
                _uuid7(optional_id)
        if not 1 <= self.profile_version <= 2**31 - 1 or any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.space_fingerprint,
                self.retention_policy_digest,
                self.preprocessing_digest,
            )
        ):
            _invalid()
        interactive = self.workload is ProviderWorkload.INTERACTIVE
        if interactive != (self.deadline_class is ProviderDeadlineClass.INTERACTIVE):
            raise ProviderSchedulingValidationError(_ERR_DEADLINE)

    @property
    def document(self) -> dict[str, object]:
        """Return the exact content-free batching partition."""
        return {
            "brain_id": self.brain_id,
            "classification": self.classification.value,
            "deadline_class": self.deadline_class.value,
            "preprocessing_digest": self.preprocessing_digest,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "project_id": self.project_id,
            "purpose": self.purpose.value,
            "repository_id": self.repository_id,
            "retention_policy_digest": self.retention_policy_digest,
            "space_fingerprint": self.space_fingerprint,
            "space_id": self.space_id,
            "workload": self.workload.value,
        }

    @property
    def digest(self) -> str:
        """Return one stable queue partition identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderWorkItem:
    """One caller-ordered, content-free, durable provider work identity."""

    item_id: str
    operation_id: str
    batch_key: ProviderBatchKey
    ordinal: int
    payload_ref: str
    content_digest: str
    token_count: int
    byte_count: int
    estimated_cost_micros: int
    enqueued_at_microseconds: int
    deadline_at_microseconds: int
    state: ProviderWorkState = ProviderWorkState.QUEUED
    attempts: int = 0

    def __post_init__(self) -> None:
        """Require immutable content identity and a future bounded deadline."""
        _uuid7(self.item_id)
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not 0 <= self.ordinal <= 2**63 - 1
            or _PAYLOAD_REF.fullmatch(self.payload_ref) is None
            or _DIGEST.fullmatch(self.content_digest) is None
            or not 1 <= self.token_count <= _MAX_ITEM_TOKENS
            or not 1 <= self.byte_count <= _MAX_INPUT_BYTES
            or not 0 <= self.estimated_cost_micros <= _MAX_COST_MICROS
            or self.enqueued_at_microseconds < 0
            or self.deadline_at_microseconds <= self.enqueued_at_microseconds
            or not 0 <= self.attempts <= 2**31 - 1
        ):
            _invalid()

    def with_state(
        self,
        state: ProviderWorkState,
        *,
        attempts: int | None = None,
    ) -> ProviderWorkItem:
        """Return a state projection while retaining immutable caller identity."""
        return replace(
            self,
            state=state,
            attempts=self.attempts if attempts is None else attempts,
        )

    @property
    def document(self) -> dict[str, object]:
        """Return idempotency fields without payload content."""
        return {
            "batch_key": self.batch_key.document,
            "byte_count": self.byte_count,
            "content_digest": self.content_digest,
            "deadline_at_microseconds": self.deadline_at_microseconds,
            "estimated_cost_micros": self.estimated_cost_micros,
            "operation_id": self.operation_id,
            "ordinal": self.ordinal,
            "payload_ref": self.payload_ref,
            "token_count": self.token_count,
        }


@dataclass(frozen=True, slots=True)
class ProviderSchedulingLimits:
    """Exact per-item and per-request batch ceilings."""

    max_items: int
    max_item_tokens: int
    max_request_tokens: int
    max_input_bytes: int
    max_batch_cost_micros: int

    def __post_init__(self) -> None:
        """Require positive, monotonic, production-bounded limits."""
        if (
            not 1 <= self.max_items <= _MAX_ITEMS
            or not 1 <= self.max_item_tokens <= _MAX_ITEM_TOKENS
            or not self.max_item_tokens <= self.max_request_tokens <= _MAX_REQUEST_TOKENS
            or not 1 <= self.max_input_bytes <= _MAX_INPUT_BYTES
            or not 0 <= self.max_batch_cost_micros <= _MAX_COST_MICROS
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderBatch:
    """One exact homogeneous provider operation and ordered child set."""

    operation_id: str
    key: ProviderBatchKey
    items: tuple[ProviderWorkItem, ...]
    token_count: int
    byte_count: int
    estimated_cost_micros: int

    def __post_init__(self) -> None:
        """Protect planner output from hand-built mixed or inconsistent batches."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not self.items
            or any(item.batch_key != self.key for item in self.items)
            or len({item.item_id for item in self.items}) != len(self.items)
            or self.token_count != sum(item.token_count for item in self.items)
            or self.byte_count != sum(item.byte_count for item in self.items)
            or self.estimated_cost_micros != sum(item.estimated_cost_micros for item in self.items)
        ):
            raise ProviderSchedulingValidationError(_ERR_HOMOGENEOUS)


class BatchPlanner:
    """Pure stable splitter over already-authorized metadata."""

    @staticmethod
    def plan(
        items: tuple[ProviderWorkItem, ...],
        limits: ProviderSchedulingLimits,
    ) -> tuple[ProviderBatch, ...]:
        """Split without reordering, dropping, duplicating, or mixing any child."""
        if not items:
            _invalid()
        first_key = items[0].batch_key
        if (
            any(item.batch_key != first_key for item in items)
            or len({item.item_id for item in items}) != len(items)
            or len({(item.operation_id, item.ordinal) for item in items}) != len(items)
        ):
            raise ProviderSchedulingValidationError(_ERR_HOMOGENEOUS)
        for value in items:
            if (
                value.token_count > limits.max_item_tokens
                or value.token_count > limits.max_request_tokens
                or value.byte_count > limits.max_input_bytes
                or value.estimated_cost_micros > limits.max_batch_cost_micros
            ):
                raise ProviderSchedulingValidationError(_ERR_LIMIT)
        batches: list[ProviderBatch] = []
        current: list[ProviderWorkItem] = []
        tokens = bytes_count = cost = 0
        for value in items:
            exceeds = bool(current) and (
                len(current) + 1 > limits.max_items
                or tokens + value.token_count > limits.max_request_tokens
                or bytes_count + value.byte_count > limits.max_input_bytes
                or cost + value.estimated_cost_micros > limits.max_batch_cost_micros
            )
            if exceeds:
                batches.append(_batch(first_key, tuple(current), len(batches)))
                current, tokens, bytes_count, cost = [], 0, 0, 0
            current.append(value)
            tokens += value.token_count
            bytes_count += value.byte_count
            cost += value.estimated_cost_micros
        batches.append(_batch(first_key, tuple(current), len(batches)))
        return tuple(batches)


_FAIR_CYCLE = (
    ProviderWorkload.INTERACTIVE,
    ProviderWorkload.CAPTURE,
    ProviderWorkload.INTERACTIVE,
    ProviderWorkload.MAINTENANCE,
    ProviderWorkload.INTERACTIVE,
    ProviderWorkload.CAPTURE,
    ProviderWorkload.BACKFILL,
    ProviderWorkload.INTERACTIVE,
    ProviderWorkload.EVALUATION,
)


@dataclass(frozen=True, slots=True)
class WeightedFairProviderScheduler:
    """Deterministic weighted round robin with one bounded slot per workload."""

    cycle: tuple[ProviderWorkload, ...] = _FAIR_CYCLE

    def __post_init__(self) -> None:
        """Require every closed workload to have a finite scheduling opportunity."""
        if not self.cycle or set(self.cycle) != set(ProviderWorkload):
            _invalid()

    @property
    def cycle_length(self) -> int:
        """Return the maximum continuously-backlogged starvation bound."""
        return len(self.cycle)

    def select(
        self,
        available: frozenset[ProviderWorkload],
        cursor: int,
    ) -> tuple[ProviderWorkload | None, int]:
        """Select the next available queue and advance past its cycle position."""
        if cursor < 0:
            _invalid()
        if not available:
            return None, cursor % len(self.cycle)
        for offset in range(len(self.cycle)):
            position = (cursor + offset) % len(self.cycle)
            candidate = self.cycle[position]
            if candidate in available:
                return candidate, (position + 1) % len(self.cycle)
        return _invalid()


@dataclass(frozen=True, slots=True)
class ProviderRatePolicy:
    """Dual token-bucket, concurrency, and monthly cost authority."""

    request_capacity: int
    requests_per_minute: int
    token_capacity: int
    tokens_per_minute: int
    max_concurrency: int
    monthly_cost_budget_micros: int

    def __post_init__(self) -> None:
        """Require usable finite ceilings with no implicit unlimited mode."""
        if (
            not 1 <= self.request_capacity <= _MAX_REQUEST_RATE
            or not 1 <= self.requests_per_minute <= _MAX_REQUEST_RATE
            or not 1 <= self.token_capacity <= _MAX_TOKEN_RATE
            or not 1 <= self.tokens_per_minute <= _MAX_TOKEN_RATE
            or not 1 <= self.max_concurrency <= _MAX_CONCURRENCY
            or not 0 <= self.monthly_cost_budget_micros <= _MAX_COST_MICROS
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderRateDecision:
    """Pure admission result carrying the next persisted state and safe reason."""

    allowed: bool
    state: ProviderRateState
    reason: str | None
    retry_at_microseconds: int | None

    def __post_init__(self) -> None:
        """Require a reason only for denied admission."""
        if (
            self.allowed == (self.reason is not None)
            or (self.reason is not None and _SAFE_CODE.fullmatch(self.reason) is None)
            or (self.allowed and self.retry_at_microseconds is not None)
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderRateState:
    """Persistable integer-micro dual-bucket state without floating-point drift."""

    request_balance_micros: int
    token_balance_micros: int
    last_refill_microseconds: int
    blocked_until_microseconds: int | None
    in_flight: int
    period_start_microseconds: int
    cost_spent_micros: int

    def __post_init__(self) -> None:
        """Reject negative or impossible persisted scheduler state."""
        if min(
            self.request_balance_micros,
            self.token_balance_micros,
            self.last_refill_microseconds,
            self.in_flight,
            self.period_start_microseconds,
            self.cost_spent_micros,
        ) < 0 or (
            self.blocked_until_microseconds is not None and self.blocked_until_microseconds < 0
        ):
            _invalid()

    @classmethod
    def full(
        cls,
        policy: ProviderRatePolicy,
        *,
        period_start_microseconds: int,
    ) -> ProviderRateState:
        """Initialize one exact full-capacity monthly period."""
        return cls(
            request_balance_micros=policy.request_capacity * _MICRO_UNITS,
            token_balance_micros=policy.token_capacity * _MICRO_UNITS,
            last_refill_microseconds=period_start_microseconds,
            blocked_until_microseconds=None,
            in_flight=0,
            period_start_microseconds=period_start_microseconds,
            cost_spent_micros=0,
        )

    def admit(
        self,
        policy: ProviderRatePolicy,
        *,
        now_microseconds: int,
        token_count: int,
        estimated_cost_micros: int,
    ) -> ProviderRateDecision:
        """Consume one request/tokens/cost atomically or return an exact retry hint."""
        if now_microseconds < self.last_refill_microseconds or token_count < 1:
            _invalid()
        if (
            self.blocked_until_microseconds is not None
            and now_microseconds < self.blocked_until_microseconds
        ):
            return ProviderRateDecision(
                allowed=False,
                state=self,
                reason="provider_rate_hint",
                retry_at_microseconds=self.blocked_until_microseconds,
            )
        if self.in_flight >= policy.max_concurrency:
            return ProviderRateDecision(
                allowed=False,
                state=self,
                reason="concurrency_limit",
                retry_at_microseconds=None,
            )
        if self.cost_spent_micros + estimated_cost_micros > policy.monthly_cost_budget_micros:
            return ProviderRateDecision(
                allowed=False,
                state=self,
                reason="cost_budget",
                retry_at_microseconds=None,
            )
        refilled = self._refill(policy, now_microseconds)
        request_need = _MICRO_UNITS
        token_need = token_count * _MICRO_UNITS
        if refilled.request_balance_micros < request_need:
            retry = _retry_at(
                now_microseconds,
                request_need - refilled.request_balance_micros,
                policy.requests_per_minute,
            )
            return ProviderRateDecision(
                allowed=False,
                state=refilled,
                reason="request_rate",
                retry_at_microseconds=retry,
            )
        if refilled.token_balance_micros < token_need:
            retry = _retry_at(
                now_microseconds,
                token_need - refilled.token_balance_micros,
                policy.tokens_per_minute,
            )
            return ProviderRateDecision(
                allowed=False,
                state=refilled,
                reason="token_rate",
                retry_at_microseconds=retry,
            )
        consumed = replace(
            refilled,
            request_balance_micros=refilled.request_balance_micros - request_need,
            token_balance_micros=refilled.token_balance_micros - token_need,
            blocked_until_microseconds=None,
            in_flight=refilled.in_flight + 1,
            cost_spent_micros=refilled.cost_spent_micros + estimated_cost_micros,
        )
        return ProviderRateDecision(
            allowed=True,
            state=consumed,
            reason=None,
            retry_at_microseconds=None,
        )

    def release(self) -> ProviderRateState:
        """Release one exact in-flight slot without refunding rate or budget."""
        if self.in_flight < 1:
            _invalid()
        return replace(self, in_flight=self.in_flight - 1)

    def _refill(
        self,
        policy: ProviderRatePolicy,
        now_microseconds: int,
    ) -> ProviderRateState:
        elapsed = now_microseconds - self.last_refill_microseconds
        request_added = (
            elapsed * policy.requests_per_minute * _MICRO_UNITS // (_MINUTE_MICROSECONDS)
        )
        token_added = elapsed * policy.tokens_per_minute * _MICRO_UNITS // (_MINUTE_MICROSECONDS)
        return replace(
            self,
            request_balance_micros=min(
                policy.request_capacity * _MICRO_UNITS,
                self.request_balance_micros + request_added,
            ),
            token_balance_micros=min(
                policy.token_capacity * _MICRO_UNITS,
                self.token_balance_micros + token_added,
            ),
            last_refill_microseconds=now_microseconds,
        )


@dataclass(frozen=True, slots=True)
class ProviderItemResult:
    """One exact child result with content-addressed success or typed failure."""

    item_id: str
    status: ProviderItemResultStatus
    result_digest: str | None
    result_ref: str | None
    error_code: str | None
    retry_at_microseconds: int | None

    def __post_init__(self) -> None:
        """Require mutually exclusive complete success/failure shapes."""
        _uuid7(self.item_id)
        succeeded = self.status is ProviderItemResultStatus.SUCCEEDED
        if succeeded:
            if (
                self.result_digest is None
                or _DIGEST.fullmatch(self.result_digest) is None
                or self.result_ref != f"cas://sha256/{self.result_digest}"
                or self.error_code is not None
                or self.retry_at_microseconds is not None
            ):
                raise ProviderSchedulingValidationError(_ERR_RESULT)
            return
        if (
            self.result_digest is not None
            or self.result_ref is not None
            or self.error_code is None
            or _SAFE_CODE.fullmatch(self.error_code) is None
            or (
                self.retry_at_microseconds is not None
                and (
                    self.status is not ProviderItemResultStatus.RETRYABLE_FAILURE
                    or self.retry_at_microseconds < 0
                )
            )
        ):
            raise ProviderSchedulingValidationError(_ERR_RESULT)

    @classmethod
    def succeeded(cls, item_id: str, result_digest: str) -> ProviderItemResult:
        """Build one content-addressed successful child result."""
        return cls(
            item_id,
            ProviderItemResultStatus.SUCCEEDED,
            result_digest,
            f"cas://sha256/{result_digest}",
            None,
            None,
        )

    @classmethod
    def failed(
        cls,
        item_id: str,
        status: ProviderItemResultStatus,
        error_code: str,
        *,
        retry_at_microseconds: int | None = None,
    ) -> ProviderItemResult:
        """Build one typed retryable, permanent, or cancelled result."""
        if status is ProviderItemResultStatus.SUCCEEDED:
            raise ProviderSchedulingValidationError(_ERR_RESULT)
        return cls(item_id, status, None, None, error_code, retry_at_microseconds)


@dataclass(frozen=True, slots=True)
class ProviderBatchOutcome:
    """Ordered child results bound to one batch operation."""

    batch_operation_id: str
    results: tuple[ProviderItemResult, ...]

    def __post_init__(self) -> None:
        """Require one stable batch coordinate before batch-specific validation."""
        if _OPERATION.fullmatch(self.batch_operation_id) is None:
            raise ProviderSchedulingValidationError(_ERR_RESULT)

    def validate_for(self, batch: ProviderBatch) -> None:
        """Require every expected child exactly once in original order."""
        if self.batch_operation_id != batch.operation_id or tuple(
            result.item_id for result in self.results
        ) != tuple(item.item_id for item in batch.items):
            raise ProviderSchedulingValidationError(_ERR_RESULT)

    @property
    def retryable_item_ids(self) -> tuple[str, ...]:
        """Return only retryable children, preserving provider response order."""
        return tuple(
            result.item_id
            for result in self.results
            if result.status is ProviderItemResultStatus.RETRYABLE_FAILURE
        )

    @property
    def retry_at_microseconds(self) -> int | None:
        """Return the latest provider hint required by all retryable children."""
        values = tuple(
            result.retry_at_microseconds
            for result in self.results
            if result.status is ProviderItemResultStatus.RETRYABLE_FAILURE
            and result.retry_at_microseconds is not None
        )
        return max(values, default=None)


@dataclass(frozen=True, slots=True)
class ProviderBatchLease:
    """One durable exact-owner batch lease."""

    batch: ProviderBatch
    owner: str
    lease_until_microseconds: int
    attempt: int

    def __post_init__(self) -> None:
        """Require a bounded worker identity and positive lease/attempt."""
        if (
            _OPERATION.fullmatch(self.owner) is None
            or self.lease_until_microseconds < 1
            or not 1 <= self.attempt <= 2**31 - 1
        ):
            _invalid()


def _batch(
    key: ProviderBatchKey,
    items: tuple[ProviderWorkItem, ...],
    index: int,
) -> ProviderBatch:
    operation_id = (
        "provider-batch-"
        + _digest(
            {
                "index": index,
                "item_ids": [item.item_id for item in items],
                "key": key.digest,
            }
        )[:32]
    )
    return ProviderBatch(
        operation_id,
        key,
        items,
        sum(item.token_count for item in items),
        sum(item.byte_count for item in items),
        sum(item.estimated_cost_micros for item in items),
    )


def _retry_at(now_microseconds: int, deficit_micros: int, rate_per_minute: int) -> int:
    numerator = deficit_micros * _MINUTE_MICROSECONDS
    denominator = rate_per_minute * _MICRO_UNITS
    delay = (numerator + denominator - 1) // denominator
    return now_microseconds + max(1, delay)


def _digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderSchedulingValidationError(_ERR_INPUT) from error
    return hashlib.sha256(payload).hexdigest()


def _uuid7(value: str) -> None:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise ProviderSchedulingValidationError(_ERR_INPUT) from error
    if parsed.version != _UUID_VERSION or str(parsed) != value:
        _invalid()


def _invalid() -> Never:
    raise ProviderSchedulingValidationError(_ERR_INPUT)
