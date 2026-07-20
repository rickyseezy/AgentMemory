"""Priority admission, retry, and immutable dead-letter policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Never
from urllib.parse import urlsplit

from agentmemory.ingestion.domain.errors import IngestionValidationError

_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_DIAGNOSTIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_REFERENCE_SCHEMES = frozenset({"artifact", "cas", "local-object"})
_MIN_BACKGROUND_STRIDE = 2
_MAX_BACKGROUND_STRIDE = 1024
_PERCENT_MAX = 100
_MIN_RETRY_ATTEMPTS = 2
_MAX_IDEMPOTENCY_KEY_LENGTH = 256
_MAX_REFERENCE_LENGTH = 512
_PRINTABLE_ASCII_MIN = 33
_PRINTABLE_ASCII_MAX = 126
_NORMAL_DISPATCH_CYCLE = (
    "interactive",
    "capture",
    "interactive",
    "standard",
    "capture",
    "interactive",
    "standard",
    "background",
)


class JobPriority(StrEnum):
    """Closed independently queued scheduling classes."""

    INTERACTIVE = "interactive"
    CAPTURE = "capture"
    STANDARD = "standard"
    BACKGROUND = "background"


class JobState(StrEnum):
    """Closed durable job lifecycle including immutable terminal DLQ state."""

    QUEUED = "queued"
    LEASED = "leased"
    RETRY_SCHEDULED = "retry_scheduled"
    SUCCEEDED = "succeeded"
    DEAD_LETTERED = "dead_lettered"


class JobErrorCode(StrEnum):
    """Safe typed worker outcomes; arbitrary exceptions never enter durable state."""

    INVALID_INPUT = "invalid_input"
    AUTHORIZATION_DENIED = "authorization_denied"
    INTEGRITY_VIOLATION = "integrity_violation"
    POISON_JOB = "poison_job"
    RATE_LIMITED = "rate_limited"
    CAPACITY_EXHAUSTED = "capacity_exhausted"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    TRANSIENT_STORAGE = "transient_storage"
    INTERNAL_ERROR = "internal_error"


class AdmissionDisposition(StrEnum):
    """Closed admission decision before any new durable write."""

    ADMIT = "admit"
    THROTTLE = "throttle"
    REJECT_CAPACITY = "reject_capacity"


class RetryMode(StrEnum):
    """Closed retry algorithms."""

    NONE = "none"
    BOUNDED = "bounded"
    EXPONENTIAL_BACKOFF = "exponential_backoff"


class RetryDisposition(StrEnum):
    """Retry-policy terminal decision for one failed attempt."""

    RETRY = "retry"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class CapacitySnapshot:
    """Content-free queue and local-storage facts used for admission."""

    total_pending: int
    interactive_pending: int
    capture_pending: int
    standard_pending: int
    background_pending: int
    free_bytes: int
    existing_identity: bool

    def __post_init__(self) -> None:
        """Reject negative or internally impossible capacity evidence."""
        counts = (
            self.total_pending,
            self.interactive_pending,
            self.capture_pending,
            self.standard_pending,
            self.background_pending,
            self.free_bytes,
        )
        if any(value < 0 for value in counts):
            _invalid("capacity_snapshot", "out_of_range")
        classified = sum(counts[1:5])
        if classified > self.total_pending:
            _invalid("capacity_snapshot", "inconsistent_counts")


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """Content-free admission result plus stable threshold reason."""

    disposition: AdmissionDisposition
    reason_code: str | None

    def __post_init__(self) -> None:
        """Require a reason only when work was not immediately admitted."""
        if (self.disposition is AdmissionDisposition.ADMIT) != (self.reason_code is None):
            _invalid("admission_decision", "invalid_shape")
        if self.reason_code is not None and _SAFE_DIAGNOSTIC.fullmatch(self.reason_code) is None:
            _invalid("reason_code", "invalid")


@dataclass(frozen=True, slots=True)
class QueueLimits:
    """Immutable queue/disk thresholds and reserved admission capacity."""

    soft_pending: int
    hard_pending: int
    reserved_interactive: int
    reserved_capture: int
    soft_free_bytes: int
    hard_free_bytes: int
    soft_background_stride: int
    alert_percentages: tuple[int, ...]

    def __post_init__(self) -> None:
        """Require monotonic limits with usable reserved capacity."""
        if self.soft_pending < 1 or self.hard_pending <= self.soft_pending:
            _invalid("queue_pending_limits", "invalid")
        if (
            self.reserved_interactive < 1
            or self.reserved_capture < 1
            or self.reserved_interactive >= self.soft_pending
            or self.reserved_capture >= self.soft_pending
            or self.reserved_interactive + self.reserved_capture >= self.hard_pending
        ):
            _invalid("queue_reservations", "invalid")
        if self.hard_free_bytes < 0 or self.soft_free_bytes <= self.hard_free_bytes:
            _invalid("queue_disk_limits", "invalid")
        if not _MIN_BACKGROUND_STRIDE <= self.soft_background_stride <= _MAX_BACKGROUND_STRIDE:
            _invalid("soft_background_stride", "out_of_range")
        if (
            not self.alert_percentages
            or tuple(sorted(set(self.alert_percentages))) != self.alert_percentages
            or any(not 1 <= value <= _PERCENT_MAX for value in self.alert_percentages)
            or self.alert_percentages[-1] != _PERCENT_MAX
        ):
            _invalid("alert_percentages", "invalid")

    def admit(self, priority: JobPriority, snapshot: CapacitySnapshot) -> AdmissionDecision:
        """Reserve capacity and slow background work before hard exhaustion."""
        if snapshot.existing_identity:
            return AdmissionDecision(AdmissionDisposition.ADMIT, None)
        if snapshot.free_bytes <= self.hard_free_bytes:
            return AdmissionDecision(AdmissionDisposition.REJECT_CAPACITY, "disk_hard_limit")
        if snapshot.total_pending >= self._ceiling(priority):
            return AdmissionDecision(AdmissionDisposition.REJECT_CAPACITY, "queue_hard_limit")
        soft_pressure = (
            snapshot.total_pending >= self.soft_pending
            or snapshot.free_bytes <= self.soft_free_bytes
        )
        if soft_pressure and priority is JobPriority.BACKGROUND:
            return AdmissionDecision(AdmissionDisposition.THROTTLE, "background_soft_limit")
        return AdmissionDecision(AdmissionDisposition.ADMIT, None)

    def _ceiling(self, priority: JobPriority) -> int:
        if priority is JobPriority.INTERACTIVE:
            return self.hard_pending
        if priority is JobPriority.CAPTURE:
            return self.hard_pending - self.reserved_interactive
        return self.hard_pending - self.reserved_interactive - self.reserved_capture


@dataclass(frozen=True, slots=True)
class RetryRule:
    """One typed none, bounded, or exponential retry rule."""

    error_code: JobErrorCode
    mode: RetryMode
    max_attempts: int
    base_delay_microseconds: int
    maximum_delay_microseconds: int

    def __post_init__(self) -> None:
        """Reject rules that can retry forever or compute invalid delays."""
        if self.max_attempts < 1:
            _invalid("max_attempts", "out_of_range")
        if self.mode is RetryMode.NONE:
            if self.base_delay_microseconds != 0 or self.maximum_delay_microseconds != 0:
                _invalid("retry_delay", "unexpected")
            return
        if (
            self.max_attempts < _MIN_RETRY_ATTEMPTS
            or self.base_delay_microseconds < 1
            or self.maximum_delay_microseconds < self.base_delay_microseconds
        ):
            _invalid("retry_delay", "invalid")
        if (
            self.mode is RetryMode.BOUNDED
            and self.maximum_delay_microseconds != self.base_delay_microseconds
        ):
            _invalid("retry_delay", "bounded_mismatch")


@dataclass(frozen=True, slots=True)
class RetryDecision:
    """Pure failure outcome with deterministic delay evidence."""

    disposition: RetryDisposition
    delay_microseconds: int | None

    def __post_init__(self) -> None:
        """Require delays only for retries."""
        retry = self.disposition is RetryDisposition.RETRY
        if retry != (self.delay_microseconds is not None):
            _invalid("retry_decision", "invalid_shape")
        if self.delay_microseconds is not None and self.delay_microseconds < 1:
            _invalid("delay_microseconds", "out_of_range")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Complete typed mapping from safe worker failure to retry or DLQ."""

    rules: tuple[RetryRule, ...]

    def __post_init__(self) -> None:
        """Require exactly one rule for every closed error code."""
        codes = tuple(rule.error_code for rule in self.rules)
        if len(set(codes)) != len(codes):
            _invalid("retry_rules", "duplicate_error_code")
        if set(codes) != set(JobErrorCode):
            _invalid("retry_rules", "incomplete")

    @classmethod
    def default(cls) -> RetryPolicy:
        """Return the version-one production retry policy."""
        no_retry = (
            JobErrorCode.INVALID_INPUT,
            JobErrorCode.AUTHORIZATION_DENIED,
            JobErrorCode.INTEGRITY_VIOLATION,
            JobErrorCode.POISON_JOB,
        )
        rules = [RetryRule(code, RetryMode.NONE, 1, 0, 0) for code in no_retry]
        rules.extend(
            (
                RetryRule(JobErrorCode.RATE_LIMITED, RetryMode.BOUNDED, 5, 5_000_000, 5_000_000),
                RetryRule(
                    JobErrorCode.CAPACITY_EXHAUSTED,
                    RetryMode.BOUNDED,
                    12,
                    30_000_000,
                    30_000_000,
                ),
                RetryRule(
                    JobErrorCode.DEPENDENCY_UNAVAILABLE,
                    RetryMode.EXPONENTIAL_BACKOFF,
                    9,
                    1_000_000,
                    60_000_000,
                ),
                RetryRule(
                    JobErrorCode.TRANSIENT_STORAGE,
                    RetryMode.EXPONENTIAL_BACKOFF,
                    9,
                    1_000_000,
                    60_000_000,
                ),
                RetryRule(
                    JobErrorCode.INTERNAL_ERROR,
                    RetryMode.EXPONENTIAL_BACKOFF,
                    3,
                    1_000_000,
                    4_000_000,
                ),
            )
        )
        return cls(tuple(rules))

    def decide(self, error_code: JobErrorCode, attempts: int) -> RetryDecision:
        """Return a deterministic bounded outcome for the completed attempt count."""
        if attempts < 1:
            _invalid("attempts", "out_of_range")
        rule = next(rule for rule in self.rules if rule.error_code is error_code)
        if rule.mode is RetryMode.NONE or attempts >= rule.max_attempts:
            return RetryDecision(RetryDisposition.DEAD_LETTER, None)
        if rule.mode is RetryMode.BOUNDED:
            delay = rule.base_delay_microseconds
        else:
            delay = min(
                rule.base_delay_microseconds * (2 ** (attempts - 1)),
                rule.maximum_delay_microseconds,
            )
        return RetryDecision(RetryDisposition.RETRY, delay)


@dataclass(frozen=True, slots=True)
class JobRequest:
    """Authorized immutable work identity and content-addressed input."""

    job_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    kind: str
    idempotency_key: str
    request_sha256: str
    priority: JobPriority
    input_ref: str | None

    def __post_init__(self) -> None:
        """Reject ambiguous IDs, mutable input, and unsafe references."""
        for value, field_name in (
            (self.job_id, "job_id"),
            (self.brain_id, "brain_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field_name)
        if _SAFE_NAME.fullmatch(self.kind) is None:
            _invalid("kind", "invalid")
        if not self.idempotency_key or len(self.idempotency_key) > _MAX_IDEMPOTENCY_KEY_LENGTH:
            _invalid("idempotency_key", "invalid")
        if any(
            not _PRINTABLE_ASCII_MIN <= ord(character) <= _PRINTABLE_ASCII_MAX
            for character in self.idempotency_key
        ):
            _invalid("idempotency_key", "invalid")
        _require_digest(self.request_sha256, "request_sha256")
        if self.input_ref is not None:
            _require_safe_reference(self.input_ref)


@dataclass(frozen=True, slots=True)
class ScheduledJob:
    """Durable content-free scheduling and lineage evidence."""

    request: JobRequest
    state: JobState
    attempts: int
    next_attempt_at_microseconds: int
    lease_owner: str | None
    lease_until_microseconds: int | None
    last_error_code: JobErrorCode | None
    result_sha256: str | None
    completed_at_microseconds: int | None
    parent_job_id: str | None
    source_dead_letter_id: str | None
    created_at_microseconds: int
    updated_at_microseconds: int

    def __post_init__(self) -> None:  # noqa: C901 -- Closed lifecycle validator.
        """Reject incomplete leases, results, failures, and replay lineage."""
        if self.attempts < 0 or self.next_attempt_at_microseconds < 0:
            _invalid("job_progress", "out_of_range")
        if min(self.created_at_microseconds, self.updated_at_microseconds) < 0:
            _invalid("job_timestamp", "out_of_range")
        leased = self.state is JobState.LEASED
        if leased != (self.lease_owner is not None and self.lease_until_microseconds is not None):
            _invalid("job_lease", "invalid_shape")
        if self.lease_owner is not None and _SAFE_NAME.fullmatch(self.lease_owner) is None:
            _invalid("lease_owner", "invalid")
        if self.lease_until_microseconds is not None and self.lease_until_microseconds < 0:
            _invalid("lease_until_microseconds", "out_of_range")
        succeeded = self.state is JobState.SUCCEEDED
        has_result = self.result_sha256 is not None and self.completed_at_microseconds is not None
        if succeeded != has_result:
            _invalid("job_completion", "invalid_shape")
        if self.result_sha256 is not None:
            _require_digest(self.result_sha256, "result_sha256")
        if self.completed_at_microseconds is not None and self.completed_at_microseconds < 0:
            _invalid("completed_at_microseconds", "out_of_range")
        failed = self.state in {JobState.RETRY_SCHEDULED, JobState.DEAD_LETTERED}
        if failed != (self.last_error_code is not None):
            _invalid("job_failure", "invalid_shape")
        for value, field_name in (
            (self.parent_job_id, "parent_job_id"),
            (self.source_dead_letter_id, "source_dead_letter_id"),
        ):
            if value is not None:
                _require_uuid7(value, field_name)
        if self.source_dead_letter_id is not None and self.parent_job_id is None:
            _invalid("job_lineage", "missing_parent")


@dataclass(frozen=True, slots=True)
class DeadLetter:
    """Immutable safe failure evidence for one exhausted/nonretryable job."""

    dead_letter_id: str
    original_job_id: str
    brain_id: str
    priority: JobPriority
    kind: str
    request_sha256: str
    attempts: int
    error_code: JobErrorCode
    diagnostic_code: str
    failed_at_microseconds: int
    created_at_microseconds: int

    def __post_init__(self) -> None:
        """Require content-free typed evidence and exact immutable identity."""
        for value, field_name in (
            (self.dead_letter_id, "dead_letter_id"),
            (self.original_job_id, "original_job_id"),
            (self.brain_id, "brain_id"),
        ):
            _require_uuid7(value, field_name)
        if _SAFE_NAME.fullmatch(self.kind) is None:
            _invalid("kind", "invalid")
        _require_digest(self.request_sha256, "request_sha256")
        if self.attempts < 1:
            _invalid("attempts", "out_of_range")
        if _SAFE_DIAGNOSTIC.fullmatch(self.diagnostic_code) is None:
            _invalid("diagnostic_code", "invalid")
        if min(self.failed_at_microseconds, self.created_at_microseconds) < 0:
            _invalid("dead_letter_timestamp", "out_of_range")


@dataclass(frozen=True, slots=True)
class ReplayDeadLetterRequest:
    """Authorized immutable request to create a linked new attempt."""

    operation_id: str
    dead_letter_id: str
    new_job_id: str
    actor_id: str
    grant_id: str
    corrected_request_sha256: str
    corrected_input_ref: str | None

    def __post_init__(self) -> None:
        """Require new identities and content-addressed corrected input."""
        for value, field_name in (
            (self.operation_id, "operation_id"),
            (self.dead_letter_id, "dead_letter_id"),
            (self.new_job_id, "new_job_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field_name)
        _require_digest(self.corrected_request_sha256, "corrected_request_sha256")
        if self.corrected_input_ref is not None:
            _require_safe_reference(self.corrected_input_ref)

    @property
    def request_sha256(self) -> str:
        """Bind dead letter, corrected work, and authorizing identities."""
        document = {
            "actor_id": self.actor_id,
            "corrected_input_ref": self.corrected_input_ref,
            "corrected_request_sha256": self.corrected_request_sha256,
            "dead_letter_id": self.dead_letter_id,
            "grant_id": self.grant_id,
            "new_job_id": self.new_job_id,
            "schema_version": 1,
        }
        return hashlib.sha256(
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()


def select_dispatch_priority(
    available: frozenset[JobPriority],
    cursor: int,
    *,
    soft_limited: bool,
    background_stride: int,
) -> tuple[JobPriority | None, int]:
    """Select one available independent queue through a persisted weighted cycle."""
    if cursor < 0:
        _invalid("dispatch_cursor", "out_of_range")
    if not _MIN_BACKGROUND_STRIDE <= background_stride <= _MAX_BACKGROUND_STRIDE:
        _invalid("background_stride", "out_of_range")
    if not available:
        return None, cursor
    if soft_limited:
        foreground = _NORMAL_DISPATCH_CYCLE[:-1]
        cycle = tuple(
            JobPriority.BACKGROUND
            if index == background_stride - 1
            else JobPriority(foreground[index % len(foreground)])
            for index in range(background_stride)
        )
    else:
        cycle = tuple(JobPriority(value) for value in _NORMAL_DISPATCH_CYCLE)
    for offset in range(len(cycle)):
        candidate = cycle[(cursor + offset) % len(cycle)]
        if candidate in available:
            return candidate, cursor + offset + 1
    return None, cursor


def _require_uuid7(value: str, field_name: str) -> None:
    if _UUID7.fullmatch(value) is None:
        _invalid(field_name, "invalid_id")


def _require_digest(value: str, field_name: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        _invalid(field_name, "invalid_digest")


def _require_safe_reference(value: str) -> None:
    if not 1 <= len(value) <= _MAX_REFERENCE_LENGTH:
        _invalid("input_ref", "invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in _SAFE_REFERENCE_SCHEMES
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(
            not _PRINTABLE_ASCII_MIN <= ord(character) <= _PRINTABLE_ASCII_MAX
            for character in value
        )
    ):
        _invalid("input_ref", "unsafe")


def _invalid(field_name: str, code: str) -> Never:
    raise IngestionValidationError.single(field_name, code)
