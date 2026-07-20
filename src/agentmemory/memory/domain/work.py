"""Durable automatic MEM-001 consolidation work model and retry policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agentmemory.memory.domain.consolidation import (
    ExtractorIdentity,
    MemoryScope,
    validate_consolidation_command_actor,
    validate_consolidation_command_trace,
)
from agentmemory.memory.domain.errors import MemoryValidationError

_MAX_ATTEMPTS = 9
_MIN_RETRY_ATTEMPTS = 2
_MAX_OWNER_LENGTH = 128
_DIGEST_LENGTH = 64


class MemoryWorkState(StrEnum):
    """Closed durable automatic-consolidation lifecycle."""

    QUEUED = "queued"
    LEASED = "leased"
    RETRY_SCHEDULED = "retry_scheduled"
    SUCCEEDED = "succeeded"
    DEAD_LETTERED = "dead_lettered"


class MemoryWorkErrorCode(StrEnum):
    """Content-free worker failure taxonomy."""

    INVALID_INPUT = "invalid_input"
    AUTHORIZATION_DENIED = "authorization_denied"
    INTEGRITY_VIOLATION = "integrity_violation"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True, slots=True)
class MemoryConsolidationWork:
    """One exact leased terminal snapshot and extractor generation."""

    operation_id: str
    idempotency_key: str
    task_id: str
    terminal_event_id: str
    actor_id: str
    grant_id: str
    correlation_id: str
    causation_id: str
    scope: MemoryScope
    evidence_watermark_sha256: str
    extractor: ExtractorIdentity
    state: MemoryWorkState
    attempts: int
    lease_owner: str
    lease_until_microseconds: int

    def __post_init__(self) -> None:
        """Require a complete exact lease and command identity."""
        validate_consolidation_command_actor(self.operation_id, self.actor_id, self.grant_id)
        validate_consolidation_command_trace(
            self.correlation_id,
            self.causation_id,
            self.task_id,
            self.terminal_event_id,
        )
        _digest(self.idempotency_key, "idempotency_key")
        _digest(self.evidence_watermark_sha256, "evidence_watermark_sha256")
        if self.state is not MemoryWorkState.LEASED:
            _invalid("state", "lease_required")
        if not self.lease_owner or len(self.lease_owner) > _MAX_OWNER_LENGTH:
            _invalid("lease_owner", "invalid")
        if not 1 <= self.attempts <= _MAX_ATTEMPTS or self.lease_until_microseconds < 1:
            _invalid("lease", "invalid")


@dataclass(frozen=True, slots=True)
class MemoryWorkRetryDecision:
    """Bounded retry/dead-letter decision."""

    retry: bool
    delay_microseconds: int | None

    def __post_init__(self) -> None:
        """Require a positive delay exactly for retry decisions."""
        if self.retry != (self.delay_microseconds is not None):
            _invalid("retry", "invalid_shape")
        if self.delay_microseconds is not None and self.delay_microseconds < 1:
            _invalid("retry.delay", "out_of_range")


@dataclass(frozen=True, slots=True)
class MemoryWorkRetryPolicy:
    """Retry only dependency/internal failures within immutable ceilings."""

    dependency_attempts: int = 9
    internal_attempts: int = 3
    base_delay_microseconds: int = 1_000_000
    maximum_delay_microseconds: int = 60_000_000

    def __post_init__(self) -> None:
        """Require usable retry ceilings and monotonic positive delays."""
        if (
            not _MIN_RETRY_ATTEMPTS <= self.dependency_attempts <= _MAX_ATTEMPTS
            or not _MIN_RETRY_ATTEMPTS <= self.internal_attempts <= self.dependency_attempts
            or self.base_delay_microseconds < 1
            or self.maximum_delay_microseconds < self.base_delay_microseconds
        ):
            _invalid("retry_policy", "invalid")

    def decide(
        self,
        error_code: MemoryWorkErrorCode,
        attempts: int,
    ) -> MemoryWorkRetryDecision:
        """Return deterministic exponential delay or terminal disposition."""
        if not 1 <= attempts <= _MAX_ATTEMPTS:
            _invalid("attempts", "out_of_range")
        ceiling = {
            MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE: self.dependency_attempts,
            MemoryWorkErrorCode.INTERNAL_ERROR: self.internal_attempts,
        }.get(error_code, 1)
        if attempts >= ceiling:
            return MemoryWorkRetryDecision(retry=False, delay_microseconds=None)
        delay = min(
            self.base_delay_microseconds * (2 ** (attempts - 1)),
            self.maximum_delay_microseconds,
        )
        return MemoryWorkRetryDecision(retry=True, delay_microseconds=delay)


def _digest(value: str, field: str) -> None:
    if (
        len(value) != _DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
        or set(value) == {"0"}
    ):
        _invalid(field, "invalid_digest")


def _invalid(field: str, code: str) -> None:
    raise MemoryValidationError.single(field, code)
