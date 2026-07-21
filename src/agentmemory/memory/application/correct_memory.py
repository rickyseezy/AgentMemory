"""MEM-004 authorization-first explicit memory correction use case."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.memory.domain.correction import (
    MemoryCorrectionCommit,
    MemoryCorrectionPlan,
    MemoryCorrectionResult,
    MemoryPrecedencePolicy,
    correction_idempotency_key,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from agentmemory.memory.domain.consolidation import MemoryScope
    from agentmemory.memory.domain.ports import (
        MemoryCorrectionReadRepository,
        MemoryCorrectionUnitOfWorkFactory,
    )
    from agentmemory.shared.clock import Clock

_UUID_VERSION = 7
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MAX_STATEMENT_CHARACTERS = 8_192
_MAX_EVIDENCE = 64


@dataclass(frozen=True, slots=True)
class CorrectMemoryCommand:
    """One explicit correction bound to exact authority, version, scope, and deadline."""

    operation_id: str
    actor_id: str
    grant_id: str
    brain_id: str
    correlation_id: str
    causation_id: str
    assertion_id: str
    expected_version: int
    statement: str
    scope: MemoryScope
    valid_from: datetime
    valid_to: datetime | None
    reason: str
    evidence_ids: tuple[str, ...]
    requested_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        """Reject ambiguous command coordinates before any repository access."""
        correction_idempotency_key(self.operation_id, self.assertion_id, self.brain_id)
        for value, field in (
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
            (self.correlation_id, "correlation_id"),
            (self.causation_id, "causation_id"),
        ):
            _require_uuid7(value, field)
        if self.scope.brain_id != self.brain_id:
            _invalid("scope.brain_id", "mismatch")
        if isinstance(self.expected_version, bool) or self.expected_version < 1:
            _invalid("expected_version", "out_of_range")
        if (
            not self.statement
            or len(self.statement) > _MAX_STATEMENT_CHARACTERS
            or self.statement != unicodedata.normalize("NFC", self.statement).strip()
        ):
            _invalid("statement", "invalid")
        if _TOKEN.fullmatch(self.reason) is None:
            _invalid("reason", "invalid_token")
        if (
            len(self.evidence_ids) > _MAX_EVIDENCE
            or tuple(sorted(set(self.evidence_ids))) != self.evidence_ids
        ):
            _invalid("evidence_ids", "not_canonical")
        for event_id in self.evidence_ids:
            _require_uuid7(event_id, "evidence_ids")
        _require_range(self.valid_from, self.valid_to, "valid")
        _require_utc(self.requested_at, "requested_at")
        _require_utc(self.deadline, "deadline")
        if self.deadline <= self.requested_at:
            _invalid("deadline", "not_after_request")

    @property
    def request_sha256(self) -> str:
        """Bind idempotent replay to every semantic and authority coordinate."""
        return hashlib.sha256(
            json.dumps(
                {
                    "actor_id": self.actor_id,
                    "assertion_id": self.assertion_id,
                    "brain_id": self.brain_id,
                    "causation_id": self.causation_id,
                    "correlation_id": self.correlation_id,
                    "deadline": _format_time(self.deadline),
                    "evidence_ids": list(self.evidence_ids),
                    "expected_version": self.expected_version,
                    "grant_id": self.grant_id,
                    "operation_id": self.operation_id,
                    "reason": self.reason,
                    "requested_at": _format_time(self.requested_at),
                    "scope": dict(self.scope.canonical),
                    "statement": self.statement,
                    "valid_from": _format_time(self.valid_from),
                    "valid_to": None if self.valid_to is None else _format_time(self.valid_to),
                },
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class CorrectMemoryHandler:
    """Plan outside the writer, then reauthorize and CAS the correction atomically."""

    reads: MemoryCorrectionReadRepository
    unit_of_work: MemoryCorrectionUnitOfWorkFactory
    policy: MemoryPrecedencePolicy
    clock: Clock

    async def execute(self, command: CorrectMemoryCommand) -> MemoryCorrectionResult:
        """Commit one explicit correction or return its exact request-bound receipt."""
        now = self.clock.now()
        if command.requested_at > now:
            _invalid("requested_at", "in_future")
        if command.deadline <= now:
            _invalid("deadline", "expired")
        key = correction_idempotency_key(
            command.operation_id,
            command.assertion_id,
            command.brain_id,
        )
        existing = await self.reads.get_result(key)
        if existing is not None:
            return _replay(existing, command.request_sha256)
        target = await self.reads.load_authorized(
            command.assertion_id,
            command.brain_id,
            command.actor_id,
            command.grant_id,
            now,
        )
        if target is None:
            raise MemoryEvidenceNotFoundError
        evidence = await self.reads.load_evidence_authorized(
            command.evidence_ids,
            command.brain_id,
            command.actor_id,
            command.grant_id,
            now,
        )
        if evidence is None or tuple(item.event_id for item in evidence) != command.evidence_ids:
            raise MemoryEvidenceNotFoundError
        plan = MemoryCorrectionPlan.create(
            correction_id=command.operation_id,
            target=target,
            expected_version=command.expected_version,
            statement=command.statement,
            scope=command.scope,
            valid_from=command.valid_from,
            valid_to=command.valid_to,
            reason=command.reason,
            evidence=evidence,
            actor_id=command.actor_id,
            grant_id=command.grant_id,
            recorded_at=now,
            policy=self.policy,
        )
        result = MemoryCorrectionResult.create(key, command.request_sha256, plan)
        commit = MemoryCorrectionCommit(
            command.operation_id,
            command.actor_id,
            command.grant_id,
            command.brain_id,
            command.correlation_id,
            command.causation_id,
            target,
            plan,
            result,
            command.requested_at,
            now,
        )
        async with self.unit_of_work() as unit_of_work:
            concurrent = await unit_of_work.repository.get_result(key)
            if concurrent is not None:
                return _replay(concurrent, command.request_sha256)
            current = await unit_of_work.repository.load_authorized(
                command.assertion_id,
                command.brain_id,
                command.actor_id,
                command.grant_id,
                self.clock.now(),
            )
            if current is None:
                raise MemoryEvidenceNotFoundError
            if current != target:
                raise MemoryConflictError
            current_evidence = await unit_of_work.repository.load_evidence_authorized(
                command.evidence_ids,
                command.brain_id,
                command.actor_id,
                command.grant_id,
                self.clock.now(),
            )
            if current_evidence != evidence:
                raise MemoryConflictError
            await unit_of_work.repository.add(commit)
            await unit_of_work.commit()
        return result


def _replay(result: MemoryCorrectionResult, request_sha256: str) -> MemoryCorrectionResult:
    if result.request_sha256 != request_sha256:
        raise MemoryConflictError
    return result


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise MemoryValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        _invalid(field, "invalid_uuid7")


def _require_range(start: datetime, end: datetime | None, field: str) -> None:
    _require_utc(start, f"{field}_from")
    if end is not None:
        _require_utc(end, f"{field}_to")
        if end <= start:
            _invalid(f"{field}_to", "not_after_start")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
