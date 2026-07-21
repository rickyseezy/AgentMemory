"""MEM-005 separate explicit lifecycle commands and injected-clock expiry scheduler."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar, Never, override
from uuid import UUID, uuid7

from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)
from agentmemory.memory.domain.lifecycle import (
    MemoryLifecycleAction,
    MemoryLifecycleCommit,
    MemoryLifecyclePlan,
    MemoryLifecycleResult,
    lifecycle_idempotency_key,
    require_forget_confirmation,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.domain.lifecycle import MemoryLifecycleSnapshot
    from agentmemory.memory.domain.ports import (
        MemoryLifecycleReadRepository,
        MemoryLifecycleUnitOfWorkFactory,
    )
    from agentmemory.shared.clock import Clock

_UUID_VERSION = 7
_SYSTEM_ACTOR_ID = "018f0000-0000-7000-8000-000000000005"
_MAX_SCHEDULER_BATCH = 100
_DEFAULT_POLL_SECONDS = 0.5
_MAX_POLL_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class _LifecycleCommand:
    """Shared validated coordinates; concrete commands remain separate public types."""

    operation_id: str
    actor_id: str
    grant_id: str
    brain_id: str
    correlation_id: str
    causation_id: str
    memory_id: str
    expected_version: int
    requested_at: datetime
    deadline: datetime

    action: ClassVar[MemoryLifecycleAction]

    def __post_init__(self) -> None:
        """Reject ambiguous authority, identity, version, and deadline coordinates."""
        lifecycle_idempotency_key(self.operation_id, self.memory_id, self.action.value)
        for value, field in (
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
            (self.brain_id, "brain_id"),
            (self.correlation_id, "correlation_id"),
            (self.causation_id, "causation_id"),
        ):
            _require_uuid7(value, field)
        if isinstance(self.expected_version, bool) or self.expected_version < 1:
            _invalid("expected_version", "out_of_range")
        _require_utc(self.requested_at, "requested_at")
        _require_utc(self.deadline, "deadline")
        if self.deadline <= self.requested_at:
            _invalid("deadline", "not_after_request")

    @property
    def request_sha256(self) -> str:
        """Bind exact authority and action-specific coordinates for replay."""
        document: dict[str, object] = {
            "action": self.action.value,
            "actor_id": self.actor_id,
            "brain_id": self.brain_id,
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
            "deadline": _format_time(self.deadline),
            "expected_version": self.expected_version,
            "grant_id": self.grant_id,
            "memory_id": self.memory_id,
            "operation_id": self.operation_id,
            "requested_at": _format_time(self.requested_at),
        }
        document.update(self._request_extras())
        return _digest_document(document)

    def _request_extras(self) -> dict[str, object]:
        return {}


@dataclass(frozen=True, slots=True)
class PinMemoryCommand(_LifecycleCommand):
    """Explicitly boost one active authorized root memory."""

    action: ClassVar[MemoryLifecycleAction] = MemoryLifecycleAction.PIN


@dataclass(frozen=True, slots=True)
class ArchiveMemoryCommand(_LifecycleCommand):
    """Remove one active root memory from ordinary recall while retaining history."""

    action: ClassVar[MemoryLifecycleAction] = MemoryLifecycleAction.ARCHIVE


@dataclass(frozen=True, slots=True)
class SetMemoryExpiryCommand(_LifecycleCommand):
    """Set the exact future expiry boundary for one authorized root memory."""

    expires_at: datetime
    action: ClassVar[MemoryLifecycleAction] = MemoryLifecycleAction.SET_EXPIRY

    @override
    def __post_init__(self) -> None:
        """Validate common coordinates and a strict future UTC expiry."""
        super(SetMemoryExpiryCommand, self).__post_init__()
        _require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.requested_at:
            _invalid("expires_at", "not_after_request")

    @override
    def _request_extras(self) -> dict[str, object]:
        return {"expires_at": _format_time(self.expires_at)}


@dataclass(frozen=True, slots=True)
class ForgetMemoryCommand(_LifecycleCommand):
    """Tombstone one root memory and start its governance deletion saga."""

    confirmation: str
    action: ClassVar[MemoryLifecycleAction] = MemoryLifecycleAction.FORGET

    @override
    def __post_init__(self) -> None:
        """Validate common coordinates and the closed destructive confirmation."""
        super(ForgetMemoryCommand, self).__post_init__()
        require_forget_confirmation(self.confirmation)

    @override
    def _request_extras(self) -> dict[str, object]:
        return {"confirmation": self.confirmation}


@dataclass(frozen=True, slots=True)
class PinMemoryHandler:
    """Handle only explicit pin commands."""

    reads: MemoryLifecycleReadRepository
    unit_of_work: MemoryLifecycleUnitOfWorkFactory
    clock: Clock

    async def execute(self, command: PinMemoryCommand) -> MemoryLifecycleResult:
        """Pin the exact active authorized aggregate version."""
        return await _execute_explicit(command, self.reads, self.unit_of_work, self.clock)


@dataclass(frozen=True, slots=True)
class ArchiveMemoryHandler:
    """Handle only explicit archive commands."""

    reads: MemoryLifecycleReadRepository
    unit_of_work: MemoryLifecycleUnitOfWorkFactory
    clock: Clock

    async def execute(self, command: ArchiveMemoryCommand) -> MemoryLifecycleResult:
        """Archive the exact active authorized aggregate version."""
        return await _execute_explicit(command, self.reads, self.unit_of_work, self.clock)


@dataclass(frozen=True, slots=True)
class SetMemoryExpiryHandler:
    """Handle only explicit expiry-boundary commands."""

    reads: MemoryLifecycleReadRepository
    unit_of_work: MemoryLifecycleUnitOfWorkFactory
    clock: Clock

    async def execute(self, command: SetMemoryExpiryCommand) -> MemoryLifecycleResult:
        """Set a future expiry on the exact authorized aggregate version."""
        return await _execute_explicit(command, self.reads, self.unit_of_work, self.clock)


@dataclass(frozen=True, slots=True)
class ForgetMemoryHandler:
    """Handle only explicit forget commands."""

    reads: MemoryLifecycleReadRepository
    unit_of_work: MemoryLifecycleUnitOfWorkFactory
    clock: Clock

    async def execute(self, command: ForgetMemoryCommand) -> MemoryLifecycleResult:
        """Commit the immediate deny tombstone before any asynchronous purge."""
        return await _execute_explicit(command, self.reads, self.unit_of_work, self.clock)


@dataclass(frozen=True, slots=True)
class MemoryExpiryRunResult:
    """Content-free bounded scheduler outcome."""

    scanned: int
    expired: int
    conflicts: int


@dataclass(frozen=True, slots=True)
class MemoryExpiryScheduler:
    """Expire due memories through the same state machine and atomic repository boundary."""

    reads: MemoryLifecycleReadRepository
    unit_of_work: MemoryLifecycleUnitOfWorkFactory
    clock: Clock
    identity: Callable[[], UUID] = uuid7
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        """Bound idle polling and therefore graceful local shutdown latency."""
        if not 0 < self.poll_seconds <= _MAX_POLL_SECONDS:
            message = "memory expiry poll interval is invalid"
            raise ValueError(message)

    async def run(self, stop: asyncio.Event) -> None:
        """Continuously expire bounded batches until graceful shutdown."""
        while not stop.is_set():
            try:
                await self.run_once()
            except Exception:  # noqa: BLE001 -- A dependency fault must not kill expiry forever.
                await _wait_or_stop(stop, self.poll_seconds)
                continue
            await _wait_or_stop(stop, self.poll_seconds)

    async def run_once(self, *, limit: int = _MAX_SCHEDULER_BATCH) -> MemoryExpiryRunResult:
        """Process one bounded deterministic due snapshot without wall-clock globals."""
        if isinstance(limit, bool) or not 1 <= limit <= _MAX_SCHEDULER_BATCH:
            _invalid("limit", "out_of_range")
        now = self.clock.now()
        _require_utc(now, "clock.now")
        candidates = await self.reads.list_due(now, limit)
        expired = 0
        conflicts = 0
        for source in candidates:
            if source.expires_at is None or source.expires_at > now:
                continue
            try:
                await self._expire(source, now)
            except MemoryConflictError:
                conflicts += 1
            else:
                expired += 1
        return MemoryExpiryRunResult(len(candidates), expired, conflicts)

    async def _expire(self, source: MemoryLifecycleSnapshot, now: datetime) -> None:
        operation_id = str(self.identity())
        request_sha256 = _digest_document(
            {
                "action": MemoryLifecycleAction.EXPIRE.value,
                "expires_at": _format_time(source.expires_at) if source.expires_at else None,
                "memory_id": source.memory_id,
                "operation_id": operation_id,
                "version": source.version,
            }
        )
        key = lifecycle_idempotency_key(
            operation_id,
            source.memory_id,
            MemoryLifecycleAction.EXPIRE.value,
        )
        plan = MemoryLifecyclePlan.create(
            source,
            MemoryLifecycleAction.EXPIRE,
            expected_version=source.version,
            occurred_at=now,
        )
        result = MemoryLifecycleResult.create(key, request_sha256, operation_id, plan)
        commit = MemoryLifecycleCommit(
            operation_id,
            _SYSTEM_ACTOR_ID,
            None,
            source.scope.brain_id,
            operation_id,
            operation_id,
            source,
            plan,
            result,
            now,
            now,
            plan.event_type,
        )
        async with self.unit_of_work() as unit:
            current = next(
                (
                    item
                    for item in await unit.repository.list_due(now, _MAX_SCHEDULER_BATCH)
                    if item.memory_id == source.memory_id
                ),
                None,
            )
            if current != source:
                raise MemoryConflictError
            await unit.repository.add(commit)
            await unit.commit()


async def _execute_explicit(
    command: _LifecycleCommand,
    reads: MemoryLifecycleReadRepository,
    unit_of_work: MemoryLifecycleUnitOfWorkFactory,
    clock: Clock,
) -> MemoryLifecycleResult:
    now = clock.now()
    _require_utc(now, "clock.now")
    if command.requested_at > now:
        _invalid("requested_at", "in_future")
    if command.deadline <= now:
        _invalid("deadline", "expired")
    key = lifecycle_idempotency_key(
        command.operation_id,
        command.memory_id,
        command.action.value,
    )
    existing = await reads.get_result(key)
    if existing is not None:
        return _replay(existing, command.request_sha256)
    source = await reads.load_authorized(
        command.memory_id,
        command.brain_id,
        command.actor_id,
        command.grant_id,
        now,
    )
    if source is None:
        raise MemoryEvidenceNotFoundError
    expires_at = command.expires_at if isinstance(command, SetMemoryExpiryCommand) else None
    try:
        plan = MemoryLifecyclePlan.create(
            source,
            command.action,
            expected_version=command.expected_version,
            occurred_at=now,
            expires_at=expires_at,
        )
    except MemoryConflictError:
        # A concurrent exact request can commit between the optimistic receipt
        # lookup and source load. Its receipt is authoritative over the stale
        # expected version; divergent reuse still fails in _replay.
        concurrent = await reads.get_result(key)
        if concurrent is not None:
            return _replay(concurrent, command.request_sha256)
        raise
    result = MemoryLifecycleResult.create(key, command.request_sha256, command.operation_id, plan)
    commit = MemoryLifecycleCommit(
        command.operation_id,
        command.actor_id,
        command.grant_id,
        command.brain_id,
        command.correlation_id,
        command.causation_id,
        source,
        plan,
        result,
        command.requested_at,
        now,
        plan.event_type,
    )
    async with unit_of_work() as unit:
        concurrent = await unit.repository.get_result(key)
        if concurrent is not None:
            return _replay(concurrent, command.request_sha256)
        current = await unit.repository.load_authorized(
            command.memory_id,
            command.brain_id,
            command.actor_id,
            command.grant_id,
            now,
        )
        if current is None:
            raise MemoryEvidenceNotFoundError
        if current != source:
            raise MemoryConflictError
        await unit.repository.add(commit)
        await unit.commit()
    return result


def _replay(result: MemoryLifecycleResult, request_sha256: str) -> MemoryLifecycleResult:
    if result.request_sha256 != request_sha256:
        raise MemoryConflictError
    return result


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return


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


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        _invalid(field, "not_utc")


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
