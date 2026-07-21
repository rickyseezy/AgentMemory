"""MEM-005 separate lifecycle command handlers and scheduler TDD tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, override

import pytest

from agentmemory.memory.application.memory_lifecycle import (
    ArchiveMemoryCommand,
    ArchiveMemoryHandler,
    ForgetMemoryCommand,
    ForgetMemoryHandler,
    MemoryExpiryScheduler,
    PinMemoryCommand,
    PinMemoryHandler,
    SetMemoryExpiryCommand,
    SetMemoryExpiryHandler,
    _digest_document,  # pyright: ignore[reportPrivateUsage]
    _invalid,  # pyright: ignore[reportPrivateUsage]
    _wait_or_stop,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)
from agentmemory.memory.domain.lifecycle import (
    MemoryLifecycleAction,
    MemoryLifecycleCommit,
    MemoryLifecycleResult,
    MemoryLifecycleSnapshot,
    MemoryRecallState,
)
from tests.memory.test_mem005_lifecycle_domain import (
    BRAIN_ID,
    CHECKOUT_ID,
    MEMORY_ID,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
)

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Self

ACTOR_ID = "018f0000-0000-7000-8000-000000000611"
GRANT_ID = "018f0000-0000-7000-8000-000000000612"
OPERATION_ID = "018f0000-0000-7000-8000-000000000613"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000614"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000615"


@pytest.mark.asyncio
async def test_each_explicit_command_uses_its_own_handler_and_atomic_commit() -> None:
    pin_repository = _Repository(_snapshot())
    pin_unit = _UnitOfWork(pin_repository)
    pin = await PinMemoryHandler(
        pin_repository,
        _UnitOfWorkFactory(pin_unit),
        _Clock(),
    ).execute(_pin())
    archive_repository = _Repository(_snapshot())
    archive_unit = _UnitOfWork(archive_repository)
    archive = await ArchiveMemoryHandler(
        archive_repository,
        _UnitOfWorkFactory(archive_unit),
        _Clock(),
    ).execute(_archive())
    expiry_repository = _Repository(_snapshot())
    expiry_unit = _UnitOfWork(expiry_repository)
    expiry = await SetMemoryExpiryHandler(
        expiry_repository,
        _UnitOfWorkFactory(expiry_unit),
        _Clock(),
    ).execute(_expiry())
    forget_repository = _Repository(_snapshot())
    forget_unit = _UnitOfWork(forget_repository)
    forget = await ForgetMemoryHandler(
        forget_repository,
        _UnitOfWorkFactory(forget_unit),
        _Clock(),
    ).execute(_forget())

    results = (pin, archive, expiry, forget)
    expected = (
        MemoryLifecycleAction.PIN,
        MemoryLifecycleAction.ARCHIVE,
        MemoryLifecycleAction.SET_EXPIRY,
        MemoryLifecycleAction.FORGET,
    )
    repositories = (
        pin_repository,
        archive_repository,
        expiry_repository,
        forget_repository,
    )
    units = (pin_unit, archive_unit, expiry_unit, forget_unit)
    assert tuple(result.action for result in results) == expected
    assert all(repository.commit is not None for repository in repositories)
    assert all(unit.committed for unit in units)


@pytest.mark.asyncio
async def test_authorization_absence_and_transaction_race_fail_closed() -> None:
    missing = _Repository(None)
    with pytest.raises(MemoryEvidenceNotFoundError):
        await PinMemoryHandler(missing, lambda: _UnitOfWork(missing), _Clock()).execute(_pin())

    changed = _Repository(_snapshot(), transactional=replace(_snapshot(), version=2))
    with pytest.raises(MemoryConflictError):
        await PinMemoryHandler(changed, lambda: _UnitOfWork(changed), _Clock()).execute(_pin())
    assert changed.commit is None


@pytest.mark.asyncio
async def test_exact_replay_returns_receipt_and_divergent_reuse_conflicts() -> None:
    repository = _Repository(_snapshot())
    handler = PinMemoryHandler(repository, lambda: _UnitOfWork(repository), _Clock())
    first = await handler.execute(_pin())

    replay = _Repository(_snapshot(), existing=first)
    replay_handler = PinMemoryHandler(replay, lambda: _UnitOfWork(replay), _Clock())
    assert await replay_handler.execute(_pin()) == first
    with pytest.raises(MemoryConflictError):
        await replay_handler.execute(replace(_pin(), expected_version=2))


@pytest.mark.asyncio
async def test_exact_receipt_wins_when_concurrent_commit_precedes_source_load() -> None:
    initial = _Repository(_snapshot())
    result = await PinMemoryHandler(initial, lambda: _UnitOfWork(initial), _Clock()).execute(_pin())
    racing = _RacingRepository(replace(_snapshot(), version=2), existing=result)

    replay = await PinMemoryHandler(racing, lambda: _UnitOfWork(racing), _Clock()).execute(_pin())

    assert replay == result
    assert racing.result_reads == 2
    assert racing.commit is None


@pytest.mark.asyncio
async def test_missing_concurrent_receipt_preserves_version_conflict() -> None:
    changed = _Repository(replace(_snapshot(), version=2))

    with pytest.raises(MemoryConflictError):
        await PinMemoryHandler(changed, lambda: _UnitOfWork(changed), _Clock()).execute(_pin())

    assert changed.commit is None


@pytest.mark.asyncio
async def test_scheduler_expires_exact_due_rows_and_emits_memory_expired() -> None:
    due = replace(_snapshot(), expires_at=NOW + timedelta(minutes=1))
    future = replace(
        _snapshot(),
        memory_id="018f0000-0000-7000-8000-000000000616",
        expires_at=NOW + timedelta(hours=1),
    )
    repository = _Repository(due, due=(due, future))
    scheduler = MemoryExpiryScheduler(repository, lambda: _UnitOfWork(repository), _Clock())

    result = await scheduler.run_once(limit=10)

    assert result.scanned == 2
    assert result.expired == 1
    assert repository.commit is not None
    assert repository.commit.plan.action is MemoryLifecycleAction.EXPIRE
    assert repository.commit.event_type == "MemoryExpired"


def test_command_request_digests_are_stable_and_action_specific() -> None:
    assert _pin().request_sha256 == (
        "e9c007dd97d79eccb2c7d2616bac73e09611724ddf11ede91fc943c9e6153102"
    )
    assert _expiry().request_sha256 == (
        "3bb91b8b8e661467df0bc584b5d4db4ed8b8e3f1e2c9de3e15cc8c5a3f55cfb0"
    )
    assert _pin().request_sha256 != _archive().request_sha256
    assert _digest_document({"z": "Mémoire", "a": 1}) == (
        "c2d7850577d48fa92c589f0330eda385789d2e5787ad20c76e53aef3ecee17a4"
    )
    with pytest.raises(ValueError, match="Out of range float values"):
        _digest_document({"score": float("nan")})


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("operation_id", "not-a-uuid", "invalid_uuid7"),
        ("actor_id", "not-a-uuid", "invalid_uuid7"),
        ("grant_id", "not-a-uuid", "invalid_uuid7"),
        ("brain_id", "not-a-uuid", "invalid_uuid7"),
        ("correlation_id", "not-a-uuid", "invalid_uuid7"),
        ("causation_id", "not-a-uuid", "invalid_uuid7"),
        ("expected_version", True, "out_of_range"),
        ("expected_version", 0, "out_of_range"),
        ("requested_at", NOW.replace(tzinfo=None), "not_utc"),
        ("deadline", NOW.replace(tzinfo=None), "not_utc"),
        ("deadline", NOW, "not_after_request"),
    ],
)
def test_common_command_validation_identifies_exact_field_and_code(
    field: str,
    value: Any,
    code: str,
) -> None:
    with pytest.raises(MemoryValidationError) as caught:
        replace(_pin(), **{field: value})
    assert caught.value.code_for(field) == code


def test_expiry_and_forget_commands_enforce_closed_action_coordinates() -> None:
    with pytest.raises(MemoryValidationError) as caught_expiry_timezone:
        replace(_expiry(), expires_at=NOW.replace(tzinfo=None))
    assert caught_expiry_timezone.value.code_for("expires_at") == "not_utc"

    with pytest.raises(MemoryValidationError) as caught_expiry_boundary:
        replace(_expiry(), expires_at=NOW)
    assert caught_expiry_boundary.value.code_for("expires_at") == "not_after_request"

    with pytest.raises(MemoryValidationError) as caught_confirmation:
        replace(_forget(), confirmation="FORGET-MEMORY")
    assert caught_confirmation.value.code_for("confirmation") == "mismatch"


@pytest.mark.asyncio
async def test_execution_rejects_invalid_clock_and_request_window_exactly() -> None:
    repository = _Repository(_snapshot())
    command = _pin()
    cases = (
        (
            _VariableClock(NOW.replace(tzinfo=None)),
            command,
            "clock.now",
            "not_utc",
        ),
        (
            _VariableClock(NOW - timedelta(microseconds=1)),
            command,
            "requested_at",
            "in_future",
        ),
        (
            _VariableClock(command.deadline),
            command,
            "deadline",
            "expired",
        ),
    )
    for clock, candidate, field, code in cases:
        with pytest.raises(MemoryValidationError) as caught:
            await PinMemoryHandler(repository, lambda: _UnitOfWork(repository), clock).execute(
                candidate
            )
        assert caught.value.code_for(field) == code


@pytest.mark.asyncio
async def test_scheduler_validates_bounds_clock_and_compare_and_swap() -> None:
    scheduler = MemoryExpiryScheduler(
        _Repository(_snapshot()),
        lambda: _UnitOfWork(_Repository(_snapshot())),
        _Clock(),
    )
    for limit in (True, 0, 101):
        with pytest.raises(MemoryValidationError) as caught:
            await scheduler.run_once(limit=limit)
        assert caught.value.code_for("limit") == "out_of_range"

    naive_scheduler = replace(scheduler, clock=_VariableClock(NOW.replace(tzinfo=None)))
    with pytest.raises(MemoryValidationError) as caught_clock:
        await naive_scheduler.run_once()
    assert caught_clock.value.code_for("clock.now") == "not_utc"

    due = replace(_snapshot(), expires_at=NOW + timedelta(minutes=1))
    changed = replace(due, version=2)
    repository = _Repository(due, transactional=changed, due=(due,))
    conflict_scheduler = MemoryExpiryScheduler(
        repository,
        lambda: _UnitOfWork(repository),
        _Clock(),
    )
    outcome = await conflict_scheduler.run_once()
    assert outcome.scanned == 1
    assert outcome.expired == 0
    assert outcome.conflicts == 1
    assert repository.commit is None


@pytest.mark.asyncio
async def test_scheduler_wait_helper_observes_stop_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[float | None] = []

    async def inspect_timeout(
        awaitable: Any,
        *,
        timeout: float | None,  # noqa: ASYNC109 -- Mirrors asyncio.wait_for for mutation proof.
    ) -> None:
        observed.append(timeout)
        awaitable.close()
        assert timeout is not None
        raise TimeoutError

    with monkeypatch.context() as context:
        context.setattr(asyncio, "wait_for", inspect_timeout)
        waiting = asyncio.Event()
        await _wait_or_stop(waiting, 0.001)

    assert observed == [0.001]
    assert not waiting.is_set()

    stopped = asyncio.Event()
    stopped.set()
    await _wait_or_stop(stopped, 1)
    assert stopped.is_set()


def test_private_validation_boundary_preserves_stable_field_and_code() -> None:
    with pytest.raises(MemoryValidationError) as caught:
        _invalid("boundary", "closed")
    assert caught.value.code_for("boundary") == "closed"


def _pin() -> PinMemoryCommand:
    return PinMemoryCommand(*_coordinates())


def _archive() -> ArchiveMemoryCommand:
    return ArchiveMemoryCommand(*_coordinates())


def _forget() -> ForgetMemoryCommand:
    return ForgetMemoryCommand(*_coordinates(), confirmation="forget-memory")


def _expiry() -> SetMemoryExpiryCommand:
    return SetMemoryExpiryCommand(
        *_coordinates(),
        expires_at=NOW + timedelta(hours=1),
    )


def _coordinates() -> tuple[str, str, str, str, str, str, str, int, datetime, datetime]:
    return (
        OPERATION_ID,
        ACTOR_ID,
        GRANT_ID,
        BRAIN_ID,
        CORRELATION_ID,
        CAUSATION_ID,
        MEMORY_ID,
        1,
        NOW,
        NOW + timedelta(minutes=5),
    )


def _snapshot() -> MemoryLifecycleSnapshot:
    return MemoryLifecycleSnapshot(
        MEMORY_ID,
        MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID),
        MemoryRecallState.ACTIVE,
        pinned=False,
        expires_at=None,
        version=1,
        updated_at=NOW,
    )


@dataclass(frozen=True, slots=True)
class _Clock:
    def now(self) -> datetime:
        return NOW + timedelta(minutes=1)


@dataclass(frozen=True, slots=True)
class _VariableClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


class _Repository:
    def __init__(
        self,
        target: MemoryLifecycleSnapshot | None,
        *,
        transactional: MemoryLifecycleSnapshot | None = None,
        existing: MemoryLifecycleResult | None = None,
        due: tuple[MemoryLifecycleSnapshot, ...] = (),
    ) -> None:
        self.target = target
        self.transactional = transactional
        self.existing = existing
        self.due = due
        self.in_transaction = False
        self.commit: MemoryLifecycleCommit | None = None

    async def get_result(self, idempotency_key: str) -> MemoryLifecycleResult | None:
        del idempotency_key
        return self.existing

    async def load_authorized(
        self,
        memory_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> MemoryLifecycleSnapshot | None:
        del memory_id, brain_id, actor_id, grant_id, at
        if self.in_transaction and self.transactional is not None:
            return self.transactional
        return self.target

    async def list_due(self, at: datetime, limit: int) -> tuple[MemoryLifecycleSnapshot, ...]:
        del at, limit
        if self.in_transaction and self.transactional is not None and self.due:
            return (self.transactional,)
        return self.due

    async def add(self, commit: MemoryLifecycleCommit) -> None:
        self.commit = commit


class _RacingRepository(_Repository):
    def __init__(
        self,
        target: MemoryLifecycleSnapshot,
        *,
        existing: MemoryLifecycleResult,
    ) -> None:
        super().__init__(target, existing=existing)
        self.result_reads = 0

    @override
    async def get_result(self, idempotency_key: str) -> MemoryLifecycleResult | None:
        del idempotency_key
        self.result_reads += 1
        return None if self.result_reads == 1 else self.existing


class _UnitOfWork:
    def __init__(self, repository: _Repository) -> None:
        self.repository = repository
        self.committed = False

    async def __aenter__(self) -> Self:
        self.repository.in_transaction = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.repository.in_transaction = False

    async def commit(self) -> None:
        self.committed = True


@dataclass(frozen=True, slots=True)
class _UnitOfWorkFactory:
    unit: _UnitOfWork

    def __call__(self) -> _UnitOfWork:
        return self.unit
