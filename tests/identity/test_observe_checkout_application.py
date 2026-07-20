"""ID-002 ObserveCheckoutCommand application acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Self

import pytest

from agentmemory.identity.application.commands.observe_checkout import (
    ObserveCheckoutCommand,
    ObserveCheckoutHandler,
)
from agentmemory.identity.domain.checkout import CheckoutAggregate, CheckoutEvent, CheckoutEventType
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityValidationError,
)
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    StableId,
    VcsIdentity,
    VcsType,
)

if TYPE_CHECKING:
    from types import TracebackType

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
ACTOR_ID = StableId("018f0000-0000-7000-8000-000000000002")
GRANT_ID = StableId("018f0000-0000-7000-8000-000000000003")
DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHECKOUT_A = StableId("018f0000-0000-7000-8000-000000000030")
EVENT_A = StableId("018f0000-0000-7000-8000-000000000031")
CHECKOUT_B = StableId("018f0000-0000-7000-8000-000000000032")
EVENT_B = StableId("018f0000-0000-7000-8000-000000000033")


def _fingerprint(seed: str) -> Fingerprint:
    return Fingerprint.from_bytes(seed.encode())


def _device(path: str = "path-a", file_id: str = "file-a") -> DeviceIdentity:
    return DeviceIdentity(
        device_id=DEVICE_ID,
        device_fingerprint=_fingerprint("device"),
        volume_fingerprint=_fingerprint("volume"),
        path_fingerprint=_fingerprint(path),
        verified=True,
        logical_path_fingerprint=_fingerprint(f"logical-{path}"),
        file_fingerprint=_fingerprint(file_id),
    )


def _vcs(
    checkout: str = "checkout-a",
    worktree: str = "worktree-a",
    common: str = "common-a",
) -> VcsIdentity:
    return VcsIdentity(
        vcs_type=VcsType.GIT,
        repository_fingerprint=_fingerprint("repository"),
        checkout_fingerprint=_fingerprint(checkout),
        worktree_fingerprint=_fingerprint(worktree),
        repository_lookup_approved=True,
        common_directory_fingerprint=_fingerprint(common),
        branch="main",
        head_commit="a" * 40,
        remote_fingerprints=(_fingerprint("origin"),),
        dirty_digest=_fingerprint("clean"),
    )


def _command(
    operation: str,
    *,
    device: DeviceIdentity | None = None,
    vcs: VcsIdentity | None = None,
    expected_version: int | None = None,
) -> ObserveCheckoutCommand:
    return ObserveCheckoutCommand(
        operation,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        REPOSITORY_ID,
        device or _device(),
        vcs or _vcs(),
        expected_version,
    )


@dataclass
class FakeIds:
    values: list[StableId]

    def new(self) -> StableId:
        return self.values.pop(0)


@dataclass
class FakeAuthorization:
    denied: bool = False
    calls: int = 0

    async def authorize(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        self.calls += 1
        assert (brain_id, actor_id, grant_id) == (BRAIN_ID, ACTOR_ID, GRANT_ID)
        if self.denied:
            raise IdentityAuthorizationError


@dataclass
class FakeCheckoutRepository:
    candidates: list[CheckoutAggregate] = field(default_factory=list[CheckoutAggregate])
    operations: dict[str, CheckoutAggregate] = field(default_factory=dict[str, CheckoutAggregate])
    events: list[tuple[str, CheckoutEventType, int | None]] = field(
        default_factory=list[tuple[str, CheckoutEventType, int | None]]
    )

    async def require_repository(
        self,
        brain_id: StableId,
        repository_id: StableId,
    ) -> None:
        assert (brain_id, repository_id) == (BRAIN_ID, REPOSITORY_ID)

    async def find_operation(
        self,
        brain_id: StableId,
        operation_id: str,
    ) -> CheckoutAggregate | None:
        assert brain_id == BRAIN_ID
        return self.operations.get(operation_id)

    async def find_continuity(
        self,
        brain_id: StableId,
        repository_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity,
    ) -> tuple[CheckoutAggregate, ...]:
        del device, vcs
        assert (brain_id, repository_id) == (BRAIN_ID, REPOSITORY_ID)
        return tuple(self.candidates)

    async def append(
        self,
        operation_id: str,
        event_id: StableId,
        aggregate: CheckoutAggregate,
        event: CheckoutEvent,
        *,
        expected_previous_version: int | None,
    ) -> None:
        del event_id
        self.operations[operation_id] = aggregate
        self.events.append((operation_id, event.event_type, expected_previous_version))
        self.candidates = [
            candidate
            for candidate in self.candidates
            if candidate.checkout_id != aggregate.checkout_id
        ]
        self.candidates.append(aggregate)


@dataclass
class FakeUnitOfWork:
    authorization: FakeAuthorization = field(default_factory=FakeAuthorization)
    checkouts: FakeCheckoutRepository = field(default_factory=FakeCheckoutRepository)
    commits: int = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    async def commit(self) -> None:
        self.commits += 1


@dataclass
class FakeFactory:
    unit_of_work: FakeUnitOfWork

    def __call__(self) -> FakeUnitOfWork:
        return self.unit_of_work


def _handler(unit_of_work: FakeUnitOfWork, *ids: StableId) -> ObserveCheckoutHandler:
    return ObserveCheckoutHandler(FakeFactory(unit_of_work), FakeIds(list(ids)))


@pytest.mark.asyncio
async def test_create_is_atomic_and_retry_is_idempotent() -> None:
    unit_of_work = FakeUnitOfWork()
    handler = _handler(unit_of_work, CHECKOUT_A, EVENT_A)
    created = await handler.execute(_command("observe-1"))
    retried = await handler.execute(_command("observe-1"))
    assert created == retried
    assert created.checkout_id == CHECKOUT_A
    assert unit_of_work.checkouts.events == [("observe-1", CheckoutEventType.OBSERVED, None)]
    assert unit_of_work.commits == 1
    assert unit_of_work.authorization.calls == 2


@pytest.mark.asyncio
async def test_idempotency_key_reuse_with_different_evidence_conflicts() -> None:
    unit_of_work = FakeUnitOfWork()
    handler = _handler(unit_of_work, CHECKOUT_A, EVENT_A)
    await handler.execute(_command("observe-1"))
    with pytest.raises(IdentityConflictError):
        await handler.execute(_command("observe-1", device=_device("different")))
    assert unit_of_work.commits == 1


@pytest.mark.asyncio
async def test_move_preserves_checkout_and_appends_moved_version() -> None:
    unit_of_work = FakeUnitOfWork()
    handler = _handler(unit_of_work, CHECKOUT_A, EVENT_A, EVENT_B)
    created = await handler.execute(_command("observe-1"))
    moved = await handler.execute(_command("observe-2", device=_device("path-b")))
    assert moved.checkout_id == created.checkout_id
    assert moved.version == 2
    assert unit_of_work.checkouts.events[-1] == (
        "observe-2",
        CheckoutEventType.MOVED,
        1,
    )


@pytest.mark.asyncio
async def test_clone_and_linked_worktree_receive_distinct_checkouts() -> None:
    unit_of_work = FakeUnitOfWork()
    handler = _handler(
        unit_of_work,
        CHECKOUT_A,
        EVENT_A,
        CHECKOUT_B,
        EVENT_B,
    )
    first = await handler.execute(_command("observe-1"))
    clone = await handler.execute(
        _command(
            "observe-2",
            device=_device("clone", "clone-file"),
            vcs=_vcs("clone-checkout", "clone-worktree", "clone-common"),
        )
    )
    assert first.checkout_id != clone.checkout_id
    assert first.current.repository_id == clone.current.repository_id


@pytest.mark.asyncio
async def test_stale_or_ambiguous_continuity_fails_without_commit() -> None:
    first, _ = CheckoutAggregate.create(CHECKOUT_A, BRAIN_ID, _command("seed").observation())
    duplicate, _ = CheckoutAggregate.create(CHECKOUT_B, BRAIN_ID, _command("seed").observation())
    ambiguous = FakeUnitOfWork(checkouts=FakeCheckoutRepository([first, duplicate]))
    with pytest.raises(IdentityConflictError):
        await _handler(ambiguous, EVENT_A).execute(_command("ambiguous"))
    assert ambiguous.commits == 0

    stale = FakeUnitOfWork(checkouts=FakeCheckoutRepository([first]))
    with pytest.raises(IdentityConflictError):
        await _handler(stale, EVENT_A).execute(_command("stale", expected_version=2))
    assert stale.commits == 0


@pytest.mark.asyncio
async def test_denial_precedes_repository_access_and_incomplete_evidence_is_rejected() -> None:
    denied = FakeUnitOfWork(authorization=FakeAuthorization(denied=True))
    with pytest.raises(IdentityAuthorizationError):
        await _handler(denied, CHECKOUT_A, EVENT_A).execute(_command("denied"))
    assert denied.checkouts.events == []

    incomplete = replace(_device(), logical_path_fingerprint=None)
    with pytest.raises(IdentityValidationError, match="incomplete"):
        replace(_command("invalid"), device=incomplete).observation()
