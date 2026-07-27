"""PRO-006 authorization, cancellation, and worker orchestration tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, cast

import pytest

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
from agentmemory.providers.application.scheduling import (
    CancelProviderWorkCommand,
    CancelProviderWorkHandler,
    EnqueueProviderWorkCommand,
    EnqueueProviderWorkHandler,
    GetProviderWorkHandler,
    GetProviderWorkQuery,
    ProviderSchedulerWorker,
    _wait_or_stop,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.providers.domain.errors import (
    ProviderBudgetExhaustedError,
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingDependencyError,
    ProviderSchedulingValidationError,
)
from agentmemory.providers.domain.scheduling import (
    BatchPlanner,
    ProviderBatch,
    ProviderBatchLease,
    ProviderBatchOutcome,
    ProviderItemResult,
    ProviderItemResultStatus,
    ProviderSchedulingLimits,
    ProviderWorkItem,
    ProviderWorkState,
)
from tests.core.support import NOW, FixedClock, digest
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro006_scheduling_domain import item

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(slots=True)
class _Identities:
    value: str = "018f0000-0000-7000-8000-000000000999"

    def new(self) -> str:
        return self.value


@dataclass(slots=True)
class _Repository:
    value: ProviderWorkItem | None = None
    lease: ProviderBatchLease | None = None
    stop_on_claim: asyncio.Event | None = None
    fail_claim_once: bool = False
    enqueued: list[tuple[AuthorizedScope, str, str, ProviderWorkItem]] = field(
        default_factory=list[tuple[AuthorizedScope, str, str, ProviderWorkItem]]
    )
    completed: list[tuple[ProviderBatchLease, ProviderBatchOutcome, int]] = field(
        default_factory=list[tuple[ProviderBatchLease, ProviderBatchOutcome, int]]
    )
    released: list[tuple[ProviderBatchLease, str, int | None, int]] = field(
        default_factory=list[tuple[ProviderBatchLease, str, int | None, int]]
    )
    cancellations: list[tuple[AuthorizedScope, str, str, int]] = field(
        default_factory=list[tuple[AuthorizedScope, str, str, int]]
    )
    recoveries: list[int] = field(default_factory=list[int])

    async def enqueue(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        work: ProviderWorkItem,
    ) -> ProviderWorkItem:
        self.enqueued.append((scope, operation_id, request_digest, work))
        self.value = work
        return work

    async def get(
        self,
        scope: AuthorizedScope,
        item_id: str,
    ) -> ProviderWorkItem | None:
        del scope
        return self.value if self.value is not None and self.value.item_id == item_id else None

    async def cancel(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        item_id: str,
        cancelled_at_microseconds: int,
    ) -> ProviderWorkItem:
        self.cancellations.append((scope, operation_id, item_id, cancelled_at_microseconds))
        assert self.value is not None
        self.value = self.value.with_state(ProviderWorkState.CANCELLED)
        return self.value

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderBatchLease | None:
        del owner, now_microseconds, lease_until_microseconds
        if self.stop_on_claim is not None:
            self.stop_on_claim.set()
        if self.fail_claim_once:
            self.fail_claim_once = False
            message = "one isolated claim failure"
            raise RuntimeError(message)
        lease, self.lease = self.lease, None
        return lease

    async def complete(
        self,
        lease: ProviderBatchLease,
        outcome: ProviderBatchOutcome,
        completed_at_microseconds: int,
    ) -> None:
        self.completed.append((lease, outcome, completed_at_microseconds))

    async def release(
        self,
        lease: ProviderBatchLease,
        reason: str,
        retry_at_microseconds: int | None,
        released_at_microseconds: int,
    ) -> None:
        self.released.append((lease, reason, retry_at_microseconds, released_at_microseconds))

    async def recover_expired(self, now_microseconds: int) -> int:
        self.recoveries.append(now_microseconds)
        return 0


@dataclass(slots=True)
class _Authorizer:
    calls: list[str] = field(default_factory=list[str])
    denied: str | None = None

    async def authorize(self, work: ProviderWorkItem, now_microseconds: int) -> None:
        del now_microseconds
        self.calls.append(work.item_id)
        if work.item_id == self.denied:
            message = "provider scheduling action is denied"
            raise ProviderSchedulingAuthorizationError(message)


@dataclass(slots=True)
class _Materializer:
    authorizer: _Authorizer
    calls: list[str] = field(default_factory=list[str])
    buffers: list[bytearray] = field(default_factory=list[bytearray])

    async def materialize(self, work: ProviderWorkItem) -> bytearray:
        assert work.item_id in self.authorizer.calls
        self.calls.append(work.item_id)
        payload = bytearray(f"payload:{work.item_id}".encode())
        self.buffers.append(payload)
        return payload


@dataclass(slots=True)
class _Gateway:
    outcome: ProviderBatchOutcome
    calls: list[tuple[ProviderBatch, tuple[bytes, ...]]] = field(
        default_factory=list[tuple[ProviderBatch, tuple[bytes, ...]]]
    )
    started: asyncio.Event | None = None

    async def execute(
        self,
        batch: ProviderBatch,
        payloads: Sequence[bytearray],
    ) -> ProviderBatchOutcome:
        self.calls.append((batch, tuple(bytes(value) for value in payloads)))
        if self.started is not None:
            self.started.set()
            await asyncio.Future()
        return self.outcome


def _command(authorized_scope: AuthorizedScope | None = None) -> EnqueueProviderWorkCommand:
    work = item(0)
    deadline = round(NOW.timestamp() * 1_000_000) + 100_000
    return EnqueueProviderWorkCommand(
        operation_id="enqueue-provider-work-1",
        scope=authorized_scope or scope("provider.schedule.enqueue"),
        batch_key=work.batch_key,
        ordinal=work.ordinal,
        payload_ref=work.payload_ref,
        content_digest=work.content_digest,
        token_count=work.token_count,
        byte_count=work.byte_count,
        estimated_cost_micros=work.estimated_cost_micros,
        deadline_at_microseconds=deadline,
        enqueued_at=NOW,
    )


def _lease() -> ProviderBatchLease:
    batch = BatchPlanner.plan(
        (item(0), item(1)),
        ProviderSchedulingLimits(10, 100, 100, 1_000, 1_000),
    )[0]
    return ProviderBatchLease(
        batch=batch,
        owner="provider-scheduler-v1",
        lease_until_microseconds=9_000_000,
        attempt=1,
    )


@pytest.mark.asyncio
async def test_worker_wait_observes_zero_delay_stop_and_timeout_paths() -> None:
    """Exercise every bounded wait mode used by the worker run loop."""
    stop = asyncio.Event()
    await _wait_or_stop(stop, 0)
    stop.set()
    await _wait_or_stop(stop, 0.01)
    stop.clear()
    await _wait_or_stop(stop, 0.001)
    assert not stop.is_set()


@pytest.mark.parametrize(
    "changed",
    [
        {"operation_id": ""},
        {
            "batch_key": replace(
                item(0).batch_key,
                brain_id="018f0000-0000-7000-8000-000000000998",
            )
        },
        {"enqueued_at": NOW.replace(tzinfo=None)},
        {"deadline_at_microseconds": round(NOW.timestamp() * 1_000_000)},
    ],
)
def test_enqueue_command_rejects_each_invalid_boundary(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ProviderSchedulingValidationError, match="request is invalid"):
        replace(_command(), **cast("Any", changed))


@pytest.mark.parametrize(
    "changed",
    [
        {"operation_id": ""},
        {"cancelled_at": NOW.replace(tzinfo=None)},
    ],
)
def test_cancel_command_rejects_each_invalid_boundary(
    changed: dict[str, object],
) -> None:
    command = CancelProviderWorkCommand(
        operation_id="cancel-provider-work-1",
        scope=scope("provider.schedule.cancel"),
        item_id=item(0).item_id,
        cancelled_at=NOW,
    )
    with pytest.raises(ProviderSchedulingValidationError, match="request is invalid"):
        replace(command, **cast("Any", changed))


@pytest.mark.parametrize(
    ("owner", "poll_seconds"),
    [
        ("", 0.05),
        ("provider-scheduler", -0.01),
        ("provider-scheduler", 1.01),
    ],
)
def test_worker_rejects_invalid_owner_or_poll_interval(
    owner: str,
    poll_seconds: float,
) -> None:
    authorizer = _Authorizer()
    with pytest.raises(ProviderSchedulingValidationError, match="request is invalid"):
        ProviderSchedulerWorker(
            _Repository(),
            authorizer,
            _Materializer(authorizer),
            _Gateway(ProviderBatchOutcome("valid-operation", ())),
            FixedClock(),
            owner,
            poll_seconds=poll_seconds,
        )


@pytest.mark.asyncio
async def test_worker_run_once_reports_an_idle_queue() -> None:
    authorizer = _Authorizer()
    worker = ProviderSchedulerWorker(
        _Repository(),
        authorizer,
        _Materializer(authorizer),
        _Gateway(ProviderBatchOutcome("valid-operation", ())),
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )
    assert not await worker.run_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("claim_mode", ["idle", "error"])
async def test_worker_run_recovers_leases_and_isolates_one_claim_failure(
    claim_mode: str,
) -> None:
    stop = asyncio.Event()
    repository = _Repository(
        stop_on_claim=stop,
        fail_claim_once=claim_mode == "error",
    )
    authorizer = _Authorizer()
    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        _Materializer(authorizer),
        _Gateway(ProviderBatchOutcome("valid-operation", ())),
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )

    await worker.run(stop)

    assert repository.recoveries == [round(NOW.timestamp() * 1_000_000)]
    assert not repository.fail_claim_once


@pytest.mark.asyncio
async def test_enqueue_authorizes_builds_identity_and_persists_only_metadata() -> None:
    repository = _Repository()
    command = _command()
    result = await EnqueueProviderWorkHandler(repository, _Identities()).execute(command)

    assert command.request_digest == (
        "9f109e528488e1411f39440008f030281902f11790970d6d174cc26948e9c339"
    )
    assert result.item_id == _Identities().value
    assert result.state is ProviderWorkState.QUEUED
    assert repository.enqueued[0][0].action == "provider.schedule.enqueue"
    assert repository.enqueued[0][1] == command.operation_id
    assert repository.enqueued[0][2] == command.request_digest
    assert "payload:" not in repr(result)


@pytest.mark.asyncio
async def test_enqueue_get_and_cancel_require_exact_actions_and_roles() -> None:
    repository = _Repository(value=item(0))
    with pytest.raises(
        ProviderSchedulingAuthorizationError,
        match="provider scheduling action is not authorized",
    ):
        await EnqueueProviderWorkHandler(repository, _Identities()).execute(
            _command(scope("provider.schedule.read"))
        )
    with pytest.raises(ProviderSchedulingAuthorizationError):
        await GetProviderWorkHandler(repository).execute(
            GetProviderWorkQuery(scope=scope("provider.schedule.cancel"), item_id=item(0).item_id)
        )
    with pytest.raises(ProviderSchedulingAuthorizationError):
        await CancelProviderWorkHandler(repository).execute(
            CancelProviderWorkCommand(
                operation_id="cancel-provider-work-1",
                scope=scope("provider.schedule.read"),
                item_id=item(0).item_id,
                cancelled_at=NOW,
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed_key",
    [
        {"project_id": "018f0000-0000-7000-8000-000000000998"},
        {"repository_id": "018f0000-0000-7000-8000-000000000997"},
    ],
)
async def test_enqueue_denies_each_out_of_scope_project_or_repository_coordinate(
    changed_key: dict[str, object],
) -> None:
    command = _command()
    command = EnqueueProviderWorkCommand(
        operation_id=command.operation_id,
        scope=command.scope,
        batch_key=replace(command.batch_key, **cast("Any", changed_key)),
        ordinal=command.ordinal,
        payload_ref=command.payload_ref,
        content_digest=command.content_digest,
        token_count=command.token_count,
        byte_count=command.byte_count,
        estimated_cost_micros=command.estimated_cost_micros,
        deadline_at_microseconds=command.deadline_at_microseconds,
        enqueued_at=command.enqueued_at,
    )

    with pytest.raises(
        ProviderSchedulingAuthorizationError,
        match="provider scheduling action is not authorized",
    ):
        await EnqueueProviderWorkHandler(_Repository(), _Identities()).execute(command)


@pytest.mark.asyncio
async def test_worker_authorizes_every_item_before_materializing_and_executes_once() -> None:
    lease = _lease()
    repository = _Repository(lease=lease)
    authorizer = _Authorizer()
    materializer = _Materializer(authorizer)
    outcome = ProviderBatchOutcome(
        lease.batch.operation_id,
        tuple(
            ProviderItemResult.succeeded(value.item_id, digest(value.item_id).value)
            for value in lease.batch.items
        ),
    )
    gateway = _Gateway(outcome)
    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        materializer,
        gateway,
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )

    assert await worker.run_once()
    assert authorizer.calls == [value.item_id for value in lease.batch.items]
    assert materializer.calls == authorizer.calls
    assert gateway.calls[0][0] == lease.batch
    assert repository.completed == [(lease, outcome, round(NOW.timestamp() * 1_000_000))]
    assert materializer.buffers
    assert all(payload == bytearray(len(payload)) for payload in materializer.buffers)


@pytest.mark.asyncio
async def test_final_authorization_denial_prevents_materialization_and_gateway() -> None:
    lease = _lease()
    repository = _Repository(lease=lease)
    authorizer = _Authorizer(denied=lease.batch.items[1].item_id)
    materializer = _Materializer(authorizer)
    gateway = _Gateway(ProviderBatchOutcome(lease.batch.operation_id, ()))
    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        materializer,
        gateway,
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )

    assert await worker.run_once()
    assert materializer.calls == [lease.batch.items[0].item_id]
    assert gateway.calls == []
    assert repository.released[0][1] == "authorization_denied"
    assert repository.released[0][2] is None
    assert materializer.buffers
    assert all(payload == bytearray(len(payload)) for payload in materializer.buffers)


@pytest.mark.asyncio
async def test_partial_response_is_validated_and_delegated_to_atomic_completion() -> None:
    lease = _lease()
    outcome = ProviderBatchOutcome(
        lease.batch.operation_id,
        (
            ProviderItemResult.succeeded(
                lease.batch.items[0].item_id,
                digest("result").value,
            ),
            ProviderItemResult.failed(
                lease.batch.items[1].item_id,
                ProviderItemResultStatus.RETRYABLE_FAILURE,
                "rate_limit",
                retry_at_microseconds=50_000_000,
            ),
        ),
    )
    repository = _Repository(lease=lease)
    authorizer = _Authorizer()
    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        _Materializer(authorizer),
        _Gateway(outcome),
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )

    assert await worker.run_once()
    assert repository.completed[0][1].retryable_item_ids == (lease.batch.items[1].item_id,)


@pytest.mark.asyncio
async def test_dependency_failure_releases_exact_lease_without_fabricating_results() -> None:
    lease = _lease()
    repository = _Repository(lease=lease)
    authorizer = _Authorizer()

    @dataclass(slots=True)
    class _Unavailable:
        async def execute(
            self,
            batch: ProviderBatch,
            payloads: Sequence[bytearray],
        ) -> ProviderBatchOutcome:
            del batch, payloads
            message = "provider dependency is unavailable"
            raise ProviderSchedulingDependencyError(message)

    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        _Materializer(authorizer),
        _Unavailable(),
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )
    assert await worker.run_once()
    assert repository.completed == []
    assert repository.released[0][1] == "dependency_unavailable"
    assert repository.released[0][2] is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision", "channels", "retry"),
    [("queued", (), True), ("degraded", ("exact", "graph"), False)],
)
async def test_budget_exhaustion_releases_without_provider_result(
    decision: str,
    channels: tuple[str, ...],
    retry: bool,  # noqa: FBT001 -- Explicit parametrized expectation.
) -> None:
    lease = _lease()
    repository = _Repository(lease=lease)
    authorizer = _Authorizer()

    @dataclass(slots=True)
    class _BudgetDenied:
        async def execute(
            self,
            batch: ProviderBatch,
            payloads: Sequence[bytearray],
        ) -> ProviderBatchOutcome:
            del batch, payloads
            raise ProviderBudgetExhaustedError(decision, channels)

    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        _Materializer(authorizer),
        _BudgetDenied(),
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )

    assert await worker.run_once()
    assert repository.completed == []
    assert repository.released[0][1] == f"budget_{decision}"
    assert (repository.released[0][2] is not None) is retry


@pytest.mark.asyncio
async def test_worker_cancellation_releases_lease_and_zeroes_materialized_buffers() -> None:
    lease = _lease()
    repository = _Repository(lease=lease)
    authorizer = _Authorizer()
    materializer = _Materializer(authorizer)
    gateway = _Gateway(
        ProviderBatchOutcome(lease.batch.operation_id, ()),
        started=asyncio.Event(),
    )
    worker = ProviderSchedulerWorker(
        repository,
        authorizer,
        materializer,
        gateway,
        FixedClock(),
        "provider-scheduler-v1",
        poll_seconds=0,
    )
    task = asyncio.create_task(worker.run_once())
    assert gateway.started is not None
    await gateway.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert repository.released[0][1] == "worker_cancelled"
    assert materializer.buffers
    assert all(payload == bytearray(len(payload)) for payload in materializer.buffers)
