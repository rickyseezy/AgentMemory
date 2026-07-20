"""ING-003 authorized deterministic replay into isolated shadow state."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionDependencyError,
    IngestionIntegrityError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.ordered_replay import (
    OrderedProjectionState,
    OrderedReplayRun,
    ReplayRunRequest,
    ReplayRunState,
    generation_digest,
    reduce_projection,
)

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.ports import (
        OrderedReplayAccessPolicy,
        OrderedReplayRepository,
    )
    from agentmemory.shared.clock import Clock

_ZERO_DIGEST = "0" * 64
_DEFAULT_PAGE_SIZE = 256
_MAX_PAGE_SIZE = 4096
_LEASE_MICROSECONDS = 60 * 1_000_000
_DEFAULT_POLL_SECONDS = 0.5
_MAX_POLL_SECONDS = 10.0
_MAX_OWNER_LENGTH = 128
_ERR_NOT_FOUND = "Ordered replay operation was not found"
_ERR_CURSOR = "Ordered replay source cursor did not advance"
_ERR_SOURCE_ORDER = "Ordered replay source order diverged"
_ERR_PAGE = "Ordered replay page completion diverged"
_ERR_SEQUENCE = "Ordered replay sequence is not strictly increasing"
_FIELD_OPERATION_ID = "operation_id"


@dataclass(frozen=True, slots=True)
class StartOrderedReplayHandler:
    """Authorize and durably capture one immutable replay selection."""

    access: OrderedReplayAccessPolicy
    repository: OrderedReplayRepository
    clock: Clock

    async def execute(self, request: ReplayRunRequest) -> OrderedReplayRun:
        """Return the exact existing run or one newly queued shadow generation."""
        now = _microseconds(self.clock)
        await self.access.authorize(request, now)
        return await self.repository.create(request, now)


@dataclass(frozen=True, slots=True)
class GetOrderedReplayHandler:
    """Return status only while the original replay grant remains active."""

    access: OrderedReplayAccessPolicy
    repository: OrderedReplayRepository
    clock: Clock

    async def execute(self, operation_id: str) -> OrderedReplayRun:
        """Load, reauthorize, and return content-free durable status."""
        run = await self.repository.get(operation_id)
        if run is None:
            raise IngestionValidationError.single(_FIELD_OPERATION_ID, "not_found")
        await self.access.authorize(run.request, _microseconds(self.clock))
        return run


@dataclass(frozen=True, slots=True)
class OrderedReplayExecutor:
    """Resume pure reductions and compare shadow state with live state."""

    access: OrderedReplayAccessPolicy
    repository: OrderedReplayRepository
    clock: Clock
    owner: str
    page_size: int = _DEFAULT_PAGE_SIZE

    def __post_init__(self) -> None:
        """Bound memory, transactions, and worker identity."""
        if not self.owner or len(self.owner) > _MAX_OWNER_LENGTH:
            msg = "ordered replay worker owner is invalid"
            raise ValueError(msg)
        if not 1 <= self.page_size <= _MAX_PAGE_SIZE:
            msg = "ordered replay page size is invalid"
            raise ValueError(msg)

    async def execute(self, operation_id: str) -> OrderedReplayRun:
        """Build only shadow state, then persist a deterministic live comparison."""
        current = await self.repository.get(operation_id)
        if current is None:
            raise IngestionIntegrityError(_ERR_NOT_FOUND)
        if current.state in {ReplayRunState.READY, ReplayRunState.SUPERSEDED}:
            return current
        now = _microseconds(self.clock)
        run = await self.repository.claim(
            operation_id,
            self.owner,
            now,
            now + _LEASE_MICROSECONDS,
        )
        await self.access.authorize(run.request, now)
        while run.processed_count < run.source_count:
            page = await self.repository.read_page(run, self.page_size)
            if not page.records:
                raise IngestionIntegrityError(_ERR_CURSOR)
            for source in page.records:
                if source.source_ordinal != run.processed_count + 1:
                    raise IngestionIntegrityError(_ERR_SOURCE_ORDER)
                prior = await self.repository.shadow_state(
                    run.request.operation_id,
                    source.reduction.ordering_key,
                )
                prior_digest, state = _next_state(source.reduction.event_sequence, prior)
                state_sha256 = reduce_projection(
                    prior_digest,
                    source.reduction,
                    run.request.code_fingerprint,
                )
                next_state = (
                    None
                    if state is None
                    else OrderedProjectionState(
                        source.reduction.ordering_key,
                        state,
                        state_sha256,
                    )
                )
                run = await self.repository.append(
                    run,
                    source,
                    prior_digest,
                    next_state,
                    state_sha256,
                    _microseconds(self.clock),
                )
            if page.complete != (run.processed_count == run.source_count):
                raise IngestionIntegrityError(_ERR_PAGE)
        now = _microseconds(self.clock)
        run = await self.repository.begin_validation(
            run,
            now,
            now + _LEASE_MICROSECONDS,
        )
        await self.access.authorize(run.request, now)
        shadow = await self.repository.shadow_states(operation_id)
        live = await self.repository.live_states(run)
        shadow_digest = generation_digest(shadow, run.request.code_fingerprint)
        live_digest = generation_digest(live, run.request.code_fingerprint)
        return await self.repository.finish_validation(
            run,
            shadow_digest,
            live_digest,
            _microseconds(self.clock),
        )


def _next_state(
    event_sequence: int | None,
    prior: OrderedProjectionState | None,
) -> tuple[str, int | None]:
    if event_sequence is None:
        return _ZERO_DIGEST, None
    if prior is None:
        return _ZERO_DIGEST, event_sequence
    if event_sequence <= prior.applied_sequence:
        raise IngestionIntegrityError(_ERR_SEQUENCE)
    return prior.state_sha256, event_sequence


@dataclass(frozen=True, slots=True)
class OrderedReplayWorker:
    """Recover and drain durable replay work without stopping ingestion."""

    repository: OrderedReplayRepository
    executor: OrderedReplayExecutor
    clock: Clock
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        """Bound idle wakeups and shutdown latency."""
        if not 0 < self.poll_seconds <= _MAX_POLL_SECONDS:
            msg = "ordered replay worker poll interval is invalid"
            raise ValueError(msg)

    async def run(self, stop: asyncio.Event) -> None:
        """Recover once, then isolate typed and unknown failures per operation."""
        if stop.is_set():
            return
        await self.repository.recover_expired(_microseconds(self.clock))
        while not stop.is_set():
            operation_id = await self.repository.next_runnable(_microseconds(self.clock))
            if operation_id is None:
                await _wait_or_stop(stop, self.poll_seconds)
                continue
            await self._execute(operation_id)

    async def _execute(self, operation_id: str) -> None:
        try:
            await self.executor.execute(operation_id)
        except IngestionAuthorizationError:
            await self._partial(operation_id, "authorization_revoked")
        except IngestionDependencyError:
            await self._partial(operation_id, "dependency_unavailable")
        except IngestionIntegrityError:
            await self._partial(operation_id, "integrity_violation")
        except Exception:  # noqa: BLE001 -- Worker must contain one corrupt job.
            await self._partial(operation_id, "internal_error")

    async def _partial(self, operation_id: str, code: str) -> None:
        run = await self.repository.get(operation_id)
        if run is not None and run.state in {ReplayRunState.BUILDING, ReplayRunState.VALIDATING}:
            await self.repository.mark_partial(run, code, _microseconds(self.clock))


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return


def _microseconds(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)
