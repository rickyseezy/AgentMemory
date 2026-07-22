"""PF-004 structured-concurrency recall with bulkheads and circuit breakers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.resilience.domain.errors import (
    RecallAuthorizationError,
    RecallDependencyError,
    RecallIntegrityError,
    ResilienceValidationError,
)
from agentmemory.resilience.domain.models import (
    ChannelFailure,
    ChannelFailureKind,
    ChannelOutcome,
    ChannelStatus,
    DegradationPolicy,
    RecallResponse,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.resilience.domain.models import (
        ChannelName,
        CircuitPolicy,
        DependencyName,
        RecallCandidate,
        RecallChannelSuccess,
        RecallExecutionPolicy,
        RecallQuery,
    )
    from agentmemory.resilience.domain.ports import (
        DependencyHealthRepository,
        RecallAuthorization,
        RecallChannelSource,
        RecallClock,
    )

_ERR_EXECUTION_POLICY = "recall execution policy is invalid"
_ERR_CHANNEL_SUBSTITUTION = "channel identity substitution"


@dataclass(frozen=True, slots=True)
class DependencyHealthRegistry:
    """Circuit policy facade over one atomic repository."""

    repository: DependencyHealthRepository
    policy: CircuitPolicy

    async def acquire(self, dependency: DependencyName, now: datetime) -> bool:
        """Reserve an allowed dependency call or sole half-open probe."""
        return (await self.repository.acquire(dependency, self.policy, now)).allowed

    async def success(self, dependency: DependencyName, now: datetime) -> None:
        """Record a successful dependency call."""
        await self.repository.record_success(dependency, self.policy, now)

    async def failure(self, dependency: DependencyName, now: datetime) -> None:
        """Record a typed dependency or timeout failure."""
        await self.repository.record_failure(dependency, self.policy, now)

    async def abandon(self, dependency: DependencyName, now: datetime) -> None:
        """Release a cancelled call without counting it as dependency failure."""
        await self.repository.record_abandon(dependency, self.policy, now)


@dataclass(frozen=True, slots=True)
class RecallQueryHandler:
    """Authorize once then execute isolated channel calls under structured concurrency."""

    authorization: RecallAuthorization
    sources: tuple[RecallChannelSource, ...]
    health: DependencyHealthRegistry
    execution_policy: RecallExecutionPolicy
    clock: RecallClock
    bulkhead: asyncio.Semaphore
    policy: DegradationPolicy

    @classmethod
    def create(
        cls,
        *,
        authorization: RecallAuthorization,
        sources: tuple[RecallChannelSource, ...],
        health: DependencyHealthRepository,
        execution_policy: RecallExecutionPolicy,
        clock: RecallClock,
    ) -> RecallQueryHandler:
        """Validate source topology and assemble the isolated recall handler."""
        channels = tuple(source.channel for source in sources)
        if len(set(channels)) != len(channels) or set(channels) != set(
            execution_policy.channel_deadlines
        ):
            raise ResilienceValidationError(_ERR_EXECUTION_POLICY)
        return cls(
            authorization=authorization,
            sources=sources,
            health=DependencyHealthRegistry(health, execution_policy.circuit),
            execution_policy=execution_policy,
            clock=clock,
            bulkhead=asyncio.Semaphore(execution_policy.bulkhead_limit),
            policy=DegradationPolicy(),
        )

    async def execute(self, query: RecallQuery) -> RecallResponse:
        """Return every available channel and explicit evidence for every degradation."""
        await self.authorization.authorize(query)
        tasks = tuple(asyncio.create_task(self._channel(source, query)) for source in self.sources)
        try:
            results = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        successes = tuple(item for item in results if not isinstance(item, ChannelOutcome))
        outcomes = tuple(
            item
            if isinstance(item, ChannelOutcome)
            else ChannelOutcome(item.channel, ChannelStatus.AVAILABLE, "AM_OK", item.freshness)
            for item in results
        )
        candidates = _merge_candidates(successes)
        return RecallResponse(candidates, outcomes)

    async def _channel(
        self, source: RecallChannelSource, query: RecallQuery
    ) -> RecallChannelSuccess | ChannelOutcome:
        observed_at = self.clock.now()
        remaining = (query.deadline_at - observed_at).total_seconds()
        timeout = min(self.execution_policy.channel_deadlines[source.channel], remaining)
        if timeout <= 0:
            return self.policy.channel_failure(
                source.channel,
                ChannelFailure(ChannelFailureKind.DEADLINE, "AM_DEADLINE_EXCEEDED"),
                observed_at,
            )
        dependency_acquired = False
        try:
            async with asyncio.timeout(timeout):
                async with self.bulkhead:
                    circuit_observed_at = self.clock.now()
                    if not await self.health.acquire(source.dependency, circuit_observed_at):
                        return self.policy.channel_failure(
                            source.channel,
                            ChannelFailure(ChannelFailureKind.CIRCUIT_OPEN, "AM_CIRCUIT_OPEN"),
                            circuit_observed_at,
                        )
                    dependency_acquired = True
                    success = await source.recall(query)
                    _require_source_channel(success, source.channel)
        except asyncio.CancelledError:
            await self._abandon_if_acquired(source.dependency, acquired=dependency_acquired)
            raise
        except TimeoutError:
            return await self._deadline_failure(source, dependency_acquired=dependency_acquired)
        except RecallAuthorizationError, RecallIntegrityError:
            await self._abandon_if_acquired(source.dependency, acquired=dependency_acquired)
            raise
        except RecallDependencyError:
            failure_at = self.clock.now()
            await self.health.failure(source.dependency, failure_at)
            return self.policy.channel_failure(
                source.channel,
                ChannelFailure(ChannelFailureKind.DEPENDENCY, "AM_DEPENDENCY_UNAVAILABLE"),
                failure_at,
            )
        await self.health.success(source.dependency, self.clock.now())
        return success

    async def _abandon_if_acquired(self, dependency: DependencyName, *, acquired: bool) -> None:
        """Release a reserved half-open probe only when this call owns one."""
        if acquired:
            await self.health.abandon(dependency, self.clock.now())

    async def _deadline_failure(
        self, source: RecallChannelSource, *, dependency_acquired: bool
    ) -> ChannelOutcome:
        """Return typed timeout evidence and bill only a started dependency call."""
        failure_at = self.clock.now()
        if dependency_acquired:
            await self.health.failure(source.dependency, failure_at)
        return self.policy.channel_failure(
            source.channel,
            ChannelFailure(ChannelFailureKind.DEADLINE, "AM_DEADLINE_EXCEEDED"),
            failure_at,
        )


def _require_source_channel(success: RecallChannelSuccess, expected: ChannelName) -> None:
    """Fail closed when an adapter substitutes another channel identity."""
    if success.channel is not expected:
        raise RecallIntegrityError(_ERR_CHANNEL_SUBSTITUTION)


def _merge_candidates(successes: tuple[RecallChannelSuccess, ...]) -> tuple[RecallCandidate, ...]:
    """Deduplicate stable IDs by highest channel score and return deterministic ranking."""
    selected: dict[str, RecallCandidate] = {}
    for candidate in (candidate for success in successes for candidate in success.candidates):
        current = selected.get(candidate.candidate_id)
        if current is None or candidate.score_basis_points > current.score_basis_points:
            selected[candidate.candidate_id] = candidate
    return tuple(
        sorted(selected.values(), key=lambda item: (-item.score_basis_points, item.candidate_id))
    )
