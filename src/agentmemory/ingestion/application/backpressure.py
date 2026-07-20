"""ING-004 authorized scheduling, failure containment, and DLQ replay."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.backpressure import (
    JobErrorCode,
    JobRequest,
    QueueLimits,
    ReplayDeadLetterRequest,
    RetryPolicy,
    ScheduledJob,
)
from agentmemory.ingestion.domain.errors import (
    IngestionIntegrityError,
    IngestionValidationError,
    ScheduledJobExecutionError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from agentmemory.ingestion.domain.backpressure import DeadLetter
    from agentmemory.ingestion.domain.ports import (
        JobSchedulerAccessPolicy,
        JobSchedulerRepository,
        ScheduledJobExecutor,
    )
    from agentmemory.shared.clock import Clock

_DEFAULT_LEASE_MICROSECONDS = 60 * 1_000_000
_DEFAULT_POLL_SECONDS = 0.5
_MAX_POLL_SECONDS = 10.0
_MAX_OWNER_LENGTH = 128
_MAX_DEAD_LETTERS = 500
_ERR_MISSING_JOB = "Claimed scheduler job disappeared"
_ERR_OWNER = "scheduler worker owner is invalid"
_ERR_LEASE = "scheduler worker lease is invalid"
_ERR_POLL = "scheduler worker poll interval is invalid"
_FIELD_MAXIMUM = "maximum"
_FIELD_DEAD_LETTER_ID = "dead_letter_id"
_FIELD_JOB_ID = "job_id"


@dataclass(frozen=True, slots=True)
class SubmitJobHandler:
    """Authorize and durably admit one job through configured reservations."""

    access: JobSchedulerAccessPolicy
    repository: JobSchedulerRepository
    limits: QueueLimits
    clock: Clock

    async def execute(self, request: JobRequest) -> ScheduledJob:
        """Return an exact prior job or one new admitted durable job."""
        now = _microseconds(self.clock)
        await self.access.authorize(request.actor_id, request.grant_id, request.brain_id, now)
        return await self.repository.submit(request, self.limits, now)


@dataclass(frozen=True, slots=True)
class ListDeadLettersHandler:
    """Return bounded failure evidence after current Brain authorization."""

    access: JobSchedulerAccessPolicy
    repository: JobSchedulerRepository
    clock: Clock

    async def execute(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        *,
        maximum: int = 100,
    ) -> tuple[DeadLetter, ...]:
        """Reauthorize every query and return no input or arbitrary diagnostic text."""
        if not 1 <= maximum <= _MAX_DEAD_LETTERS:
            raise IngestionValidationError.single(_FIELD_MAXIMUM, "out_of_range")
        await self.access.authorize(
            actor_id,
            grant_id,
            brain_id,
            _microseconds(self.clock),
        )
        return await self.repository.list_dead_letters(brain_id, maximum=maximum)


@dataclass(frozen=True, slots=True)
class GetScheduledJobHandler:
    """Return content-free job state after current authorization."""

    access: JobSchedulerAccessPolicy
    repository: JobSchedulerRepository
    clock: Clock

    async def execute(self, job_id: str) -> ScheduledJob:
        """Load scheduler state and reauthorize its exact current Brain grant."""
        job = await self.repository.get(job_id)
        if job is None:
            raise IngestionValidationError.single(_FIELD_JOB_ID, "not_found")
        await self.access.authorize(
            job.request.actor_id,
            job.request.grant_id,
            job.request.brain_id,
            _microseconds(self.clock),
        )
        return job


@dataclass(frozen=True, slots=True)
class ReplayDeadLetterHandler:
    """Authorize replay and create a new linked attempt without editing history."""

    access: JobSchedulerAccessPolicy
    repository: JobSchedulerRepository
    limits: QueueLimits
    clock: Clock

    async def execute(self, request: ReplayDeadLetterRequest) -> ScheduledJob:
        """Reauthorize the dead letter's Brain before persisting corrected work."""
        dead_letter = await self.repository.get_dead_letter(request.dead_letter_id)
        if dead_letter is None:
            raise IngestionValidationError.single(_FIELD_DEAD_LETTER_ID, "not_found")
        now = _microseconds(self.clock)
        await self.access.authorize(
            request.actor_id,
            request.grant_id,
            dead_letter.brain_id,
            now,
        )
        return await self.repository.replay_dead_letter(request, self.limits, now)


@dataclass(frozen=True, slots=True)
class JobSchedulerWorker:
    """Recover and fairly drain durable queues while containing poison work."""

    repository: JobSchedulerRepository
    executor: ScheduledJobExecutor
    retry_policy: RetryPolicy
    limits: QueueLimits
    clock: Clock
    owner: str
    lease_microseconds: int = _DEFAULT_LEASE_MICROSECONDS
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        """Bound worker identity, shutdown latency, and lease duration."""
        if not self.owner or len(self.owner) > _MAX_OWNER_LENGTH:
            raise ValueError(_ERR_OWNER)
        if self.lease_microseconds < 1:
            raise ValueError(_ERR_LEASE)
        if not 0 < self.poll_seconds <= _MAX_POLL_SECONDS:
            raise ValueError(_ERR_POLL)

    async def run(self, stop: asyncio.Event) -> None:
        """Recover once and continue after all typed or unexpected job failures."""
        if stop.is_set():
            return
        recovered = False
        while not stop.is_set():
            try:
                if not recovered:
                    await self.repository.recover_expired(_microseconds(self.clock))
                    recovered = True
                claimed = await self.run_once()
            except Exception:  # noqa: BLE001 -- Storage recovery must not kill the worker task.
                await _wait_or_stop(stop, self.poll_seconds)
                continue
            if not claimed:
                await _wait_or_stop(stop, self.poll_seconds)

    async def run_once(self) -> bool:
        """Execute at most one due job and report whether work was claimed."""
        now = _microseconds(self.clock)
        job = await self.repository.claim_next(
            self.owner,
            now,
            now + self.lease_microseconds,
            self.limits,
        )
        if job is None:
            return False
        await self._execute(job)
        return True

    async def _execute(self, job: ScheduledJob) -> None:
        try:
            result_sha256 = await self.executor.execute(job)
        except ScheduledJobExecutionError as error:
            await self._fail(job, error.error_code, error.diagnostic_code)
        except Exception:  # noqa: BLE001 -- One corrupt adapter job cannot stop other queues.
            await self._fail(job, JobErrorCode.INTERNAL_ERROR, "unexpected_worker_failure")
        else:
            completed = await self.repository.succeed(
                job,
                self.owner,
                result_sha256,
                _microseconds(self.clock),
            )
            if completed.request.job_id != job.request.job_id:
                raise IngestionIntegrityError(_ERR_MISSING_JOB)

    async def _fail(
        self,
        job: ScheduledJob,
        error_code: JobErrorCode,
        diagnostic_code: str,
    ) -> None:
        decision = self.retry_policy.decide(error_code, job.attempts)
        await self.repository.fail(
            job,
            self.owner,
            error_code,
            decision,
            diagnostic_code,
            _microseconds(self.clock),
        )


@dataclass(frozen=True, slots=True)
class ScheduledJobExecutorRegistry:
    """Route closed job kinds to independently implemented execution adapters."""

    executors: Mapping[str, ScheduledJobExecutor]

    async def execute(self, job: ScheduledJob) -> str:
        """Execute a registered kind or classify unsupported durable work as poison."""
        executor = self.executors.get(job.request.kind)
        if executor is None:
            raise ScheduledJobExecutionError(JobErrorCode.POISON_JOB, "unsupported_job_kind")
        return await executor.execute(job)


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return


def _microseconds(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)
