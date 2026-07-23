"""ING-004 application authorization, retry, poison, and recovery tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Any, cast, override

import pytest

from agentmemory.ingestion.application.backpressure import (
    GetScheduledJobHandler,
    JobSchedulerWorker,
    ListDeadLettersHandler,
    ReplayDeadLetterHandler,
    ScheduledJobExecutorRegistry,
    SubmitJobHandler,
)
from agentmemory.ingestion.domain.backpressure import (
    CapacitySnapshot,
    DeadLetter,
    JobErrorCode,
    JobPriority,
    JobRequest,
    JobState,
    QueueLimits,
    ReplayDeadLetterRequest,
    RetryDecision,
    RetryPolicy,
    ScheduledJob,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionIntegrityError,
    IngestionValidationError,
    ScheduledJobExecutionError,
)
from tests.core.support import BRAIN_ID, GRANT_ID, NOW, FixedClock, digest
from tests.ingestion.adp002_support import PRINCIPAL_ID

JOB_ID = "018f0000-0000-7000-8000-000000000301"
DLQ_ID = "018f0000-0000-7000-8000-000000000302"
OPERATION_ID = "018f0000-0000-7000-8000-000000000303"
REPLAY_JOB_ID = "018f0000-0000-7000-8000-000000000304"


def limits() -> QueueLimits:
    return QueueLimits(100, 200, 20, 30, 1_000_000, 500_000, 16, (70, 85, 100))


def request(**changes: object) -> JobRequest:
    value = JobRequest(
        JOB_ID,
        BRAIN_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        "memory-index",
        "memory-index:event-301",
        digest("request").value,
        JobPriority.STANDARD,
        "cas://sha256/" + digest("input").value,
    )
    return replace(value, **cast("Any", changes))


def scheduled(**changes: object) -> ScheduledJob:
    value = ScheduledJob(
        request(),
        JobState.QUEUED,
        0,
        1,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1,
        1,
    )
    return replace(value, **cast("Any", changes))


def dead_letter() -> DeadLetter:
    return DeadLetter(
        DLQ_ID,
        JOB_ID,
        BRAIN_ID,
        JobPriority.STANDARD,
        "memory-index",
        digest("request").value,
        3,
        JobErrorCode.POISON_JOB,
        "malformed_projection_input",
        20,
        20,
    )


@dataclass
class Access:
    allowed: bool = True
    calls: list[tuple[str, str, str, int]] | None = None

    async def authorize(
        self,
        actor_id: str,
        grant_id: str,
        brain_id: str,
        now_microseconds: int,
    ) -> None:
        if self.calls is not None:
            self.calls.append((actor_id, grant_id, brain_id, now_microseconds))
        if not self.allowed:
            message = "denied"
            raise IngestionAuthorizationError(message)


class Repository:
    def __init__(self) -> None:
        self.jobs: dict[str, ScheduledJob] = {}
        self.dead = (dead_letter(),)
        self.failures: list[tuple[JobErrorCode, RetryDecision, str]] = []
        self.recovered = 0
        self.claim: ScheduledJob | None = None

    async def submit(
        self,
        request: JobRequest,
        limits: QueueLimits,
        now_microseconds: int,
    ) -> ScheduledJob:
        del limits
        result = scheduled(
            request=request,
            next_attempt_at_microseconds=now_microseconds,
            created_at_microseconds=now_microseconds,
            updated_at_microseconds=now_microseconds,
        )
        self.jobs[request.job_id] = result
        return result

    async def get(self, job_id: str) -> ScheduledJob | None:
        return self.jobs.get(job_id)

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
        limits: QueueLimits,
    ) -> ScheduledJob | None:
        del now_microseconds, limits
        if self.claim is None:
            return None
        claimed = replace(
            self.claim,
            state=JobState.LEASED,
            attempts=self.claim.attempts + 1,
            lease_owner=owner,
            lease_until_microseconds=lease_until_microseconds,
        )
        self.claim = None
        return claimed

    async def succeed(
        self,
        job: ScheduledJob,
        owner: str,
        result_sha256: str,
        completed_at_microseconds: int,
    ) -> ScheduledJob:
        del owner
        value = replace(
            job,
            state=JobState.SUCCEEDED,
            lease_owner=None,
            lease_until_microseconds=None,
            result_sha256=result_sha256,
            completed_at_microseconds=completed_at_microseconds,
            updated_at_microseconds=completed_at_microseconds,
        )
        self.jobs[job.request.job_id] = value
        return value

    async def fail(  # noqa: PLR0913 -- Fake mirrors the production port exactly.
        self,
        job: ScheduledJob,
        owner: str,
        error_code: JobErrorCode,
        decision: RetryDecision,
        diagnostic_code: str,
        failed_at_microseconds: int,
    ) -> ScheduledJob:
        del owner, failed_at_microseconds
        self.failures.append((error_code, decision, diagnostic_code))
        return job

    async def recover_expired(self, now_microseconds: int) -> int:
        del now_microseconds
        self.recovered += 1
        return 1

    async def capacity_snapshot(self, *, kind: str, idempotency_key: str) -> CapacitySnapshot:
        del kind, idempotency_key
        return CapacitySnapshot(0, 0, 0, 0, 0, 10_000_000, existing_identity=False)

    async def list_dead_letters(self, brain_id: str, *, maximum: int) -> tuple[DeadLetter, ...]:
        assert brain_id == BRAIN_ID
        return self.dead[:maximum]

    async def get_dead_letter(self, dead_letter_id: str) -> DeadLetter | None:
        return self.dead[0] if dead_letter_id == DLQ_ID else None

    async def replay_dead_letter(
        self,
        request: ReplayDeadLetterRequest,
        limits: QueueLimits,
        now_microseconds: int,
    ) -> ScheduledJob:
        del limits
        original = self.dead[0]
        item = JobRequest(
            request.new_job_id,
            BRAIN_ID,
            request.actor_id,
            request.grant_id,
            original.kind,
            f"dlq-replay:{request.operation_id}",
            request.corrected_request_sha256,
            original.priority,
            request.corrected_input_ref,
        )
        return scheduled(
            request=item,
            parent_job_id=original.original_job_id,
            source_dead_letter_id=original.dead_letter_id,
            next_attempt_at_microseconds=now_microseconds,
            created_at_microseconds=now_microseconds,
            updated_at_microseconds=now_microseconds,
        )


class Executor:
    def __init__(self, outcome: str | Exception) -> None:
        self.outcome = outcome

    async def execute(self, job: ScheduledJob) -> str:
        del job
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.asyncio
async def test_submit_and_list_reauthorize_current_exact_brain_grant() -> None:
    calls: list[tuple[str, str, str, int]] = []
    access = Access(calls=calls)
    repository = Repository()
    submitted = await SubmitJobHandler(access, repository, limits(), FixedClock()).execute(
        request()
    )
    listed = await ListDeadLettersHandler(access, repository, FixedClock()).execute(
        PRINCIPAL_ID, GRANT_ID, BRAIN_ID
    )
    assert submitted.request.job_id == JOB_ID
    assert listed == (dead_letter(),)
    expected_now = round(NOW.timestamp() * 1_000_000)
    assert calls == [
        (PRINCIPAL_ID, GRANT_ID, BRAIN_ID, expected_now),
        (PRINCIPAL_ID, GRANT_ID, BRAIN_ID, expected_now),
    ]


@pytest.mark.asyncio
async def test_get_job_reauthorizes_and_reports_missing_identity() -> None:
    repository = Repository()
    repository.jobs[JOB_ID] = scheduled()
    handler = GetScheduledJobHandler(Access(), repository, FixedClock())
    assert await handler.execute(JOB_ID) == scheduled()
    with pytest.raises(IngestionValidationError):
        await handler.execute("018f0000-0000-7000-8000-000000000399")


@pytest.mark.asyncio
async def test_denied_list_does_not_query_dead_letters_and_limit_is_bounded() -> None:
    repository = Repository()
    with pytest.raises(IngestionAuthorizationError):
        await ListDeadLettersHandler(Access(allowed=False), repository, FixedClock()).execute(
            PRINCIPAL_ID, GRANT_ID, BRAIN_ID
        )
    with pytest.raises(IngestionValidationError):
        await ListDeadLettersHandler(Access(), repository, FixedClock()).execute(
            PRINCIPAL_ID, GRANT_ID, BRAIN_ID, maximum=501
        )


@pytest.mark.asyncio
async def test_dead_letter_replay_authorizes_source_brain_and_creates_linked_new_job() -> None:
    repository = Repository()
    replay = ReplayDeadLetterRequest(
        OPERATION_ID,
        DLQ_ID,
        REPLAY_JOB_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        digest("corrected").value,
        "cas://sha256/" + digest("corrected-input").value,
    )
    result = await ReplayDeadLetterHandler(Access(), repository, limits(), FixedClock()).execute(
        replay
    )
    assert result.request.job_id == REPLAY_JOB_ID
    assert result.parent_job_id == JOB_ID
    assert result.source_dead_letter_id == DLQ_ID
    assert repository.dead == (dead_letter(),)


@pytest.mark.asyncio
async def test_replay_missing_dead_letter_fails_before_authorization() -> None:
    repository = Repository()
    replay = ReplayDeadLetterRequest(
        OPERATION_ID,
        "018f0000-0000-7000-8000-000000000399",
        REPLAY_JOB_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        digest("corrected").value,
        None,
    )
    with pytest.raises(IngestionValidationError):
        await ReplayDeadLetterHandler(Access(), repository, limits(), FixedClock()).execute(replay)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected_code", "diagnostic"),
    [
        (
            ScheduledJobExecutionError(JobErrorCode.POISON_JOB, "malformed_projection_input"),
            JobErrorCode.POISON_JOB,
            "malformed_projection_input",
        ),
        (
            RuntimeError("secret provider detail"),
            JobErrorCode.INTERNAL_ERROR,
            "unexpected_worker_failure",
        ),
    ],
)
async def test_worker_contains_poison_and_unknown_failures_with_safe_retry_policy(
    outcome: Exception,
    expected_code: JobErrorCode,
    diagnostic: str,
) -> None:
    repository = Repository()
    repository.claim = scheduled()
    worker = JobSchedulerWorker(
        repository,
        Executor(outcome),
        RetryPolicy.default(),
        limits(),
        FixedClock(),
        "scheduler-v1",
    )
    assert await worker.run_once()
    code, decision, actual_diagnostic = repository.failures[0]
    assert code is expected_code
    assert actual_diagnostic == diagnostic
    assert decision.delay_microseconds is None if code is JobErrorCode.POISON_JOB else 1_000_000


@pytest.mark.asyncio
async def test_worker_completes_success_and_reports_empty_queue() -> None:
    repository = Repository()
    repository.claim = scheduled()
    worker = JobSchedulerWorker(
        repository,
        Executor(digest("result").value),
        RetryPolicy.default(),
        limits(),
        FixedClock(),
        "scheduler-v1",
    )
    assert await worker.run_once()
    assert repository.jobs[JOB_ID].state is JobState.SUCCEEDED
    assert not await worker.run_once()


@pytest.mark.asyncio
async def test_worker_run_honors_pre_stop_and_recovers_then_waits_until_stop() -> None:
    repository = Repository()
    worker = JobSchedulerWorker(
        repository,
        Executor(digest("result").value),
        RetryPolicy.default(),
        limits(),
        FixedClock(),
        "scheduler-v1",
        poll_seconds=0.001,
    )
    stopped = asyncio.Event()
    stopped.set()
    await worker.run(stopped)
    assert repository.recovered == 0

    running = asyncio.Event()
    task = asyncio.create_task(worker.run(running))
    await asyncio.sleep(0.005)
    running.set()
    await task
    assert repository.recovered == 1


@pytest.mark.asyncio
async def test_worker_contains_recovery_error_and_detects_mismatched_completion() -> None:
    stop = asyncio.Event()

    class FailingRecovery(Repository):
        @override
        async def recover_expired(self, now_microseconds: int) -> int:
            del now_microseconds
            stop.set()
            message = "temporary"
            raise RuntimeError(message)

    worker = JobSchedulerWorker(
        FailingRecovery(),
        Executor(digest("result").value),
        RetryPolicy.default(),
        limits(),
        FixedClock(),
        "scheduler-v1",
        poll_seconds=0.001,
    )
    await worker.run(stop)

    class MismatchedCompletion(Repository):
        @override
        async def succeed(
            self,
            job: ScheduledJob,
            owner: str,
            result_sha256: str,
            completed_at_microseconds: int,
        ) -> ScheduledJob:
            completed = await super().succeed(
                job,
                owner,
                result_sha256,
                completed_at_microseconds,
            )
            return replace(
                completed,
                request=replace(
                    completed.request,
                    job_id="018f0000-0000-7000-8000-000000000399",
                ),
            )

    repository = MismatchedCompletion()
    repository.claim = scheduled()
    mismatched = JobSchedulerWorker(
        repository,
        Executor(digest("result").value),
        RetryPolicy.default(),
        limits(),
        FixedClock(),
        "scheduler-v1",
    )
    with pytest.raises(IngestionIntegrityError):
        await mismatched.run_once()


@pytest.mark.asyncio
async def test_executor_registry_routes_known_kind_and_types_unknown_kind_as_poison() -> None:
    known = ScheduledJobExecutorRegistry({"memory-index": Executor(digest("result").value)})
    assert await known.execute(scheduled()) == digest("result").value
    with pytest.raises(ScheduledJobExecutionError) as captured:
        await ScheduledJobExecutorRegistry({}).execute(scheduled())
    assert captured.value.error_code is JobErrorCode.POISON_JOB
    assert captured.value.diagnostic_code == "unsupported_job_kind"


@pytest.mark.parametrize(
    "changes",
    [
        {"owner": ""},
        {"lease_microseconds": 0},
        {"poll_seconds": 0},
    ],
)
def test_worker_rejects_unbounded_runtime_configuration(changes: dict[str, object]) -> None:
    arguments: dict[str, object] = {
        "repository": Repository(),
        "executor": Executor(digest("result").value),
        "retry_policy": RetryPolicy.default(),
        "limits": limits(),
        "clock": FixedClock(),
        "owner": "scheduler-v1",
    }
    arguments.update(changes)
    with pytest.raises(ValueError, match="scheduler worker"):
        JobSchedulerWorker(**cast("Any", arguments))
