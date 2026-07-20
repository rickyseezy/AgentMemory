# pyright: reportPrivateUsage=false
"""MEM-001 automatic worker retry, containment, and exact binding tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest

import agentmemory.memory.application.consolidation_worker as worker_module
import agentmemory.memory.domain.work as work_module
from agentmemory.memory.application.consolidation_worker import MemoryConsolidationWorker
from agentmemory.memory.domain.errors import MemoryDependencyError, MemoryValidationError
from agentmemory.memory.domain.work import (
    MemoryConsolidationWork,
    MemoryWorkErrorCode,
    MemoryWorkRetryDecision,
    MemoryWorkRetryPolicy,
    MemoryWorkState,
)
from tests.core.support import FixedClock
from tests.memory.test_mem001_consolidation_boundaries import _commit

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.application.consolidate_task import (
        ConsolidateTaskCommand,
        ConsolidateTaskHandler,
    )
    from agentmemory.memory.domain.consolidation import ConsolidationResult, ExtractorIdentity
    from agentmemory.memory.domain.ports import MemoryConsolidationWorkRepository


def _succeeded_results() -> list[tuple[MemoryConsolidationWork, str]]:
    return []


def _failed_results() -> list[
    tuple[MemoryConsolidationWork, MemoryWorkErrorCode, MemoryWorkRetryDecision]
]:
    return []


def _commands() -> list[ConsolidateTaskCommand]:
    return []


def _work(attempts: int = 1) -> MemoryConsolidationWork:
    commit = _commit()
    return MemoryConsolidationWork(
        commit.operation_id,
        commit.idempotency_key,
        commit.task_id,
        commit.source_terminal_event_id,
        commit.actor_id,
        commit.grant_id,
        commit.correlation_id,
        commit.causation_id,
        commit.scope,
        commit.evidence_watermark_sha256,
        commit.extractor,
        MemoryWorkState.LEASED,
        attempts,
        "worker-1",
        9_999_999_999_999_999,
    )


@dataclass
class _Repository:
    work: MemoryConsolidationWork | None
    succeeded: list[tuple[MemoryConsolidationWork, str]] = field(default_factory=_succeeded_results)
    failed: list[tuple[MemoryConsolidationWork, MemoryWorkErrorCode, MemoryWorkRetryDecision]] = (
        field(default_factory=_failed_results)
    )

    async def claim_next(
        self,
        extractor: ExtractorIdentity,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> MemoryConsolidationWork | None:
        del extractor, owner, now_microseconds, lease_until_microseconds
        result, self.work = self.work, None
        return result

    async def succeed(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        result_sha256: str,
        completed_at_microseconds: int,
    ) -> None:
        del owner, completed_at_microseconds
        self.succeeded.append((work, result_sha256))

    async def fail(
        self,
        work: MemoryConsolidationWork,
        owner: str,
        error_code: MemoryWorkErrorCode,
        decision: MemoryWorkRetryDecision,
        failed_at_microseconds: int,
    ) -> None:
        del owner, failed_at_microseconds
        self.failed.append((work, error_code, decision))

    async def recover_expired(self, now_microseconds: int) -> int:
        del now_microseconds
        return 0


@dataclass
class _Handler:
    result: ConsolidationResult | Exception
    commands: list[ConsolidateTaskCommand] = field(default_factory=_commands)

    async def execute(self, command: ConsolidateTaskCommand) -> ConsolidationResult:
        self.commands.append(command)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _worker(repository: _Repository, handler: _Handler) -> MemoryConsolidationWorker:
    return MemoryConsolidationWorker(
        cast("MemoryConsolidationWorkRepository", repository),
        cast("ConsolidateTaskHandler", handler),
        _commit().extractor,
        MemoryWorkRetryPolicy(),
        FixedClock(_commit().completed_at + timedelta(seconds=1)),
        owner="worker-1",
    )


@pytest.mark.asyncio
async def test_worker_executes_exact_terminal_snapshot_and_completes_receipt() -> None:
    work = _work()
    repository = _Repository(work)
    handler = _Handler(_commit().result)
    assert await _worker(repository, handler).run_once()
    assert repository.succeeded == [(work, _commit().result.result_sha256)]
    assert not repository.failed
    assert handler.commands[0].terminal_event_id == work.terminal_event_id
    assert handler.commands[0].grant_id == work.grant_id


@pytest.mark.asyncio
async def test_worker_retries_dependency_and_dead_letters_integrity() -> None:
    dependency_repository = _Repository(_work())
    await _worker(dependency_repository, _Handler(MemoryDependencyError())).run_once()
    assert dependency_repository.failed[0][1] is MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE
    assert dependency_repository.failed[0][2].retry

    divergent = _commit().result
    object.__setattr__(divergent, "idempotency_key", "f" * 64)
    integrity_repository = _Repository(_work())
    await _worker(integrity_repository, _Handler(divergent)).run_once()
    assert integrity_repository.failed[0][1] is MemoryWorkErrorCode.INTEGRITY_VIOLATION
    assert not integrity_repository.failed[0][2].retry


def test_retry_policy_is_bounded_and_exponential() -> None:
    policy = MemoryWorkRetryPolicy()
    assert (
        policy.decide(MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE, 1).delay_microseconds == 1_000_000
    )
    assert policy.decide(MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE, 8).retry
    assert not policy.decide(MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE, 9).retry
    assert not policy.decide(MemoryWorkErrorCode.AUTHORIZATION_DENIED, 1).retry


def test_work_model_rejects_every_invalid_lease_and_digest_boundary() -> None:
    source = _work()
    mutations: tuple[tuple[Callable[[], MemoryConsolidationWork], str, str], ...] = (
        (
            lambda: replace(source, idempotency_key="0" * 64),
            "idempotency_key",
            "invalid_digest",
        ),
        (
            lambda: replace(source, evidence_watermark_sha256="A" * 64),
            "evidence_watermark_sha256",
            "invalid_digest",
        ),
        (lambda: replace(source, state=MemoryWorkState.QUEUED), "state", "lease_required"),
        (lambda: replace(source, lease_owner=""), "lease_owner", "invalid"),
        (lambda: replace(source, lease_owner="x" * 129), "lease_owner", "invalid"),
        (lambda: replace(source, attempts=0), "lease", "invalid"),
        (lambda: replace(source, attempts=10), "lease", "invalid"),
        (lambda: replace(source, lease_until_microseconds=0), "lease", "invalid"),
    )
    for mutation, field_name, code in mutations:
        with pytest.raises(MemoryValidationError) as failure:
            mutation()
        assert failure.value.code_for(field_name) == code


def test_retry_decision_and_policy_reject_invalid_shapes_and_cap_delays() -> None:
    assert MemoryWorkRetryDecision(retry=True, delay_microseconds=1).delay_microseconds == 1
    assert MemoryWorkRetryDecision(retry=False, delay_microseconds=None).delay_microseconds is None
    for retry, delay, field_name, code in (
        (True, None, "retry", "invalid_shape"),
        (False, 1, "retry", "invalid_shape"),
        (True, 0, "retry.delay", "out_of_range"),
    ):
        with pytest.raises(MemoryValidationError) as failure:
            MemoryWorkRetryDecision(retry, delay)
        assert failure.value.code_for(field_name) == code

    for values in ((1, 1, 1, 1), (10, 2, 1, 1), (3, 4, 1, 1), (3, 2, 0, 1), (3, 2, 2, 1)):
        with pytest.raises(MemoryValidationError) as failure:
            MemoryWorkRetryPolicy(*values)
        assert failure.value.code_for("retry_policy") == "invalid"

    policy = MemoryWorkRetryPolicy(
        dependency_attempts=4,
        internal_attempts=2,
        base_delay_microseconds=3,
        maximum_delay_microseconds=5,
    )
    assert policy.decide(MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE, 2) == (
        MemoryWorkRetryDecision(retry=True, delay_microseconds=5)
    )
    assert not policy.decide(MemoryWorkErrorCode.INTERNAL_ERROR, 2).retry
    for attempts in (0, 10):
        with pytest.raises(MemoryValidationError) as failure:
            policy.decide(MemoryWorkErrorCode.INTERNAL_ERROR, attempts)
        assert failure.value.code_for("attempts") == "out_of_range"


def test_work_internal_validation_retains_exact_content_free_field_and_code() -> None:
    with pytest.raises(MemoryValidationError) as failure:
        work_module._invalid("field", "code")
    assert failure.value.code_for("field") == "code"
    for invalid in ("a" * 63, "A" * 64, "0" * 64):
        with pytest.raises(MemoryValidationError) as digest:
            work_module._digest(invalid, "digest")
        assert digest.value.code_for("digest") == "invalid_digest"


def test_worker_constructor_bounds_identity_poll_and_lease() -> None:
    repository = _Repository(None)
    handler = _Handler(_commit().result)
    valid = _worker(repository, handler)
    assert valid.owner == "worker-1"
    for changes, message in (
        ({"owner": ""}, "owner is invalid"),
        ({"owner": "x" * 129}, "owner is invalid"),
        ({"poll_seconds": 0}, "poll interval is invalid"),
        ({"poll_seconds": 11}, "poll interval is invalid"),
        ({"lease_microseconds": 0}, "lease is invalid"),
    ):
        with pytest.raises(ValueError, match=message):
            replace(valid, **changes)


@pytest.mark.asyncio
async def test_worker_returns_false_without_work_and_waits_boundedly() -> None:
    repository = _Repository(None)
    worker = _worker(repository, _Handler(_commit().result))
    assert not await worker.run_once()

    stop = asyncio.Event()
    await asyncio.wait_for(worker_module._wait_or_stop(stop, 0), timeout=0.1)
    stop.set()
    await asyncio.wait_for(worker_module._wait_or_stop(stop, 1), timeout=0.1)
    assert worker_module._micros(worker.clock) == 1_784_548_803_000_000
