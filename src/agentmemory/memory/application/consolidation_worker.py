"""Bounded durable automatic MEM-001 consolidation worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.memory.application.consolidate_task import ConsolidateTaskCommand
from agentmemory.memory.application.deduplicate_memories import DeduplicateMemoriesCommand
from agentmemory.memory.domain.consolidation import ConsolidationResult
from agentmemory.memory.domain.errors import (
    MemoryAuthorizationError,
    MemoryConflictError,
    MemoryDependencyError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from agentmemory.memory.domain.work import MemoryWorkErrorCode

if TYPE_CHECKING:
    from agentmemory.memory.application.consolidate_task import ConsolidateTaskHandler
    from agentmemory.memory.application.deduplicate_memories import DeduplicateMemoriesHandler
    from agentmemory.memory.domain.consolidation import ExtractorIdentity
    from agentmemory.memory.domain.ports import MemoryConsolidationWorkRepository
    from agentmemory.memory.domain.work import MemoryConsolidationWork, MemoryWorkRetryPolicy
    from agentmemory.shared.clock import Clock

_POLL_SECONDS = 0.5
_LEASE_MICROSECONDS = 60 * 1_000_000
_REQUEST_SECONDS = 8
_MAX_OWNER_LENGTH = 128
_MAX_POLL_SECONDS = 10
_ERR_OWNER = "memory worker owner is invalid"
_ERR_POLL = "memory worker poll interval is invalid"
_ERR_LEASE = "memory worker lease is invalid"


@dataclass(frozen=True, slots=True)
class MemoryConsolidationWorker:
    """Discover terminal snapshots and contain every typed extraction failure."""

    repository: MemoryConsolidationWorkRepository
    handler: ConsolidateTaskHandler
    extractor: ExtractorIdentity
    retry_policy: MemoryWorkRetryPolicy
    clock: Clock
    deduplicator: DeduplicateMemoriesHandler | None = None
    owner: str = "core-memory-v1"
    poll_seconds: float = _POLL_SECONDS
    lease_microseconds: int = _LEASE_MICROSECONDS

    def __post_init__(self) -> None:
        """Bound worker identity, polling, and lease duration."""
        if not self.owner or len(self.owner) > _MAX_OWNER_LENGTH:
            raise ValueError(_ERR_OWNER)
        if not 0 < self.poll_seconds <= _MAX_POLL_SECONDS:
            raise ValueError(_ERR_POLL)
        if self.lease_microseconds < 1:
            raise ValueError(_ERR_LEASE)

    async def run(self, stop: asyncio.Event) -> None:
        """Recover once, drain continuously, and never let poison work stop the loop."""
        if stop.is_set():
            return
        recovered = False
        while not stop.is_set():
            try:
                if not recovered:
                    await self.repository.recover_expired(_micros(self.clock))
                    recovered = True
                claimed = await self.run_once()
            except Exception:  # noqa: BLE001 -- Storage failure must not kill all future work.
                claimed = False
            if not claimed:
                await _wait_or_stop(stop, self.poll_seconds)

    async def run_once(self) -> bool:
        """Execute at most one leased terminal snapshot."""
        now = self.clock.now()
        now_us = round(now.timestamp() * 1_000_000)
        work = await self.repository.claim_next(
            self.extractor,
            self.owner,
            now_us,
            now_us + self.lease_microseconds,
        )
        if work is None:
            return False
        await self._execute(work)
        return True

    async def _execute(self, work: MemoryConsolidationWork) -> None:
        now = self.clock.now()
        command = ConsolidateTaskCommand(
            work.operation_id,
            work.actor_id,
            work.grant_id,
            work.correlation_id,
            work.causation_id,
            work.task_id,
            work.terminal_event_id,
            work.scope,
            work.extractor,
            now,
            now + timedelta(seconds=_REQUEST_SECONDS),
        )
        try:
            result = await self.handler.execute(command)
            _require_result(work, result)
            await self._deduplicate(work, result)
        except MemoryAuthorizationError:
            await self._fail(work, MemoryWorkErrorCode.AUTHORIZATION_DENIED)
        except MemoryValidationError, MemoryEvidenceNotFoundError:
            await self._fail(work, MemoryWorkErrorCode.INVALID_INPUT)
        except MemoryIntegrityError, MemoryConflictError:
            await self._fail(work, MemoryWorkErrorCode.INTEGRITY_VIOLATION)
        except MemoryDependencyError:
            await self._fail(work, MemoryWorkErrorCode.DEPENDENCY_UNAVAILABLE)
        except Exception:  # noqa: BLE001 -- Unknown provider bugs remain content-free and bounded.
            await self._fail(work, MemoryWorkErrorCode.INTERNAL_ERROR)
        else:
            await self.repository.succeed(
                work,
                self.owner,
                result.result_sha256,
                _micros(self.clock),
            )

    async def _deduplicate(
        self,
        work: MemoryConsolidationWork,
        result: ConsolidationResult,
    ) -> None:
        """Run idempotent exact-first deduplication before acknowledging durable work."""
        if self.deduplicator is None:
            return
        for memory_id in result.memory_ids:
            now = self.clock.now()
            try:
                await self.deduplicator.execute(
                    DeduplicateMemoriesCommand(
                        memory_id,
                        work.actor_id,
                        work.grant_id,
                        work.scope.brain_id,
                        work.correlation_id,
                        work.terminal_event_id,
                        memory_id,
                        now,
                        now + timedelta(seconds=_REQUEST_SECONDS),
                    )
                )
            except MemoryEvidenceNotFoundError:
                # A prior item in the same deterministic batch may already have
                # redirected this newly committed identity.
                continue

    async def _fail(
        self,
        work: MemoryConsolidationWork,
        error_code: MemoryWorkErrorCode,
    ) -> None:
        await self.repository.fail(
            work,
            self.owner,
            error_code,
            self.retry_policy.decide(error_code, work.attempts),
            _micros(self.clock),
        )


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return


def _micros(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)


def _require_result(work: MemoryConsolidationWork, result: object) -> None:
    if not isinstance(result, ConsolidationResult) or (
        result.idempotency_key != work.idempotency_key
        or result.evidence_watermark_sha256 != work.evidence_watermark_sha256
        or result.extractor_fingerprint != work.extractor.fingerprint
    ):
        raise MemoryIntegrityError
