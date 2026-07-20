"""MEM-001 evidence-bound task consolidation use case."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.memory.domain.consolidation import (
    CandidateRejection,
    ConsolidationCommit,
    ConsolidationResult,
    ExtractorIdentity,
    ExtractorRequest,
    Memory,
    MemoryCandidateBatch,
    MemoryPromotionPolicy,
    MemoryScope,
    PromotionDisposition,
    consolidation_idempotency_key,
    validate_consolidation_command_actor,
    validate_consolidation_command_time,
    validate_consolidation_command_trace,
)
from agentmemory.memory.domain.errors import (
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.memory.domain.ports import (
        MemoryCandidateExtractor,
        MemoryConsolidationAccessPolicy,
        MemoryConsolidationReceiptQuery,
        MemoryConsolidationUnitOfWorkFactory,
        TaskEvidenceQuery,
    )
    from agentmemory.shared.clock import Clock

_MAX_EVIDENCE_ITEMS = 256
_MAX_EVIDENCE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ConsolidateTaskCommand:
    """Authorized internal request to consolidate one terminal task snapshot."""

    operation_id: str
    actor_id: str
    grant_id: str
    correlation_id: str
    causation_id: str
    task_id: str
    terminal_event_id: str
    scope: MemoryScope
    extractor: ExtractorIdentity
    requested_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        """Reuse domain validation without duplicating identity or time rules."""
        validate_consolidation_command_actor(
            self.operation_id,
            self.actor_id,
            self.grant_id,
        )
        validate_consolidation_command_trace(
            self.correlation_id,
            self.causation_id,
            self.task_id,
            self.terminal_event_id,
        )
        validate_consolidation_command_time(
            self.requested_at,
            self.deadline,
        )


@dataclass(frozen=True, slots=True)
class ConsolidateTaskHandler:
    """Validate extractor output and apply promotion before one atomic commit."""

    evidence_query: TaskEvidenceQuery
    extractor: MemoryCandidateExtractor
    access: MemoryConsolidationAccessPolicy
    receipts: MemoryConsolidationReceiptQuery
    unit_of_work: MemoryConsolidationUnitOfWorkFactory
    promotion_policy: MemoryPromotionPolicy
    clock: Clock

    async def execute(self, command: ConsolidateTaskCommand) -> ConsolidationResult:
        """Consolidate an immutable task snapshot without granting the model authority."""
        now = self.clock.now()
        if command.requested_at > now:
            requested_at_field = "requested_at"
            raise MemoryValidationError.single(requested_at_field, "in_future")
        if command.deadline <= now:
            deadline_field = "deadline"
            raise MemoryValidationError.single(deadline_field, "expired")
        await self.access.authorize(command.actor_id, command.grant_id, command.scope, now)
        source = await self.evidence_query.load(
            command.task_id,
            command.terminal_event_id,
            command.scope,
            _MAX_EVIDENCE_ITEMS,
            _MAX_EVIDENCE_BYTES,
        )
        if source is None:
            raise MemoryEvidenceNotFoundError
        if (
            source.task_id != command.task_id
            or source.terminal_event_id != command.terminal_event_id
            or source.scope != command.scope
        ):
            raise MemoryIntegrityError
        idempotency_key = consolidation_idempotency_key(
            command.task_id,
            source.watermark_sha256,
            command.extractor.fingerprint,
        )
        existing = await self.receipts.get(idempotency_key)
        if existing is not None:
            return existing
        request = ExtractorRequest(
            command.operation_id,
            idempotency_key,
            command.task_id,
            source.extractor_input_bytes,
            source.extractor_input_sha256,
            source.classification,
            "memory_consolidation",
            command.deadline,
            command.extractor,
        )
        response = await self.extractor.extract(request)
        if not response.matches(request):
            raise MemoryIntegrityError
        batch = MemoryCandidateBatch.decode(response.output_bytes, request.input_sha256)
        memories: list[Memory] = []
        rejections: list[CandidateRejection] = []
        for candidate in batch.candidates:
            decision = self.promotion_policy.evaluate(candidate, source)
            if decision.disposition is PromotionDisposition.PROMOTE:
                memories.append(
                    candidate.activate(
                        decision,
                        source,
                        command.extractor,
                        command.actor_id,
                        now,
                    )
                )
            else:
                rejections.append(
                    CandidateRejection(
                        hashlib.sha256(candidate.candidate_key.encode()).hexdigest(),
                        candidate.memory_class,
                        candidate.content_sha256,
                        decision.reason_code,
                    )
                )
        commit = ConsolidationCommit(
            command.operation_id,
            command.actor_id,
            command.grant_id,
            command.correlation_id,
            command.causation_id,
            idempotency_key,
            command.task_id,
            command.scope,
            source.watermark_sha256,
            source.extractor_input_sha256,
            command.extractor,
            source.terminal_event_id,
            self.promotion_policy.policy_version,
            source.classification,
            source.retention_policy_id,
            tuple(memories),
            tuple(rejections),
            command.requested_at,
            now,
        )
        expected = commit.result
        async with self.unit_of_work() as unit_of_work:
            await unit_of_work.access.authorize(
                command.actor_id,
                command.grant_id,
                command.scope,
                self.clock.now(),
            )
            concurrent = await unit_of_work.repository.get(idempotency_key)
            if concurrent is not None:
                return concurrent
            await unit_of_work.repository.add(commit)
            await unit_of_work.commit()
        return expected
