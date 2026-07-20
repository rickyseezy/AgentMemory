"""PF-002 durable start and deterministic replay application services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRebuild,
    RebuildState,
    StartProjectionRebuildCommand,
    derive_generation_id,
    derive_rebuild_key,
)

if TYPE_CHECKING:
    from agentmemory.operations.domain.ports import (
        CanonicalProjectionSourcePort,
        ProjectionAccessPolicyPort,
        ProjectionGenerationPort,
        ProjectionRebuildRepository,
    )
    from agentmemory.operations.domain.projection_rebuild import SourcePage

_DEFAULT_PAGE_SIZE = 256
_MAX_PAGE_SIZE = 4096


@dataclass(frozen=True, slots=True)
class StartProjectionRebuildHandler:
    """Capture a canonical watermark and enqueue one idempotent rebuild."""

    source: CanonicalProjectionSourcePort
    access: ProjectionAccessPolicyPort
    repository: ProjectionRebuildRepository

    async def execute(self, command: StartProjectionRebuildCommand) -> ProjectionRebuild:
        """Authorize and persist the immutable shadow-generation identity."""
        await self.access.authorize(command.brain_id, command.actor_id, command.grant_id)
        latest = await self.source.latest_watermark(command.brain_id)
        watermark = latest if command.requested_watermark is None else command.requested_watermark
        if watermark > latest:
            raise OperationError(ErrorCode.VALIDATION, "requested watermark is not committed")
        rebuild_key = derive_rebuild_key(
            command.projection_type,
            command.brain_id,
            watermark,
            command.manifest.implementation_fingerprint,
        )
        generation_id = derive_generation_id(rebuild_key, command.manifest.digest)
        return await self.repository.create(command, watermark, rebuild_key, generation_id)


@dataclass(frozen=True, slots=True)
class ProjectionRebuilder:
    """Replay one durable job through shadow validation and atomic activation."""

    source: CanonicalProjectionSourcePort
    access: ProjectionAccessPolicyPort
    generations: ProjectionGenerationPort
    repository: ProjectionRebuildRepository
    page_size: int = _DEFAULT_PAGE_SIZE

    def __post_init__(self) -> None:
        """Keep replay memory and transaction work bounded."""
        if self.page_size < 1 or self.page_size > _MAX_PAGE_SIZE:
            msg = "projection rebuild page size is outside the supported range"
            raise ValueError(msg)

    async def execute(self, operation_id: str) -> ProjectionRebuild:
        """Resume safely after any committed cursor without duplicating effective state."""
        current = await self.repository.get(operation_id)
        if current is None:
            raise OperationError(ErrorCode.VALIDATION, "projection rebuild was not found")
        if current.state in {RebuildState.ACTIVE, RebuildState.SUPERSEDED}:
            return current
        job = await self.repository.claim(operation_id)
        await self.access.authorize(job.brain_id, job.actor_id, job.grant_id)
        await self.generations.prepare(
            job.brain_id,
            job.projection_type,
            job.generation_id,
            job.manifest,
        )
        job = await self._replay(operation_id, job)
        if job.state is RebuildState.PARTIAL:
            return job
        return await self._validate_and_activate(operation_id, job)

    async def _replay(
        self,
        operation_id: str,
        job: ProjectionRebuild,
    ) -> ProjectionRebuild:
        """Replay canonical pages until complete or a dependency pauses progress."""
        while job.cursor < job.source_watermark:
            page = await self.source.read_page(
                job.brain_id,
                job.projection_type,
                job.cursor,
                job.source_watermark,
                self.page_size,
            )
            if page.next_cursor <= job.cursor:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "canonical replay cursor did not advance",
                )
            job = await self._process_page(operation_id, job, page)
            if job.state is RebuildState.PARTIAL:
                return job
            if page.next_cursor > job.cursor:
                job = await self.repository.checkpoint(operation_id, page.next_cursor, 0, 0)
            if page.complete and job.cursor != job.source_watermark:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "canonical replay ended before its watermark",
                )
        return job

    async def _process_page(
        self,
        operation_id: str,
        job: ProjectionRebuild,
        page: SourcePage,
    ) -> ProjectionRebuild:
        """Apply policy and write each page record with a durable cursor checkpoint."""
        for source_record in page.records:
            sequence = source_record.projection.source_sequence
            if sequence <= job.cursor:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "canonical replay returned an out-of-order source",
                )
            if source_record.missing_dependency is not None:
                return await self.repository.mark_partial(
                    operation_id,
                    source_record.missing_dependency,
                )
            await self.access.authorize(job.brain_id, job.actor_id, job.grant_id)
            if await self.access.is_tombstoned(job.brain_id, source_record):
                job = await self.repository.checkpoint(operation_id, sequence, 0, 1)
                continue
            inserted = await self.generations.put(
                job.brain_id,
                job.projection_type,
                job.generation_id,
                source_record,
                job.manifest,
            )
            job = await self.repository.checkpoint(
                operation_id,
                sequence,
                int(inserted),
                0,
            )
        return job

    async def _validate_and_activate(
        self,
        operation_id: str,
        job: ProjectionRebuild,
    ) -> ProjectionRebuild:
        """Run all closed validation gates and compare-and-swap query visibility."""
        await self.access.authorize(job.brain_id, job.actor_id, job.grant_id)
        job = await self.repository.begin_validation(operation_id)
        validation = await self.generations.validate(
            job.brain_id,
            job.projection_type,
            job.generation_id,
            job.manifest,
        )
        if not validation.passed or validation.record_count != job.record_count:
            return await self.repository.fail(operation_id, "projection_validation_failed")
        await self.repository.mark_ready(operation_id, validation)
        await self.access.authorize(job.brain_id, job.actor_id, job.grant_id)
        return await self.repository.activate(operation_id)
