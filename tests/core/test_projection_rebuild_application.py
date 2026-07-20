"""PF-002 application acceptance tests with deterministic port fakes."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from time import perf_counter
from typing import TYPE_CHECKING

import pytest

from agentmemory.operations.application.commands.projection_rebuild import (
    ProjectionRebuilder,
    StartProjectionRebuildHandler,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRebuild,
    ProjectionRecord,
    ProjectionType,
    ProjectionValidation,
    RebuildManifest,
    RebuildState,
    SourcePage,
    SourceRecord,
    StartProjectionRebuildCommand,
    canonical_json,
    projection_digest,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from tests.core.support import BRAIN_ID, GRANT_ID, NOW, OWNER_ID, digest

if TYPE_CHECKING:
    from collections.abc import Iterable


def _manifest() -> RebuildManifest:
    return RebuildManifest(
        application_build="1.0.0",
        relational_schema="0002",
        graph_schema="0002",
        parser_version="parser@1",
        extractor_version="extractor@1",
        provider_versions=("provider@1",),
        embedding_space="embedding@1",
        implementation_fingerprint=digest("implementation"),
    )


def _record(sequence: int, *, missing: str | None = None) -> SourceRecord:
    payload = canonical_json({"sequence": sequence, "text": f"record-{sequence}"})
    projection = ProjectionRecord(
        stable_id=f"record-{sequence}",
        source_event_id=f"event-{sequence}",
        source_sequence=sequence,
        source_digest=digest(f"event-{sequence}"),
        content_digest=Sha256Digest.from_bytes(payload.encode()),
        payload_json=payload,
    )
    return SourceRecord(projection, "event", digest(f"target-{sequence}"), missing)


def _command(operation_id: str = "rebuild-1") -> StartProjectionRebuildCommand:
    return StartProjectionRebuildCommand(
        operation_id=operation_id,
        brain_id=Uuid7Id(BRAIN_ID),
        actor_id=Uuid7Id(OWNER_ID),
        grant_id=Uuid7Id(GRANT_ID),
        projection_type=ProjectionType.GRAPH,
        manifest=_manifest(),
    )


@dataclass(slots=True)
class _Source:
    records: tuple[SourceRecord, ...]

    async def latest_watermark(self, brain_id: Uuid7Id) -> int:
        del brain_id
        return max((record.projection.source_sequence for record in self.records), default=0)

    async def read_page(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        after_cursor: int,
        watermark: int,
        limit: int,
    ) -> SourcePage:
        del brain_id, projection_type
        values = tuple(
            record
            for record in self.records
            if after_cursor < record.projection.source_sequence <= watermark
        )[:limit]
        next_cursor = values[-1].projection.source_sequence if values else watermark
        return SourcePage(values, next_cursor, next_cursor == watermark)


@dataclass(slots=True)
class _Access:
    tombstones: set[str] = field(default_factory=set[str])
    authorized: bool = True

    async def authorize(
        self,
        brain_id: Uuid7Id,
        actor_id: Uuid7Id,
        grant_id: Uuid7Id,
    ) -> None:
        del brain_id, actor_id, grant_id
        if not self.authorized:
            msg = "revoked"
            raise PermissionError(msg)

    async def is_tombstoned(self, brain_id: Uuid7Id, source: SourceRecord) -> bool:
        del brain_id
        return source.projection.stable_id in self.tombstones


@dataclass(slots=True)
class _Generations:
    records: dict[str, ProjectionRecord] = field(default_factory=dict[str, ProjectionRecord])
    prepared: int = 0
    validation_override: ProjectionValidation | None = None

    async def prepare(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> None:
        del brain_id, projection_type, generation_id, manifest
        self.prepared += 1

    async def put(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        record: SourceRecord,
        manifest: RebuildManifest,
    ) -> bool:
        del brain_id, projection_type, generation_id, manifest
        projection = record.projection
        existing = self.records.get(projection.stable_id)
        if existing is not None and existing != projection:
            msg = "divergent duplicate"
            raise RuntimeError(msg)
        self.records[projection.stable_id] = projection
        return existing is None

    async def validate(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        generation_id: Sha256Digest,
        manifest: RebuildManifest,
    ) -> ProjectionValidation:
        del brain_id, projection_type, generation_id, manifest
        if self.validation_override is not None:
            return self.validation_override
        values = tuple(self.records.values())
        return ProjectionValidation(
            record_count=len(values),
            generation_digest=projection_digest(values),
            lineage_complete=True,
            integrity_valid=True,
            authorization_valid=True,
            tombstones_current=True,
            golden_queries_passed=True,
        )


@dataclass(slots=True)
class _Repository:
    jobs: dict[str, ProjectionRebuild] = field(default_factory=dict[str, ProjectionRebuild])

    async def create(
        self,
        command: StartProjectionRebuildCommand,
        source_watermark: int,
        rebuild_key: Sha256Digest,
        generation_id: Sha256Digest,
    ) -> ProjectionRebuild:
        current = self.jobs.get(command.operation_id)
        if current is not None:
            return current
        job = ProjectionRebuild(
            command.operation_id,
            command.brain_id,
            command.actor_id,
            command.grant_id,
            command.projection_type,
            source_watermark,
            0,
            rebuild_key,
            generation_id,
            command.manifest,
            RebuildState.QUEUED,
            None,
            0,
            0,
            None,
            None,
            NOW,
            NOW,
        )
        self.jobs[command.operation_id] = job
        return job

    async def get(self, operation_id: str) -> ProjectionRebuild | None:
        return self.jobs.get(operation_id)

    async def next_runnable(self) -> str | None:
        return next(iter(self.jobs), None)

    async def claim(self, operation_id: str) -> ProjectionRebuild:
        job = self.jobs[operation_id]
        target = RebuildState.BUILDING
        job.state.require_transition(target)
        return self._save(replace(job, state=target, partial_reason=None))

    async def checkpoint(
        self,
        operation_id: str,
        cursor: int,
        inserted: int,
        skipped_tombstones: int,
    ) -> ProjectionRebuild:
        job = self.jobs[operation_id]
        return self._save(
            replace(
                job,
                cursor=cursor,
                record_count=job.record_count + inserted,
                skipped_tombstones=job.skipped_tombstones + skipped_tombstones,
            )
        )

    async def mark_partial(self, operation_id: str, reason: str) -> ProjectionRebuild:
        job = self.jobs[operation_id]
        return self._save(replace(job, state=RebuildState.PARTIAL, partial_reason=reason))

    async def begin_validation(self, operation_id: str) -> ProjectionRebuild:
        return self._state(operation_id, RebuildState.VALIDATING)

    async def mark_ready(
        self,
        operation_id: str,
        validation: ProjectionValidation,
    ) -> ProjectionRebuild:
        job = self.jobs[operation_id]
        return self._save(
            replace(
                job,
                state=RebuildState.READY,
                generation_digest=validation.generation_digest,
            )
        )

    async def activate(self, operation_id: str) -> ProjectionRebuild:
        return self._state(operation_id, RebuildState.ACTIVE)

    async def fail(self, operation_id: str, reason: str) -> ProjectionRebuild:
        job = self.jobs[operation_id]
        return self._save(replace(job, state=RebuildState.FAILED, partial_reason=reason))

    def _state(self, operation_id: str, target: RebuildState) -> ProjectionRebuild:
        job = self.jobs[operation_id]
        job.state.require_transition(target)
        return self._save(replace(job, state=target))

    def _save(self, job: ProjectionRebuild) -> ProjectionRebuild:
        self.jobs[job.operation_id] = job
        return job


async def _run(
    records: Iterable[SourceRecord],
    access: _Access | None = None,
    repository: _Repository | None = None,
    generations: _Generations | None = None,
    page_size: int = 2,
) -> tuple[ProjectionRebuild, _Repository, _Generations]:
    source = _Source(tuple(records))
    policy = access or _Access()
    jobs = repository or _Repository()
    sink = generations or _Generations()
    await StartProjectionRebuildHandler(source, policy, jobs).execute(_command())
    result = await ProjectionRebuilder(
        source,
        policy,
        sink,
        jobs,
        page_size=page_size,
    ).execute("rebuild-1")
    return result, jobs, sink


@pytest.mark.asyncio
async def test_rebuild_replays_deterministically_and_activates_only_after_validation() -> None:
    result, _, sink = await _run((_record(1), _record(2), _record(3)))
    assert result.state is RebuildState.ACTIVE
    assert result.cursor == 3
    assert result.record_count == 3
    assert result.generation_digest == projection_digest(sink.records.values())


@pytest.mark.asyncio
async def test_tombstoned_source_never_reappears_in_shadow_generation() -> None:
    result, _, sink = await _run((_record(1), _record(2)), _Access(tombstones={"record-2"}))
    assert result.state is RebuildState.ACTIVE
    assert result.skipped_tombstones == 1
    assert set(sink.records) == {"record-1"}


@pytest.mark.asyncio
async def test_missing_dependency_returns_partial_cursor_and_resumes_without_duplicates() -> None:
    source_records = (_record(1), _record(2, missing="artifact_unavailable"))
    source = _Source(source_records)
    access = _Access()
    jobs = _Repository()
    sink = _Generations()
    await StartProjectionRebuildHandler(source, access, jobs).execute(_command())
    first = await ProjectionRebuilder(source, access, sink, jobs).execute("rebuild-1")
    assert first.state is RebuildState.PARTIAL
    assert first.cursor == 1
    assert first.partial_reason == "artifact_unavailable"
    source.records = (_record(1), _record(2))
    resumed = await ProjectionRebuilder(source, access, sink, jobs).execute("rebuild-1")
    assert resumed.state is RebuildState.ACTIVE
    assert resumed.record_count == 2
    assert len(sink.records) == 2


@pytest.mark.asyncio
@pytest.mark.load
async def test_production_profile_replays_ten_thousand_records_with_bounded_pages() -> None:
    records = tuple(_record(sequence) for sequence in range(1, 10_001))
    started = perf_counter()
    result, _, sink = await _run(records, page_size=4096)
    elapsed = perf_counter() - started
    assert result.state is RebuildState.ACTIVE
    assert result.record_count == 10_000
    assert len(sink.records) == 10_000
    assert elapsed < 30


@pytest.mark.asyncio
async def test_start_rejects_watermark_beyond_committed_source() -> None:
    source = _Source((_record(1),))
    with pytest.raises(OperationError) as raised:
        await StartProjectionRebuildHandler(source, _Access(), _Repository()).execute(
            replace(_command(), requested_watermark=2)
        )
    assert raised.value.code is ErrorCode.VALIDATION


@pytest.mark.parametrize("page_size", [0, 4097])
def test_rebuilder_rejects_unbounded_page_sizes(page_size: int) -> None:
    with pytest.raises(ValueError, match="page size"):
        ProjectionRebuilder(_Source(()), _Access(), _Generations(), _Repository(), page_size)


@pytest.mark.asyncio
async def test_rebuilder_rejects_unknown_operation_and_returns_closed_operation() -> None:
    jobs = _Repository()
    rebuilder = ProjectionRebuilder(_Source(()), _Access(), _Generations(), jobs)
    with pytest.raises(OperationError) as raised:
        await rebuilder.execute("missing")
    assert raised.value.code is ErrorCode.VALIDATION

    created = await StartProjectionRebuildHandler(_Source(()), _Access(), jobs).execute(_command())
    jobs.jobs[created.operation_id] = replace(created, state=RebuildState.ACTIVE)
    assert (await rebuilder.execute(created.operation_id)).state is RebuildState.ACTIVE


@dataclass(slots=True)
class _StaticPageSource:
    page: SourcePage
    watermark: int

    async def latest_watermark(self, brain_id: Uuid7Id) -> int:
        del brain_id
        return self.watermark

    async def read_page(
        self,
        brain_id: Uuid7Id,
        projection_type: ProjectionType,
        after_cursor: int,
        watermark: int,
        limit: int,
    ) -> SourcePage:
        del brain_id, projection_type, after_cursor, watermark, limit
        return self.page


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("page", "message"),
    [
        (SourcePage((), 0, complete=False), "did not advance"),
        (SourcePage((), 1, complete=True), "ended before"),
    ],
)
async def test_rebuilder_rejects_invalid_canonical_page_contracts(
    page: SourcePage,
    message: str,
) -> None:
    source = _StaticPageSource(page, 2)
    jobs = _Repository()
    await StartProjectionRebuildHandler(source, _Access(), jobs).execute(_command())
    with pytest.raises(OperationError, match=message) as raised:
        await ProjectionRebuilder(source, _Access(), _Generations(), jobs).execute("rebuild-1")
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION


@pytest.mark.asyncio
async def test_rebuilder_rejects_out_of_order_source_record() -> None:
    source = _StaticPageSource(SourcePage((_record(1),), 2, complete=False), 2)
    jobs = _Repository()
    job = await StartProjectionRebuildHandler(source, _Access(), jobs).execute(_command())
    jobs.jobs[job.operation_id] = replace(job, cursor=1)
    with pytest.raises(OperationError, match="out-of-order"):
        await ProjectionRebuilder(source, _Access(), _Generations(), jobs).execute("rebuild-1")


@pytest.mark.asyncio
@pytest.mark.parametrize("record_count", [0, 2])
async def test_rebuilder_fails_closed_when_validation_gate_or_count_fails(
    record_count: int,
) -> None:
    validation = ProjectionValidation(
        record_count=record_count,
        generation_digest=digest("invalid-generation"),
        lineage_complete=record_count != 0,
        integrity_valid=True,
        authorization_valid=True,
        tombstones_current=True,
        golden_queries_passed=True,
    )
    result, _, _ = await _run(
        (_record(1),),
        generations=_Generations(validation_override=validation),
    )
    assert result.state is RebuildState.FAILED
    assert result.partial_reason == "projection_validation_failed"
