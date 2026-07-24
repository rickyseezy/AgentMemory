"""PRO-008 resumable live migration application orchestration tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, override

import pytest

from agentmemory.providers.adapters.backup_bound_migration_retention import (
    BackupBoundEmbeddingGenerationRetentionGuard,
)
from agentmemory.providers.application.migration import (
    ActivateEmbeddingMigrationCommand,
    ActivateEmbeddingMigrationHandler,
    DeleteExpiredEmbeddingGenerationCommand,
    DeleteExpiredEmbeddingGenerationHandler,
    EmbeddingMigrationWorker,
    PauseEmbeddingMigrationCommand,
    PauseEmbeddingMigrationHandler,
    PlanEmbeddingMigrationByIdCommand,
    PlanEmbeddingMigrationByIdHandler,
    PlanEmbeddingMigrationCommand,
    PlanEmbeddingMigrationHandler,
    ResumeEmbeddingMigrationCommand,
    ResumeEmbeddingMigrationHandler,
    RollbackEmbeddingMigrationCommand,
    RollbackEmbeddingMigrationHandler,
)
from agentmemory.providers.domain.embedding_space_ports import (
    EmbeddingGenerationBinding,
)
from agentmemory.providers.domain.embedding_spaces import IndexGenerationState
from agentmemory.providers.domain.errors import (
    EmbeddingMigrationAuthorizationError,
    EmbeddingMigrationConflictError,
    EmbeddingMigrationDependencyError,
    EmbeddingMigrationValidationError,
)
from agentmemory.providers.domain.migration import (
    EmbeddingGenerationMigration,
    EmbeddingMigrationPolicy,
    EmbeddingMigrationState,
    EmbeddingMigrationValidation,
    MigrationContent,
    MigrationContentPage,
    MigrationProgress,
)
from agentmemory.providers.domain.migration_ports import (
    EmbeddingMigrationActivationRequest,
    EmbeddingMigrationPlan,
    GenerationWriteTarget,
)
from tests.core.support import GRANT_ID, NOW, FixedClock, digest
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro004_sqlite_embedding_spaces import (
    attested_descriptor,
    candidates,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.embedding_spaces import EmbeddingSpace, IndexGeneration

SOURCE_SPACE_ID = "018f0000-0000-7000-8000-000000000501"
TARGET_SPACE_ID = "018f0000-0000-7000-8000-000000000502"
SOURCE_GENERATION_ID = "018f0000-0000-7000-8000-000000000111"
TARGET_GENERATION_ID = "018f0000-0000-7000-8000-000000000112"
MIGRATION_ID = "018f0000-0000-7000-8000-000000000801"


def generation_pair() -> tuple[
    EmbeddingSpace,
    IndexGeneration,
    EmbeddingSpace,
    IndexGeneration,
]:
    source_space, source_generation = candidates(
        digest("source-attestation").value,
        space_id=SOURCE_SPACE_ID,
        generation_id=SOURCE_GENERATION_ID,
    )
    target_space, target_generation = candidates(
        digest("target-attestation").value,
        space_id=TARGET_SPACE_ID,
        generation_id=TARGET_GENERATION_ID,
        space_descriptor=attested_descriptor(
            model_revision="2026-08-01",
            inference_settings_digest=digest("target-inference").value,
        ),
    )
    return (
        source_space,
        replace(source_generation, state=IndexGenerationState.ACTIVE),
        target_space,
        replace(target_generation, state=IndexGenerationState.POPULATING),
    )


@dataclass
class _Identities:
    def new(self) -> str:
        return MIGRATION_ID


@dataclass
class _Bindings:
    values: dict[str, EmbeddingGenerationBinding]

    async def get_binding(
        self,
        scope: AuthorizedScope,
        generation_id: str,
        at: datetime,
    ) -> EmbeddingGenerationBinding | None:
        del scope, at
        return self.values.get(generation_id)


@dataclass
class _Source:
    latest_values: list[int] = field(default_factory=lambda: [100, 105])
    pages: list[tuple[int, int]] = field(default_factory=list[tuple[int, int]])

    async def latest_watermark(self, brain_id: str) -> int:
        del brain_id
        return self.latest_values.pop(0) if len(self.latest_values) > 1 else self.latest_values[0]

    async def read_page(
        self,
        brain_id: str,
        after_sequence: int,
        through_sequence: int,
        limit: int,
    ) -> MigrationContentPage:
        del brain_id
        self.pages.append((after_sequence, through_sequence))
        end = min(after_sequence + limit, through_sequence)
        records = tuple(
            MigrationContent(
                sequence=sequence,
                source_entity_id="018f0000-0000-7000-8000-000000000901",
                source_content_hash=digest(f"content-{sequence}").value,
                content_ref=f"cas://canonical/{sequence}",
                classification="internal",
            )
            for sequence in range(after_sequence + 1, end + 1)
        )
        return MigrationContentPage(
            records,
            next_cursor=end,
            complete=end == through_sequence,
        )


@dataclass
class _Target:
    prepared: list[str] = field(default_factory=list[str])
    writes: list[tuple[int, ...]] = field(default_factory=list[tuple[int, ...]])
    fail_after_write: int | None = None

    async def prepare(self, migration: EmbeddingGenerationMigration) -> None:
        self.prepared.append(migration.target_generation_id)

    async def write(
        self,
        migration: EmbeddingGenerationMigration,
        records: tuple[MigrationContent, ...],
    ) -> None:
        del migration
        if self.fail_after_write is not None and len(self.writes) == self.fail_after_write:
            message = "simulated target outage"
            raise RuntimeError(message)
        self.writes.append(tuple(record.sequence for record in records))


def _validation(**changes: object) -> EmbeddingMigrationValidation:
    values: dict[str, object] = {
        "canonical_count": 105,
        "target_count": 105,
        "covered_count": 105,
        "missing_count": 0,
        "stale_count": 0,
        "duplicate_count": 0,
        "privacy_violation_count": 0,
        "quality_score_micros": 950_000,
        "baseline_quality_score_micros": 940_000,
        "p95_latency_microseconds": 100_000,
        "baseline_p95_latency_microseconds": 100_000,
        "shadow_sample_count": 100,
        "shadow_mismatch_count": 0,
        "evidence_digest": digest("validation-evidence").value,
    }
    values.update(changes)
    return EmbeddingMigrationValidation(**values)  # type: ignore[arg-type]


@dataclass
class _Inspector:
    structural: bool = True
    result: EmbeddingMigrationValidation = field(default_factory=_validation)

    async def structurally_valid(self, migration: EmbeddingGenerationMigration) -> bool:
        del migration
        return self.structural

    async def validate(
        self,
        migration: EmbeddingGenerationMigration,
    ) -> EmbeddingMigrationValidation:
        del migration
        return self.result


@dataclass
class _Repository:
    current: EmbeddingGenerationMigration | None = None
    targets: tuple[GenerationWriteTarget, ...] = ()
    source_retired: bool = False
    source_deleted: bool = False
    active_generation_id: str = SOURCE_GENERATION_ID

    async def create(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        plan: EmbeddingMigrationPlan,
    ) -> EmbeddingGenerationMigration:
        del scope, operation_id, request_digest
        if self.current is None:
            self.current = plan.migration
        return self.current

    async def get(
        self,
        scope: AuthorizedScope,
        migration_id: str,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration | None:
        del scope, at_microseconds
        return self.current if self.current is not None and migration_id == MIGRATION_ID else None

    async def advance(
        self,
        current: EmbeddingGenerationMigration,
        target: EmbeddingMigrationState,
        at_microseconds: int,
        *,
        progress: MigrationProgress | None = None,
        validation_digest: str | None = None,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        self.current = current.transition(
            target,
            at_microseconds=at_microseconds,
            progress=progress,
            validation_digest=validation_digest,
        )
        if target is EmbeddingMigrationState.FAILED and self.targets:
            self.targets = (self.targets[0],)
        return self.current

    async def checkpoint(
        self,
        current: EmbeddingGenerationMigration,
        progress: MigrationProgress,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        self.current = replace(
            current,
            progress=progress,
            version=current.version + 1,
            updated_at_microseconds=at_microseconds,
        )
        return self.current

    async def resume(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        self.current = current.resume(at_microseconds=at_microseconds)
        return self.current

    async def begin_dual_write(
        self,
        current: EmbeddingGenerationMigration,
        catchup_watermark: int,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        progress = MigrationProgress(
            current.source_watermark,
            catchup_watermark,
            current.source_watermark,
        )
        self.current = current.transition(
            EmbeddingMigrationState.CATCHING_UP,
            at_microseconds=at_microseconds,
            progress=progress,
        )
        self.targets = (
            GenerationWriteTarget(
                current.source_space_id,
                current.source_space_fingerprint,
                current.source_generation_id,
            ),
            GenerationWriteTarget(
                current.target_space_id,
                current.target_space_fingerprint,
                current.target_generation_id,
            ),
        )
        return self.current

    async def activate(
        self,
        current: EmbeddingGenerationMigration,
        request: EmbeddingMigrationActivationRequest,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        if current.state is EmbeddingMigrationState.ACTIVE:
            return current
        assert current.version == request.expected_version
        self.current = current.activate(
            at_microseconds=request.at_microseconds,
            rollback_until_microseconds=request.rollback_until_microseconds,
        )
        self.targets = (
            GenerationWriteTarget(
                current.target_space_id,
                current.target_space_fingerprint,
                current.target_generation_id,
            ),
        )
        self.active_generation_id = current.target_generation_id
        return self.current

    async def rollback(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        self.current = current.transition(
            EmbeddingMigrationState.ROLLED_BACK,
            at_microseconds=at_microseconds,
        )
        self.targets = (
            GenerationWriteTarget(
                current.source_space_id,
                current.source_space_fingerprint,
                current.source_generation_id,
            ),
        )
        self.active_generation_id = current.source_generation_id
        return self.current

    async def retire_source(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        self.source_retired = True
        self.current = replace(
            current,
            source_retired_at_microseconds=at_microseconds,
            version=current.version + 1,
            updated_at_microseconds=at_microseconds,
        )
        return self.current

    async def complete_source_deletion(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        self._current(current)
        self.source_deleted = True
        self.current = replace(
            current,
            source_deleted_at_microseconds=at_microseconds,
            version=current.version + 1,
            updated_at_microseconds=at_microseconds,
        )
        return self.current

    async def write_targets(
        self,
        brain_id: str,
        source_space_id: str,
    ) -> tuple[GenerationWriteTarget, ...]:
        del brain_id, source_space_id
        return self.targets

    async def active_target(
        self,
        brain_id: str,
        purpose: str,
    ) -> GenerationWriteTarget | None:
        del brain_id, purpose
        return self.targets[0] if self.targets else None

    def _current(self, candidate: EmbeddingGenerationMigration) -> None:
        if self.current != candidate:
            message = "stale migration"
            raise EmbeddingMigrationConflictError(message)


@dataclass
class _ScriptedGetRepository(_Repository):
    scripted_gets: list[EmbeddingGenerationMigration | None] = field(
        default_factory=list[EmbeddingGenerationMigration | None]
    )

    @override
    async def get(
        self,
        scope: AuthorizedScope,
        migration_id: str,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration | None:
        if self.scripted_gets:
            return self.scripted_gets.pop(0)
        return await super().get(scope, migration_id, at_microseconds)


@dataclass
class _Cleaner:
    deleted: list[str] = field(default_factory=list[str])

    async def delete(self, generation_id: str) -> None:
        self.deleted.append(generation_id)


@dataclass
class _Retention:
    checked: list[str] = field(default_factory=list[str])

    async def require_source_deletion(
        self,
        scope: AuthorizedScope,
        migration: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> None:
        del scope, at_microseconds
        self.checked.append(migration.source_generation_id)


def _plan_command(
    *,
    authorized_scope: AuthorizedScope | None = None,
) -> PlanEmbeddingMigrationCommand:
    source_space, source_generation, target_space, target_generation = generation_pair()
    return PlanEmbeddingMigrationCommand(
        operation_id="pro008-plan",
        scope=authorized_scope or scope("provider.embedding_migration.plan"),
        source_space=source_space,
        source_generation=source_generation,
        target_space=target_space,
        target_generation=target_generation,
        requested_at=NOW,
    )


@pytest.mark.asyncio
async def test_public_planner_resolves_canonical_generation_bindings() -> None:
    source_space, source_generation, target_space, target_generation = generation_pair()
    source = _Source()
    repository = _Repository()
    bindings = _Bindings(
        {
            SOURCE_GENERATION_ID: EmbeddingGenerationBinding(
                source_space,
                source_generation,
            ),
            TARGET_GENERATION_ID: EmbeddingGenerationBinding(
                target_space,
                target_generation,
            ),
        }
    )
    handler = PlanEmbeddingMigrationByIdHandler(
        bindings,
        PlanEmbeddingMigrationHandler(source, repository, _Identities()),
    )
    planned = await handler.execute(
        PlanEmbeddingMigrationByIdCommand(
            operation_id="pro008-plan-by-id",
            scope=scope("provider.embedding_migration.plan"),
            source_generation_id=SOURCE_GENERATION_ID,
            target_generation_id=TARGET_GENERATION_ID,
            requested_at=NOW,
        )
    )
    assert planned.source_generation_id == SOURCE_GENERATION_ID
    assert planned.target_generation_id == TARGET_GENERATION_ID

    bindings.values.pop(TARGET_GENERATION_ID)
    with pytest.raises(EmbeddingMigrationConflictError, match="not found"):
        await handler.execute(
            PlanEmbeddingMigrationByIdCommand(
                operation_id="pro008-plan-missing",
                scope=scope("provider.embedding_migration.plan"),
                source_generation_id=SOURCE_GENERATION_ID,
                target_generation_id=TARGET_GENERATION_ID,
                requested_at=NOW,
            )
        )


@pytest.mark.asyncio
async def test_worker_rebuilds_from_canonical_content_and_stops_ready_before_cutover() -> None:
    repository = _Repository()
    source = _Source()
    target = _Target()
    command = _plan_command()
    planned = await PlanEmbeddingMigrationHandler(
        source,
        repository,
        _Identities(),
    ).execute(command)
    assert planned.source_watermark == 100

    ready = await EmbeddingMigrationWorker(
        source,
        target,
        _Inspector(),
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
        page_size=25,
    ).execute(scope("provider.embedding_migration.run"), MIGRATION_ID)

    assert ready.state is EmbeddingMigrationState.READY
    assert target.prepared == [TARGET_GENERATION_ID]
    assert target.writes == [
        tuple(range(1, 26)),
        tuple(range(26, 51)),
        tuple(range(51, 76)),
        tuple(range(76, 101)),
        tuple(range(101, 106)),
    ]
    assert [target.generation_id for target in repository.targets] == [
        SOURCE_GENERATION_ID,
        TARGET_GENERATION_ID,
    ]
    assert ready.validation_digest == _validation().digest
    assert ready.rollback_until_microseconds is None

    active = await ActivateEmbeddingMigrationHandler(
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(
        ActivateEmbeddingMigrationCommand(
            "pro008-activate",
            scope("provider.embedding_migration.activate"),
            MIGRATION_ID,
            GRANT_ID,
            ready.version,
        )
    )
    assert active.state is EmbeddingMigrationState.ACTIVE
    assert repository.targets[0].generation_id == TARGET_GENERATION_ID
    assert active.rollback_until_microseconds is not None
    replayed = await ActivateEmbeddingMigrationHandler(
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(
        ActivateEmbeddingMigrationCommand(
            "pro008-activate-replay",
            scope("provider.embedding_migration.activate"),
            MIGRATION_ID,
            GRANT_ID,
            1,
        )
    )
    assert replayed == active


def test_commands_and_worker_reject_invalid_bounded_inputs() -> None:
    with pytest.raises(EmbeddingMigrationValidationError, match="invalid"):
        replace(_plan_command(), operation_id="invalid operation")
    with pytest.raises(EmbeddingMigrationValidationError, match="invalid"):
        ActivateEmbeddingMigrationCommand(
            "pro008-activate",
            scope("provider.embedding_migration.activate"),
            MIGRATION_ID,
            GRANT_ID,
            0,
        )
    with pytest.raises(EmbeddingMigrationValidationError, match="invalid"):
        EmbeddingMigrationWorker(
            _Source(),
            _Target(),
            _Inspector(),
            _Repository(),
            FixedClock(NOW),
            EmbeddingMigrationPolicy.production(),
            page_size=0,
        )


@pytest.mark.asyncio
async def test_worker_fails_closed_when_canonical_state_disappears_or_changes() -> None:
    missing = _Repository()
    worker = EmbeddingMigrationWorker(
        _Source(),
        _Target(),
        _Inspector(),
        missing,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    )
    with pytest.raises(EmbeddingMigrationConflictError, match="not found"):
        await worker.execute(scope("provider.embedding_migration.run"), MIGRATION_ID)

    vanished = _ScriptedGetRepository()
    planned = await PlanEmbeddingMigrationHandler(
        _Source(),
        vanished,
        _Identities(),
    ).execute(_plan_command())
    vanished.scripted_gets = [planned, None]
    with pytest.raises(EmbeddingMigrationConflictError, match="not found"):
        await EmbeddingMigrationWorker(
            _Source(),
            _Target(),
            _Inspector(),
            vanished,
            FixedClock(NOW),
            EmbeddingMigrationPolicy.production(),
        ).execute(scope("provider.embedding_migration.run"), MIGRATION_ID)

    stopped = _ScriptedGetRepository()
    planned = await PlanEmbeddingMigrationHandler(
        _Source(),
        stopped,
        _Identities(),
    ).execute(_plan_command())
    ready = replace(
        planned,
        state=EmbeddingMigrationState.READY,
        progress=MigrationProgress(100, 100, 100),
        validation_digest=digest("ready").value,
    )
    stopped.scripted_gets = [planned, ready]
    result = await EmbeddingMigrationWorker(
        _Source(),
        _Target(),
        _Inspector(),
        stopped,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(scope("provider.embedding_migration.run"), MIGRATION_ID)
    assert result == ready


@pytest.mark.asyncio
async def test_worker_rejects_unroutable_state_regressed_watermark_and_cursor() -> None:
    repository = _Repository()
    planned = await PlanEmbeddingMigrationHandler(
        _Source(),
        repository,
        _Identities(),
    ).execute(_plan_command())
    worker = EmbeddingMigrationWorker(
        _Source(latest_values=[99]),
        _Target(),
        _Inspector(),
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    )
    paused = planned.transition(
        EmbeddingMigrationState.PAUSED,
        at_microseconds=planned.updated_at_microseconds,
    )
    with pytest.raises(EmbeddingMigrationConflictError, match="validation"):
        await worker._step(paused)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(EmbeddingMigrationConflictError, match="cursor"):
        await worker._begin_dual_write(  # pyright: ignore[reportPrivateUsage]
            planned
        )

    class _InvalidCursorSource(_Source):
        @override
        async def read_page(
            self,
            brain_id: str,
            after_sequence: int,
            through_sequence: int,
            limit: int,
        ) -> MigrationContentPage:
            del brain_id, after_sequence, through_sequence, limit
            return MigrationContentPage((), next_cursor=0, complete=True)

    cursor_worker = EmbeddingMigrationWorker(
        _InvalidCursorSource(),
        _Target(),
        _Inspector(),
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    )
    with pytest.raises(EmbeddingMigrationConflictError, match="cursor"):
        await cursor_worker._replay(  # pyright: ignore[reportPrivateUsage]
            planned,
            through=100,
            catchup=False,
        )


@pytest.mark.asyncio
async def test_worker_resumes_from_last_committed_cursor_after_target_failure() -> None:
    repository = _Repository()
    source = _Source()
    target = _Target(fail_after_write=1)
    await PlanEmbeddingMigrationHandler(source, repository, _Identities()).execute(_plan_command())
    worker = EmbeddingMigrationWorker(
        source,
        target,
        _Inspector(),
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
        page_size=50,
    )
    with pytest.raises(RuntimeError, match="simulated target outage"):
        await worker.execute(scope("provider.embedding_migration.run"), MIGRATION_ID)
    assert repository.current is not None
    assert repository.current.progress.backfill_cursor == 50

    target.fail_after_write = None
    ready = await worker.execute(scope("provider.embedding_migration.run"), MIGRATION_ID)
    assert ready.state is EmbeddingMigrationState.READY
    assert target.writes.count(tuple(range(1, 51))) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "inspector",
    [
        _Inspector(structural=False),
        _Inspector(result=_validation(privacy_violation_count=1)),
        _Inspector(result=_validation(quality_score_micros=899_999)),
        _Inspector(result=_validation(p95_latency_microseconds=125_001)),
        _Inspector(result=_validation(covered_count=104, target_count=104)),
    ],
)
async def test_every_validation_regression_fails_without_cutover(
    inspector: _Inspector,
) -> None:
    repository = _Repository()
    source = _Source()
    await PlanEmbeddingMigrationHandler(source, repository, _Identities()).execute(_plan_command())
    failed = await EmbeddingMigrationWorker(
        source,
        _Target(),
        inspector,
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(scope("provider.embedding_migration.run"), MIGRATION_ID)
    assert failed.state is EmbeddingMigrationState.FAILED
    assert repository.active_generation_id == SOURCE_GENERATION_ID
    assert [target.generation_id for target in repository.targets] == [SOURCE_GENERATION_ID]


@pytest.mark.asyncio
async def test_rollback_is_window_bounded_and_deletion_requires_expiry() -> None:
    repository = _Repository()
    source = _Source()
    await PlanEmbeddingMigrationHandler(source, repository, _Identities()).execute(_plan_command())
    ready = await EmbeddingMigrationWorker(
        source,
        _Target(),
        _Inspector(),
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(scope("provider.embedding_migration.run"), MIGRATION_ID)
    assert ready.state is EmbeddingMigrationState.READY
    active = await ActivateEmbeddingMigrationHandler(
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(
        ActivateEmbeddingMigrationCommand(
            "pro008-delete-activate",
            scope("provider.embedding_migration.activate"),
            MIGRATION_ID,
            GRANT_ID,
            ready.version,
        )
    )
    assert active.state is EmbeddingMigrationState.ACTIVE

    with pytest.raises(EmbeddingMigrationConflictError, match="rollback window"):
        await RollbackEmbeddingMigrationHandler(
            repository,
            FixedClock(NOW + timedelta(days=36)),
        ).execute(
            RollbackEmbeddingMigrationCommand(
                scope("provider.embedding_migration.rollback"),
                MIGRATION_ID,
            )
        )
    rolled_back = await RollbackEmbeddingMigrationHandler(
        repository,
        FixedClock(NOW + timedelta(days=1)),
    ).execute(
        RollbackEmbeddingMigrationCommand(
            scope("provider.embedding_migration.rollback"),
            MIGRATION_ID,
        )
    )
    assert rolled_back.state is EmbeddingMigrationState.ROLLED_BACK
    assert repository.targets[0].generation_id == SOURCE_GENERATION_ID

    repository.current = active
    cleaner = _Cleaner()
    retention = _Retention()
    with pytest.raises(EmbeddingMigrationConflictError, match="rollback window"):
        await DeleteExpiredEmbeddingGenerationHandler(
            repository,
            retention,
            cleaner,
            FixedClock(NOW + timedelta(days=34)),
        ).execute(
            DeleteExpiredEmbeddingGenerationCommand(
                scope("provider.embedding_migration.delete"),
                MIGRATION_ID,
            )
        )
    with pytest.raises(EmbeddingMigrationDependencyError, match="backup anchor"):
        await DeleteExpiredEmbeddingGenerationHandler(
            repository,
            BackupBoundEmbeddingGenerationRetentionGuard(),
            cleaner,
            FixedClock(NOW + timedelta(days=36)),
        ).execute(
            DeleteExpiredEmbeddingGenerationCommand(
                scope("provider.embedding_migration.delete"),
                MIGRATION_ID,
            )
        )
    assert [repository.source_retired, repository.source_deleted] == [False, False]
    assert cleaner.deleted == []
    await DeleteExpiredEmbeddingGenerationHandler(
        repository,
        retention,
        cleaner,
        FixedClock(NOW + timedelta(days=36)),
    ).execute(
        DeleteExpiredEmbeddingGenerationCommand(
            scope("provider.embedding_migration.delete"),
            MIGRATION_ID,
        )
    )
    assert repository.source_retired
    assert repository.source_deleted
    assert retention.checked == [SOURCE_GENERATION_ID]
    assert cleaner.deleted == [SOURCE_GENERATION_ID]


@pytest.mark.asyncio
async def test_every_handler_rejects_wrong_action_before_ports() -> None:
    repository = _Repository()
    source = _Source()
    with pytest.raises(EmbeddingMigrationAuthorizationError, match="not authorized"):
        await PlanEmbeddingMigrationHandler(source, repository, _Identities()).execute(
            _plan_command(authorized_scope=scope("wrong.action"))
        )
    assert repository.current is None


@pytest.mark.asyncio
async def test_pause_resume_is_version_checked_and_worker_respects_pause() -> None:
    repository = _Repository()
    source = _Source()
    planned = await PlanEmbeddingMigrationHandler(
        source,
        repository,
        _Identities(),
    ).execute(_plan_command())
    building = await repository.advance(
        planned,
        EmbeddingMigrationState.BUILDING,
        planned.updated_at_microseconds,
    )
    paused = await PauseEmbeddingMigrationHandler(
        repository,
        FixedClock(NOW),
    ).execute(
        PauseEmbeddingMigrationCommand(
            scope("provider.embedding_migration.pause"),
            MIGRATION_ID,
            building.version,
        )
    )
    assert paused.state is EmbeddingMigrationState.PAUSED
    assert paused.resume_state is EmbeddingMigrationState.BUILDING
    assert (
        await PauseEmbeddingMigrationHandler(repository, FixedClock(NOW)).execute(
            PauseEmbeddingMigrationCommand(
                scope("provider.embedding_migration.pause"),
                MIGRATION_ID,
                paused.version,
            )
        )
        == paused
    )

    target = _Target()
    unchanged = await EmbeddingMigrationWorker(
        source,
        target,
        _Inspector(),
        repository,
        FixedClock(NOW),
        EmbeddingMigrationPolicy.production(),
    ).execute(scope("provider.embedding_migration.run"), MIGRATION_ID)
    assert unchanged == paused
    assert target.prepared == []

    with pytest.raises(EmbeddingMigrationConflictError, match="version"):
        await ResumeEmbeddingMigrationHandler(repository, FixedClock(NOW)).execute(
            ResumeEmbeddingMigrationCommand(
                scope("provider.embedding_migration.resume"),
                MIGRATION_ID,
                paused.version - 1,
            )
        )
    resumed = await ResumeEmbeddingMigrationHandler(
        repository,
        FixedClock(NOW),
    ).execute(
        ResumeEmbeddingMigrationCommand(
            scope("provider.embedding_migration.resume"),
            MIGRATION_ID,
            paused.version,
        )
    )
    assert resumed.state is EmbeddingMigrationState.BUILDING
    assert resumed.resume_state is None


@pytest.mark.asyncio
async def test_state_changing_handlers_return_not_found_without_mutation() -> None:
    repository = _Repository()
    with pytest.raises(EmbeddingMigrationConflictError, match="not found"):
        await PauseEmbeddingMigrationHandler(repository, FixedClock(NOW)).execute(
            PauseEmbeddingMigrationCommand(
                scope("provider.embedding_migration.pause"),
                MIGRATION_ID,
                1,
            )
        )
    with pytest.raises(EmbeddingMigrationConflictError, match="not found"):
        await RollbackEmbeddingMigrationHandler(repository, FixedClock(NOW)).execute(
            RollbackEmbeddingMigrationCommand(
                scope("provider.embedding_migration.rollback"),
                MIGRATION_ID,
            )
        )
    with pytest.raises(EmbeddingMigrationConflictError, match="not found"):
        await DeleteExpiredEmbeddingGenerationHandler(
            repository,
            _Retention(),
            _Cleaner(),
            FixedClock(NOW),
        ).execute(
            DeleteExpiredEmbeddingGenerationCommand(
                scope("provider.embedding_migration.delete"),
                MIGRATION_ID,
            )
        )
