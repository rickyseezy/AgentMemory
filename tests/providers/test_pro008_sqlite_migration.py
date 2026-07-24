"""PRO-008 canonical SQLite migration, cutover, rollback, and deletion tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.providers.adapters import sqlite_embedding_spaces
from agentmemory.providers.adapters.sqlite_embedding_spaces import (
    SqliteEmbeddingSpaceRepository,
)
from agentmemory.providers.adapters.sqlite_migration import (
    SqliteEmbeddingMigrationRepository,
)
from agentmemory.providers.domain.embedding_space_ports import (
    EmbeddingGenerationBinding,
)
from agentmemory.providers.domain.embedding_spaces import IndexGenerationState
from agentmemory.providers.domain.errors import (
    EmbeddingMigrationConflictError,
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceValidationError,
)
from agentmemory.providers.domain.migration import (
    EmbeddingGenerationMigration,
    EmbeddingMigrationState,
    MigrationProgress,
    migration_request_digest,
)
from agentmemory.providers.domain.migration_ports import (
    EmbeddingMigrationActivationRequest,
    EmbeddingMigrationPlan,
)
from tests.core.support import GRANT_ID, NOW, digest, migrated_store
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro004_sqlite_embedding_spaces import (
    attested_descriptor,
    candidates,
    seed_active_provider,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.embedding_spaces import EmbeddingSpace, IndexGeneration

SOURCE_SPACE_ID = "018f0000-0000-7000-8000-000000000511"
TARGET_SPACE_ID = "018f0000-0000-7000-8000-000000000512"
SOURCE_GENERATION_ID = "018f0000-0000-7000-8000-000000000121"
TARGET_GENERATION_ID = "018f0000-0000-7000-8000-000000000122"
MIGRATION_ID = "018f0000-0000-7000-8000-000000000811"


async def _seed_generations(
    store: SqliteCoreStore,
) -> tuple[EmbeddingSpace, IndexGeneration, EmbeddingSpace, IndexGeneration]:
    attestation_id = await seed_active_provider(store)
    source_space, source_generation = candidates(
        attestation_id,
        space_id=SOURCE_SPACE_ID,
        generation_id=SOURCE_GENERATION_ID,
    )
    target_space, target_generation = candidates(
        attestation_id,
        space_id=TARGET_SPACE_ID,
        generation_id=TARGET_GENERATION_ID,
        space_descriptor=attested_descriptor(preprocessing_version="agentmemory-preprocess-v2"),
    )
    spaces = SqliteEmbeddingSpaceRepository(store)
    for ordinal, (embedding_space, generation) in enumerate(
        (
            (source_space, source_generation),
            (target_space, target_generation),
        ),
        start=1,
    ):
        operation_id = f"pro008-space-{ordinal}"
        await spaces.reserve(
            scope("provider.embedding_space.ensure"),
            operation_id,
            digest(f"space-request-{ordinal}").value,
            embedding_space,
            generation,
        )
        await spaces.complete(
            scope("provider.embedding_space.ensure"),
            operation_id,
            generation.generation_id,
            NOW + timedelta(seconds=3 + ordinal),
        )
    async with store.engine.begin() as connection:
        for state in (
            IndexGenerationState.VALIDATING,
            IndexGenerationState.SHADOW_READY,
            IndexGenerationState.ACTIVE,
        ):
            await connection.execute(
                text(
                    "UPDATE embedding_index_generations SET state=:state,"
                    "updated_at=updated_at+1,version=version+1 WHERE id=:generation"
                ),
                {"generation": SOURCE_GENERATION_ID, "state": state.value},
            )
    return (
        source_space,
        replace(source_generation, state=IndexGenerationState.ACTIVE),
        target_space,
        replace(target_generation, state=IndexGenerationState.POPULATING),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_generation_binding_fails_closed_when_space_authority_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed_generations(store)

        async def missing_space(*args: object) -> None:
            del args

        monkeypatch.setattr(
            sqlite_embedding_spaces,
            "_space_by_id",
            missing_space,
        )
        with pytest.raises(EmbeddingSpaceConflictError, match="integrity"):
            await SqliteEmbeddingSpaceRepository(store).get_binding(
                scope("provider.embedding_migration.plan"),
                SOURCE_GENERATION_ID,
                NOW + timedelta(seconds=10),
            )
    finally:
        await store.close()


def _candidate(
    source_space: EmbeddingSpace,
    source_generation: IndexGeneration,
    target_space: EmbeddingSpace,
    target_generation: IndexGeneration,
) -> tuple[EmbeddingGenerationMigration, EmbeddingMigrationPlan, str]:
    created = round((NOW + timedelta(seconds=10)).timestamp() * 1_000_000)
    migration = EmbeddingGenerationMigration(
        migration_id=MIGRATION_ID,
        brain_id=source_generation.brain_id,
        source_space_id=source_space.space_id,
        source_space_fingerprint=source_space.immutable_fingerprint,
        source_generation_id=source_generation.generation_id,
        target_space_id=target_space.space_id,
        target_space_fingerprint=target_space.immutable_fingerprint,
        target_generation_id=target_generation.generation_id,
        source_watermark=100,
        progress=MigrationProgress(0, 100, 100),
        state=EmbeddingMigrationState.PLANNED,
        validation_digest=None,
        rollback_until_microseconds=None,
        source_retired_at_microseconds=None,
        source_deleted_at_microseconds=None,
        resume_state=None,
        version=1,
        created_at_microseconds=created,
        updated_at_microseconds=created,
    )
    plan = EmbeddingMigrationPlan(
        migration,
        source_space,
        source_generation,
        target_space,
        target_generation,
    )
    request_digest = migration_request_digest(
        brain_id=migration.brain_id,
        source_space_id=migration.source_space_id,
        source_generation_id=migration.source_generation_id,
        target_space_id=migration.target_space_id,
        target_generation_id=migration.target_generation_id,
        source_watermark=migration.source_watermark,
    )
    return migration, plan, request_digest


async def _ready_migration(
    repository: SqliteEmbeddingMigrationRepository,
    migration: EmbeddingGenerationMigration,
) -> EmbeddingGenerationMigration:
    at = migration.updated_at_microseconds
    current = await repository.advance(
        migration,
        EmbeddingMigrationState.BUILDING,
        at + 1,
    )
    current = await repository.advance(
        current,
        EmbeddingMigrationState.BACKFILLING,
        at + 2,
    )
    current = await repository.checkpoint(
        current,
        MigrationProgress(100, 100, 100),
        at + 3,
    )
    current = await repository.advance(
        current,
        EmbeddingMigrationState.DUAL_WRITE,
        at + 4,
    )
    current = await repository.begin_dual_write(current, 105, at + 5)
    current = await repository.checkpoint(
        current,
        MigrationProgress(100, 105, 105),
        at + 6,
    )
    current = await repository.advance(
        current,
        EmbeddingMigrationState.VALIDATING,
        at + 7,
    )
    current = await repository.advance(
        current,
        EmbeddingMigrationState.SHADOWING,
        at + 8,
    )
    return await repository.advance(
        current,
        EmbeddingMigrationState.READY,
        at + 9,
        validation_digest=digest("validated-shadow").value,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_migration_is_resumable_dual_writes_and_atomically_cuts_over(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingMigrationRepository(store)
    try:
        bindings = await _seed_generations(store)
        migration, plan, request_digest = _candidate(*bindings)
        source_binding = await SqliteEmbeddingSpaceRepository(store).get_binding(
            scope("provider.embedding_migration.plan"),
            SOURCE_GENERATION_ID,
            NOW + timedelta(seconds=10),
        )
        assert source_binding is not None
        assert source_binding.space.space_id == SOURCE_SPACE_ID
        assert (
            await SqliteEmbeddingSpaceRepository(store).get_binding(
                scope("provider.embedding_migration.plan"),
                "018f0000-0000-7000-8000-000000000999",
                NOW + timedelta(seconds=10),
            )
            is None
        )
        with pytest.raises(EmbeddingSpaceValidationError):
            EmbeddingGenerationBinding(plan.target_space, plan.source_generation)
        with pytest.raises(EmbeddingSpaceAuthorizationError):
            await SqliteEmbeddingSpaceRepository(store).get_binding(
                scope("provider.profile.read"),
                SOURCE_GENERATION_ID,
                NOW + timedelta(seconds=10),
            )
        authorized = scope("provider.embedding_migration.plan")
        assert (
            await repository.create(
                authorized,
                "pro008-plan",
                request_digest,
                plan,
            )
            == migration
        )
        assert (
            await repository.create(
                authorized,
                "pro008-plan",
                request_digest,
                plan,
            )
            == migration
        )
        assert (
            await repository.get(
                scope("provider.embedding_migration.read"),
                MIGRATION_ID,
                migration.created_at_microseconds,
            )
            == migration
        )

        ready = await _ready_migration(repository, migration)
        dual_targets = await repository.write_targets(
            ready.brain_id,
            ready.source_space_id,
        )
        assert [target.generation_id for target in dual_targets] == [
            SOURCE_GENERATION_ID,
            TARGET_GENERATION_ID,
        ]
        assert (
            await repository.active_target(
                ready.brain_id,
                "retrieval_document",
            )
        ) == dual_targets[0]
        activation = EmbeddingMigrationActivationRequest(
            scope("provider.embedding_migration.activate"),
            "pro008-activate",
            GRANT_ID,
            ready.version,
            ready.updated_at_microseconds + 1,
            ready.updated_at_microseconds + 1_000,
        )
        active = await repository.activate(
            ready,
            activation,
        )
        assert await repository.activate(active, activation) == active
        with pytest.raises(EmbeddingMigrationConflictError):
            await repository.activate(
                active,
                replace(activation, operation_id="different-activation"),
            )
        assert active.state is EmbeddingMigrationState.ACTIVE
        assert [
            target.generation_id
            for target in await repository.write_targets(
                active.brain_id,
                active.source_space_id,
            )
        ] == [TARGET_GENERATION_ID]
        active_target = await repository.active_target(
            active.brain_id,
            "retrieval_document",
        )
        assert active_target is not None
        assert active_target.generation_id == TARGET_GENERATION_ID

        async with store.engine.connect() as connection:
            pointer = (
                await connection.execute(
                    text("SELECT generation_id,version FROM active_embedding_generations")
                )
            ).one()
            states = {
                str(row[0]): str(row[1])
                for row in (
                    await connection.execute(
                        text(
                            "SELECT id,state FROM embedding_index_generations "
                            "WHERE id IN (:source,:target)"
                        ),
                        {
                            "source": SOURCE_GENERATION_ID,
                            "target": TARGET_GENERATION_ID,
                        },
                    )
                ).all()
            }
            evidence_count = (
                await connection.execute(text("SELECT COUNT(*) FROM embedding_migration_evidence"))
            ).scalar_one()
            activation_count = (
                await connection.execute(
                    text("SELECT COUNT(*) FROM embedding_migration_activations")
                )
            ).scalar_one()
        assert tuple(pointer) == (TARGET_GENERATION_ID, 2)
        assert states == {
            SOURCE_GENERATION_ID: IndexGenerationState.ROLLBACK_READY.value,
            TARGET_GENERATION_ID: IndexGenerationState.ACTIVE.value,
        }
        assert int(evidence_count) == active.version
        assert int(activation_count) == 1

        rolled_back = await repository.rollback(
            active,
            active.updated_at_microseconds + 1,
        )
        assert rolled_back.state is EmbeddingMigrationState.ROLLED_BACK
        assert [
            target.generation_id
            for target in await repository.write_targets(
                active.brain_id,
                active.source_space_id,
            )
        ] == [SOURCE_GENERATION_ID]
        restored = await repository.active_target(
            rolled_back.brain_id,
            "retrieval_document",
        )
        assert restored is not None
        assert restored.generation_id == SOURCE_GENERATION_ID
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_expired_source_retirement_and_deletion_receipt_are_resumable(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingMigrationRepository(store)
    try:
        bindings = await _seed_generations(store)
        migration, plan, request_digest = _candidate(*bindings)
        await repository.create(
            scope("provider.embedding_migration.plan"),
            "pro008-delete-plan",
            request_digest,
            plan,
        )
        ready = await _ready_migration(repository, migration)
        active = await repository.activate(
            ready,
            EmbeddingMigrationActivationRequest(
                scope("provider.embedding_migration.activate"),
                "pro008-delete-activate",
                GRANT_ID,
                ready.version,
                ready.updated_at_microseconds + 1,
                ready.updated_at_microseconds + 100,
            ),
        )
        with pytest.raises(EmbeddingMigrationConflictError):
            await repository.retire_source(active, active.updated_at_microseconds + 50)
        retired = await repository.retire_source(
            active,
            active.rollback_until_microseconds or 0,
        )
        assert retired.source_retired_at_microseconds is not None
        completed = await repository.complete_source_deletion(
            retired,
            retired.updated_at_microseconds + 1,
        )
        assert completed.source_deleted_at_microseconds is not None
        assert (
            await repository.complete_source_deletion(
                completed,
                completed.updated_at_microseconds + 1,
            )
            == completed
        )
        async with store.engine.connect() as connection:
            state = (
                await connection.execute(
                    text("SELECT state FROM embedding_index_generations WHERE id=:source"),
                    {"source": SOURCE_GENERATION_ID},
                )
            ).scalar_one()
        assert state == IndexGenerationState.RETIRED.value
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pause_resume_and_validation_failure_preserve_safe_source_routing(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingMigrationRepository(store)
    try:
        bindings = await _seed_generations(store)
        migration, plan, request_digest = _candidate(*bindings)
        await repository.create(
            scope("provider.embedding_migration.plan"),
            "pro008-pause-plan",
            request_digest,
            plan,
        )
        paused = await repository.advance(
            migration,
            EmbeddingMigrationState.PAUSED,
            migration.updated_at_microseconds + 1,
        )
        assert paused.resume_state is EmbeddingMigrationState.PLANNED
        resumed = await repository.resume(
            paused,
            paused.updated_at_microseconds + 1,
        )
        assert resumed.state is EmbeddingMigrationState.PLANNED
        assert resumed.resume_state is None

        ready = await _ready_migration(repository, resumed)
        failed = await repository.advance(
            ready,
            EmbeddingMigrationState.FAILED,
            ready.updated_at_microseconds + 1,
        )
        targets = await repository.write_targets(
            failed.brain_id,
            failed.source_space_id,
        )
        assert [target.generation_id for target in targets] == [SOURCE_GENERATION_ID]
        async with store.engine.connect() as connection:
            state = (
                await connection.execute(
                    text("SELECT state FROM embedding_index_generations WHERE id=:target"),
                    {"target": TARGET_GENERATION_ID},
                )
            ).scalar_one()
        assert state == IndexGenerationState.FAILED.value
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_stale_snapshot_and_divergent_operation_replay_fail_closed(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingMigrationRepository(store)
    try:
        bindings = await _seed_generations(store)
        migration, plan, request_digest = _candidate(*bindings)
        await repository.create(
            scope("provider.embedding_migration.plan"),
            "pro008-conflict-plan",
            request_digest,
            plan,
        )
        await repository.advance(
            migration,
            EmbeddingMigrationState.BUILDING,
            migration.updated_at_microseconds + 1,
        )
        with pytest.raises(EmbeddingMigrationConflictError):
            await repository.advance(
                migration,
                EmbeddingMigrationState.BUILDING,
                migration.updated_at_microseconds + 1,
            )
        with pytest.raises(EmbeddingMigrationConflictError):
            await repository.create(
                scope("provider.embedding_migration.plan"),
                "pro008-conflict-plan",
                digest("different-request").value,
                plan,
            )
    finally:
        await store.close()
