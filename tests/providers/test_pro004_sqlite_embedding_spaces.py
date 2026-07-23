"""PRO-004 real SQLite repository, concurrency, and attestation-binding tests."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.providers.adapters.sqlite_embedding_spaces import (
    SqliteEmbeddingSpaceRepository,
    _conflict,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.providers.adapters.sqlite_profiles import SqliteProviderProfileRepository
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpace,
    IndexGeneration,
    IndexGenerationState,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceConflictError,
    EmbeddingSpaceValidationError,
)
from tests.core.support import (
    BRAIN_ID,
    GENERATION_ID,
    NOW,
    FixedClock,
    bootstrap_request,
    digest,
    migrated_store,
)
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    manifest,
    probe_evidence,
    probe_result,
    remote_configuration,
    scope,
)
from tests.providers.test_pro004_embedding_spaces_domain import (
    SPACE_ID,
    descriptor,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.embedding_spaces import EmbeddingSpaceDescriptor


def attested_descriptor(**changes: object) -> EmbeddingSpaceDescriptor:
    provider_manifest = manifest()
    result = probe_result()
    assert result.similarity is not None
    values: dict[str, object] = {
        "adapter_digest": provider_manifest.implementation_digest,
        "adapter_version": provider_manifest.implementation_version,
        "model_revision": result.model_revision,
        "dimension": result.dimension,
        "dtype": result.dtype,
        "normalization": result.normalization,
        "similarity": result.similarity.value,
    }
    values.update(changes)
    return descriptor(**values)


async def seed_active_provider(store: SqliteCoreStore) -> str:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    profile_repository = SqliteProviderProfileRepository(store)
    provider_manifest = manifest()
    configuration = remote_configuration()
    await profile_repository.create(
        scope("provider.profile.create"),
        "pro004-profile-create",
        PROFILE_ID,
        configuration,
        provider_manifest.digest,
        NOW,
    )
    evidence = probe_evidence(
        at=NOW + timedelta(seconds=1),
        configuration=configuration,
        provider_manifest=provider_manifest,
    )
    await profile_repository.activate(
        scope("provider.profile.probe"),
        "pro004-profile-probe",
        1,
        evidence,
    )
    return evidence.evidence_id


def candidates(
    attestation_id: str,
    *,
    space_id: str = SPACE_ID,
    generation_id: str = GENERATION_ID,
    space_descriptor: EmbeddingSpaceDescriptor | None = None,
) -> tuple[EmbeddingSpace, IndexGeneration]:
    embedding_space = EmbeddingSpace.create(
        space_id=space_id,
        profile_id=PROFILE_ID,
        capability_attestation_id=attestation_id,
        descriptor=space_descriptor or attested_descriptor(),
        created_at=NOW + timedelta(seconds=2),
    )
    index_generation = IndexGeneration.create(
        generation_id=generation_id,
        brain_id=BRAIN_ID,
        space=embedding_space,
        state=IndexGenerationState.CREATING,
        created_at=NOW + timedelta(seconds=2),
    )
    return embedding_space, index_generation


def test_conflict_helper_raises_only_the_stable_content_free_error() -> None:
    with pytest.raises(
        EmbeddingSpaceConflictError,
        match=r"^embedding space conflicts with immutable history$",
    ):
        _conflict()


@pytest.mark.asyncio
async def test_sqlite_reservation_is_attested_replayable_and_completes_once(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingSpaceRepository(store)
    try:
        attestation_id = await seed_active_provider(store)
        embedding_space, index_generation = candidates(attestation_id)
        request_digest = digest("pro004-request").value
        reservation = await repository.reserve(
            scope("provider.embedding_space.ensure"),
            "pro004-ensure-1",
            request_digest,
            embedding_space,
            index_generation,
        )
        assert reservation.created
        assert reservation.space == embedding_space
        assert reservation.generation == index_generation

        replay = await repository.reserve(
            scope("provider.embedding_space.ensure"),
            "pro004-ensure-1",
            request_digest,
            *candidates(
                attestation_id,
                space_id="018f0000-0000-7000-8000-000000000121",
                generation_id="018f0000-0000-7000-8000-000000000122",
            ),
        )
        assert replay.space == embedding_space
        assert replay.generation == index_generation
        assert not replay.created

        completed = await repository.complete(
            scope("provider.embedding_space.ensure"),
            "pro004-ensure-1",
            GENERATION_ID,
            NOW + timedelta(seconds=3),
        )
        assert completed.state is IndexGenerationState.POPULATING
        assert (
            await repository.complete(
                scope("provider.embedding_space.ensure"),
                "pro004-ensure-1",
                GENERATION_ID,
                NOW + timedelta(seconds=3),
            )
            == completed
        )
        async with store.engine.connect() as connection:
            audits = (
                (
                    await connection.execute(
                        text(
                            "SELECT action,before_hash,after_hash,previous_hash,event_hash "
                            "FROM audit_events "
                            "WHERE action LIKE 'provider.embedding_space.%' "
                            "ORDER BY sequence"
                        )
                    )
                )
                .mappings()
                .all()
            )
            outbox = (
                await connection.execute(
                    text(
                        "SELECT topic,payload FROM outbox_messages "
                        "WHERE topic LIKE 'provider.embedding_generation.%' "
                        "ORDER BY created_at"
                    )
                )
            ).all()
            domain_events = (
                (
                    await connection.execute(
                        text(
                            "SELECT type FROM agent_events "
                            "WHERE type LIKE 'EmbeddingIndexGeneration%' "
                            "ORDER BY occurred_at"
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert [str(row["action"]) for row in audits] == [
            "provider.embedding_space.ensured",
            "provider.embedding_space.populating",
        ]
        assert bytes(audits[1]["previous_hash"]) == bytes(audits[0]["event_hash"])
        assert bytes(audits[0]["before_hash"]) == bytes(32)
        assert bytes(audits[0]["after_hash"]) != bytes(32)
        assert [str(row[0]) for row in outbox] == [
            "provider.embedding_generation.ensured.v1",
            "provider.embedding_generation.populating.v1",
        ]
        assert all("text-embedding" not in str(row[1]) for row in outbox)
        assert list(domain_events) == [
            "EmbeddingIndexGenerationEnsured",
            "EmbeddingIndexGenerationPopulating",
        ]
        with pytest.raises(
            EmbeddingSpaceConflictError,
            match="embedding space conflicts with immutable history",
        ):
            await repository.reserve(
                scope("provider.embedding_space.ensure"),
                "pro004-ensure-1",
                digest("different-request").value,
                embedding_space,
                index_generation,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_same_space_concurrent_creation_converges_on_one_generation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingSpaceRepository(store)
    try:
        attestation_id = await seed_active_provider(store)
        first = candidates(attestation_id)
        second = candidates(
            attestation_id,
            space_id="018f0000-0000-7000-8000-000000000121",
            generation_id="018f0000-0000-7000-8000-000000000122",
        )
        results = await asyncio.gather(
            repository.reserve(
                scope("provider.embedding_space.ensure"),
                "pro004-concurrent-1",
                digest("same-request").value,
                *first,
            ),
            repository.reserve(
                scope("provider.embedding_space.ensure"),
                "pro004-concurrent-2",
                digest("same-request").value,
                *second,
            ),
        )
        assert {result.space.space_id for result in results} == {SPACE_ID}
        assert {result.generation.generation_id for result in results} == {GENERATION_ID}
        assert [result.created for result in results].count(True) == 1
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM embedding_spaces),"
                        "(SELECT COUNT(*) FROM embedding_index_generations),"
                        "(SELECT COUNT(*) FROM embedding_generation_operations)"
                    )
                )
            ).one()
        assert tuple(int(value) for value in counts) == (1, 1, 2)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_attestation_mismatch_rejects_without_partial_space_or_generation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingSpaceRepository(store)
    try:
        attestation_id = await seed_active_provider(store)
        wrong = candidates(
            attestation_id,
            space_descriptor=attested_descriptor(dimension=1536),
        )
        with pytest.raises(EmbeddingSpaceValidationError, match="attestation"):
            await repository.reserve(
                scope("provider.embedding_space.ensure"),
                "pro004-invalid-attestation",
                digest("invalid-request").value,
                *wrong,
            )
        async with store.engine.connect() as connection:
            count = (
                await connection.execute(text("SELECT COUNT(*) FROM embedding_spaces"))
            ).scalar_one()
        assert int(count) == 0
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_triggers_reject_semantic_and_physical_contract_tampering(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteEmbeddingSpaceRepository(store)
    try:
        attestation_id = await seed_active_provider(store)
        await repository.reserve(
            scope("provider.embedding_space.ensure"),
            "pro004-tamper",
            digest("tamper-request").value,
            *candidates(attestation_id),
        )
        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable embedding space"):
                await connection.execute(text("UPDATE embedding_spaces SET dimension=dimension-1"))
            with pytest.raises(IntegrityError, match="immutable embedding generation"):
                await connection.execute(
                    text(
                        "UPDATE embedding_index_generations "
                        "SET vector_index_name='am_vec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
                    )
                )
    finally:
        await store.close()
