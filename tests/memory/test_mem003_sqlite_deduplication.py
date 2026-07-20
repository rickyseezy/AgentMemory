"""MEM-003 SQLite CAS, redirect, evidence, event, and replay integration tests."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.memory.adapters.outbound.sqlite_deduplication import (
    SqliteMemoryDeduplicationRepository,
    SqliteMemoryDeduplicationUnitOfWorkFactory,
    SqliteSemanticMemoryCandidateFinder,
)
from agentmemory.memory.adapters.outbound.sqlite_provenance import SqliteMemoryRepository
from agentmemory.memory.application.deduplicate_memories import (
    DeduplicateMemoriesCommand,
    DeduplicateMemoriesHandler,
)
from agentmemory.memory.domain.consolidation import MemoryStatus
from agentmemory.memory.domain.deduplication import MemoryCompatibilityPolicy
from agentmemory.memory.domain.errors import MemoryIntegrityError, MemoryValidationError
from agentmemory.operations.domain.dependency_ports import EmbeddingVector, ProviderAttestation
from tests.core.support import migrated_store, write_secret
from tests.memory.test_mem001_consolidation_domain import NOW
from tests.memory.test_mem002_sqlite_repository import (
    _access,  # pyright: ignore[reportPrivateUsage]
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.memory.domain.deduplication import (
        MemoryDeduplicationProfile,
        SemanticMemoryCandidate,
    )
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

CLONE_ID = "018f0000-0000-7000-8000-000000000451"
REVISION_ID = "018f0000-0000-7000-8000-000000000452"
OPERATION_ID = "018f0000-0000-7000-8000-000000000453"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000454"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000455"


class _NoSemanticCandidates:
    calls = 0

    async def find(
        self,
        target: MemoryDeduplicationProfile,
        limit: int,
    ) -> tuple[SemanticMemoryCandidate, ...]:
        del target, limit
        self.calls += 1
        return ()


class _Clock:
    def now(self) -> datetime:
        return NOW + timedelta(seconds=10)


class _Embeddings:
    def __init__(self, *, mismatched_document_identity: bool = False) -> None:
        self.mismatched_document_identity = mismatched_document_identity

    async def probe(self) -> ProviderAttestation:
        return ProviderAttestation(
            role="embedding",
            model_id="model",
            model_revision="revision",
            dimension=2,
            supports_cancellation=True,
            local_only=True,
        )

    async def embed_query(self, content_id: str, content: str) -> EmbeddingVector:
        assert content
        return EmbeddingVector(content_id, (1.0, 0.0), "model", "revision")

    async def embed_document(self, content_id: str, content: str) -> EmbeddingVector:
        assert content
        revision = "other" if self.mismatched_document_identity else "revision"
        return EmbeddingVector(content_id, (1.0, 0.0), "model", revision)


@pytest.mark.asyncio
async def test_exact_merge_is_atomic_replayable_and_preserves_redirect_evidence(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    semantic = _NoSemanticCandidates()
    try:
        commit = await _persist_memory(store, key_file)
        survivor_id = commit.memories[0].memory_id
        await _clone_memory(store, survivor_id)
        repository = SqliteMemoryDeduplicationRepository(store)
        handler = DeduplicateMemoriesHandler(
            repository,
            semantic,
            SqliteMemoryDeduplicationUnitOfWorkFactory(store),
            MemoryCompatibilityPolicy(),
            _Clock(),
        )
        command = DeduplicateMemoriesCommand(
            OPERATION_ID,
            commit.actor_id,
            commit.grant_id,
            commit.scope.brain_id,
            CORRELATION_ID,
            CAUSATION_ID,
            survivor_id,
            NOW + timedelta(seconds=5),
            NOW + timedelta(minutes=1),
        )

        result, replay = await asyncio.gather(handler.execute(command), handler.execute(command))
        historical_source = await SqliteMemoryRepository(store).explain_authorized(
            _access(commit, memory_id=CLONE_ID)
        )
        async with store.engine.connect() as connection:
            memory_rows = (
                (await connection.execute(text("SELECT id,status,aggregate_version FROM memories")))
                .mappings()
                .all()
            )
            memories = {
                str(row["id"]): (str(row["status"]), int(row["aggregate_version"]))
                for row in memory_rows
            }
            redirect = (
                (await connection.execute(text("SELECT * FROM memory_redirects"))).mappings().one()
            )
            merge_evidence = (
                await connection.execute(text("SELECT COUNT(*) FROM memory_merge_evidence"))
            ).scalar_one()
            event = (
                (
                    await connection.execute(
                        text("SELECT * FROM domain_events WHERE event_id=:event"),
                        {"event": OPERATION_ID},
                    )
                )
                .mappings()
                .one()
            )
            outbox = (
                await connection.execute(
                    text("SELECT topic FROM outbox_messages WHERE topic='memory.merged.v1'")
                )
            ).scalar_one()
    finally:
        await store.close()

    assert replay == result
    assert historical_source is not None
    assert historical_source.memory.status is MemoryStatus.MERGED
    assert result.survivor_memory_id == survivor_id
    assert result.merged_memory_ids == (CLONE_ID,)
    assert semantic.calls == 0
    assert memories[survivor_id] == ("active", 2)
    assert memories[CLONE_ID] == ("merged", 2)
    assert redirect["source_memory_id"] == CLONE_ID
    assert redirect["survivor_memory_id"] == survivor_id
    assert merge_evidence == len(commit.memories[0].evidence_ids)
    assert event["event_type"] == "MemoryMerged"
    assert event["aggregate_version"] == 2
    assert outbox == "memory.merged.v1"


@pytest.mark.asyncio
async def test_semantic_finder_ranks_prefiltered_profiles_and_rejects_model_drift(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        target_id = commit.memories[0].memory_id
        await _clone_memory(store, target_id)
        repository = SqliteMemoryDeduplicationRepository(store)
        target = await repository.load_authorized(
            target_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            NOW + timedelta(seconds=5),
        )
        assert target is not None

        candidates = await SqliteSemanticMemoryCandidateFinder(store, _Embeddings()).find(target, 1)
        with pytest.raises(MemoryIntegrityError):
            await SqliteSemanticMemoryCandidateFinder(
                store, _Embeddings(mismatched_document_identity=True)
            ).find(target, 1)
        with pytest.raises(MemoryValidationError):
            await SqliteSemanticMemoryCandidateFinder(store, _Embeddings()).find(target, 0)
        with pytest.raises(MemoryValidationError):
            await repository.find_exact(target, 257)
    finally:
        await store.close()

    assert len(candidates) == 1
    assert candidates[0].profile.memory_id == CLONE_ID
    assert candidates[0].similarity_basis_points == 10_000


async def _clone_memory(store: SqliteCoreStore, source_id: str) -> None:
    async with store.write_lock, store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO memories SELECT :clone,brain_id,memory_class,project_id,repository_id,"
                "checkout_id,scope_json,status,current_revision,valid_from,valid_to,recorded_from+1,"
                "recorded_to,confidence_json,retention_policy_id,classification,aggregate_version,"
                "source_task_id,extractor_fingerprint,content_hash,consolidation_key,created_at+1,"
                "updated_at+1,schema_version FROM memories WHERE id=:source"
            ),
            {"clone": CLONE_ID, "source": source_id},
        )
        await connection.execute(
            text(
                "INSERT INTO memory_revisions SELECT :revision,:clone,revision,content_hash,"
                "'sqlite://memory-revisions/'||:revision,content_json,provenance_json,"
                "created_by_event,created_at+1,schema_version FROM memory_revisions "
                "WHERE memory_id=:source"
            ),
            {"revision": REVISION_ID, "clone": CLONE_ID, "source": source_id},
        )
        await connection.execute(
            text(
                "INSERT INTO memory_evidence SELECT :clone,event_id,relation,"
                "canonical_event_sha256,added_by_event,created_at+1,schema_version "
                "FROM memory_evidence WHERE memory_id=:source"
            ),
            {"clone": CLONE_ID, "source": source_id},
        )
