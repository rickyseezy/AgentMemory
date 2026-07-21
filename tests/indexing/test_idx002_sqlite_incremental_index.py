"""IDX-002 migration and durable SQLite incremental-index integration tests."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
)
from agentmemory.graph.domain.assertions import (
    AssertionEvidenceReference,
    AssertionStatus,
    EvidenceKind,
)
from agentmemory.indexing.adapters.outbound.sqlite_code_index import SqliteCodeIndexRepository
from agentmemory.indexing.adapters.outbound.sqlite_incremental_index import (
    SqliteIncrementalIndexRepository,
)
from agentmemory.indexing.adapters.outbound.sqlite_index_projection import (
    SqliteIndexProjectionConsumer,
)
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.application.incremental_index import (
    CancelIndexRunCommand,
    CancelIndexRunHandler,
    GetIndexRunHandler,
    GetIndexRunQuery,
    IncrementalIndexWorker,
    IndexProjectionWorker,
    StartIndexRunCommand,
    StartIndexRunHandler,
)
from agentmemory.indexing.domain.errors import IndexingAuthorizationError
from agentmemory.indexing.domain.incremental import (
    IndexFingerprint,
    IndexRevisionContext,
    IndexRunState,
    PriorIndexedUnit,
    VcsDelta,
    VcsDeltaKind,
)
from agentmemory.indexing.domain.incremental_ports import (
    RepositoryInspection,
    RepositoryManifestEntry,
)
from agentmemory.indexing.domain.ports import SourceArtifact
from agentmemory.operations.domain.dependency_ports import EmbeddingVector
from tests.core.support import NOW, FixedClock, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    ACTIVATED_EVENT_ID,
    ASSERTION_ID,
    PROMPT_EVENT_ID,
    PROMPT_EVIDENCE_ID,
)
from tests.graph.test_gra002_sqlite_assertions import (
    NOW as ASSERTION_NOW,
)
from tests.graph.test_gra002_sqlite_assertions import (
    _candidate as assertion_candidate,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra002_sqlite_assertions import (
    _scope as assertion_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra002_sqlite_assertions import (
    _seed_sources as seed_assertion_sources,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    REPOSITORY_ID,
    _configuration,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
    _seed,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class _Fingerprints:
    @property
    def implementation_digest(self) -> str:
        return _digest(b"idx002-implementation-v1")

    def for_path(self, relative_path: str) -> IndexFingerprint:
        del relative_path
        return IndexFingerprint(
            "tree-sitter-0.26.0",
            "grammar-lock-v1",
            _digest(b"queries"),
            _digest(b"extraction"),
            "privacy-v1",
        )


@dataclass(slots=True)
class _Source:
    content: dict[str, bytes]
    target_commit: str
    working_digest: str
    deltas: tuple[VcsDelta, ...]
    revision_context: IndexRevisionContext = IndexRevisionContext.WORKTREE
    reads: list[str] = field(default_factory=list[str])
    inspections: int = 0

    async def inspect(
        self,
        repository_id: str,
        base_commit_id: str | None,
        target_commit_id: str | None,
        previous: tuple[PriorIndexedUnit, ...],
    ) -> RepositoryInspection:
        del repository_id, base_commit_id, previous
        assert target_commit_id == self.target_commit
        self.inspections += 1
        return RepositoryInspection(
            self.target_commit,
            self.working_digest,
            tuple(
                RepositoryManifestEntry(
                    path,
                    _digest(value),
                    len(value),
                    generated=False,
                )
                for path, value in sorted(self.content.items())
            ),
            self.deltas,
            self.revision_context,
        )

    async def read(
        self,
        repository_id: str,
        target_commit_id: str | None,
        relative_path: str,
        expected_digest: str,
        revision_context: IndexRevisionContext,
    ) -> SourceArtifact:
        del target_commit_id, revision_context
        assert repository_id == REPOSITORY_ID
        value = self.content[relative_path]
        assert _digest(value) == expected_digest
        self.reads.append(relative_path)
        return SourceArtifact(relative_path, value)


@dataclass(frozen=True, slots=True)
class _Embeddings:
    async def embed_document(self, content_id: str, content: str) -> EmbeddingVector:
        assert content
        return EmbeddingVector(content_id, (0.25, 0.5, 0.75), "local-test", "revision-1")


def test_idx002_migration_round_trip_and_history_guard(tmp_path: Path) -> None:
    database = tmp_path / "idx002-migration.sqlite3"
    configuration = _configuration(database)
    alembic_command.upgrade(configuration, "0026_idx001_code_entities")
    alembic_command.upgrade(configuration, "0027_idx002_incremental_index")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "incremental_index_runs",
            "incremental_index_plan_operations",
            "incremental_index_run_snapshots",
            "snapshot_file_bindings",
            "source_file_lineage",
            "index_projection_events",
            "index_projection_delivery_snapshots",
            "code_semantic_vector_projections",
            "code_semantic_vector_invalidations",
            "index_topology_fact_invalidations",
        } <= tables
    alembic_command.downgrade(configuration, "0026_idx001_code_entities")
    alembic_command.upgrade(configuration, "head")


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_sqlite_incremental_reuse_change_outbox_replay_and_immutability(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        at = ASSERTION_NOW
        await _seed(store)
        await seed_assertion_sources(store)
        assertion_factory = SqliteAssertionRepositoryFactory(store)
        await assertion_factory.evidence_catalog(
            assertion_scope("graph.assertion.evidence.register")
        ).register(
            AssertionEvidenceReference(
                PROMPT_EVIDENCE_ID,
                PROMPT_EVENT_ID,
                EvidenceKind.USER_STATEMENT,
            ),
            at,
        )
        candidate = assertion_candidate()
        await ProposeAssertionHandler(assertion_factory).execute(
            ProposeAssertionCommand(
                "idx002-assertion-propose",
                assertion_scope("graph.assertion.propose"),
                candidate,
            )
        )
        await ActivateAssertionHandler(assertion_factory).execute(
            ActivateAssertionCommand(
                "idx002-assertion-activate",
                ACTIVATED_EVENT_ID,
                ASSERTION_ID,
                assertion_scope("graph.assertion.activate"),
                at + timedelta(seconds=1),
            )
        )
        clock = FixedClock(at + timedelta(seconds=2))
        repository = SqliteIncrementalIndexRepository(store, clock)
        initial_content = {
            "src/a.py": b"def a():\n    return 1\n",
            "src/b.py": b"def b():\n    return 1\n",
        }
        initial_source = _Source(
            initial_content,
            "commit-1",
            _digest(b"working-1"),
            (),
        )
        initial_command = StartIndexRunCommand(
            "idx002-run-1",
            _scope("indexing.run.start"),
            "commit-1",
            include_generated=True,
            detected_at=at + timedelta(seconds=2),
        )
        initial = await StartIndexRunHandler(initial_source, _Fingerprints(), repository).execute(
            initial_command
        )
        await IncrementalIndexWorker(
            initial_source,
            TreeSitterLanguagePlugin(),
            repository,
            clock,
        ).run_once()
        completed = await GetIndexRunHandler(repository).execute(
            GetIndexRunQuery(_scope("indexing.run.read"), initial.id)
        )
        assert completed.state is IndexRunState.COMPLETED
        assert completed.indexed_count == 2
        assert initial_source.reads == ["src/a.py", "src/b.py"]

        replay = await StartIndexRunHandler(initial_source, _Fingerprints(), repository).execute(
            initial_command
        )
        assert replay == completed
        assert initial_source.inspections == 1

        previous = await repository.latest_completed(_scope("indexing.run.start"))
        assert previous is not None
        old_b = next(item for item in previous.units if item.relative_path == "src/b.py")
        dependency_id = hashlib.sha256(b"dependency").hexdigest()
        dependent_fact = hashlib.sha256(b"dependent-fact").hexdigest()
        assertion_evidence = PROMPT_EVIDENCE_ID
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO index_semantic_dependencies(dependency_id,repository_id,"
                    "source_semantic_id,dependent_fact_id,assertion_evidence_id,registered_at) "
                    "VALUES(:id,:repository,:source,:fact,:evidence,:at)"
                ),
                {
                    "id": dependency_id,
                    "repository": REPOSITORY_ID,
                    "source": old_b.semantic_ids[0],
                    "fact": dependent_fact,
                    "evidence": assertion_evidence,
                    "at": round(at.timestamp() * 1_000_000),
                },
            )

        changed_content = {**initial_content, "src/b.py": b"def b():\n    return 2\n"}
        changed_source = _Source(
            changed_content,
            "commit-2",
            _digest(b"working-2"),
            (VcsDelta(VcsDeltaKind.MODIFY, "src/b.py"),),
        )
        changed = await StartIndexRunHandler(changed_source, _Fingerprints(), repository).execute(
            StartIndexRunCommand(
                "idx002-run-2",
                _scope("indexing.run.start"),
                "commit-2",
                include_generated=True,
                detected_at=at + timedelta(seconds=3),
            )
        )
        await IncrementalIndexWorker(
            changed_source,
            TreeSitterLanguagePlugin(),
            repository,
            FixedClock(at + timedelta(seconds=3)),
        ).run_once()
        changed_status = await repository.get(_scope("indexing.run.read"), changed.id)
        assert changed_status is not None
        assert changed_status.indexed_count == 1
        assert changed_status.reused_count == 1
        assert changed_source.reads == ["src/b.py"]
        visible_files = await SqliteCodeIndexRepository(store, clock).list_files(
            _scope("indexing.search"), changed.target_snapshot_id
        )
        assert tuple(item.file.relative_path for item in visible_files) == (
            "src/a.py",
            "src/b.py",
        )

        async with store.engine.connect() as connection:
            event = (
                (
                    await connection.execute(
                        text("SELECT * FROM index_projection_events WHERE run_id=:run"),
                        {"run": changed.id},
                    )
                )
                .mappings()
                .one()
            )
            assert dependent_fact.encode() in bytes(event["dependent_fact_ids_json"])
            assert assertion_evidence.encode() in bytes(event["assertion_evidence_ids_json"])
            bindings = (
                await connection.execute(
                    text("SELECT COUNT(*) FROM snapshot_file_bindings WHERE snapshot_id=:snapshot"),
                    {"snapshot": changed.target_snapshot_id},
                )
            ).scalar_one()
            assert bindings == 2

        projection_worker = IndexProjectionWorker(
            repository,
            SqliteIndexProjectionConsumer(store, _Embeddings(), assertion_factory),
            FixedClock(at + timedelta(minutes=1)),
        )
        delivered = 0
        while await projection_worker.run_once():
            delivered += 1
        assert delivered == 3
        disputed = await assertion_factory.assertions(
            assertion_scope("graph.assertion.reconcile")
        ).get_assertion(ASSERTION_ID)
        assert disputed is not None
        assert disputed.status is AssertionStatus.DISPUTED
        async with store.engine.begin() as connection:
            vector_count = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM code_semantic_vector_projections "
                        "WHERE event_id=:event"
                    ),
                    {"event": str(event["event_id"])},
                )
            ).scalar_one()
            invalidation_count = (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM index_topology_fact_invalidations "
                        "WHERE event_id=:event"
                    ),
                    {"event": str(event["event_id"])},
                )
            ).scalar_one()
            assert vector_count == 1
            assert invalidation_count == 1
            with pytest.raises(IntegrityError, match="immutable"):
                await connection.execute(
                    text("UPDATE incremental_index_runs SET operation_id='changed'")
                )
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="IDX-003 revision history"):
        alembic_command.downgrade(
            _configuration(tmp_path / "agentmemory.sqlite3"),
            "0026_idx001_code_entities",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_cancel_and_worker_revalidate_current_grant(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        repository = SqliteIncrementalIndexRepository(store, FixedClock())
        content = {"src/a.py": b"def a(): pass\n"}
        source = _Source(content, "commit-cancel", _digest(b"cancel"), ())
        run = await StartIndexRunHandler(source, _Fingerprints(), repository).execute(
            StartIndexRunCommand(
                "idx002-cancel-run",
                _scope("indexing.run.start"),
                "commit-cancel",
                include_generated=True,
                detected_at=NOW,
            )
        )
        cancelled = await CancelIndexRunHandler(repository).execute(
            CancelIndexRunCommand(
                "idx002-cancel-request",
                _scope("indexing.run.cancel"),
                run.id,
                NOW + timedelta(milliseconds=1),
            )
        )
        assert cancelled.state is IndexRunState.CANCELLING
        await IncrementalIndexWorker(
            source,
            TreeSitterLanguagePlugin(),
            repository,
            FixedClock(NOW + timedelta(seconds=1)),
        ).run_once()
        status = await repository.get(_scope("indexing.run.read"), run.id)
        assert status is not None
        assert status.state is IndexRunState.CANCELLED
        assert source.reads == []

        second_source = _Source(content, "commit-revoked", _digest(b"revoked"), ())
        await StartIndexRunHandler(second_source, _Fingerprints(), repository).execute(
            StartIndexRunCommand(
                "idx002-revoked-run",
                _scope("indexing.run.start"),
                "commit-revoked",
                include_generated=True,
                detected_at=NOW + timedelta(seconds=2),
            )
        )
        await _revoke_grant(store)
        with pytest.raises(IndexingAuthorizationError):
            await repository.claim_next(NOW + timedelta(seconds=3))
    finally:
        await store.close()


async def _revoke_grant(store: SqliteCoreStore) -> None:
    async with store.engine.begin() as connection:
        await connection.execute(
            text("UPDATE scope_grants SET valid_to=:at"),
            {"at": round((NOW + timedelta(seconds=2)).timestamp() * 1_000_000)},
        )
