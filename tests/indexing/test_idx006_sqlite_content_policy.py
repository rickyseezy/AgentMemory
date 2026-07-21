"""IDX-006 real SQLite policy, reconciliation, migration, and secrecy tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.indexing.adapters.outbound.sqlite_code_index import SqliteCodeIndexRepository
from agentmemory.indexing.adapters.outbound.sqlite_content_policy import (
    SqliteIndexContentPolicyAdapter,
    SqliteIndexPolicyProjection,
)
from agentmemory.indexing.application.code_index import IndexRepositorySnapshotHandler
from agentmemory.indexing.application.content_policy import (
    ActivateIndexPolicyCommand,
    ActivateIndexPolicyHandler,
    GetIndexPolicyChangeHandler,
    GetIndexPolicyChangeQuery,
    IndexContentPolicyGate,
    PolicyReconciliationWorker,
)
from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyAction,
    PolicyLayer,
    PolicyRule,
    PolicyRuleSource,
)
from agentmemory.indexing.domain.content_policy_ports import PolicySourceDocuments
from agentmemory.indexing.domain.errors import IndexingConflictError
from agentmemory.indexing.domain.ports import SourceArtifact
from tests.core.support import BRAIN_ID, NOW, FixedClock, migrated_store
from tests.indexing.test_idx001_sqlite_code_index import REPOSITORY_ID
from tests.indexing.test_idx001_sqlite_code_index import (
    _command as code_command,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _configuration as configuration,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _Plugin as CodePlugin,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _seed as seed,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _Source as CodeSource,  # pyright: ignore[reportPrivateUsage]
)

POLICY_ID = "018f0000-0000-7000-8000-000000000601"
RAW_SECRET = b"idx006-raw-secret-must-never-persist"

if TYPE_CHECKING:
    from pathlib import Path


def _revision(version: int, *rules: tuple[str, PolicyAction]) -> IndexPolicyRevision:
    source = PolicyRuleSource.create(
        PolicyLayer.BRAIN,
        version,
        tuple(
            PolicyRule(PolicyLayer.BRAIN, f"brain.{index}", version, pattern, action)
            for index, (pattern, action) in enumerate(rules, start=1)
        ),
    )
    return IndexPolicyRevision(
        policy_id=POLICY_ID,
        version=version,
        brain_id=BRAIN_ID,
        repository_id=REPOSITORY_ID,
        brain_rules=source,
        max_file_bytes=1024,
        private_block_pairs=(("<private>", "</private>"),),
        exclude_binary=True,
        exclude_generated=True,
        exclude_encrypted=True,
        activated_at=NOW + timedelta(minutes=version),
    )


def test_idx006_migration_round_trip_and_history_guard(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    config = configuration(database)
    alembic_command.upgrade(config, "0030_idx005_artifact_topology")
    alembic_command.upgrade(config, "0031_idx006_content_policy")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert {
        "index_content_policy_versions",
        "index_policy_rule_sources",
        "index_policy_decisions",
        "index_policy_changes",
        "index_policy_reconciliation_items",
        "index_policy_reconciliation_snapshots",
        "index_policy_derivative_invalidations",
        "index_policy_reindex_requests",
    } <= tables
    alembic_command.downgrade(config, "0030_idx005_artifact_topology")
    alembic_command.upgrade(config, "head")


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
async def test_policy_activation_is_replayable_secret_free_and_reconciles_derivatives(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed(store)
        clock = FixedClock(NOW + timedelta(minutes=2))
        repository = SqliteIndexContentPolicyAdapter(store, clock)
        gate = IndexContentPolicyGate(repository)
        policy = await gate.prepare(
            REPOSITORY_ID,
            PolicySourceDocuments(b"tmp/**\n", b"*.ignored\n"),
            NOW,
        )
        included = policy.evaluate_content("src/a.py", b"print('ok')\n", NOW)
        excluded = policy.evaluate_content("src/b.bin", b"prefix\x00" + RAW_SECRET, NOW)
        await gate.record(included)
        await gate.record(excluded)
        await gate.record(included)

        revision = _revision(
            2,
            ("src/a.py", PolicyAction.EXCLUDE),
            ("src/b.bin", PolicyAction.INCLUDE),
        )
        scope = indexing_scope("indexing.policy.activate")
        command = ActivateIndexPolicyCommand(
            "idx006-activate-2",
            scope,
            revision,
            revision.activated_at,
        )
        handler = ActivateIndexPolicyHandler(repository)
        change = await handler.execute(command)

        assert await handler.execute(command) == change
        assert change.delete_count == 1
        assert change.reindex_count == 1
        assert await repository.resolve_revision(REPOSITORY_ID, NOW) == revision
        read_scope = indexing_scope("indexing.policy.read")
        assert (
            await GetIndexPolicyChangeHandler(repository).execute(
                GetIndexPolicyChangeQuery(read_scope, change.change_id)
            )
            == change
        )

        worker = PolicyReconciliationWorker(
            repository,
            SqliteIndexPolicyProjection(store),
            clock,
        )
        assert await worker.run_once()
        assert await worker.run_once()
        assert not await worker.run_once()
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM index_policy_derivative_invalidations")
                )
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM index_policy_reindex_requests"))
            ).scalar_one() == 1
            decisions = (
                (
                    await connection.execute(
                        text(
                            "SELECT decision_json FROM index_policy_decisions ORDER BY decision_id"
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert decisions
        assert all(RAW_SECRET not in bytes(document) for document in decisions)
        assert RAW_SECRET not in (tmp_path / "agentmemory.sqlite3").read_bytes()

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable"):
                await connection.execute(text("UPDATE index_policy_changes SET delete_count=999"))
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="IDX-006 content-policy history"):
        alembic_command.downgrade(
            configuration(tmp_path / "agentmemory.sqlite3"),
            "0030_idx005_artifact_topology",
        )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.resilience
async def test_expired_reconciliation_lease_reclaims_and_wrong_revision_conflicts(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed(store)
        repository = SqliteIndexContentPolicyAdapter(store, FixedClock(NOW))
        default = IndexContentPolicy.production_default(BRAIN_ID, REPOSITORY_ID, NOW)
        await repository.record_decision(default.evaluate_content("src/a.py", b"print('ok')", NOW))
        revision = _revision(2, ("src/a.py", PolicyAction.EXCLUDE))
        await repository.activate(
            indexing_scope("indexing.policy.activate"),
            "idx006-lease",
            revision,
            revision.activated_at,
        )
        first = await repository.claim_next(NOW + timedelta(minutes=3))
        assert first is not None
        assert await repository.claim_next(NOW + timedelta(minutes=4)) is None
        reclaimed = await repository.claim_next(NOW + timedelta(minutes=9))
        assert reclaimed is not None
        assert reclaimed.item_id == first.item_id
        await repository.complete(reclaimed.item_id, NOW + timedelta(minutes=10))

        wrong = _revision(4)
        with pytest.raises(IndexingConflictError, match="immutable history"):
            await repository.activate(
                indexing_scope("indexing.policy.activate"),
                "idx006-wrong-version",
                wrong,
                wrong.activated_at,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
async def test_completed_policy_deletion_immediately_hides_old_code_projection(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed(store)
        code_repository = SqliteCodeIndexRepository(store, FixedClock(NOW))
        indexed = await IndexRepositorySnapshotHandler(
            CodeSource((SourceArtifact("src/main.py", b"def hidden():\n    return 1\n"),)),
            CodePlugin(),
            code_repository,
        ).execute(code_command(indexing_scope("indexing.snapshot")))
        async with store.engine.begin() as connection:
            file_revision_id = str(
                (
                    await connection.execute(
                        text(
                            "SELECT revision.id FROM file_revisions AS revision JOIN "
                            "source_files AS source ON source.id=revision.file_id "
                            "WHERE source.repository_id=:repository "
                            "AND source.relative_path='src/main.py'"
                        ),
                        {"repository": REPOSITORY_ID},
                    )
                ).scalar_one()
            )
            await connection.execute(
                text(
                    "INSERT INTO index_semantic_dependencies(dependency_id,repository_id,"
                    "source_semantic_id,dependent_fact_id,assertion_evidence_id,registered_at,"
                    "schema_version) VALUES(:id,:repository,:source,:fact,:evidence,:at,1)"
                ),
                {
                    "at": round(NOW.timestamp() * 1_000_000),
                    "evidence": "b" * 64,
                    "fact": "a" * 64,
                    "id": "c" * 64,
                    "repository": REPOSITORY_ID,
                    "source": file_revision_id,
                },
            )
        policy_repository = SqliteIndexContentPolicyAdapter(store, FixedClock(NOW))
        default = IndexContentPolicy.production_default(BRAIN_ID, REPOSITORY_ID, NOW)
        await policy_repository.record_decision(
            default.evaluate_content("src/main.py", b"def hidden():\n    return 1\n", NOW)
        )
        revision = _revision(2, ("src/main.py", PolicyAction.EXCLUDE))
        await policy_repository.activate(
            indexing_scope("indexing.policy.activate"),
            "idx006-hide-old-code",
            revision,
            revision.activated_at,
        )
        worker = PolicyReconciliationWorker(
            policy_repository,
            SqliteIndexPolicyProjection(store),
            FixedClock(NOW + timedelta(minutes=2)),
        )
        assert await worker.run_once()
        assert not await worker.run_once()

        visible = await code_repository.list_files(
            indexing_scope("indexing.search"), indexed.snapshot.id
        )
        assert visible == ()
        async with store.engine.connect() as connection:
            invalidation = (
                (
                    await connection.execute(
                        text(
                            "SELECT semantic_ids_json,dependent_fact_ids_json,"
                            "assertion_evidence_ids_json FROM index_policy_derivative_invalidations"
                        )
                    )
                )
                .mappings()
                .one()
            )
        semantics = bytes(invalidation["semantic_ids_json"])
        assert b"hidden" not in semantics
        assert file_revision_id.encode() in semantics
        assert bytes(invalidation["dependent_fact_ids_json"]) == b'["' + b"a" * 64 + b'"]'
        assert bytes(invalidation["assertion_evidence_ids_json"]) == (b'["' + b"b" * 64 + b'"]')

        reauthorized = IndexContentPolicy(
            _revision(3, ("src/main.py", PolicyAction.INCLUDE)), None, None
        ).evaluate_content(
            "src/main.py", b"def hidden():\n    return 1\n", NOW + timedelta(minutes=3)
        )
        await policy_repository.record_decision(reauthorized)
        assert await code_repository.list_files(
            indexing_scope("indexing.search"), indexed.snapshot.id
        )
    finally:
        await store.close()
