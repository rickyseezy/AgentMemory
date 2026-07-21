"""IDX-003 real SQLite commit ancestry, source lineage, and invalidation integration tests."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.adapters.outbound.sqlite_temporal_truth import (
    SqliteTemporalAssertionRepository,
    SqliteVcsRevisionRepository,
)
from agentmemory.graph.application.temporal_truth import (
    QueryTemporalAssertionsHandler,
    QueryTemporalAssertionsQuery,
)
from agentmemory.graph.domain.assertions import AssertionStatus
from agentmemory.graph.domain.temporal_truth import (
    TruthTemporalScope,
    VcsRefObservation,
    VcsRevisionNode,
    VcsRevisionSelector,
)
from agentmemory.indexing.adapters.outbound.sqlite_incremental_index import (
    SqliteIncrementalIndexRepository,
)
from agentmemory.indexing.adapters.outbound.sqlite_index_projection import (
    SqliteIndexProjectionConsumer,
)
from agentmemory.indexing.adapters.outbound.sqlite_revision_history import (
    SqliteCommitGraphAdapter,
    SqliteSourceRevisionRepository,
)
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.application.incremental_index import (
    IncrementalIndexWorker,
    IndexProjectionWorker,
    StartIndexRunCommand,
    StartIndexRunHandler,
)
from agentmemory.indexing.application.revision_history import (
    ProcessSourceRevisionHandler,
    QuerySourceRevisionHistoryHandler,
    QuerySourceRevisionHistoryQuery,
    RegisterEvidenceLineageCommand,
    RegisterEvidenceLineageHandler,
    SourceRevisionWorker,
)
from agentmemory.indexing.domain.errors import IndexingConflictError
from agentmemory.indexing.domain.incremental import (
    IndexRevisionContext,
    VcsDelta,
    VcsDeltaKind,
)
from agentmemory.indexing.domain.revision_history import SourceRevisionApplicability
from tests.core.support import BRAIN_ID, FixedClock, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    ASSERTION_ID,
    NOW,
    PROMPT_EVIDENCE_ID,
)
from tests.graph.test_gra002_sqlite_assertions import (
    _scope as graph_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra004_sqlite_temporal_truth import (
    _batch,  # pyright: ignore[reportPrivateUsage]
    _insert_anchor,  # pyright: ignore[reportPrivateUsage]
    _seed_active_assertion,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import REPOSITORY_ID
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx002_incremental_application import (
    _Fingerprints,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx002_sqlite_incremental_index import (
    _Embeddings,  # pyright: ignore[reportPrivateUsage]
    _Source,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from agentmemory.graph.domain.temporal_truth import TemporalAssertionResult
    from agentmemory.indexing.domain.incremental import IndexRun
    from agentmemory.indexing.domain.revision_history import SourceRevisionHistoryEntry
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

ROOT = "1" * 40
BASE = "2" * 40
MAIN = "3" * 40
FEATURE = "4" * 40
CHERRY_PICK = "5" * 40
MERGE = "6" * 40
REVERT = "7" * 40
DELETE = "8" * 40
REWRITTEN = "9" * 40


def _digest(value: str | bytes) -> str:
    encoded = value if isinstance(value, bytes) else value.encode()
    return hashlib.sha256(encoded).hexdigest()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pinned_graph_answers_cover_merge_cherry_pick_and_force_push(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed_active_assertion(store)
        revisions = SqliteVcsRevisionRepository(store, FixedClock(NOW + timedelta(hours=1)))
        record_scope = graph_scope("graph.vcs.revision.record")
        t0 = NOW + timedelta(seconds=10)
        await revisions.append(
            record_scope,
            _batch(
                "idx003-graph-base",
                (VcsRevisionNode(ROOT, ()), VcsRevisionNode(BASE, (ROOT,))),
                (VcsRefObservation("main", BASE, t0),),
                (),
                t0,
            ),
        )
        t1 = NOW + timedelta(seconds=20)
        await revisions.append(
            record_scope,
            _batch(
                "idx003-graph-diverge",
                (
                    VcsRevisionNode(MAIN, (BASE,)),
                    VcsRevisionNode(FEATURE, (BASE,)),
                    VcsRevisionNode(CHERRY_PICK, (MAIN,)),
                ),
                (
                    VcsRefObservation("feature", FEATURE, t1),
                    VcsRefObservation("main", CHERRY_PICK, t1),
                ),
                (),
                t1,
            ),
        )
        graph = SqliteCommitGraphAdapter(store)
        snapshot = await graph.pin_branch(BRAIN_ID, REPOSITORY_ID.value, "main", t1, t1)
        ancestry = await graph.ancestry(snapshot, FEATURE, CHERRY_PICK, t1)
        bases = await graph.merge_bases(snapshot, FEATURE, CHERRY_PICK, t1)
        replay = await graph.merge_bases(
            snapshot,
            FEATURE,
            CHERRY_PICK,
            t1 + timedelta(seconds=1),
        )

        assert not ancestry.is_ancestor
        assert bases.merge_base_shas == (BASE,)
        assert replay.id == bases.id
        assert replay.answered_at == bases.answered_at

        t2 = NOW + timedelta(seconds=30)
        await revisions.append(
            record_scope,
            _batch(
                "idx003-graph-merge",
                (VcsRevisionNode(MERGE, tuple(sorted((CHERRY_PICK, FEATURE)))),),
                (VcsRefObservation("main", MERGE, t2),),
                (),
                t2,
            ),
        )
        merged = await graph.pin_branch(BRAIN_ID, REPOSITORY_ID.value, "main", t2, t2)
        assert (await graph.ancestry(merged, FEATURE, MERGE, t2)).is_ancestor

        t3 = NOW + timedelta(seconds=40)
        await revisions.append(
            record_scope,
            _batch(
                "idx003-graph-force-push",
                (VcsRevisionNode(REWRITTEN, (ROOT,)),),
                (VcsRefObservation("main", REWRITTEN, t3),),
                (),
                t3,
            ),
        )
        rewritten = await graph.pin_branch(BRAIN_ID, REPOSITORY_ID.value, "main", t3, t3)
        assert not (await graph.ancestry(rewritten, BASE, REWRITTEN, t3)).is_ancestor
        assert snapshot.target_commit_sha == CHERRY_PICK
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_changed_deleted_and_reintroduced_history_is_branch_scoped(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        checkout_id = await _seed_active_assertion(store)
        await _insert_anchor(store, checkout_id, BASE)
        await _record_history_graph(store)
        graph = SqliteCommitGraphAdapter(store)
        history_repository = SqliteSourceRevisionRepository(
            store, FixedClock(NOW + timedelta(hours=1))
        )
        history_worker = SourceRevisionWorker(
            handler=_process_handler(graph, history_repository),
            repository=history_repository,
            clock=FixedClock(NOW + timedelta(minutes=1)),
        )

        original = b"def service():\n    return 'original'\n"
        changed = b"def service():\n    return 'changed'\n"
        first = await _index_commit(store, BASE, original, (), NOW + timedelta(seconds=11))
        assert await history_worker.run_once()
        first_context = await _context_for_snapshot(store, first.target_snapshot_id)
        lineage = RegisterEvidenceLineageHandler(history_repository)
        registration = RegisterEvidenceLineageCommand(
            "idx003-register-original",
            indexing_scope("indexing.revision.lineage.register"),
            first_context,
            PROMPT_EVIDENCE_ID,
            ASSERTION_ID,
            NOW + timedelta(seconds=12),
        )
        registration_digest = await lineage.execute(registration)
        assert await lineage.execute(registration) == registration_digest
        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable"):
                await connection.execute(
                    text(
                        "UPDATE source_revision_contexts SET relative_path='changed.py' "
                        "WHERE context_id=:context"
                    ),
                    {"context": first_context},
                )
        await _link_snapshot_semantics(store, first.target_snapshot_id)

        second = await _index_commit(
            store,
            MAIN,
            changed,
            (VcsDelta(VcsDeltaKind.MODIFY, "src/service.py"),),
            NOW + timedelta(seconds=21),
        )
        assert await history_worker.run_once()
        await _link_snapshot_semantics(store, second.target_snapshot_id)
        second_context = await _context_for_snapshot(store, second.target_snapshot_id)
        with pytest.raises(IndexingConflictError, match="conflicts"):
            await lineage.execute(
                RegisterEvidenceLineageCommand(
                    registration.operation_id,
                    registration.scope,
                    second_context,
                    registration.evidence_id,
                    registration.assertion_id,
                    NOW + timedelta(seconds=22),
                )
            )

        await _index_commit(
            store,
            REVERT,
            original,
            (VcsDelta(VcsDeltaKind.MODIFY, "src/service.py"),),
            NOW + timedelta(seconds=41),
        )
        assert await history_worker.run_once()

        fourth = await _index_commit(
            store,
            DELETE,
            None,
            (VcsDelta(VcsDeltaKind.DELETE, "src/service.py"),),
            NOW + timedelta(seconds=51),
        )
        assert await history_worker.run_once()
        assert fourth.deleted_count == 1

        handler = QuerySourceRevisionHistoryHandler(
            graph,
            history_repository,
            FixedClock(NOW + timedelta(hours=1)),
        )
        main_history = await _history(handler, "main", NOW + timedelta(seconds=52))
        feature_history = await _history(handler, "feature", NOW + timedelta(seconds=52))
        revert_history = await _history(handler, "main", NOW + timedelta(seconds=42))

        assert [item.applicability for item in main_history] == [
            SourceRevisionApplicability.STALE,
            SourceRevisionApplicability.STALE,
            SourceRevisionApplicability.STALE,
            SourceRevisionApplicability.DELETED,
        ]
        assert len(feature_history) == 1
        assert feature_history[0].applicability is SourceRevisionApplicability.CURRENT
        assert len(revert_history) == 3
        assert revert_history[-1].applicability is SourceRevisionApplicability.CURRENT
        assert revert_history[-1].candidate.reintroduced_from_context_id == first_context
        assert revert_history[-1].candidate.file_revision_id != (
            revert_history[0].candidate.file_revision_id
        )

        truth = QueryTemporalAssertionsHandler(
            SqliteTemporalAssertionRepository(store),
            SqliteVcsRevisionRepository(store, FixedClock(NOW + timedelta(hours=1))),
        )
        assert await _truth(truth, "main", NOW + timedelta(seconds=22)) == ()
        assert len(await _truth(truth, "feature", NOW + timedelta(seconds=22))) == 1

        projection_worker = IndexProjectionWorker(
            SqliteIncrementalIndexRepository(store, FixedClock(NOW + timedelta(hours=1))),
            SqliteIndexProjectionConsumer(
                store,
                _Embeddings(),
                SqliteAssertionRepositoryFactory(store),
            ),
            FixedClock(NOW + timedelta(hours=1)),
        )
        while await projection_worker.run_once():
            pass
        assertion = (
            await SqliteAssertionRepositoryFactory(store)
            .assertions(graph_scope("graph.assertion.reconcile"))
            .get_assertion(ASSERTION_ID)
        )
        assert assertion is not None
        assert assertion.status is AssertionStatus.ACTIVE
    finally:
        await store.close()


def _process_handler(
    graph: SqliteCommitGraphAdapter,
    repository: SqliteSourceRevisionRepository,
) -> ProcessSourceRevisionHandler:
    return ProcessSourceRevisionHandler(graph, repository)


async def _record_history_graph(store: SqliteCoreStore) -> None:
    repository = SqliteVcsRevisionRepository(store, FixedClock(NOW + timedelta(hours=1)))
    scope = graph_scope("graph.vcs.revision.record")
    await repository.append(
        scope,
        _batch(
            "idx003-history-base",
            (VcsRevisionNode(ROOT, ()), VcsRevisionNode(BASE, (ROOT,))),
            (
                VcsRefObservation("feature", BASE, NOW + timedelta(seconds=10)),
                VcsRefObservation("main", BASE, NOW + timedelta(seconds=10)),
            ),
            (),
            NOW + timedelta(seconds=10),
        ),
    )
    await repository.append(
        scope,
        _batch(
            "idx003-history-change",
            (
                VcsRevisionNode(MAIN, (BASE,)),
                VcsRevisionNode(FEATURE, (BASE,)),
            ),
            (
                VcsRefObservation("feature", FEATURE, NOW + timedelta(seconds=20)),
                VcsRefObservation("main", MAIN, NOW + timedelta(seconds=20)),
            ),
            (),
            NOW + timedelta(seconds=20),
        ),
    )
    await repository.append(
        scope,
        _batch(
            "idx003-history-revert",
            (VcsRevisionNode(REVERT, (MAIN,)),),
            (VcsRefObservation("main", REVERT, NOW + timedelta(seconds=40)),),
            (),
            NOW + timedelta(seconds=40),
        ),
    )
    await repository.append(
        scope,
        _batch(
            "idx003-history-delete",
            (VcsRevisionNode(DELETE, (REVERT,)),),
            (VcsRefObservation("main", DELETE, NOW + timedelta(seconds=50)),),
            (),
            NOW + timedelta(seconds=50),
        ),
    )


async def _index_commit(
    store: SqliteCoreStore,
    commit_sha: str,
    content: bytes | None,
    deltas: tuple[VcsDelta, ...],
    detected_at: datetime,
) -> IndexRun:
    source = _Source(
        {} if content is None else {"src/service.py": content},
        commit_sha,
        _digest(f"working:{commit_sha}"),
        deltas,
        revision_context=IndexRevisionContext.COMMITTED,
    )
    repository = SqliteIncrementalIndexRepository(store, FixedClock(detected_at))
    run = await StartIndexRunHandler(source, _Fingerprints(), repository).execute(
        StartIndexRunCommand(
            operation_id=f"idx003-index-{commit_sha[0]}",
            scope=indexing_scope("indexing.run.start"),
            target_commit_id=commit_sha,
            include_generated=False,
            detected_at=detected_at,
        )
    )
    worker = IncrementalIndexWorker(
        source,
        TreeSitterLanguagePlugin(),
        repository,
        FixedClock(detected_at + timedelta(microseconds=1)),
    )
    assert await worker.run_once()
    return await repository.current(run.id)


async def _context_for_snapshot(store: SqliteCoreStore, snapshot_id: str) -> str:
    async with store.engine.connect() as connection:
        value = await connection.scalar(
            text("SELECT context_id FROM source_revision_contexts WHERE snapshot_id=:snapshot"),
            {"snapshot": snapshot_id},
        )
    assert value is not None
    return str(value)


async def _link_snapshot_semantics(store: SqliteCoreStore, snapshot_id: str) -> None:
    async with store.engine.begin() as connection:
        values = (
            await connection.execute(
                text(
                    "SELECT symbol.id FROM symbol_revisions AS symbol JOIN file_revisions AS file "
                    "ON file.id=symbol.file_revision_id WHERE file.snapshot_id=:snapshot"
                ),
                {"snapshot": snapshot_id},
            )
        ).scalars()
        for semantic_id in values:
            identity = _digest(f"dependency:{semantic_id}")
            await connection.execute(
                text(
                    "INSERT INTO index_semantic_dependencies "
                    "(dependency_id,repository_id,source_semantic_id,assertion_evidence_id,"
                    "registered_at,schema_version) VALUES "
                    "(:id,:repository,:semantic,:evidence,:at,1)"
                ),
                {
                    "id": identity,
                    "repository": REPOSITORY_ID.value,
                    "semantic": str(semantic_id),
                    "evidence": PROMPT_EVIDENCE_ID,
                    "at": round(NOW.timestamp() * 1_000_000),
                },
            )


async def _history(
    handler: QuerySourceRevisionHistoryHandler,
    branch_name: str,
    recorded_at: datetime,
) -> tuple[SourceRevisionHistoryEntry, ...]:
    scope = indexing_scope("indexing.revision.history.read")
    return await handler.execute(
        QuerySourceRevisionHistoryQuery(
            scope,
            REPOSITORY_ID.value,
            "src/service.py",
            recorded_at,
            branch_name=branch_name,
        )
    )


async def _truth(
    handler: QueryTemporalAssertionsHandler,
    branch_name: str,
    recorded_at: datetime,
) -> tuple[TemporalAssertionResult, ...]:
    return await handler.execute(
        QueryTemporalAssertionsQuery(
            graph_scope("graph.assertion.truth.query"),
            TruthTemporalScope.historical(
                as_of_recorded=recorded_at,
                revision=VcsRevisionSelector(
                    REPOSITORY_ID.value,
                    branch_name=branch_name,
                ),
            ),
        ),
        recorded_at,
    )
