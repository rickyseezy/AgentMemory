"""IDX-005 real SQLite, canonical graph, secrecy, replay, and temporal tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.domain.assertions import (
    AssertionEvidenceReference,
    AssertionStatus,
    EvidenceKind,
)
from agentmemory.graph.domain.models import GraphEntity, GraphWriteResult
from agentmemory.indexing.adapters.outbound.artifact_topology_graph import (
    CanonicalArtifactTopologyProjection,
)
from agentmemory.indexing.adapters.outbound.artifact_topology_plugins import (
    EnvironmentTemplateParser,
)
from agentmemory.indexing.adapters.outbound.sqlite_artifact_topology import (
    SqliteArtifactTopologyRepository,
)
from agentmemory.indexing.adapters.outbound.sqlite_revision_history import (
    SqliteCommitGraphAdapter,
    SqliteSourceRevisionRepository,
)
from agentmemory.indexing.application.artifact_topology import (
    RegisterArtifactTopologyBatchCommand,
    RegisterArtifactTopologyBatchHandler,
)
from agentmemory.indexing.application.revision_history import SourceRevisionWorker
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    ArtifactTopologyEvidence,
    ArtifactTopologySourceArtifact,
)
from agentmemory.indexing.domain.errors import IndexingConflictError
from tests.core.support import FixedClock, migrated_store
from tests.graph.test_gra001_domain_application import (
    _Repository as GraphRepository,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra002_sqlite_assertions import (
    ARTIFACT_EVENT_ID,
    ARTIFACT_EVIDENCE_ID,
    ARTIFACT_ID,
    NOW,
)
from tests.graph.test_gra002_sqlite_assertions import (
    _scope as graph_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra004_sqlite_temporal_truth import (
    _seed_active_assertion,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx003_sqlite_revision_history import (
    BASE,
    _context_for_snapshot,  # pyright: ignore[reportPrivateUsage]
    _index_commit,  # pyright: ignore[reportPrivateUsage]
    _process_handler,  # pyright: ignore[reportPrivateUsage]
    _record_history_graph,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx004_sqlite_api_topology import (
    _topology_evidence,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from agentmemory.graph.domain.ports import AuthorizedGraphQuery, GraphProjectionWriter
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.artifact_topology import TopologyRelationCandidate
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_RAW_SECRET = "idx005-raw-secret-must-never-persist"  # noqa: S105
_ERR_RELATIONSHIP = "IDX-005 projects relationships through canonical assertions"


@dataclass(slots=True)
class _GraphFactory:
    """Capture projected entities while satisfying the canonical graph port."""

    entities: list[GraphEntity] = field(default_factory=list[GraphEntity])

    def writer(self, scope: AuthorizedScope) -> GraphProjectionWriter:
        assert scope.action == "graph.project"
        return _GraphWriter(self.entities)

    def query(self, scope: AuthorizedScope) -> AuthorizedGraphQuery:
        del scope
        return GraphRepository()


@dataclass(slots=True)
class _GraphWriter:
    entities: list[GraphEntity]

    async def merge_entity(self, entity: GraphEntity) -> GraphWriteResult:
        self.entities.append(entity)
        return GraphWriteResult(
            stable_id=entity.id,
            revision_id=entity.revision_id,
            created=True,
        )

    async def merge_relationship(self, relationship: object) -> GraphWriteResult:
        del relationship
        raise AssertionError(_ERR_RELATIONSHIP)


@dataclass(frozen=True, slots=True)
class _Lineage:
    async def register(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        relation: TopologyRelationCandidate,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        del scope, operation_id, assertion_id, registered_at
        return relation.id


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_real_registration_is_append_only_secret_free_and_projects_active_assertions(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        evidence = await _seed_source_evidence(store)
        raw = f"PUBLIC_URL=https://localhost\nDATABASE_PASSWORD={_RAW_SECRET}\n".encode()
        batch = EnvironmentTemplateParser().parse(
            ArtifactTopologySourceArtifact(evidence, BASE, raw)
        )
        repository = SqliteArtifactTopologyRepository(store, FixedClock(NOW + timedelta(hours=1)))
        graph = _GraphFactory()
        projection = CanonicalArtifactTopologyProjection(
            store,
            graph,
            SqliteAssertionRepositoryFactory(store),
        )
        handler = RegisterArtifactTopologyBatchHandler(repository, projection, _Lineage())
        register_scope = indexing_scope("indexing.artifact_topology.register")
        command = RegisterArtifactTopologyBatchCommand(
            "idx005-register-real",
            register_scope,
            batch,
            NOW + timedelta(seconds=12),
        )

        assert await handler.execute(command) == batch
        assert await handler.execute(command) == batch
        with pytest.raises(IndexingConflictError, match="conflicts"):
            await handler.execute(
                RegisterArtifactTopologyBatchCommand(
                    command.operation_id,
                    command.scope,
                    ArtifactTopologyBatch(
                        batch.plugin_kind,
                        batch.plugin_version,
                        batch.source_revision_context_id,
                        batch.source_file_id,
                        batch.commit_sha,
                    ),
                    command.registered_at,
                )
            )

        read_scope = indexing_scope("indexing.artifact_topology.read")
        snapshot = await repository.snapshot(read_scope, NOW + timedelta(seconds=13))
        assert snapshot.candidates == batch.candidates
        assert snapshot.relations == batch.relations
        assert {item.environment_reference for item in snapshot.candidates} == {
            "DATABASE_PASSWORD",
            "PUBLIC_URL",
        }

        assert len(graph.entities) == len(batch.candidates) * 2
        async with store.engine.connect() as connection:
            assertion_ids = tuple(
                str(value)
                for value in (
                    await connection.execute(
                        text(
                            "SELECT assertion_id FROM artifact_topology_projection_receipts "
                            "ORDER BY assertion_id"
                        )
                    )
                ).scalars()
            )
        assertions = SqliteAssertionRepositoryFactory(store).assertions(
            graph_scope("graph.assertion.reconcile")
        )
        for assertion_id in assertion_ids:
            assertion = await assertions.get_assertion(assertion_id)
            assert assertion is not None
            assert assertion.status is AssertionStatus.ACTIVE

        empty = ArtifactTopologyBatch(
            batch.plugin_kind,
            batch.plugin_version,
            batch.source_revision_context_id,
            batch.source_file_id,
            batch.commit_sha,
        )
        await handler.execute(
            RegisterArtifactTopologyBatchCommand(
                "idx005-register-removal",
                register_scope,
                empty,
                NOW + timedelta(seconds=15),
            )
        )
        assert (await repository.snapshot(read_scope, NOW + timedelta(seconds=16))).candidates == ()
        assert (
            await repository.snapshot(read_scope, NOW + timedelta(seconds=14))
        ).candidates == batch.candidates

        await _assert_secret_absent_and_history_retained(store, batch)
    finally:
        await store.close()


async def _seed_source_evidence(store: SqliteCoreStore) -> ArtifactTopologyEvidence:
    await _seed_active_assertion(store)
    await (
        SqliteAssertionRepositoryFactory(store)
        .evidence_catalog(graph_scope("graph.assertion.evidence.register"))
        .register(
            AssertionEvidenceReference(
                ARTIFACT_EVIDENCE_ID,
                ARTIFACT_EVENT_ID,
                EvidenceKind.ARTIFACT,
                ARTIFACT_ID,
            ),
            NOW,
        )
    )
    await _record_history_graph(store)
    run = await _index_commit(
        store,
        BASE,
        b"def topology_fixture():\n    return 'placeholder'\n",
        (),
        NOW + timedelta(seconds=11),
    )
    history = SqliteSourceRevisionRepository(store, FixedClock(NOW + timedelta(hours=1)))
    worker = SourceRevisionWorker(
        _process_handler(SqliteCommitGraphAdapter(store), history),
        history,
        FixedClock(NOW + timedelta(minutes=1)),
    )
    assert await worker.run_once()
    context_id = await _context_for_snapshot(store, run.target_snapshot_id)
    source = await _topology_evidence(store, context_id)
    return ArtifactTopologyEvidence(
        source.brain_id,
        source.project_id,
        source.repository_id,
        source.source_file_id,
        source.source_revision_context_id,
        source.source_semantic_id,
        ARTIFACT_EVIDENCE_ID,
        source.relative_path,
        source.classification,
        source.observed_at,
    )


async def _assert_secret_absent_and_history_retained(
    store: SqliteCoreStore, batch: ArtifactTopologyBatch
) -> None:
    async with store.engine.connect() as connection:
        rows = (
            await connection.execute(
                text(
                    "SELECT candidate_id,name,version,environment_reference,sensitivity,"
                    "qualifiers_json FROM artifact_topology_candidates"
                )
            )
        ).all()
        batch_count = await connection.scalar(
            text("SELECT count(*) FROM artifact_topology_batches")
        )
        dependency_count = await connection.scalar(
            text(
                "SELECT count(*) FROM index_semantic_dependencies "
                "WHERE dependent_fact_id IN "
                "(SELECT candidate_id FROM artifact_topology_candidates UNION ALL "
                "SELECT relation_id FROM artifact_topology_relations)"
            )
        )
    serialized = repr(rows)
    assert _RAW_SECRET not in serialized
    assert "placeholder" not in serialized
    assert batch_count == 2
    assert dependency_count == len(batch.candidates) + len(batch.relations)
