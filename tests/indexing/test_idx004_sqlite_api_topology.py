"""IDX-004 real SQLite registration, linking, replay, and lineage integration tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
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
from agentmemory.indexing.adapters.outbound.api_topology_graph import (
    SourceRevisionTopologyLineageAdapter,
    SqliteConsumesAssertionAdapter,
)
from agentmemory.indexing.adapters.outbound.sqlite_api_topology import (
    SqliteApiTopologyRepository,
)
from agentmemory.indexing.adapters.outbound.sqlite_revision_history import (
    SqliteCommitGraphAdapter,
    SqliteSourceRevisionRepository,
)
from agentmemory.indexing.application.api_topology import (
    LinkApiTopologyCommand,
    LinkApiTopologyHandler,
    RegisterApiTopologyBatchCommand,
    RegisterApiTopologyBatchHandler,
)
from agentmemory.indexing.application.revision_history import SourceRevisionWorker
from agentmemory.indexing.domain.api_topology import (
    ApiMatchDisposition,
    ApiMatchRule,
    ApiProtocol,
    ApiTopologyCandidateBatch,
    ApiTopologyEvidence,
    ApiTopologyPluginKind,
    ClientCallCandidate,
    ContractBindingCandidate,
    EndpointCandidate,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
)
from tests.core.support import FixedClock, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    ARTIFACT_EVENT_ID,
    ARTIFACT_EVIDENCE_ID,
    ARTIFACT_ID,
    ASSERTION_ID,
    NOW,
    PROMPT_EVIDENCE_ID,
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

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.api_topology import ApiTopologyMatch
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

CLIENT_ENTITY = "018f0000-0000-7000-8000-000000000410"
ENDPOINT_ENTITY = "018f0000-0000-7000-8000-000000000411"


def _empty_matches() -> list[ApiTopologyMatch]:
    return []


def _empty_strings() -> list[str]:
    return []


@dataclass(slots=True)
class _Assertions:
    matches: list[ApiTopologyMatch] = field(default_factory=_empty_matches)

    async def record(
        self, scope: AuthorizedScope, match: ApiTopologyMatch, occurred_at: datetime
    ) -> str:
        del scope, occurred_at
        self.matches.append(match)
        return ASSERTION_ID


@dataclass(slots=True)
class _Lineage:
    evidence_ids: list[str] = field(default_factory=_empty_strings)

    async def register(  # noqa: PLR0913
        self,
        scope: AuthorizedScope,
        operation_id: str,
        source_revision_context_id: str,
        source_semantic_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        del (
            scope,
            operation_id,
            source_revision_context_id,
            source_semantic_id,
            assertion_id,
            registered_at,
        )
        self.evidence_ids.append(evidence_id)
        return evidence_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_complete_batch_links_persists_replays_and_registers_stale_dependencies(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
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
            b"def get_user(user_id):\n    return user_id\n",
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
        evidence = await _topology_evidence(store, context_id)
        endpoint = EndpointCandidate(
            evidence,
            ENDPOINT_ENTITY,
            ApiProtocol.REST,
            "user-api",
            "GET",
            "/users/{}",
            "users.get",
        )
        client = ClientCallCandidate(
            evidence,
            CLIENT_ENTITY,
            ApiProtocol.REST,
            "GET",
            "/users/{}",
            "users.get",
            "UsersClient.get",
            "user-api",
        )
        contract = ContractBindingCandidate(
            evidence,
            ApiProtocol.REST,
            "users.get",
            "user-api",
            "GET",
            "/users/{}",
            ("UsersClient.get",),
        )
        batch = ApiTopologyCandidateBatch(
            ApiTopologyPluginKind.SOURCE_CALLS,
            "v1.0.0",
            context_id,
            evidence.source_file_id,
            BASE,
            (endpoint,),
            (client,),
            (contract,),
        )
        repository = SqliteApiTopologyRepository(store, FixedClock(NOW + timedelta(hours=1)))
        registration = RegisterApiTopologyBatchHandler(repository)
        register_scope = indexing_scope("indexing.api_topology.register")
        command = RegisterApiTopologyBatchCommand(
            "idx004-register",
            register_scope,
            batch,
            NOW + timedelta(seconds=12),
        )
        assert await registration.execute(command) == batch
        assert await registration.execute(command) == batch

        assertions = _Assertions()
        lineage = _Lineage()
        linker = LinkApiTopologyHandler(repository, assertions, lineage)
        link_scope = indexing_scope("indexing.api_topology.link")
        link = LinkApiTopologyCommand(
            "idx004-link",
            link_scope,
            client.id,
            NOW + timedelta(seconds=13),
        )
        decision = await linker.execute(link)
        replay = await linker.execute(link)

        assert replay == decision
        assert decision.matches[0].rule is ApiMatchRule.CONTRACT_OPERATION
        assert decision.matches[0].disposition is ApiMatchDisposition.CONFIRMED
        assert assertions.matches == [decision.matches[0]]
        assert lineage.evidence_ids == [PROMPT_EVIDENCE_ID, PROMPT_EVIDENCE_ID]
        async with store.engine.connect() as connection:
            dependency_count = await connection.scalar(
                text(
                    "SELECT count(*) FROM index_semantic_dependencies "
                    "WHERE source_semantic_id=:semantic"
                ),
                {"semantic": evidence.source_semantic_id},
            )
            receipt = await connection.scalar(
                text("SELECT assertion_id FROM api_topology_match_decisions WHERE match_id=:match"),
                {"match": decision.matches[0].id},
            )
        assert dependency_count == 3
        assert receipt == ASSERTION_ID

        graph_adapter = SqliteConsumesAssertionAdapter(
            store, SqliteAssertionRepositoryFactory(store)
        )
        graph_match = replace(
            decision.matches[0],
            server_evidence_id=ARTIFACT_EVIDENCE_ID,
            supporting_evidence_ids=tuple(sorted((PROMPT_EVIDENCE_ID, ARTIFACT_EVIDENCE_ID))),
        )
        graph_assertion_id = await graph_adapter.record(
            link_scope, graph_match, NOW + timedelta(seconds=13, microseconds=1)
        )
        assert (
            await graph_adapter.record(
                link_scope,
                replace(graph_match, disposition=ApiMatchDisposition.QUALIFIED),
                NOW + timedelta(seconds=13, microseconds=1),
            )
            == graph_assertion_id
        )
        with pytest.raises(IndexingConflictError, match="unavailable"):
            await graph_adapter.record(
                link_scope,
                replace(
                    graph_match,
                    client_call_id="f" * 64,
                    supporting_candidate_ids=tuple(
                        sorted(
                            "f" * 64 if item == graph_match.client_call_id else item
                            for item in graph_match.supporting_candidate_ids
                        )
                    ),
                ),
                NOW + timedelta(seconds=13, microseconds=1),
            )
        graph_assertion = (
            await SqliteAssertionRepositoryFactory(store)
            .assertions(indexing_scope("graph.assertion.reconcile"))
            .get_assertion(graph_assertion_id)
        )
        assert graph_assertion is not None
        assert graph_assertion.status is AssertionStatus.ACTIVE
        lineage_digest = await SourceRevisionTopologyLineageAdapter(history).register(
            link_scope,
            "idx004-real-lineage",
            context_id,
            evidence.source_semantic_id,
            PROMPT_EVIDENCE_ID,
            graph_assertion_id,
            NOW + timedelta(seconds=13, microseconds=2),
        )
        assert len(lineage_digest) == 64

        empty = ApiTopologyCandidateBatch(
            ApiTopologyPluginKind.SOURCE_CALLS,
            "v1.0.0",
            context_id,
            evidence.source_file_id,
            BASE,
        )
        await registration.execute(
            RegisterApiTopologyBatchCommand(
                "idx004-register-removal",
                register_scope,
                empty,
                NOW + timedelta(seconds=14),
            )
        )
        with pytest.raises(IndexingAuthorizationError, match="not authorized"):
            await repository.load_link_universe(link_scope, client.id, NOW + timedelta(seconds=15))

        with pytest.raises(IndexingConflictError, match="conflicts"):
            await registration.execute(
                RegisterApiTopologyBatchCommand(
                    command.operation_id,
                    command.scope,
                    ApiTopologyCandidateBatch(
                        ApiTopologyPluginKind.SOURCE_CALLS,
                        "v1.0.0",
                        context_id,
                        evidence.source_file_id,
                        BASE,
                    ),
                    command.registered_at,
                )
            )
    finally:
        await store.close()


async def _topology_evidence(store: SqliteCoreStore, context_id: str) -> ApiTopologyEvidence:
    async with store.engine.connect() as connection:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT context.*,semantic.id AS semantic_id FROM "
                        "source_revision_contexts AS context JOIN "
                        "(SELECT id,file_revision_id FROM symbol_revisions UNION ALL "
                        "SELECT id,file_revision_id FROM symbol_occurrences) AS semantic "
                        "ON semantic.file_revision_id=context.file_revision_id "
                        "WHERE context.context_id=:context ORDER BY semantic.id LIMIT 1"
                    ),
                    {"context": context_id},
                )
            )
            .mappings()
            .one()
        )
    return ApiTopologyEvidence(
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        str(row["source_file_id"]),
        context_id,
        str(row["semantic_id"]),
        PROMPT_EVIDENCE_ID,
        str(row["relative_path"]),
        "internal",
        NOW,
    )
