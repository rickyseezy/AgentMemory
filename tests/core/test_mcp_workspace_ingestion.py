"""PF-005 production checkpoint-to-canonical-ingestion tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.identity.adapters.outbound.sqlite_retrieval_scope import (
    SqliteRelatedProjectGraph,
    SqliteRetrievalScopeAuthorizationRepository,
)
from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeHandler,
    ResolveRetrievalScopeQuery,
)
from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, RetrievalScopeMode
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.indexing.adapters.outbound.git_incremental_source import (
    LanguagePluginFingerprintProvider,
)
from agentmemory.indexing.adapters.outbound.sqlite_checkpoint_source import (
    SqliteCheckpointIncrementalRepositorySource,
)
from agentmemory.indexing.adapters.outbound.sqlite_incremental_index import (
    SqliteIncrementalIndexRepository,
)
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.application.incremental_index import (
    IncrementalIndexWorker,
    StartIndexRunHandler,
)
from agentmemory.indexing.domain.incremental import IndexRunState
from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAgentEventScopeResolver,
    SqliteAgentEventUnitOfWorkFactory,
)
from agentmemory.ingestion.adapters.outbound.sqlite_privacy import (
    SqliteCapturePolicyDecisionRepository,
    SqliteCapturePolicyRepository,
)
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
from agentmemory.ingestion.application.privacy import CapturePolicyPipeline
from agentmemory.operations.adapters.outbound.sqlite_mcp_session import (
    SqliteMcpSessionRepository,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.adapters.outbound.sqlite_workspace_checkpoint import (
    SqliteWorkspaceCheckpointRepository,
)
from agentmemory.operations.adapters.outbound.workspace_checkpoint_indexing import (
    WorkspaceCheckpointIndexProjection,
)
from agentmemory.operations.adapters.outbound.workspace_checkpoint_ingestion import (
    CanonicalWorkspaceCheckpointIngestor,
    SqlitePreparedWorkspaceChangeRepository,
)
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.application.mcp_session import (
    ReconcileWorkspaceCheckpointHandler,
    StageWorkspaceCheckpointHandler,
)
from agentmemory.operations.domain.mcp_session import McpGitCoverage, McpSessionRegistration
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
    WorkspaceIndexCoverage,
)
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    INSTALLATION_ID,
    NOW,
    OWNER_ID,
    FixedClock,
    bootstrap_request,
    digest,
    migrated_store,
    write_secret,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_SESSION_ID = Uuid7Id("019f4d50-4160-7902-b2a0-7c164ae2549f")
_PROJECT_ID = Uuid7Id("019f4d50-4161-7902-b2a0-7c164ae2549f")
_REPOSITORY_ID = Uuid7Id("019f4d50-4162-7902-b2a0-7c164ae2549f")
_SECRET = b'token = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'


def _registration() -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=_SESSION_ID,
        installation_id=Uuid7Id(INSTALLATION_ID),
        brain_id=Uuid7Id(BRAIN_ID),
        actor_id=Uuid7Id(OWNER_ID),
        grant_id=Uuid7Id(GRANT_ID),
        agent_id="codex",
        workspace_fingerprint=digest("workspace-ingestion"),
        device_identity="dev:1",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=1,
        credential_digest=digest("workspace-ingestion-credential"),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        project_id=_PROJECT_ID,
        repository_id=_REPOSITORY_ID,
    )


def _batch() -> WorkspaceCheckpointBatch:
    changes = (
        _change(".env.local", b"PASSWORD=hunter22\n"),
        WorkspaceCheckpointChange(
            relative_path="deleted.txt",
            sha256=Sha256Digest(hashlib.sha256(b"previous").hexdigest()),
            content=b"",
            deleted=True,
        ),
        _change("src/main.py", _SECRET),
    )
    document = {
        "session_id": _SESSION_ID.value,
        "workspace_fingerprint": digest("workspace-ingestion").value,
        "batch_digest": "",
        "partial": False,
        "changes": [change.document() for change in changes],
    }
    canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    return WorkspaceCheckpointBatch(
        session_id=_SESSION_ID,
        workspace_fingerprint=digest("workspace-ingestion"),
        batch_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        partial=False,
        changes=changes,
    )


def _custom_batch(
    changes: tuple[WorkspaceCheckpointChange, ...],
    *,
    partial: bool = False,
) -> WorkspaceCheckpointBatch:
    document = {
        "session_id": _SESSION_ID.value,
        "workspace_fingerprint": digest("workspace-ingestion").value,
        "batch_digest": "",
        "partial": partial,
        "changes": [change.document() for change in changes],
    }
    canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    return WorkspaceCheckpointBatch(
        session_id=_SESSION_ID,
        workspace_fingerprint=digest("workspace-ingestion"),
        batch_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        partial=partial,
        changes=changes,
    )


def _change(relative_path: str, content: bytes) -> WorkspaceCheckpointChange:
    return WorkspaceCheckpointChange(
        relative_path=relative_path,
        sha256=Sha256Digest(hashlib.sha256(content).hexdigest()),
        content=content,
        deleted=False,
    )


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects "
                "(id,brain_id,name,manifest_key,status,version,created_at,updated_at) "
                "VALUES (:id,:brain,'PF-005',:manifest,'active',1,1,1)"
            ),
            {
                "id": _PROJECT_ID.value,
                "brain": BRAIN_ID,
                "manifest": bytes.fromhex(digest("pf005-manifest").value),
            },
        )
        await connection.execute(
            text(
                "INSERT INTO repositories "
                "(id,brain_id,vcs_type,root_fingerprint,primary_remote_fingerprint,status,"
                "created_at,updated_at) VALUES "
                "(:id,:brain,'none',:root,NULL,'active',1,1)"
            ),
            {
                "id": _REPOSITORY_ID.value,
                "brain": BRAIN_ID,
                "root": bytes.fromhex(digest("pf005-root").value),
            },
        )
        await connection.execute(
            text(
                "INSERT INTO project_repositories "
                "(project_id,repository_id,relation_type,created_at,updated_at) "
                "VALUES (:project,:repository,'primary',1,1)"
            ),
            {"project": _PROJECT_ID.value, "repository": _REPOSITORY_ID.value},
        )


def _ingestor(store: SqliteCoreStore, key_file: Path) -> CanonicalWorkspaceCheckpointIngestor:
    clock = FixedClock()
    keys = SqliteWrappedBrainKeyProvider(store, key_file, clock)
    return CanonicalWorkspaceCheckpointIngestor(
        SqlitePreparedWorkspaceChangeRepository(store, keys, clock),
        CapturePolicyPipeline(SqliteCapturePolicyRepository(store)),
        SqliteCapturePolicyDecisionRepository(store),
        SqliteAgentEventScopeResolver(store.engine, clock),
        AppendAgentEventHandler(
            CanonicalAgentEventEncoder(),
            AesGcmAgentEventEncryptor(keys),
            SqliteAgentEventUnitOfWorkFactory(store, clock),
        ),
        clock,
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_pf005_checkpoint_becomes_encrypted_canonical_events_and_replays(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-root-key"
    write_secret(key_file, b"w" * 32)
    try:
        await _seed(store)
        sessions = SqliteMcpSessionRepository(store)
        registration = _registration()
        await sessions.register(registration)
        registered = await sessions.get(_SESSION_ID)
        assert registered is not None
        await sessions.save(registered, registered.begin(NOW, timedelta(seconds=120)))
        repository = SqliteWorkspaceCheckpointRepository(store, key_file, FixedClock())
        batch = _batch()
        assert await StageWorkspaceCheckpointHandler(sessions, repository).execute(batch)
        ingestor = _ingestor(store, key_file)

        first = await ingestor.ingest(batch, registration)
        replay = await ingestor.ingest(batch, registration)

        assert replay == first
        assert first.event_count == 2
        assert await repository.acknowledge(batch.batch_digest, first)
        assert (
            await ReconcileWorkspaceCheckpointHandler(
                sessions,
                repository,
                ingestor,
                _Projector(),
            ).execute()
            == 0
        )
        prepared = await ingestor.preparations.load(
            batch,
            registration,
            2,
            batch.changes[2],
        )
        assert prepared is not None
        assert prepared.artifact_content == b'token = "[REDACTED:SECRET]"\n'
        async with store.engine.connect() as connection:
            dispositions = tuple(
                (
                    await connection.execute(
                        text(
                            "SELECT disposition FROM mcp_workspace_checkpoint_changes "
                            "ORDER BY ordinal"
                        )
                    )
                ).scalars()
            )
            event_types = tuple(
                (
                    await connection.execute(
                        text(
                            "SELECT e.type FROM agent_events e JOIN agent_event_envelopes x "
                            "ON x.event_id=e.event_id ORDER BY x.sequence"
                        )
                    )
                ).scalars()
            )
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM agent_events),"
                        "(SELECT COUNT(*) FROM mcp_workspace_checkpoint_changes),"
                        "(SELECT COUNT(*) FROM privacy_decisions),"
                        "(SELECT COUNT(*) FROM mcp_workspace_checkpoint_receipts)"
                    )
                )
            ).one()
        assert dispositions == ("excluded", "event", "event")
        assert event_types == (
            "agentmemory.file.deleted.v1",
            "agentmemory.file.changed.v1",
        )
        assert tuple(counts) == (2, 3, 3, 1)
        database_bytes = (tmp_path / "agentmemory.sqlite3").read_bytes()
        assert _SECRET not in database_bytes
        assert b"[REDACTED:SECRET]" not in database_bytes
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_reconciler_ingests_and_acknowledges_a_pending_batch(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-root-key"
    write_secret(key_file, b"x" * 32)
    try:
        await _seed(store)
        sessions = SqliteMcpSessionRepository(store)
        registration = _registration()
        await sessions.register(registration)
        registered = await sessions.get(_SESSION_ID)
        assert registered is not None
        await sessions.save(registered, registered.begin(NOW, timedelta(seconds=120)))
        checkpoints = SqliteWorkspaceCheckpointRepository(store, key_file, FixedClock())
        ingestor = _ingestor(store, key_file)
        source = SqliteCheckpointIncrementalRepositorySource(store, ingestor.preparations)
        index_repository = SqliteIncrementalIndexRepository(store, FixedClock())
        plugin = TreeSitterLanguagePlugin(frozenset({"python"}))
        start = StartIndexRunHandler(
            source,
            LanguagePluginFingerprintProvider(
                plugin,
                language_lock_digest=hashlib.sha256(b"pf005-language-lock").hexdigest(),
                extraction_config_digest=hashlib.sha256(b"pf005-extraction").hexdigest(),
                privacy_policy_version="capture-policy-v1",
            ),
            index_repository,
        )
        projector = WorkspaceCheckpointIndexProjection(
            ResolveRetrievalScopeHandler(
                SqliteRetrievalScopeAuthorizationRepository(store.engine),
                SqliteRelatedProjectGraph(store.engine),
            ),
            start,
            FixedClock(),
        )
        assert await checkpoints.coverage(_SESSION_ID) is WorkspaceIndexCoverage.PENDING
        batch = _batch()
        await StageWorkspaceCheckpointHandler(sessions, checkpoints).execute(batch)
        assert await checkpoints.coverage(_SESSION_ID) is WorkspaceIndexCoverage.INDEXING
        reconciled = await ReconcileWorkspaceCheckpointHandler(
            sessions,
            checkpoints,
            ingestor,
            projector,
        ).execute()

        assert reconciled == 1
        assert await checkpoints.pending(1) == ()
        assert await checkpoints.coverage(_SESSION_ID) is WorkspaceIndexCoverage.INDEXING
        worker = IncrementalIndexWorker(source, plugin, index_repository, FixedClock())
        assert await worker.run_once()
        first = await index_repository.latest_completed(await _index_scope(store, registration))
        assert first is not None
        assert tuple(item.relative_path for item in first.units) == ("src/main.py",)
        assert first.snapshot.commit_id == batch.batch_digest.value
        assert (
            first.units[0].content_digest
            == hashlib.sha256(b'token = "[REDACTED:SECRET]"\n').hexdigest()
        )
        assert await checkpoints.coverage(_SESSION_ID) is WorkspaceIndexCoverage.COMPLETE

        await _assert_partial_incremental_update(
            _IncrementalScenario(
                store,
                sessions,
                checkpoints,
                ingestor,
                projector,
                worker,
                index_repository,
                registration,
            )
        )
    finally:
        await store.close()


@dataclass(frozen=True, slots=True)
class _IncrementalScenario:
    store: SqliteCoreStore
    sessions: SqliteMcpSessionRepository
    checkpoints: SqliteWorkspaceCheckpointRepository
    ingestor: CanonicalWorkspaceCheckpointIngestor
    projector: WorkspaceCheckpointIndexProjection
    worker: IncrementalIndexWorker
    index_repository: SqliteIncrementalIndexRepository
    registration: McpSessionRegistration


async def _assert_partial_incremental_update(scenario: _IncrementalScenario) -> None:
    second = _custom_batch(
        (
            WorkspaceCheckpointChange(
                "src/main.py",
                Sha256Digest(hashlib.sha256(_SECRET).hexdigest()),
                b"",
                deleted=True,
            ),
            _change("src/service.py", b"def serve():\n    return True\n"),
        ),
        partial=True,
    )
    await StageWorkspaceCheckpointHandler(scenario.sessions, scenario.checkpoints).execute(second)
    assert (
        await ReconcileWorkspaceCheckpointHandler(
            scenario.sessions,
            scenario.checkpoints,
            scenario.ingestor,
            scenario.projector,
        ).execute()
        == 1
    )
    assert await scenario.worker.run_once()
    latest = await scenario.index_repository.latest_completed(
        await _index_scope(scenario.store, scenario.registration)
    )
    assert latest is not None
    assert tuple(item.relative_path for item in latest.units) == ("src/service.py",)
    assert latest.snapshot.commit_id == second.batch_digest.value
    assert await scenario.checkpoints.coverage(_SESSION_ID) is WorkspaceIndexCoverage.PARTIAL
    await scenario.projector.project(second, scenario.registration)
    async with scenario.store.engine.connect() as connection:
        states = tuple(
            (
                await connection.execute(
                    text(
                        "SELECT state FROM incremental_index_run_snapshots "
                        "WHERE snapshot_version=(SELECT MAX(n.snapshot_version) FROM "
                        "incremental_index_run_snapshots n WHERE n.run_id="
                        "incremental_index_run_snapshots.run_id) ORDER BY run_id"
                    )
                )
            ).scalars()
        )
        run_count = (
            await connection.execute(text("SELECT COUNT(*) FROM incremental_index_runs"))
        ).scalar_one()
    assert states == (IndexRunState.COMPLETED.value, IndexRunState.COMPLETED.value)
    assert run_count == 2


@dataclass(slots=True)
class _Projector:
    calls: list[tuple[WorkspaceCheckpointBatch, McpSessionRegistration]] = field(
        default_factory=list[tuple[WorkspaceCheckpointBatch, McpSessionRegistration]]
    )

    async def project(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> None:
        self.calls.append((batch, registration))


async def _index_scope(
    store: SqliteCoreStore,
    registration: McpSessionRegistration,
) -> AuthorizedScope:
    resolver = ResolveRetrievalScopeHandler(
        SqliteRetrievalScopeAuthorizationRepository(store.engine),
        SqliteRelatedProjectGraph(store.engine),
    )
    resolution = await resolver.execute(
        ResolveRetrievalScopeQuery(
            "pf005-test-index-scope",
            StableId(registration.brain_id.value),
            StableId(registration.actor_id.value),
            StableId(registration.grant_id.value),
            RetrievalScopeMode.CURRENT,
            StableId(_PROJECT_ID.value),
            StableId(_REPOSITORY_ID.value),
            None,
            (),
            int(NOW.timestamp() * 1_000_000),
        )
    )
    scope = resolution.scope
    return AuthorizedScope.create(
        brain_id=scope.brain_id,
        principal_id=scope.principal_id,
        role=scope.role,
        mode=scope.mode,
        members=scope.members,
        classification_ceiling=scope.classification_ceiling,
        temporal_scope=scope.temporal_scope,
        grant_version=scope.grant_version,
        policy_version=scope.policy_version,
        security_epoch=scope.security_epoch,
        action="indexing.run.start",
        purpose="automatic_indexing",
    )
