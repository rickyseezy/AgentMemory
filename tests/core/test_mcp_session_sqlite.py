"""PF-005 real SQLite credential and session lifecycle integration tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from agentmemory.operations.adapters.outbound.sqlite_mcp_session import (
    SqliteMcpSessionRepository,
)
from agentmemory.operations.adapters.outbound.sqlite_mcp_workspace_scope import (
    SqliteMcpWorkspaceScopeProvisioner,
    SqliteMcpWorkspaceScopeResolver,
)
from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.adapters.outbound.sqlite_workspace_checkpoint import (
    SqliteWorkspaceCheckpointRepository,
)
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.application.mcp_session import (
    McpSessionLifecycleHandler,
    ReconcileWorkspaceCheckpointHandler,
    RegisterMcpSessionCredentialHandler,
    StageWorkspaceCheckpointHandler,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSessionRegistration,
    McpSessionState,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
    WorkspaceCheckpointIngestionResult,
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

_SESSION_ID = Uuid7Id("019f4d50-4154-7902-b2a0-7c164ae2549f")


async def _bootstrap(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )


def _registration(
    *,
    session_id: Uuid7Id = _SESSION_ID,
    credential: Sha256Digest | None = None,
    security_epoch: int = 1,
) -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=session_id,
        installation_id=Uuid7Id(INSTALLATION_ID),
        brain_id=Uuid7Id(BRAIN_ID),
        actor_id=Uuid7Id(OWNER_ID),
        grant_id=Uuid7Id(GRANT_ID),
        agent_id="codex",
        workspace_fingerprint=digest("workspace"),
        device_identity="dev:1",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=security_epoch,
        credential_digest=credential or digest("session-credential"),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _checkpoint() -> WorkspaceCheckpointBatch:
    content = b"package brain\n"
    change = WorkspaceCheckpointChange(
        relative_path="internal/brain.go",
        sha256=Sha256Digest(hashlib.sha256(content).hexdigest()),
        content=content,
        deleted=False,
    )
    canonical = json.dumps(
        {
            "session_id": _SESSION_ID.value,
            "workspace_fingerprint": digest("workspace").value,
            "batch_digest": "",
            "partial": False,
            "changes": [change.document()],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return WorkspaceCheckpointBatch(
        session_id=_SESSION_ID,
        workspace_fingerprint=digest("workspace"),
        batch_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        partial=False,
        changes=(change,),
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_sqlite_round_trip_is_idempotent_append_only_and_audited(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        repository = SqliteMcpSessionRepository(store)
        register = RegisterMcpSessionCredentialHandler(
            repository,
            SqliteMcpWorkspaceScopeResolver(store),
            SqliteMcpWorkspaceScopeProvisioner(store, FixedClock()),
        )
        lifecycle = McpSessionLifecycleHandler(repository)

        initial, created = await register.execute(_registration())
        replay, replay_created = await register.execute(_registration())
        assert (
            await repository.authorize(
                _registration().credential_digest,
                _SESSION_ID,
                NOW,
            )
            == initial
        )
        assert await repository.authorize(digest("wrong"), _SESSION_ID, NOW) is None
        active = await lifecycle.begin(_SESSION_ID, NOW, timedelta(seconds=120))
        heartbeat = await lifecycle.heartbeat(_SESSION_ID, NOW + timedelta(seconds=30))
        revoked, changed = await lifecycle.revoke(
            _registration().credential_digest,
            NOW + timedelta(seconds=31),
        )
        completed = await lifecycle.finish(
            _SESSION_ID,
            McpSessionState.COMPLETED,
            NOW + timedelta(seconds=32),
        )

        assert created
        assert not replay_created
        assert replay == initial
        assert active.state is McpSessionState.ACTIVE
        assert heartbeat.revision == 2
        assert revoked is not None
        assert changed
        assert (
            await repository.authorize(
                _registration().credential_digest,
                _SESSION_ID,
                NOW + timedelta(seconds=31),
            )
            is None
        )
        assert revoked.revoked_at == NOW + timedelta(seconds=31)
        assert completed.state is McpSessionState.COMPLETED
        assert await repository.get(_SESSION_ID) == completed
        assert await repository.get_by_credential(_registration().credential_digest) == completed
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM mcp_session_credentials"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM mcp_session_snapshots"))
            ).scalar_one() == 5
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM audit_events WHERE action LIKE 'mcp.session.%'")
                )
            ).scalar_one() == 5
        with pytest.raises(DBAPIError, match="immutable"):
            async with store.engine.begin() as connection:
                await connection.execute(
                    text("UPDATE mcp_session_snapshots SET state='interrupted'")
                )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_sqlite_rejects_conflicting_authority_and_stale_epoch(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        repository = SqliteMcpSessionRepository(store)
        await repository.register(_registration())
        with pytest.raises(OperationError) as collision:
            await repository.register(
                replace(_registration(), workspace_fingerprint=digest("other-workspace"))
            )
        assert collision.value.code is ErrorCode.CONFLICT
        with pytest.raises(OperationError) as stale:
            await repository.register(
                _registration(
                    session_id=Uuid7Id("019f4d50-4155-7902-b2a0-7c164ae2549f"),
                    credential=digest("other-credential"),
                    security_epoch=2,
                )
            )
        assert stale.value.code is ErrorCode.FORBIDDEN

        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:revoked WHERE id=:grant"),
                {
                    "revoked": round((NOW + timedelta(seconds=1)).timestamp() * 1_000_000),
                    "grant": GRANT_ID,
                },
            )
        assert (
            await repository.authorize(
                _registration().credential_digest,
                _SESSION_ID,
                NOW + timedelta(seconds=2),
            )
            is None
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_sqlite_recovers_expired_session_and_rejects_divergent_writers(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        repository = SqliteMcpSessionRepository(store)
        await repository.register(_registration())
        registered = await repository.get(_SESSION_ID)
        assert registered is not None
        active = registered.begin(NOW, timedelta(seconds=120))
        await repository.save(registered, active)

        first = active.heartbeat(NOW + timedelta(seconds=10))
        second = active.heartbeat(NOW + timedelta(seconds=11))
        results = await asyncio.gather(
            repository.save(active, first),
            repository.save(active, second),
            return_exceptions=True,
        )
        assert sum(isinstance(result, OperationError) for result in results) == 1
        assert sum(result is None for result in results) == 1

        recovered = await McpSessionLifecycleHandler(repository).recover_expired(
            NOW + timedelta(seconds=132)
        )
        assert len(recovered) == 1
        assert recovered[0].state is McpSessionState.INTERRUPTED
        assert recovered[0].revoked_at == NOW + timedelta(seconds=132)
        assert (
            await McpSessionLifecycleHandler(repository).recover_expired(
                NOW + timedelta(seconds=133)
            )
            == ()
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_sqlite_reconciles_cross_process_registration_races(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    database = Path(str(store.engine.url.database))
    peer = SqliteCoreStore.create(database, store.policy)
    try:
        await _bootstrap(store)
        first = SqliteMcpSessionRepository(store)
        second = SqliteMcpSessionRepository(peer)

        results = await asyncio.gather(
            first.register(_registration()),
            second.register(_registration()),
        )

        assert sorted(created for _, created in results) == [False, True]
        assert results[0][0] == results[1][0]
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM mcp_session_credentials"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM mcp_session_snapshots"))
            ).scalar_one() == 1
    finally:
        await peer.close()
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_registration_resolves_one_governed_workspace_scope(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    project_id = "019f4d50-4156-7902-b2a0-7c164ae2549f"
    repository_id = "019f4d50-4157-7902-b2a0-7c164ae2549f"
    checkout_id = "019f4d50-4158-7902-b2a0-7c164ae2549f"
    repository_fingerprint = digest("repository")
    worktree_fingerprint = digest("worktree")
    try:
        await _bootstrap(store)
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO devices (id,device_fingerprint,status,created_at,updated_at) "
                    "VALUES (:id,:fingerprint,'verified',1,1)"
                ),
                {"id": INSTALLATION_ID, "fingerprint": bytes.fromhex(digest("device").value)},
            )
            await connection.execute(
                text(
                    "INSERT INTO projects "
                    "(id,brain_id,name,manifest_key,status,version,created_at,updated_at) "
                    "VALUES (:id,:brain,'project',:manifest,'active',1,1,1)"
                ),
                {
                    "id": project_id,
                    "brain": BRAIN_ID,
                    "manifest": bytes.fromhex(digest("manifest").value),
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO repositories "
                    "(id,brain_id,vcs_type,root_fingerprint,primary_remote_fingerprint,status,"
                    "created_at,updated_at) VALUES "
                    "(:id,:brain,'git',:root,NULL,'active',1,1)"
                ),
                {
                    "id": repository_id,
                    "brain": BRAIN_ID,
                    "root": bytes.fromhex(digest("root").value),
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO repository_fingerprints "
                    "(brain_id,repository_id,algorithm,fingerprint,evidence_json,active,"
                    "created_at,updated_at) VALUES "
                    "(:brain,:repository,'McpGitRepositoryFingerprintV1',:fingerprint,'{}',1,1,1)"
                ),
                {
                    "brain": BRAIN_ID,
                    "repository": repository_id,
                    "fingerprint": bytes.fromhex(repository_fingerprint.value),
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO project_repositories "
                    "(project_id,repository_id,relation_type,created_at,updated_at) "
                    "VALUES (:project,:repository,'primary',1,1)"
                ),
                {"project": project_id, "repository": repository_id},
            )
            await connection.execute(
                text(
                    "INSERT INTO checkouts "
                    "(id,brain_id,repository_id,device_id,canonical_path_hash,"
                    "checkout_fingerprint,worktree_id,branch,head_commit,last_seen_at,status,"
                    "created_at,updated_at,version) VALUES "
                    "(:id,:brain,:repository,:device,:path,NULL,:worktree,NULL,NULL,1,'active',"
                    "1,1,1)"
                ),
                {
                    "id": checkout_id,
                    "brain": BRAIN_ID,
                    "repository": repository_id,
                    "device": INSTALLATION_ID,
                    "path": bytes.fromhex(digest("workspace").value),
                    "worktree": bytes.fromhex(worktree_fingerprint.value),
                },
            )
        repository = SqliteMcpSessionRepository(store)
        handler = RegisterMcpSessionCredentialHandler(
            repository,
            SqliteMcpWorkspaceScopeResolver(store),
            SqliteMcpWorkspaceScopeProvisioner(store, FixedClock()),
        )
        registration = replace(
            _registration(),
            git_repository_id=repository_fingerprint.value,
            git_worktree_id=worktree_fingerprint.value,
            git_coverage=McpGitCoverage.PARTIAL,
        )

        session, created = await handler.execute(registration)

        assert created
        assert session.registration.project_id == Uuid7Id(project_id)
        assert session.registration.repository_id == Uuid7Id(repository_id)
        assert session.registration.checkout_id == Uuid7Id(checkout_id)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_registration_provisions_new_directory_once_without_raw_identity(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        repository = SqliteMcpSessionRepository(store)
        handler = RegisterMcpSessionCredentialHandler(
            repository,
            SqliteMcpWorkspaceScopeResolver(store),
            SqliteMcpWorkspaceScopeProvisioner(store, FixedClock()),
        )

        first, created = await handler.execute(_registration())
        second_registration = replace(
            _registration(),
            session_id=Uuid7Id("019f4d50-4163-7902-b2a0-7c164ae2549f"),
            credential_digest=digest("second-session-credential"),
        )
        second, second_created = await handler.execute(second_registration)

        assert created
        assert second_created
        assert first.registration.project_id is not None
        assert first.registration.repository_id is not None
        assert first.registration.checkout_id is not None
        assert second.registration.project_id == first.registration.project_id
        assert second.registration.repository_id == first.registration.repository_id
        assert second.registration.checkout_id == first.registration.checkout_id
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM projects),"
                        "(SELECT COUNT(*) FROM repositories),"
                        "(SELECT COUNT(*) FROM checkouts),"
                        "(SELECT COUNT(*) FROM audit_events "
                        "WHERE action='mcp.workspace.provisioned')"
                    )
                )
            ).one()
            stored = (
                await connection.execute(
                    text("SELECT name,canonical_path_hash FROM projects,checkouts LIMIT 1")
                )
            ).one()
        assert tuple(counts) == (1, 1, 1, 1)
        assert stored[0] == f"Workspace {_registration().workspace_fingerprint.value[:12]}"
        assert bytes(stored[1]).hex() == _registration().workspace_fingerprint.value
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf005_sqlite_encrypts_checkpoint_before_durable_ack(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-root-key"
    write_secret(key_file, b"k" * 32)
    try:
        await _bootstrap(store)
        sessions = SqliteMcpSessionRepository(store)
        await sessions.register(_registration())
        registered = await sessions.get(_SESSION_ID)
        assert registered is not None
        await sessions.save(registered, registered.begin(NOW, timedelta(seconds=120)))
        checkpoints = SqliteWorkspaceCheckpointRepository(store, key_file, FixedClock())
        handler = StageWorkspaceCheckpointHandler(sessions, checkpoints)
        batch = _checkpoint()
        assert await handler.execute(batch)
        assert not await handler.execute(batch)
        assert await checkpoints.pending(1) == (batch,)
        async with store.engine.connect() as connection:
            row = (
                (await connection.execute(text("SELECT * FROM mcp_workspace_checkpoint_batches")))
                .mappings()
                .one()
            )
            assert bytes(row["batch_digest"]).hex() == batch.batch_digest.value
            assert bytes(row["canonical_sha256"]).hex() == batch.batch_digest.value
            assert b"package brain" not in bytes(row["ciphertext"])
            assert row["state"] == "pending"
        ingestor = _CheckpointIngestor()
        projector = _CheckpointProjector()
        reconciler = ReconcileWorkspaceCheckpointHandler(
            sessions,
            checkpoints,
            ingestor,
            projector,
        )
        assert await reconciler.execute() == 1
        assert await reconciler.execute() == 0
        assert ingestor.calls == [(batch, _registration())]
        assert projector.calls == [(batch, _registration())]
        assert await checkpoints.pending(1) == ()
        async with store.engine.connect() as connection:
            receipt = (
                (await connection.execute(text("SELECT * FROM mcp_workspace_checkpoint_receipts")))
                .mappings()
                .one()
            )
            assert bytes(receipt["batch_digest"]).hex() == batch.batch_digest.value
            assert receipt["event_count"] == 1
        with pytest.raises(DBAPIError, match="immutable"):
            async with store.engine.begin() as connection:
                await connection.execute(
                    text("UPDATE mcp_workspace_checkpoint_batches SET state='reconciled'")
                )
    finally:
        await store.close()


@dataclass(slots=True)
class _CheckpointIngestor:
    calls: list[tuple[WorkspaceCheckpointBatch, McpSessionRegistration]] = field(
        default_factory=list[tuple[WorkspaceCheckpointBatch, McpSessionRegistration]]
    )

    async def ingest(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> WorkspaceCheckpointIngestionResult:
        self.calls.append((batch, registration))
        return WorkspaceCheckpointIngestionResult(digest("checkpoint-result"), len(batch.changes))


@dataclass(slots=True)
class _CheckpointProjector:
    calls: list[tuple[WorkspaceCheckpointBatch, McpSessionRegistration]] = field(
        default_factory=list[tuple[WorkspaceCheckpointBatch, McpSessionRegistration]]
    )

    async def project(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> None:
        self.calls.append((batch, registration))
