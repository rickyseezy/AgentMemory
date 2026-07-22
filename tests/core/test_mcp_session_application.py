"""PF-005 session lifecycle application TDD tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from agentmemory.operations.application.mcp_session import (
    McpSessionLifecycleHandler,
    ReconcileWorkspaceCheckpointHandler,
    RegisterMcpSessionCredentialHandler,
    StageWorkspaceCheckpointHandler,
    WorkspaceCheckpointRecoveryWorker,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSession,
    McpSessionRegistration,
    McpSessionState,
    McpWorkspaceScope,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointIngestionResult,
)

NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
SESSION = Uuid7Id("019d2b4e-7a10-7def-8abc-0123456789ab")
DIGEST = Sha256Digest("b" * 64)


def _sessions() -> dict[Uuid7Id, McpSession]:
    return {}


def _saves() -> list[tuple[McpSession, McpSession]]:
    return []


@pytest.mark.asyncio
async def test_pf005_application_registers_runs_and_finishes_exact_session() -> None:
    repository = _Repository()
    registered, created = await RegisterMcpSessionCredentialHandler(
        repository,
        _WorkspaceScope(),
        _WorkspaceProvisioner(),
    ).execute(_registration())
    assert created
    lifecycle = McpSessionLifecycleHandler(repository)
    active = await lifecycle.begin(SESSION, NOW, timedelta(seconds=120))
    assert await lifecycle.begin(SESSION, NOW, timedelta(seconds=120)) is active
    heartbeat = await lifecycle.heartbeat(SESSION, NOW + timedelta(seconds=30))
    assert await lifecycle.heartbeat(SESSION, NOW + timedelta(seconds=30)) is heartbeat
    revoked, changed = await lifecycle.revoke(DIGEST, NOW + timedelta(seconds=31))
    completed = await lifecycle.finish(
        SESSION, McpSessionState.COMPLETED, NOW + timedelta(seconds=32)
    )
    assert registered.state is McpSessionState.REGISTERED
    assert active.state is McpSessionState.ACTIVE
    assert heartbeat.revision == 2
    assert revoked is not None
    assert changed
    assert completed.state is McpSessionState.COMPLETED
    assert len(repository.saves) == 4


@pytest.mark.asyncio
async def test_pf005_application_recovers_only_expired_sessions_as_interrupted() -> None:
    repository = _Repository()
    registered = McpSession.register(_registration())
    expired = registered.begin(NOW, timedelta(seconds=120))
    repository.sessions[SESSION] = expired
    recovered = await McpSessionLifecycleHandler(repository).recover_expired(
        NOW + timedelta(seconds=120)
    )
    assert len(recovered) == 1
    assert recovered[0].state is McpSessionState.INTERRUPTED
    assert recovered[0].revoked_at == NOW + timedelta(seconds=120)


@pytest.mark.asyncio
async def test_pf005_application_rejects_unknown_session_and_absent_revoke_is_idempotent() -> None:
    repository = _Repository()
    lifecycle = McpSessionLifecycleHandler(repository)
    with pytest.raises(OperationError) as raised:
        await lifecycle.begin(SESSION, NOW, timedelta(seconds=120))
    assert raised.value.code is ErrorCode.VALIDATION
    assert await lifecycle.revoke(DIGEST, NOW) == (None, False)


@pytest.mark.asyncio
async def test_pf005_checkpoint_handlers_fail_closed_and_ack_only_durable_projection() -> None:
    repository = _Repository()
    checkpoints = _Checkpoints()
    batch = _batch()
    with pytest.raises(OperationError, match="not authorized"):
        await StageWorkspaceCheckpointHandler(repository, checkpoints).execute(batch)

    registered = McpSession.register(_registration())
    repository.sessions[SESSION] = registered
    with pytest.raises(OperationError, match="not authorized"):
        await StageWorkspaceCheckpointHandler(repository, checkpoints).execute(batch)

    repository.sessions[SESSION] = registered.begin(NOW, timedelta(seconds=120))
    assert await StageWorkspaceCheckpointHandler(repository, checkpoints).execute(batch)
    checkpoints.pending_batches = (batch,)
    ingestor = _Ingestor()
    projector = _Projector()
    reconciler = ReconcileWorkspaceCheckpointHandler(
        repository,
        checkpoints,
        ingestor,
        projector,
    )
    assert await reconciler.execute() == 1
    assert ingestor.calls == 1
    assert projector.calls == 1

    checkpoints.ack_result = False
    assert await reconciler.execute() == 0
    with pytest.raises(OperationError, match="limit"):
        await reconciler.execute(0)
    with pytest.raises(OperationError, match="limit"):
        await reconciler.execute(257)


@pytest.mark.asyncio
async def test_pf005_reconciler_rejects_missing_or_divergent_session_authority() -> None:
    batch = _batch()
    checkpoints = _Checkpoints(pending_batches=(batch,))
    reconciler = ReconcileWorkspaceCheckpointHandler(
        _Repository(),
        checkpoints,
        _Ingestor(),
        _Projector(),
    )
    with pytest.raises(OperationError) as missing:
        await reconciler.execute()
    assert missing.value.code is ErrorCode.INTEGRITY_VIOLATION

    repository = _Repository()
    divergent = McpSession.register(_registration(workspace=digest_value("different")))
    repository.sessions[SESSION] = divergent
    reconciler = ReconcileWorkspaceCheckpointHandler(
        repository,
        checkpoints,
        _Ingestor(),
        _Projector(),
    )
    with pytest.raises(OperationError) as mismatch:
        await reconciler.execute()
    assert mismatch.value.code is ErrorCode.INTEGRITY_VIOLATION


@pytest.mark.asyncio
async def test_pf005_recovery_worker_progress_retry_stop_and_cancellation() -> None:
    reconciler = _Reconciler([1, 0])
    worker = WorkspaceCheckpointRecoveryWorker(reconciler)
    assert await worker.run_once()
    assert not await worker.run_once()
    with pytest.raises(OperationError, match="interval"):
        await worker.run(asyncio.Event(), idle_seconds=0)

    stop = asyncio.Event()
    progress = _Reconciler([1], stop=stop)
    await WorkspaceCheckpointRecoveryWorker(progress).run(stop)
    assert progress.calls == 1

    stop = asyncio.Event()
    retry = _Reconciler([OperationError(ErrorCode.DEPENDENCY_UNAVAILABLE, "private")], stop=stop)
    await WorkspaceCheckpointRecoveryWorker(retry).run(stop)
    assert retry.calls == 1

    cancelled = _Reconciler([asyncio.CancelledError()])
    with pytest.raises(asyncio.CancelledError):
        await WorkspaceCheckpointRecoveryWorker(cancelled).run(asyncio.Event())


@dataclass(slots=True)
class _Repository:
    sessions: dict[Uuid7Id, McpSession] = field(default_factory=_sessions)
    saves: list[tuple[McpSession, McpSession]] = field(default_factory=_saves)

    async def register(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        existing = self.sessions.get(registration.session_id)
        if existing is not None:
            return existing, False
        session = McpSession.register(registration)
        self.sessions[registration.session_id] = session
        return session, True

    async def get(self, session_id: Uuid7Id) -> McpSession | None:
        return self.sessions.get(session_id)

    async def get_by_credential(self, digest: Sha256Digest) -> McpSession | None:
        return next(
            (
                session
                for session in self.sessions.values()
                if session.registration.credential_digest == digest
            ),
            None,
        )

    async def save(self, previous: McpSession, current: McpSession) -> None:
        assert self.sessions[previous.registration.session_id] == previous
        self.sessions[previous.registration.session_id] = current
        self.saves.append((previous, current))

    async def expired(self, now: datetime, limit: int) -> tuple[McpSession, ...]:
        return tuple(session for session in self.sessions.values() if session.expired(now))[:limit]

    async def authorize(
        self, digest: Sha256Digest, session_id: Uuid7Id, now: datetime
    ) -> McpSession | None:
        session = self.sessions.get(session_id)
        if session is None or session.registration.credential_digest != digest:
            return None
        if session.revoked_at is not None or now >= session.registration.expires_at:
            return None
        return session


@dataclass(frozen=True, slots=True)
class _WorkspaceScope:
    value: McpWorkspaceScope | None = None

    async def resolve(self, registration: McpSessionRegistration) -> McpWorkspaceScope | None:
        del registration
        return self.value


@dataclass(frozen=True, slots=True)
class _WorkspaceProvisioner:
    async def ensure(
        self,
        registration: McpSessionRegistration,
        resolved: McpWorkspaceScope | None,
    ) -> McpWorkspaceScope:
        del registration
        return resolved or McpWorkspaceScope(
            Uuid7Id("019d2b4e-7a15-7def-8abc-0123456789ab"),
            Uuid7Id("019d2b4e-7a16-7def-8abc-0123456789ab"),
            Uuid7Id("019d2b4e-7a17-7def-8abc-0123456789ab"),
        )


@dataclass(slots=True)
class _Checkpoints:
    pending_batches: tuple[WorkspaceCheckpointBatch, ...] = ()
    ack_result: bool = True

    async def stage(self, batch: WorkspaceCheckpointBatch) -> bool:
        self.pending_batches = (batch,)
        return True

    async def pending(self, limit: int) -> tuple[WorkspaceCheckpointBatch, ...]:
        return self.pending_batches[:limit]

    async def acknowledge(
        self,
        batch_digest: Sha256Digest,
        result: WorkspaceCheckpointIngestionResult,
    ) -> bool:
        del batch_digest, result
        return self.ack_result


@dataclass(slots=True)
class _Ingestor:
    calls: int = 0

    async def ingest(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> WorkspaceCheckpointIngestionResult:
        del batch, registration
        self.calls += 1
        return WorkspaceCheckpointIngestionResult(digest_value("result"), 0)


@dataclass(slots=True)
class _Projector:
    calls: int = 0

    async def project(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> None:
        del batch, registration
        self.calls += 1


@dataclass(slots=True)
class _Reconciler:
    outcomes: list[int | BaseException]
    stop: asyncio.Event | None = None
    calls: int = 0

    async def execute(self, limit: int = 256) -> int:
        del limit
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if self.stop is not None:
            self.stop.set()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def digest_value(value: str) -> Sha256Digest:
    return Sha256Digest(hashlib.sha256(value.encode()).hexdigest())


def _batch() -> WorkspaceCheckpointBatch:
    fingerprint = digest_value("workspace")
    canonical = json.dumps(
        {
            "session_id": SESSION.value,
            "workspace_fingerprint": fingerprint.value,
            "batch_digest": "",
            "partial": False,
            "changes": [],
        },
        separators=(",", ":"),
    ).encode()
    return WorkspaceCheckpointBatch(
        session_id=SESSION,
        workspace_fingerprint=fingerprint,
        batch_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        partial=False,
        changes=(),
    )


def _registration(*, workspace: Sha256Digest | None = None) -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=SESSION,
        installation_id=Uuid7Id("019d2b4e-7a11-7def-8abc-0123456789ab"),
        brain_id=Uuid7Id("019d2b4e-7a12-7def-8abc-0123456789ab"),
        actor_id=Uuid7Id("019d2b4e-7a13-7def-8abc-0123456789ab"),
        grant_id=Uuid7Id("019d2b4e-7a14-7def-8abc-0123456789ab"),
        agent_id="codex",
        workspace_fingerprint=workspace or digest_value("workspace"),
        device_identity="dev:1",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=7,
        credential_digest=DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=12),
    )
