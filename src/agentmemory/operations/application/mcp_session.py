"""PF-005 session registration, lease, revocation, and recovery use cases."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Final, Protocol

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from agentmemory.operations.domain.mcp_session import (
        McpSession,
        McpSessionRegistration,
        McpSessionState,
    )
    from agentmemory.operations.domain.ports import (
        McpSessionRepository,
        McpWorkspaceScopeProvisioner,
        McpWorkspaceScopeResolver,
        WorkspaceCheckpointIngestor,
        WorkspaceCheckpointProjector,
        WorkspaceCheckpointRepository,
    )
    from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
    from agentmemory.operations.domain.workspace_checkpoint import WorkspaceCheckpointBatch

_MAX_RECOVERY_BATCH: Final = 256


class _CheckpointReconciler(Protocol):
    async def execute(self, limit: int = _MAX_RECOVERY_BATCH) -> int:
        """Reconcile one bounded page of durable checkpoint work."""
        ...


@dataclass(frozen=True, slots=True)
class RegisterMcpSessionCredentialHandler:
    """Persist one root-authorized, hash-only session credential."""

    repository: McpSessionRepository
    workspace_scope: McpWorkspaceScopeResolver
    workspace_provisioner: McpWorkspaceScopeProvisioner

    async def execute(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        """Return the session and whether a new registration was created."""
        scope = await self.workspace_scope.resolve(registration)
        if scope is None or scope.checkout_id is None:
            scope = await self.workspace_provisioner.ensure(registration, scope)
        registration = replace(
            registration,
            project_id=scope.project_id,
            repository_id=scope.repository_id,
            checkout_id=scope.checkout_id,
        )
        return await self.repository.register(registration)


@dataclass(frozen=True, slots=True)
class StageWorkspaceCheckpointHandler:
    """Authorize and durably encrypt one terminal workspace delta."""

    sessions: McpSessionRepository
    checkpoints: WorkspaceCheckpointRepository

    async def execute(self, batch: WorkspaceCheckpointBatch) -> bool:
        """Stage only for the matching active, unrevoked workspace session."""
        session = await self.sessions.get(batch.session_id)
        if (
            session is None
            or session.state.value != "active"
            or session.revoked_at is not None
            or session.registration.workspace_fingerprint != batch.workspace_fingerprint
        ):
            raise OperationError(ErrorCode.FORBIDDEN, "workspace checkpoint is not authorized")
        return await self.checkpoints.stage(batch)


@dataclass(frozen=True, slots=True)
class McpSessionLifecycleHandler:
    """Apply optimistic domain transitions through one repository port."""

    repository: McpSessionRepository

    async def begin(
        self,
        session_id: Uuid7Id,
        now: datetime,
        lease: timedelta,
    ) -> McpSession:
        """Activate one registered session."""
        previous = await self._required(session_id)
        current = previous.begin(now, lease)
        if current is not previous:
            await self.repository.save(previous, current)
        return current

    async def heartbeat(self, session_id: Uuid7Id, now: datetime) -> McpSession:
        """Renew one active session lease."""
        previous = await self._required(session_id)
        current = previous.heartbeat(now)
        if current is not previous:
            await self.repository.save(previous, current)
        return current

    async def finish(
        self,
        session_id: Uuid7Id,
        state: McpSessionState,
        now: datetime,
    ) -> McpSession:
        """Set an exact terminal status, accepting exact replay."""
        previous = await self._required(session_id)
        current = previous.finish(state, now)
        if current is not previous:
            await self.repository.save(previous, current)
        return current

    async def revoke(self, digest: Sha256Digest, now: datetime) -> tuple[McpSession | None, bool]:
        """Revoke a known digest and report whether this call changed authority."""
        previous = await self.repository.get_by_credential(digest)
        if previous is None:
            return None, False
        if previous.revoked_at is not None:
            return previous, False
        current = previous.revoke(now)
        await self.repository.save(previous, current)
        return current, True

    async def recover_expired(self, now: datetime) -> tuple[McpSession, ...]:
        """Revoke and interrupt a bounded set of expired active sessions."""
        recovered: list[McpSession] = []
        for previous in await self.repository.expired(now, _MAX_RECOVERY_BATCH):
            current = previous.interrupt_if_expired(now)
            await self.repository.save(previous, current)
            recovered.append(current)
        return tuple(recovered)

    async def _required(self, session_id: Uuid7Id) -> McpSession:
        session = await self.repository.get(session_id)
        if session is None:
            raise OperationError(ErrorCode.VALIDATION, "MCP session was not found")
        return session


@dataclass(frozen=True, slots=True)
class ReconcileWorkspaceCheckpointHandler:
    """Recover encrypted batches through an idempotent canonical ingestor."""

    sessions: McpSessionRepository
    checkpoints: WorkspaceCheckpointRepository
    ingestor: WorkspaceCheckpointIngestor
    projector: WorkspaceCheckpointProjector

    async def execute(self, limit: int = _MAX_RECOVERY_BATCH) -> int:
        """Reconcile a bounded deterministic batch and append exact ACK receipts."""
        if limit < 1 or limit > _MAX_RECOVERY_BATCH:
            raise OperationError(ErrorCode.VALIDATION, "checkpoint recovery limit is invalid")
        reconciled = 0
        for batch in await self.checkpoints.pending(limit):
            session = await self.sessions.get(batch.session_id)
            if (
                session is None
                or session.registration.workspace_fingerprint != batch.workspace_fingerprint
            ):
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "workspace checkpoint authority diverged",
                )
            result = await self.ingestor.ingest(batch, session.registration)
            await self.projector.project(batch, session.registration)
            if await self.checkpoints.acknowledge(batch.batch_digest, result):
                reconciled += 1
        return reconciled


@dataclass(frozen=True, slots=True)
class WorkspaceCheckpointRecoveryWorker:
    """Continuously drain durable PF-005 checkpoints without owning infrastructure."""

    reconciler: _CheckpointReconciler

    async def run_once(self) -> bool:
        """Reconcile one bounded page and report whether durable work completed."""
        return await self.reconciler.execute() > 0

    async def run(self, stop: asyncio.Event, *, idle_seconds: float = 0.1) -> None:
        """Retry unavailable work until graceful Core shutdown is requested."""
        if idle_seconds <= 0:
            raise OperationError(ErrorCode.VALIDATION, "checkpoint worker interval is invalid")
        while not stop.is_set():
            try:
                progressed = await self.run_once()
            except asyncio.CancelledError:
                raise
            except OperationError:
                progressed = False
            if progressed:
                continue
            try:
                await asyncio.wait_for(stop.wait(), timeout=idle_seconds)
            except TimeoutError:
                continue
