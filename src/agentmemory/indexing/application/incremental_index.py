"""IDX-002 start/status/cancel use cases and durable incremental workers."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.indexing.application.code_index import index_source_artifact
from agentmemory.indexing.domain.code_entities import ParseStatus, SourceSnapshot
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.incremental import (
    CurrentIndexUnit,
    IndexOperation,
    IndexOperationKind,
    IndexPlan,
    IndexProjectionEvent,
    IndexRun,
    IndexRunState,
)
from agentmemory.indexing.domain.incremental_ports import (
    IndexOperationCommit,
    ProjectionImpact,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.incremental_ports import (
        IncrementalIndexRepository,
        IncrementalIndexWorkRepository,
        IncrementalRepositorySource,
        IndexFingerprintProvider,
        IndexProjectionConsumer,
        IndexWork,
        RepositoryInspection,
    )
    from agentmemory.indexing.domain.ports import LanguagePluginPort
    from agentmemory.shared.clock import Clock

_OPERATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERR_ACTION = "incremental indexing action is not authorized"
_ERR_SCOPE = "incremental indexing requires one exact project and repository"
_ERR_REQUEST = "incremental indexing request is invalid"
_ERR_NOT_FOUND = "incremental indexing run was not found"
_MAX_IDENTITY = 128


@dataclass(frozen=True, slots=True)
class StartIndexRunCommand:
    """Start one content-addressed long-running incremental index operation."""

    operation_id: str
    scope: AuthorizedScope
    target_commit_id: str | None
    include_generated: bool
    detected_at: datetime

    def __post_init__(self) -> None:
        """Reject ambiguous replay and target coordinates before source access."""
        if _OPERATION_ID.fullmatch(self.operation_id) is None or (
            self.target_commit_id is not None
            and (
                not self.target_commit_id
                or len(self.target_commit_id) > _MAX_IDENTITY
                or any(char.isspace() for char in self.target_commit_id)
            )
        ):
            raise IndexingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class GetIndexRunQuery:
    """Read one currently authorized run and its coverage/failure progress."""

    scope: AuthorizedScope
    run_id: str

    def __post_init__(self) -> None:
        """Require a stable run identity."""
        if _DIGEST.fullmatch(self.run_id) is None:
            raise IndexingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class CancelIndexRunCommand:
    """Request idempotent cancellation at the next file-operation boundary."""

    operation_id: str
    scope: AuthorizedScope
    run_id: str
    requested_at: datetime

    def __post_init__(self) -> None:
        """Require stable mutation and run identities."""
        if (
            _OPERATION_ID.fullmatch(self.operation_id) is None
            or _DIGEST.fullmatch(self.run_id) is None
        ):
            raise IndexingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class StartIndexRunHandler:
    """Inspect VCS state and durably queue an immutable incremental plan."""

    source: IncrementalRepositorySource
    fingerprints: IndexFingerprintProvider
    repository: IncrementalIndexRepository

    async def execute(self, command: StartIndexRunCommand) -> IndexRun:
        """Authorize first, combine hashes with VCS topology, and append the queued run."""
        _require_action(command.scope, "indexing.run.start")
        project_id, repository_id = _exact_scope(command.scope)
        replay = await self.repository.find_by_operation(command.scope, command.operation_id)
        if replay is not None:
            return replay
        previous = await self.repository.latest_completed(command.scope)
        base_commit = None if previous is None else previous.snapshot.commit_id
        inspected = await self.source.inspect(
            repository_id,
            base_commit,
            command.target_commit_id,
            () if previous is None else previous.units,
        )
        _require_target(command, inspected)
        current = tuple(
            CurrentIndexUnit(
                item.relative_path,
                item.content_digest,
                item.byte_length,
                self.fingerprints.for_path(item.relative_path).cache_key(
                    item.relative_path, item.content_digest
                ),
                item.generated,
            )
            for item in inspected.files
        )
        plan = IndexPlan.create(
            () if previous is None else previous.units,
            current,
            inspected.vcs_deltas,
            include_generated=command.include_generated,
        )
        snapshot = SourceSnapshot.create(
            brain_id=command.scope.brain_id.value,
            project_id=project_id,
            repository_id=repository_id,
            commit_id=inspected.target_commit_id,
            working_digest=inspected.working_digest,
            created_at=command.detected_at,
        )
        run = IndexRun.queue(
            operation_id=command.operation_id,
            brain_id=command.scope.brain_id.value,
            project_id=project_id,
            repository_id=repository_id,
            base_snapshot_id=None if previous is None else previous.snapshot.id,
            target_snapshot_id=snapshot.id,
            target_commit_id=inspected.target_commit_id,
            working_digest=inspected.working_digest,
            implementation_fingerprint=self.fingerprints.implementation_digest,
            plan=plan,
            detected_at=command.detected_at,
        )
        return await self.repository.start(command.scope, run, snapshot, plan)


@dataclass(frozen=True, slots=True)
class GetIndexRunHandler:
    """Return current durable progress after current authorization."""

    repository: IncrementalIndexRepository

    async def execute(self, query: GetIndexRunQuery) -> IndexRun:
        """Return a run or a content-safe not-found result."""
        _require_action(query.scope, "indexing.run.read")
        result = await self.repository.get(query.scope, query.run_id)
        if result is None:
            raise IndexingValidationError(_ERR_NOT_FOUND)
        return result


@dataclass(frozen=True, slots=True)
class CancelIndexRunHandler:
    """Persist cancellation intent without interrupting an atomic file commit."""

    repository: IncrementalIndexRepository

    async def execute(self, command: CancelIndexRunCommand) -> IndexRun:
        """Authorize and append an idempotent cancellation request."""
        _require_action(command.scope, "indexing.run.cancel")
        return await self.repository.request_cancel(
            command.scope,
            command.run_id,
            command.operation_id,
            command.requested_at,
        )


@dataclass(frozen=True, slots=True)
class IncrementalIndexWorker:
    """Execute one durable plan with a checkpoint after every independent file."""

    source: IncrementalRepositorySource
    plugin: LanguagePluginPort
    repository: IncrementalIndexWorkRepository
    clock: Clock

    async def run_once(self) -> bool:
        """Process the oldest authorized run and return whether work was claimed."""
        work = await self.repository.claim_next(self.clock.now())
        if work is None:
            return False
        try:
            await self._execute(work)
        except asyncio.CancelledError:
            raise
        except IndexingUnavailableError:
            await self._fail_current(work.run.id, "source_unavailable")
        except Exception:  # noqa: BLE001 -- Worker failures become bounded durable state.
            await self._fail_current(work.run.id, "worker_failure")
        return True

    async def run(self, stop: asyncio.Event, *, idle_seconds: float = 0.1) -> None:
        """Drain runs until graceful process shutdown."""
        while not stop.is_set():
            if not await self.run_once():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=idle_seconds)
                except TimeoutError:
                    continue

    async def _execute(self, work: IndexWork) -> None:
        run = work.run
        current = await self.repository.current(run.id)
        if current.state is IndexRunState.CANCELLING:
            await self.repository.save_state(current, current.cancel(self.clock.now()))
            return
        if current != run:
            raise IndexingValidationError(_ERR_REQUEST)
        while run.cursor < run.total_operations:
            current = await self.repository.current(run.id)
            if current.state is IndexRunState.CANCELLING:
                await self.repository.save_state(current, current.cancel(self.clock.now()))
                return
            if current != run:
                raise IndexingValidationError(_ERR_REQUEST)
            operation = work.plan.operations[run.cursor]
            commit, failed = await self._prepare_commit(work, operation)
            next_run = run.checkpoint(operation, failed=failed, at=self.clock.now())
            run = await self.repository.commit_operation(run, next_run, commit)
        await self.repository.save_state(run, run.finish(self.clock.now()))

    async def _prepare_commit(
        self, work: IndexWork, operation: IndexOperation
    ) -> tuple[IndexOperationCommit, bool]:
        if operation.kind is IndexOperationKind.REUSE:
            return IndexOperationCommit(operation, None, None), False
        impact = await self.repository.impact(operation.invalidated_semantic_ids)
        if operation.kind is IndexOperationKind.DELETE:
            event = _projection_event(
                work,
                operation,
                _ProjectionChange((), ()),
                impact,
                self.clock.now(),
            )
            return IndexOperationCommit(operation, None, event), False
        if operation.content_digest is None:
            raise IndexingValidationError(_ERR_REQUEST)
        artifact = await self.source.read(
            work.run.repository_id,
            work.run.target_commit_id,
            operation.relative_path,
            operation.content_digest,
        )
        indexed = index_source_artifact(
            self.plugin,
            work.snapshot,
            work.run.repository_id,
            artifact,
        )
        semantic_ids = tuple(sorted(item.id for item in indexed.symbol_revisions))
        event = _projection_event(
            work,
            operation,
            _ProjectionChange((indexed.revision.id,), semantic_ids),
            impact,
            self.clock.now(),
        )
        return (
            IndexOperationCommit(operation, indexed, event),
            indexed.revision.status is ParseStatus.FAILED,
        )

    async def _fail_current(self, run_id: str, code: str) -> None:
        current = await self.repository.current(run_id)
        if current.state in {IndexRunState.QUEUED, IndexRunState.RUNNING}:
            await self.repository.save_state(current, current.fail(code, self.clock.now()))


@dataclass(frozen=True, slots=True)
class IndexProjectionWorker:
    """Deliver persisted invalidation/re-embedding events with idempotent receipts."""

    repository: IncrementalIndexWorkRepository
    consumer: IndexProjectionConsumer
    clock: Clock

    async def run_once(self) -> bool:
        """Deliver one event; absence is normal and failures remain retryable."""
        event = await self.repository.next_projection(self.clock.now())
        if event is None:
            return False
        await self.consumer.consume(event)
        await self.repository.projection_succeeded(event.id, self.clock.now())
        return True

    async def run(self, stop: asyncio.Event, *, idle_seconds: float = 0.1) -> None:
        """Drain projection events until graceful shutdown."""
        while not stop.is_set():
            if not await self.run_once():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=idle_seconds)
                except TimeoutError:
                    continue


@dataclass(frozen=True, slots=True)
class _ProjectionChange:
    current_revision_ids: tuple[str, ...]
    current_semantic_ids: tuple[str, ...]


def _projection_event(
    work: IndexWork,
    operation: IndexOperation,
    change: _ProjectionChange,
    impact: ProjectionImpact,
    occurred_at: datetime,
) -> IndexProjectionEvent:
    previous_revisions = (
        ()
        if operation.previous_file_revision_id is None
        else (operation.previous_file_revision_id,)
    )
    affected = tuple(sorted(set(operation.invalidated_semantic_ids + change.current_semantic_ids)))
    return IndexProjectionEvent(
        work.run.id,
        operation.id,
        operation.ordinal,
        work.snapshot.id,
        previous_revisions,
        change.current_revision_ids,
        affected,
        impact.dependent_fact_ids,
        impact.assertion_evidence_ids,
        change.current_semantic_ids,
        occurred_at,
    )


def _require_target(command: StartIndexRunCommand, inspected: RepositoryInspection) -> None:
    if command.target_commit_id is not None and (
        inspected.target_commit_id is None
        or not inspected.target_commit_id.startswith(command.target_commit_id)
    ):
        raise IndexingValidationError(_ERR_REQUEST)


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _exact_scope(scope: AuthorizedScope) -> tuple[str, str]:
    if len(scope.project_ids) != 1 or len(scope.repository_ids) != 1:
        raise IndexingAuthorizationError(_ERR_SCOPE)
    return scope.project_ids[0].value, scope.repository_ids[0].value
