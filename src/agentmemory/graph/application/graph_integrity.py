"""GRA-006 resumable graph migration, integrity validation, and repair use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
)
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityPolicy,
    GraphMigrationRun,
    GraphMigrationState,
    GraphRepairPolicy,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.graph_integrity import (
        GraphIntegrityFinding,
        GraphRepairPlan,
    )
    from agentmemory.graph.domain.graph_integrity_ports import (
        CanonicalGraphRebuild,
        GraphIntegrityJournal,
        GraphIntegrityScanner,
        GraphMigrationExecutor,
        GraphMigrationRepository,
        GraphRepairExecutor,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_ERR_ACTION = "graph integrity action is not authorized"
_ERR_SCOPE = "graph migration is outside authorized scope"
_ERR_NOT_FOUND = "graph migration or finding was not found"
_ERR_CURSOR = "graph migration cursor did not advance"
_ERR_VALIDATION = "graph migration validation failed"


@dataclass(frozen=True, slots=True)
class StartGraphMigrationCommand:
    """Start an exact checksum-bound migration under current Brain authority."""

    operation_id: str
    scope: AuthorizedScope
    migration_id: str
    migration_checksum: str
    batch_size: int
    started_at: datetime


@dataclass(frozen=True, slots=True)
class StartGraphMigrationHandler:
    """Capture the immutable source watermark before any graph mutation."""

    migrations: GraphMigrationRepository
    executor: GraphMigrationExecutor

    async def execute(self, command: StartGraphMigrationCommand) -> GraphMigrationRun:
        """Authorize, bind the exact migration, and persist cursor zero externally."""
        _require_action(command.scope, "graph.integrity.migrate")
        watermark = await self.executor.source_watermark(
            command.scope, command.migration_id, command.migration_checksum
        )
        run = GraphMigrationRun.start(
            operation_id=command.operation_id,
            brain_id=command.scope.brain_id.value,
            migration_id=command.migration_id,
            migration_checksum=command.migration_checksum,
            source_watermark=watermark,
            batch_size=command.batch_size,
            started_at=command.started_at,
        )
        return await self.migrations.start(command.scope, run)


@dataclass(frozen=True, slots=True)
class RunGraphMigrationCommand:
    """Resume one durable migration using its last committed cursor."""

    operation_id: str
    scope: AuthorizedScope
    resumed_at: datetime


@dataclass(frozen=True, slots=True)
class RunGraphMigrationHandler:
    """Commit each bounded batch before requesting the next one."""

    migrations: GraphMigrationRepository
    executor: GraphMigrationExecutor

    async def execute(self, command: RunGraphMigrationCommand) -> GraphMigrationRun:
        """Resume safely and validate before marking the migration complete."""
        _require_action(command.scope, "graph.integrity.migrate")
        run = await self.migrations.get(command.scope, command.operation_id)
        if run is None:
            raise GraphConflictError(_ERR_NOT_FOUND)
        if run.brain_id != command.scope.brain_id.value:
            raise GraphAuthorizationError(_ERR_SCOPE)
        if run.state is GraphMigrationState.COMPLETED:
            return run
        if run.state not in {GraphMigrationState.RUNNING, GraphMigrationState.PAUSED}:
            raise GraphConflictError(_ERR_VALIDATION)
        while run.cursor < run.source_watermark:
            batch = await self.executor.apply_batch(command.scope, run)
            if batch.next_cursor <= run.cursor:
                raise GraphIntegrityError(_ERR_CURSOR)
            run = await self.migrations.checkpoint(command.scope, run, batch, command.resumed_at)
        run = await self.migrations.save(command.scope, run.begin_validation(command.resumed_at))
        if not await self.executor.validate(command.scope, run):
            raise GraphIntegrityError(_ERR_VALIDATION)
        return await self.migrations.save(command.scope, run.complete(command.resumed_at))


@dataclass(frozen=True, slots=True)
class ValidateGraphIntegrityQuery:
    """Inspect every bounded graph projection class for one current generation."""

    scope: AuthorizedScope
    current_generation_id: str
    checked_at: datetime


@dataclass(frozen=True, slots=True)
class ValidateGraphIntegrityHandler:
    """Evaluate untrusted scanner metadata and journal findings before repair."""

    scanner: GraphIntegrityScanner
    journal: GraphIntegrityJournal

    async def execute(
        self, query: ValidateGraphIntegrityQuery
    ) -> tuple[GraphIntegrityFinding, ...]:
        """Authorize before revealing observations, counts, or findings."""
        _require_action(query.scope, "graph.integrity.validate")
        observations = await self.scanner.scan(query.scope)
        findings = GraphIntegrityPolicy.evaluate(
            observations, query.current_generation_id, query.checked_at
        )
        return await self.journal.record(query.scope, findings)


@dataclass(frozen=True, slots=True)
class RepairGraphFindingCommand:
    """Repair one journaled finding with explicit destructive authority if requested."""

    operation_id: str
    scope: AuthorizedScope
    finding_id: str
    repaired_at: datetime
    destructive: bool = False
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class RepairGraphFindingHandler:
    """Execute a closed plan and append audit evidence only after success."""

    journal: GraphIntegrityJournal
    repairs: GraphRepairExecutor
    rebuilds: CanonicalGraphRebuild

    async def execute(self, command: RepairGraphFindingCommand) -> GraphRepairPlan:
        """Authorize, load, plan, execute, and journal one exact repair."""
        _require_action(command.scope, "graph.integrity.repair")
        finding = await self.journal.get(command.scope, command.finding_id)
        if finding is None:
            raise GraphConflictError(_ERR_NOT_FOUND)
        verified = False
        if command.destructive and command.approval_id is not None:
            verified = await self.rebuilds.verify(command.scope, finding, command.approval_id)
        plan = GraphRepairPolicy.plan(
            finding,
            destructive=command.destructive,
            approval_id=command.approval_id,
            canonical_rebuild_verified=verified,
        )
        if command.destructive:
            await self.rebuilds.start(
                command.scope,
                finding,
                _approval(command.approval_id),
                command.repaired_at,
            )
        else:
            await self.repairs.execute(command.scope, finding, plan, command.repaired_at)
        await self.journal.repaired(
            command.scope,
            command.operation_id,
            finding,
            plan,
            command.repaired_at,
        )
        return plan


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)


def _approval(value: str | None) -> str:
    if value is None:
        raise GraphIntegrityError(_ERR_VALIDATION)
    return value
