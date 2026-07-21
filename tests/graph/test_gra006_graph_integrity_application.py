"""GRA-006 migration resume, validation, and repair orchestration tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.graph.application.graph_integrity import (
    RepairGraphFindingCommand,
    RepairGraphFindingHandler,
    RunGraphMigrationCommand,
    RunGraphMigrationHandler,
    StartGraphMigrationCommand,
    StartGraphMigrationHandler,
    ValidateGraphIntegrityHandler,
    ValidateGraphIntegrityQuery,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityFinding,
    GraphMigrationBatch,
    GraphMigrationRun,
    GraphRepairAction,
    GraphRepairPlan,
)
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra006_graph_integrity_domain import (
    CANONICAL,
    CHECKSUM,
    CURRENT_GENERATION,
    NOW,
    _observation,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.graph_integrity import GraphIntegrityObservation
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


@pytest.mark.asyncio
async def test_interrupted_migration_resumes_from_durable_cursor() -> None:
    repository = _MigrationRepository()
    executor = _MigrationExecutor(interrupt_once=True)
    scope = _scope("graph.integrity.migrate")
    start = StartGraphMigrationCommand(
        "graph-migration-1", scope, "gra006-backfill-v1", CHECKSUM, 4, NOW
    )
    run = await StartGraphMigrationHandler(repository, executor).execute(start)
    assert run.source_watermark == 10

    runner = RunGraphMigrationHandler(repository, executor)
    with pytest.raises(RuntimeError, match="interrupted"):
        await runner.execute(RunGraphMigrationCommand(run.operation_id, scope, NOW))
    assert repository.run is not None
    assert repository.run.cursor == 4

    completed = await runner.execute(RunGraphMigrationCommand(run.operation_id, scope, NOW))
    assert completed.state.value == "completed"
    assert completed.cursor == 10
    assert executor.requested_cursors == [0, 4, 4, 8]
    assert await runner.execute(RunGraphMigrationCommand(run.operation_id, scope, NOW)) == completed


@pytest.mark.asyncio
@pytest.mark.parametrize("interrupted_cursor", [0, 4, 8])
async def test_migration_recovers_after_crash_at_every_batch_without_duplicate_effect(
    interrupted_cursor: int,
) -> None:
    repository = _MigrationRepository()
    executor = _CrashAfterApplyExecutor(interrupted_cursor)
    scope = _scope("graph.integrity.migrate")
    run = await StartGraphMigrationHandler(repository, executor).execute(
        StartGraphMigrationCommand(
            f"graph-migration-crash-{interrupted_cursor}",
            scope,
            "gra006-backfill-v1",
            CHECKSUM,
            4,
            NOW,
        )
    )
    runner = RunGraphMigrationHandler(repository, executor)
    with pytest.raises(RuntimeError, match="power loss"):
        await runner.execute(RunGraphMigrationCommand(run.operation_id, scope, NOW))
    assert repository.run is not None
    assert repository.run.cursor == interrupted_cursor

    completed = await runner.execute(RunGraphMigrationCommand(run.operation_id, scope, NOW))
    assert completed.cursor == 10
    assert completed.state.value == "completed"
    assert len(executor.effective_projection_ids) == 10
    assert executor.requested_cursors.count(interrupted_cursor) == 2


@pytest.mark.asyncio
async def test_integrity_validation_journals_findings_before_any_repair() -> None:
    scanner = _Scanner((replace(_observation(), canonical_id=None),))
    journal = _Journal()
    findings = await ValidateGraphIntegrityHandler(scanner, journal).execute(
        ValidateGraphIntegrityQuery(_scope("graph.integrity.validate"), CURRENT_GENERATION, NOW)
    )
    assert [finding.kind.value for finding in findings] == ["orphan_edge"]
    assert journal.findings == list(findings)

    with pytest.raises(GraphAuthorizationError):
        await ValidateGraphIntegrityHandler(scanner, journal).execute(
            ValidateGraphIntegrityQuery(_scope("graph.integrity.repair"), CURRENT_GENERATION, NOW)
        )


@pytest.mark.asyncio
async def test_repair_executes_closed_plan_then_appends_audit_evidence() -> None:
    scanner = _Scanner((replace(_observation(), canonical_id=None),))
    journal = _Journal()
    finding = (
        await ValidateGraphIntegrityHandler(scanner, journal).execute(
            ValidateGraphIntegrityQuery(_scope("graph.integrity.validate"), CURRENT_GENERATION, NOW)
        )
    )[0]
    repairs = _Repairs()
    command = RepairGraphFindingCommand(
        "graph-repair-1",
        _scope("graph.integrity.repair"),
        finding.id,
        NOW,
    )
    rebuilds = _Rebuilds()
    plan = await RepairGraphFindingHandler(journal, repairs, rebuilds).execute(command)
    assert plan.action is GraphRepairAction.QUARANTINE
    assert repairs.executed == [(finding, plan)]
    assert journal.repair_records == [(command.operation_id, finding, plan)]

    destructive = await RepairGraphFindingHandler(journal, repairs, rebuilds).execute(
        replace(
            command,
            operation_id="graph-repair-2",
            destructive=True,
            approval_id=CANONICAL,
        )
    )
    assert destructive.action is GraphRepairAction.DESTRUCTIVE_REBUILD
    assert rebuilds.started == [(finding, CANONICAL)]


@dataclass
class _MigrationRepository:
    run: GraphMigrationRun | None = None

    async def start(self, scope: AuthorizedScope, run: GraphMigrationRun) -> GraphMigrationRun:
        del scope
        if self.run is None:
            self.run = run
        return self.run

    async def get(self, scope: AuthorizedScope, operation_id: str) -> GraphMigrationRun | None:
        del scope
        return self.run if self.run is not None and self.run.operation_id == operation_id else None

    async def checkpoint(
        self,
        scope: AuthorizedScope,
        run: GraphMigrationRun,
        batch: GraphMigrationBatch,
        at: datetime,
    ) -> GraphMigrationRun:
        del scope
        self.run = run.checkpoint(
            batch.next_cursor, batch.scanned, batch.changed, batch.quarantined, at
        )
        return self.run

    async def save(self, scope: AuthorizedScope, run: GraphMigrationRun) -> GraphMigrationRun:
        del scope
        self.run = run
        return run


@dataclass
class _MigrationExecutor:
    interrupt_once: bool
    requested_cursors: list[int] = field(default_factory=list[int])

    async def source_watermark(
        self, scope: AuthorizedScope, migration_id: str, migration_checksum: str
    ) -> int:
        del scope, migration_id
        assert migration_checksum == CHECKSUM
        return 10

    async def apply_batch(
        self, scope: AuthorizedScope, run: GraphMigrationRun
    ) -> GraphMigrationBatch:
        del scope
        self.requested_cursors.append(run.cursor)
        if self.interrupt_once and run.cursor == 4:
            self.interrupt_once = False
            message = "interrupted"
            raise RuntimeError(message)
        next_cursor = min(run.cursor + run.batch_size, run.source_watermark)
        scanned = next_cursor - run.cursor
        return GraphMigrationBatch(next_cursor, scanned, scanned, 0)

    async def validate(self, scope: AuthorizedScope, run: GraphMigrationRun) -> bool:
        del scope
        return run.cursor == run.source_watermark


@dataclass
class _CrashAfterApplyExecutor:
    interrupted_cursor: int
    crashed: bool = False
    requested_cursors: list[int] = field(default_factory=list[int])
    effective_projection_ids: set[int] = field(default_factory=set[int])

    async def source_watermark(
        self, scope: AuthorizedScope, migration_id: str, migration_checksum: str
    ) -> int:
        del scope, migration_id
        assert migration_checksum == CHECKSUM
        return 10

    async def apply_batch(
        self, scope: AuthorizedScope, run: GraphMigrationRun
    ) -> GraphMigrationBatch:
        del scope
        self.requested_cursors.append(run.cursor)
        next_cursor = min(run.cursor + run.batch_size, run.source_watermark)
        before = len(self.effective_projection_ids)
        self.effective_projection_ids.update(range(run.cursor, next_cursor))
        changed = len(self.effective_projection_ids) - before
        if run.cursor == self.interrupted_cursor and not self.crashed:
            self.crashed = True
            message = "simulated power loss after graph commit"
            raise RuntimeError(message)
        return GraphMigrationBatch(next_cursor, next_cursor - run.cursor, changed, 0)

    async def validate(self, scope: AuthorizedScope, run: GraphMigrationRun) -> bool:
        del scope
        return run.cursor == run.source_watermark and len(self.effective_projection_ids) == 10


@dataclass
class _Scanner:
    observations: tuple[GraphIntegrityObservation, ...]

    async def scan(self, scope: AuthorizedScope) -> tuple[GraphIntegrityObservation, ...]:
        del scope
        return self.observations


@dataclass
class _Journal:
    findings: list[GraphIntegrityFinding] = field(default_factory=list[GraphIntegrityFinding])
    repair_records: list[tuple[str, GraphIntegrityFinding, GraphRepairPlan]] = field(
        default_factory=list[tuple[str, GraphIntegrityFinding, GraphRepairPlan]]
    )

    async def record(
        self, scope: AuthorizedScope, findings: tuple[GraphIntegrityFinding, ...]
    ) -> tuple[GraphIntegrityFinding, ...]:
        del scope
        self.findings.extend(item for item in findings if item not in self.findings)
        return findings

    async def get(self, scope: AuthorizedScope, finding_id: str) -> GraphIntegrityFinding | None:
        del scope
        return next((item for item in self.findings if item.id == finding_id), None)

    async def repaired(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        finding: GraphIntegrityFinding,
        plan: GraphRepairPlan,
        repaired_at: datetime,
    ) -> None:
        del scope, repaired_at
        self.repair_records.append((operation_id, finding, plan))


@dataclass
class _Repairs:
    executed: list[tuple[GraphIntegrityFinding, GraphRepairPlan]] = field(
        default_factory=list[tuple[GraphIntegrityFinding, GraphRepairPlan]]
    )

    async def execute(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        plan: GraphRepairPlan,
        repaired_at: datetime,
    ) -> None:
        del scope, repaired_at
        self.executed.append((finding, plan))


@dataclass
class _Rebuilds:
    started: list[tuple[GraphIntegrityFinding, str]] = field(
        default_factory=list[tuple[GraphIntegrityFinding, str]]
    )

    async def verify(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        approval_id: str,
    ) -> bool:
        del scope, finding
        return approval_id == CANONICAL

    async def start(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        approval_id: str,
        requested_at: datetime,
    ) -> None:
        del scope, requested_at
        self.started.append((finding, approval_id))
