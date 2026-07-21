"""GRA-006 ports for resumable migration and governed graph repair."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.graph_integrity import (
        GraphIntegrityFinding,
        GraphIntegrityObservation,
        GraphMigrationBatch,
        GraphMigrationRun,
        GraphRepairPlan,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


class GraphMigrationRepository(Protocol):
    """Persist durable external migration progress and exact idempotency evidence."""

    async def start(self, scope: AuthorizedScope, run: GraphMigrationRun) -> GraphMigrationRun:
        """Insert or return an exactly matching migration run."""
        ...

    async def get(self, scope: AuthorizedScope, operation_id: str) -> GraphMigrationRun | None:
        """Load one currently authorized run without leaking foreign scope state."""
        ...

    async def checkpoint(
        self,
        scope: AuthorizedScope,
        run: GraphMigrationRun,
        batch: GraphMigrationBatch,
        at: datetime,
    ) -> GraphMigrationRun:
        """Atomically append one batch cursor and cumulative counters."""
        ...

    async def save(self, scope: AuthorizedScope, run: GraphMigrationRun) -> GraphMigrationRun:
        """Append a validation or completion transition."""
        ...


class GraphMigrationExecutor(Protocol):
    """Apply one closed migration implementation to a shadow graph surface."""

    async def source_watermark(
        self, scope: AuthorizedScope, migration_id: str, migration_checksum: str
    ) -> int:
        """Return the immutable upper cursor for this authorized migration."""
        ...

    async def apply_batch(
        self, scope: AuthorizedScope, run: GraphMigrationRun
    ) -> GraphMigrationBatch:
        """Apply at most the run batch size after its current durable cursor."""
        ...

    async def validate(self, scope: AuthorizedScope, run: GraphMigrationRun) -> bool:
        """Verify schema compatibility and shadow result integrity."""
        ...


class GraphIntegrityScanner(Protocol):
    """Read bounded, content-free projection metadata under current scope."""

    async def scan(self, scope: AuthorizedScope) -> tuple[GraphIntegrityObservation, ...]:
        """Return projection observations without returning source content."""
        ...


class GraphIntegrityJournal(Protocol):
    """Persist immutable findings and repair audit evidence."""

    async def record(
        self, scope: AuthorizedScope, findings: tuple[GraphIntegrityFinding, ...]
    ) -> tuple[GraphIntegrityFinding, ...]:
        """Append or replay exact findings."""
        ...

    async def get(self, scope: AuthorizedScope, finding_id: str) -> GraphIntegrityFinding | None:
        """Load one currently authorized finding."""
        ...

    async def repaired(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        finding: GraphIntegrityFinding,
        plan: GraphRepairPlan,
        repaired_at: datetime,
    ) -> None:
        """Append exact repair authority and outcome evidence."""
        ...


class GraphRepairExecutor(Protocol):
    """Execute one closed repair plan against derived graph state only."""

    async def execute(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        plan: GraphRepairPlan,
        repaired_at: datetime,
    ) -> None:
        """Shadow-write, quarantine, or start the verified rebuild path."""
        ...


class CanonicalGraphRebuild(Protocol):
    """Verify and start the separately governed PF-002 canonical rebuild path."""

    async def verify(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        approval_id: str,
    ) -> bool:
        """Prove current approval and a reproducible canonical graph source."""
        ...

    async def start(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        approval_id: str,
        requested_at: datetime,
    ) -> None:
        """Start a PF-002 shadow rebuild without deleting live or canonical history."""
        ...
