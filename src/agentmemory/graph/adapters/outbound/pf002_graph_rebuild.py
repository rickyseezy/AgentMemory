"""GRA-006 bridge to the governed PF-002 canonical graph rebuild path."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.graph.domain.errors import GraphIntegrityError, GraphUnavailableError
from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.operations.adapters.outbound.sqlite_checks import EXPECTED_MIGRATION_HEAD
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionType,
    StartProjectionRebuildCommand,
)
from agentmemory.operations.domain.value_objects import Uuid7Id

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.graph_integrity import GraphIntegrityFinding
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.projection_rebuild import ProjectionRebuild, RebuildManifest
    from agentmemory.shared.clock import Clock

_ERR_PATH = "canonical graph rebuild path failed verification"
_ERR_STORAGE = "canonical graph rebuild verification is unavailable"
_ALLOWED_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})


class ProjectionRebuildStarter(Protocol):
    """Narrow PF-002 start capability consumed by the graph repair bridge."""

    async def execute(self, command: StartProjectionRebuildCommand) -> ProjectionRebuild:
        """Create or replay the exact graph rebuild operation."""
        ...


class Pf002CanonicalGraphRebuild:
    """Authorize destructive repair only by starting an isolated PF-002 generation."""

    def __init__(
        self,
        store: SqliteCoreStore,
        clock: Clock,
        starter: ProjectionRebuildStarter,
        manifest: RebuildManifest,
    ) -> None:
        """Bind canonical authorization, integrity evidence, and exact release pins."""
        self._store = store
        self._clock = clock
        self._starter = starter
        self._manifest = manifest

    async def verify(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        approval_id: str,
    ) -> bool:
        """Verify current owner/admin approval and a healthy canonical replay source."""
        if (
            scope.role not in _ALLOWED_ROLES
            or finding.brain_id != scope.brain_id.value
            or finding.project_id not in {item.value for item in scope.project_ids}
            or finding.repository_id not in {item.value for item in scope.repository_ids}
        ):
            return False
        now = round(self._clock.now().timestamp() * 1_000_000)
        try:
            async with self._store.engine.connect() as connection:
                approved = (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM scope_grants AS grant_row "
                            "JOIN principals AS principal ON principal.id=grant_row.principal_id "
                            "JOIN brains AS brain ON brain.id=grant_row.brain_id "
                            "WHERE grant_row.id=:approval AND grant_row.principal_id=:principal "
                            "AND grant_row.brain_id=:brain AND grant_row.role IN ('owner','admin') "
                            "AND principal.status='active' AND brain.status='active' "
                            "AND grant_row.valid_from<=:now "
                            "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) "
                            "AND (grant_row.project_id IS NULL OR grant_row.project_id=:project) "
                            "AND (grant_row.repository_id IS NULL "
                            "OR grant_row.repository_id=:repository)"
                        ),
                        {
                            "approval": approval_id,
                            "principal": scope.principal_id.value,
                            "brain": scope.brain_id.value,
                            "project": finding.project_id,
                            "repository": finding.repository_id,
                            "now": now,
                        },
                    )
                ).scalar_one()
                head = (
                    await connection.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar_one_or_none()
                quick_check = (await connection.exec_driver_sql("PRAGMA quick_check")).scalar_one()
                foreign_keys = (
                    await connection.exec_driver_sql("PRAGMA foreign_key_check")
                ).first()
        except SQLAlchemyError as error:
            raise GraphUnavailableError(_ERR_STORAGE) from error
        return (
            approved == 1
            and head == EXPECTED_MIGRATION_HEAD
            and quick_check == "ok"
            and foreign_keys is None
        )

    async def start(
        self,
        scope: AuthorizedScope,
        finding: GraphIntegrityFinding,
        approval_id: str,
        requested_at: datetime,
    ) -> None:
        """Enqueue a generation-isolated graph rebuild; never mutate the active graph."""
        del requested_at
        if not await self.verify(scope, finding, approval_id):
            raise GraphIntegrityError(_ERR_PATH)
        await self._starter.execute(
            StartProjectionRebuildCommand(
                operation_id=f"gra006-rebuild-{finding.id}",
                brain_id=Uuid7Id(scope.brain_id.value),
                actor_id=Uuid7Id(scope.principal_id.value),
                grant_id=Uuid7Id(approval_id),
                projection_type=ProjectionType.GRAPH,
                manifest=self._manifest,
            )
        )
