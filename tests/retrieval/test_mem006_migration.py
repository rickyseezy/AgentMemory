"""MEM-006 relational migration and rollback-safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.retrieval.adapters.outbound.sqlite_briefing import (
    SqliteContextInjectionRepository,
)
from agentmemory.retrieval.application.start_session_briefing import (
    DeterministicBriefingRetrievalPipeline,
    StartSessionBriefingHandler,
)
from agentmemory.retrieval.domain.continuity import BriefingBudget, ProcedureEnvironment
from tests.core.support import migrated_store
from tests.identity.test_checkout_observation_sqlite import (
    _migration_config,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _seed_roots as seed_roots,  # pyright: ignore[reportPrivateUsage]
)
from tests.retrieval.support import (
    BRIEFING_OPERATION_ID,
    CONTEXT_EVENT_ID,
    FakeCodeRevisionQuery,
    FakeContinuityRepository,
    FakeProcedureRepository,
    briefing_query,
    scope,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_mem006_migration_is_reversible_before_context_evidence(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, "0019_mem005_memory_lifecycle")
    command.upgrade(configuration, "0020_mem006_session_briefing")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0020_mem006_session_briefing",
        )
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='session_briefing_receipts'"
        ).fetchone()
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE '%briefing_receipts%'"
            )
        }
    assert table == (1,)
    assert triggers == {
        "session_briefing_receipts_no_delete",
        "session_briefing_receipts_no_update",
    }

    command.downgrade(configuration, "0019_mem005_memory_lifecycle")
    command.upgrade(configuration, "head")


@pytest.mark.asyncio
@pytest.mark.migration
async def test_mem006_downgrade_refuses_after_context_evidence(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        handler = StartSessionBriefingHandler(
            FakeContinuityRepository(()),
            FakeContinuityRepository(()),
            FakeCodeRevisionQuery(),
            DeterministicBriefingRetrievalPipeline.production(),
            FakeProcedureRepository(()),
            SqliteContextInjectionRepository(store.engine),
            lambda: UUID(CONTEXT_EVENT_ID),
        )
        await handler.execute(
            briefing_query(
                scope(),
                BriefingBudget(),
                ProcedureEnvironment("darwin", ("mcp",)),
            )
        )
        with pytest.raises(IntegrityError, match="receipts are immutable"):
            async with store.engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE session_briefing_receipts SET status='ready' "
                        "WHERE operation_id=:operation"
                    ),
                    {"operation": BRIEFING_OPERATION_ID},
                )
        with pytest.raises(IntegrityError, match="ContextInjected events are immutable"):
            async with store.engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE domain_events SET recorded_at=recorded_at+1 WHERE event_id=:event"
                    ),
                    {"event": CONTEXT_EVENT_ID},
                )
    finally:
        await store.close()

    with pytest.raises(RuntimeError, match="MEM-006 downgrade refused"):
        command.downgrade(_migration_config(tmp_path / "agentmemory.sqlite3"), "0019")
