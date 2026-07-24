"""GRA-006 external graph migration and repair evidence schema tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from alembic import command
from sqlalchemy import text

from tests.core.support import migrated_store
from tests.identity.test_checkout_observation_sqlite import (
    _migration_config,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_gra006_schema_keeps_migration_and_repair_lineage_outside_graph(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    async with store.engine.connect() as connection:
        assert (
            await connection.execute(text("SELECT version_num FROM alembic_version"))
        ).scalar_one() == "0040_pro007_provider_resilience"
        tables = {
            str(row[0])
            for row in (
                await connection.execute(
                    text(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND (name LIKE 'graph_migration_%' "
                        "OR name LIKE 'graph_integrity_%')"
                    )
                )
            ).all()
        }
        assert tables == {
            "graph_integrity_findings",
            "graph_integrity_repairs",
            "graph_migration_snapshots",
        }
        triggers = {
            str(row[0])
            for row in (
                await connection.execute(
                    text(
                        "SELECT name FROM sqlite_master WHERE type='trigger' "
                        "AND (name LIKE 'graph_migration_%_no_%' "
                        "OR name LIKE 'graph_integrity_%_no_%')"
                    )
                )
            ).all()
        }
        assert len(triggers) == 6
    await store.engine.dispose()


def test_gra006_clean_downgrade_and_reapply_are_supported(tmp_path: Path) -> None:
    config = _migration_config(tmp_path / "downgrade.sqlite3")
    command.upgrade(config, "0025_gra006_graph_integrity")
    command.downgrade(config, "0024_gra005_contradictions")
    command.upgrade(config, "head")
