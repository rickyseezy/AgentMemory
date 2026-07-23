"""GRA-005 contradiction schema migration tests."""

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
async def test_gra005_schema_is_closed_append_only_and_adds_assertion_polarity(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    async with store.engine.connect() as connection:
        head = (
            await connection.execute(text("SELECT version_num FROM alembic_version"))
        ).scalar_one()
        assert head == "0037_pro004_embedding_spaces"
        columns = {
            str(row["name"])
            for row in (
                await connection.execute(text("PRAGMA table_info('assertion_candidates')"))
            ).mappings()
        }
        assert "polarity" in columns
        tables = {
            str(row[0])
            for row in (
                await connection.execute(
                    text(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name LIKE 'graph_contradiction%'"
                    )
                )
            ).all()
        }
        assert tables == {
            "graph_contradiction_evidence",
            "graph_contradiction_operations",
            "graph_contradiction_resolutions",
            "graph_contradictions",
        }
        triggers = {
            str(row[0])
            for row in (
                await connection.execute(
                    text(
                        "SELECT name FROM sqlite_master WHERE type='trigger' "
                        "AND name LIKE 'graph_contradiction%_no_%'"
                    )
                )
            ).all()
        }
        assert len(triggers) == 8
    await store.engine.dispose()


def test_gra005_downgrade_is_available_only_before_contradiction_history(tmp_path: Path) -> None:
    config = _migration_config(tmp_path / "downgrade.sqlite3")
    command.upgrade(config, "0024_gra005_contradictions")
    command.downgrade(config, "0023_gra004_temporal_revision_truth")
    command.upgrade(config, "head")
