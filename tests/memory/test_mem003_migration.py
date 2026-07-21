"""MEM-003 schema upgrade, state constraints, and downgrade-safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from alembic import command
from sqlalchemy import text

from tests.core.support import write_secret
from tests.memory.test_mem002_migration import (
    _config,  # pyright: ignore[reportPrivateUsage]
    _store,  # pyright: ignore[reportPrivateUsage]
)
from tests.memory.test_mem002_sqlite_repository import (
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.migration
def test_mem003_upgrade_installs_closed_merge_schema_and_empty_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "mem003.sqlite3"
    config = _config(database)
    command.upgrade(config, "0017_mem003_memory_deduplication")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "memory_deduplication_operations",
            "memory_redirects",
            "memory_merge_evidence",
        } <= tables
        definition = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='memories'"
        ).fetchone()[0]
        assert "status IN ('active','merged')" in definition
        assert "aggregate_version>=1" in definition
    command.downgrade(config, "0016_mem002_memory_provenance")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0016_mem002_memory_provenance",
        )


@pytest.mark.asyncio
@pytest.mark.migration
async def test_mem003_downgrade_refuses_after_deduplication_evidence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "populated.sqlite3"
    config = _config(database)
    command.upgrade(config, "0017_mem003_memory_deduplication")
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = _store(database)
    try:
        consolidation = await _persist_memory(store, key_file)
        memory_id = consolidation.memories[0].memory_id
        # Seed the irreversible lifecycle evidence directly at the historical
        # MEM-003 schema boundary. Current adapters intentionally require head.
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE memories SET aggregate_version=2 WHERE id=:memory"),
                {"memory": memory_id},
            )
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="MEM-003 downgrade refused"):
        command.downgrade(config, "0016_mem002_memory_provenance")
