"""MEM-003 schema upgrade, state constraints, and downgrade-safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from alembic import command

from agentmemory.memory.adapters.outbound.sqlite_deduplication import (
    SqliteMemoryDeduplicationRepository,
    SqliteMemoryDeduplicationUnitOfWorkFactory,
)
from agentmemory.memory.application.deduplicate_memories import (
    DeduplicateMemoriesCommand,
    DeduplicateMemoriesHandler,
)
from agentmemory.memory.domain.deduplication import MemoryCompatibilityPolicy
from tests.core.support import write_secret
from tests.memory.test_mem001_consolidation_domain import NOW
from tests.memory.test_mem002_migration import (
    _config,  # pyright: ignore[reportPrivateUsage]
    _store,  # pyright: ignore[reportPrivateUsage]
)
from tests.memory.test_mem002_sqlite_repository import (
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.memory.domain.deduplication import (
        MemoryDeduplicationProfile,
        SemanticMemoryCandidate,
    )


class _NoCandidates:
    async def find(
        self,
        target: MemoryDeduplicationProfile,
        limit: int,
    ) -> tuple[SemanticMemoryCandidate, ...]:
        del target, limit
        return ()


class _Clock:
    def now(self) -> datetime:
        return NOW + timedelta(seconds=10)


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
        repository = SqliteMemoryDeduplicationRepository(store)
        handler = DeduplicateMemoriesHandler(
            repository,
            _NoCandidates(),
            SqliteMemoryDeduplicationUnitOfWorkFactory(store),
            MemoryCompatibilityPolicy(),
            _Clock(),
        )
        await handler.execute(
            DeduplicateMemoriesCommand(
                "018f0000-0000-7000-8000-000000000461",
                consolidation.actor_id,
                consolidation.grant_id,
                consolidation.scope.brain_id,
                "018f0000-0000-7000-8000-000000000462",
                "018f0000-0000-7000-8000-000000000463",
                memory_id,
                NOW + timedelta(seconds=5),
                NOW + timedelta(minutes=1),
            )
        )
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="MEM-003 downgrade refused"):
        command.downgrade(config, "0016_mem002_memory_provenance")
