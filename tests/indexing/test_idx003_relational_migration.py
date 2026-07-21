"""IDX-003 relational migration shape, rollback, and immutable-ledger tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command

from tests.indexing.test_idx001_sqlite_code_index import (
    _configuration,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.migration
def test_idx003_migration_empty_round_trip_installs_all_append_only_ledgers(
    tmp_path: Path,
) -> None:
    database = tmp_path / "idx003-migration.sqlite3"
    configuration = _configuration(database)
    alembic_command.upgrade(configuration, "0027_idx002_incremental_index")
    alembic_command.upgrade(configuration, "0028_idx003_revision_history")

    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }

    expected = {
        "incremental_index_run_revision_contexts",
        "commit_graph_query_answers",
        "source_revision_contexts",
        "source_revision_context_invalidations",
        "source_revision_evidence_lineage",
        "source_revision_lineage_registrations",
        "source_revision_reextraction_jobs",
        "source_revision_claim_snapshots",
        "source_revision_processing_receipts",
    }
    assert expected <= tables
    assert {f"{table}_no_update" for table in expected} <= triggers
    assert {f"{table}_no_delete" for table in expected} <= triggers

    alembic_command.downgrade(configuration, "0027_idx002_incremental_index")
    alembic_command.upgrade(configuration, "head")
