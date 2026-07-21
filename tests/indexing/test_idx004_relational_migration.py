"""IDX-004 relational schema, immutability, and retained-history rollback tests."""

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
def test_idx004_migration_installs_immutable_ledgers_and_empty_round_trips(
    tmp_path: Path,
) -> None:
    database = tmp_path / "idx004-migration.sqlite3"
    configuration = _configuration(database)
    alembic_command.upgrade(configuration, "0028_idx003_revision_history")
    alembic_command.upgrade(configuration, "0029_idx004_api_topology")

    expected = {
        "api_topology_candidate_batches",
        "api_topology_endpoint_candidates",
        "api_topology_client_call_candidates",
        "api_topology_contract_binding_candidates",
        "api_topology_service_ownership_candidates",
        "api_topology_link_operations",
        "api_topology_match_decisions",
    }
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
    assert expected <= tables
    assert {f"{table}_no_update" for table in expected} <= triggers
    assert {f"{table}_no_delete" for table in expected} <= triggers

    alembic_command.downgrade(configuration, "0028_idx003_revision_history")
    alembic_command.upgrade(configuration, "head")


@pytest.mark.migration
def test_idx004_retained_candidate_history_blocks_destructive_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "idx004-retained.sqlite3"
    configuration = _configuration(database)
    alembic_command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO api_topology_candidate_batches(batch_id,operation_id,brain_id,"
            "project_id,repository_id,source_file_id,source_revision_context_id,commit_sha,"
            "plugin_kind,plugin_version,batch_digest,supersedes_batch_id,principal_id,"
            "scope_fingerprint,registered_at,schema_version) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (
                "a" * 64,
                "idx004.retained",
                "018f0000-0000-7000-8000-000000000001",
                "018f0000-0000-7000-8000-000000000002",
                "018f0000-0000-7000-8000-000000000003",
                "b" * 64,
                "c" * 64,
                "d" * 40,
                "openapi",
                "v1.0.0",
                bytes.fromhex("a" * 64),
                None,
                "018f0000-0000-7000-8000-000000000004",
                bytes.fromhex("e" * 64),
                1,
            ),
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="history prevents destructive downgrade"):
        alembic_command.downgrade(configuration, "0028_idx003_revision_history")
