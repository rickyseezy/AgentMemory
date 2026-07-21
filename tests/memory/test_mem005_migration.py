"""MEM-005 lifecycle schema, transition guards, and downgrade safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from alembic import command

from tests.memory.test_mem002_migration import _config  # pyright: ignore[reportPrivateUsage]

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.migration
def test_mem005_upgrade_backfills_lifecycle_and_empty_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "mem005.sqlite3"
    config = _config(database)
    command.upgrade(config, "0018_mem004_memory_correction")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO memories "
            "(id,brain_id,memory_class,project_id,repository_id,checkout_id,scope_json,status,"
            "current_revision,valid_from,valid_to,recorded_from,recorded_to,confidence_json,"
            "retention_policy_id,classification,aggregate_version,source_task_id,"
            "extractor_fingerprint,content_hash,consolidation_key,created_at,updated_at,"
            "schema_version) VALUES "
            "('m','b','decision','p','r',NULL,'{}','active',1,1,NULL,1,NULL,'{}','default',"
            "'internal',1,'t',zeroblob(32),zeroblob(32),zeroblob(32),1,1,1)"
        )
        connection.commit()

    command.upgrade(config, "0019_mem005_memory_lifecycle")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute(
            "SELECT recall_state,pinned,aggregate_version FROM memory_lifecycle"
        ).fetchone() == ("active", 0, 1)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "memory_lifecycle",
            "memory_lifecycle_operations",
            "memory_lifecycle_events",
            "memory_deletion_manifests",
        } <= tables

    command.downgrade(config, "0018_mem004_memory_correction")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0018_mem004_memory_correction",
        )


@pytest.mark.migration
def test_mem005_guards_transitions_and_refuses_evidence_losing_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "guarded.sqlite3"
    config = _config(database)
    command.upgrade(config, "0018_mem004_memory_correction")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO memories "
            "(id,brain_id,memory_class,project_id,repository_id,checkout_id,scope_json,status,"
            "current_revision,valid_from,valid_to,recorded_from,recorded_to,confidence_json,"
            "retention_policy_id,classification,aggregate_version,source_task_id,"
            "extractor_fingerprint,content_hash,consolidation_key,created_at,updated_at,"
            "schema_version) VALUES "
            "('m','b','decision','p','r',NULL,'{}','active',1,1,NULL,1,NULL,'{}','default',"
            "'internal',1,'t',zeroblob(32),zeroblob(32),zeroblob(32),1,1,1)"
        )
        connection.commit()
    command.upgrade(config, "0019_mem005_memory_lifecycle")

    with closing(sqlite3.connect(database)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="invalid memory lifecycle transition"):
            connection.execute(
                "UPDATE memory_lifecycle SET recall_state='forgotten' WHERE memory_id='m'"
            )
        connection.execute(
            "UPDATE memory_lifecycle SET recall_state='archived',aggregate_version=2,updated_at=2 "
            "WHERE memory_id='m'"
        )
        connection.commit()

    with pytest.raises(RuntimeError, match="MEM-005 downgrade refused"):
        command.downgrade(config, "0018_mem004_memory_correction")
