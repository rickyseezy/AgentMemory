"""MEM-004 correction schema, lifecycle constraints, and downgrade-safety tests."""

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
def test_mem004_upgrade_installs_correction_authority_and_empty_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "mem004.sqlite3"
    config = _config(database)
    command.upgrade(config, "0018_mem004_memory_correction")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "memory_correction_operations",
            "memory_corrections",
            "memory_correction_evidence",
        } <= tables
        memory_definition = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='memories'"
        ).fetchone()[0]
        assert "'disputed','superseded'" in memory_definition
        correction_definition = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='memory_corrections'"
        ).fetchone()[0]
        assert "relation IN ('supersedes','contradicts')" in correction_definition
        assert "status IN ('active','disputed','superseded')" in correction_definition
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        assert {
            "memory_correction_immutable_fields",
            "memory_correction_evidence_immutable",
            "memory_correction_operation_immutable",
        } <= triggers

    command.downgrade(config, "0017_mem003_memory_deduplication")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0017_mem003_memory_deduplication",
        )


@pytest.mark.migration
def test_mem004_downgrade_refuses_visible_correction_lifecycle(tmp_path: Path) -> None:
    database = tmp_path / "populated.sqlite3"
    config = _config(database)
    command.upgrade(config, "0018_mem004_memory_correction")
    with closing(sqlite3.connect(database)) as connection:
        # A correction lifecycle state is itself irreversible MEM-004 evidence even if
        # an interrupted writer has not yet appended the correction receipt.
        connection.execute(
            "INSERT INTO memories "
            "(id,brain_id,memory_class,project_id,repository_id,checkout_id,scope_json,status,"
            "current_revision,valid_from,valid_to,recorded_from,recorded_to,confidence_json,"
            "retention_policy_id,classification,aggregate_version,source_task_id,"
            "extractor_fingerprint,content_hash,consolidation_key,created_at,updated_at,"
            "schema_version) VALUES "
            "('m','b','decision','p','r',NULL,'{}','disputed',1,1,NULL,1,NULL,'{}','default',"
            "'internal',2,'t',zeroblob(32),zeroblob(32),zeroblob(32),1,1,1)"
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="MEM-004 downgrade refused"):
        command.downgrade(config, "0017_mem003_memory_deduplication")
