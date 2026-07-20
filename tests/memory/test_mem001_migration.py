"""MEM-001 relational migration, constraints, and rollback-safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


def _config(database: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    config = Config(str(migrations / "alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


@pytest.mark.migration
def test_mem001_upgrade_creates_constrained_memory_and_task_lineage_schema(
    tmp_path: Path,
) -> None:
    database = tmp_path / "memory.db"
    config = _config(database)
    command.upgrade(config, "0015_mem001_memory_consolidation")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "event_task_lineage",
            "memory_consolidations",
            "memories",
            "memory_revisions",
            "memory_evidence",
            "memory_candidate_rejections",
        }.issubset(tables)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0015_mem001_memory_consolidation",
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO memory_consolidations "
                "(idempotency_key,operation_id,brain_id,actor_id,grant_id,correlation_id,"
                "causation_id,task_id,"
                "project_id,repository_id,checkout_id,source_terminal_event_id,"
                "evidence_watermark_sha256,extractor_input_sha256,extractor_id,"
                "extractor_version,model_id,model_revision,output_schema,extractor_fingerprint,"
                "promotion_policy_version,classification,retention_policy_id,promoted,rejected,"
                "result_json,result_sha256,requested_at,completed_at,created_at,updated_at,"
                "schema_version) "
                "VALUES (zeroblob(32),'op','missing','missing','missing','correlation',"
                "'causation','task','project',"
                "'repository',NULL,'event',zeroblob(32),zeroblob(32),'extractor','1.0.0','model',"
                "'revision','memory-candidates.v1',zeroblob(32),'policy','internal','default',"
                "33,0,'{}',zeroblob(32),1,1,1,1,1)"
            )


@pytest.mark.migration
def test_mem001_empty_schema_can_downgrade_but_evidence_blocks_destructive_rollback(
    tmp_path: Path,
) -> None:
    empty_database = tmp_path / "empty.db"
    empty_config = _config(empty_database)
    command.upgrade(empty_config, "0015_mem001_memory_consolidation")
    command.downgrade(empty_config, "0014_ing006_schema_evolution")
    with closing(sqlite3.connect(empty_database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0014_ing006_schema_evolution",
        )

    populated_database = tmp_path / "populated.db"
    populated_config = _config(populated_database)
    command.upgrade(populated_config, "0015_mem001_memory_consolidation")
    with closing(sqlite3.connect(populated_database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO event_task_lineage "
            "(event_id,brain_id,principal_id,project_id,repository_id,checkout_id,session_id,"
            "task_id,correlation_id,causation_id,event_type,classification,retention_policy_id,"
            "occurred_at,canonical_event_sha256,created_at,schema_version) VALUES "
            "('018f0000-0000-7000-8000-000000000301','brain','principal','project',"
            "'repository',NULL,"
            "'018f0000-0000-7000-8000-000000000111',"
            "'018f0000-0000-7000-8000-000000000201',"
            "'018f0000-0000-7000-8000-000000000121',"
            "'018f0000-0000-7000-8000-000000000301',"
            "'agentmemory.task.completed.v1',"
            "'internal','default',1,zeroblob(32),1,1)"
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="MEM-001 downgrade refused"):
        command.downgrade(populated_config, "0014_ing006_schema_evolution")
