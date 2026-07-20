"""ING-005 relational migration constraints and downgrade safety."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


def configuration(tmp_path: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    config = Config(str(migrations / "alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'agentmemory.sqlite3'}")
    return config


@pytest.mark.integration
def test_migration_creates_constrained_policy_and_decision_evidence(tmp_path: Path) -> None:
    config = configuration(tmp_path)
    command.upgrade(config, "0013_ing005_capture_privacy")
    connection = sqlite3.connect(tmp_path / "agentmemory.sqlite3")
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"capture_policy_versions", "privacy_decisions"}.issubset(tables)
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "uq_capture_policy_active_scope" in indexes
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO privacy_decisions "
                "(id,subject_kind,subject_id,brain_id,actor_id,policy_id,policy_version,"
                "policy_sha256,input_sha256,output_sha256,disposition,classification,"
                "egress_decision,reason_code,finding_counts_json,redaction_count,stage_sha256,"
                "stage_evidence_json,decided_at,schema_version) VALUES "
                "('decision','agent_event','event','brain','actor','policy',1,zeroblob(32),"
                "zeroblob(32),NULL,'sanitized','internal','deny','safe','{}',0,zeroblob(32),"
                "'[]',1,1)"
            )
    finally:
        connection.close()


@pytest.mark.integration
def test_downgrade_refuses_immutable_privacy_evidence(tmp_path: Path) -> None:
    config = configuration(tmp_path)
    command.upgrade(config, "0013_ing005_capture_privacy")
    connection = sqlite3.connect(tmp_path / "agentmemory.sqlite3")
    try:
        connection.execute(
            "INSERT INTO principals "
            "(id,local_subject_digest,type,status,created_at,updated_at,schema_version) VALUES "
            "('018f0000-0000-7000-8000-000000000002',zeroblob(32),'owner','active',1,1,1)"
        )
        connection.execute(
            "INSERT INTO brains "
            "(id,normalized_name,display_name,trust_class,status,version,created_at,updated_at,"
            "schema_version) VALUES ('018f0000-0000-7000-8000-000000000004','brain','Brain',"
            "'personal','active',1,1,1,1)"
        )
        connection.execute(
            "INSERT INTO capture_policy_versions "
            "(id,brain_id,repository_id,scope_key,policy_id,policy_version,policy_sha256,"
            "document_json,status,created_at,schema_version) VALUES "
            "('018f0000-0000-7000-8000-000000000499',"
            "'018f0000-0000-7000-8000-000000000004',NULL,'@brain',"
            "'018f0000-0000-7000-8000-000000000401',1,zeroblob(32),'{}','active',1,1)"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="ING-005 downgrade refused"):
        command.downgrade(config, "0012_ing004_backpressure_dlq")
