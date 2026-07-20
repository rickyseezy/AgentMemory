"""ING-006 relational schema constraints and rollback refusal tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


def configuration(database: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    config = Config(str(migrations / "alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


def test_schema_evolution_tables_have_closed_constraints_and_indexes(tmp_path: Path) -> None:
    database = tmp_path / "schema-evolution.sqlite3"
    config = configuration(database)
    command.upgrade(config, "0014_ing006_schema_evolution")
    connection = sqlite3.connect(database)
    try:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "event_schema_sources",
            "event_schema_migrations",
            "event_schema_views",
            "event_schema_quarantine",
        } <= tables
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO event_schema_migrations "
                "(operation_id,schema_family,target_major,target_version,state,"
                "cursor_event_id,source_watermark_event_id,scanned,upcasted,current_count,"
                "quarantined,total,started_at,updated_at,schema_version) VALUES "
                "('invalid','agent_event',1,2,'completed',NULL,NULL,0,0,0,0,1,1,1,1)"
            )
    finally:
        connection.close()


def test_downgrade_refuses_to_delete_schema_lineage(tmp_path: Path) -> None:
    database = tmp_path / "schema-evolution-evidence.sqlite3"
    config = configuration(database)
    command.upgrade(config, "0014_ing006_schema_evolution")
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "INSERT INTO event_schema_migrations "
            "(operation_id,schema_family,target_major,target_version,state,"
            "cursor_event_id,source_watermark_event_id,scanned,upcasted,current_count,"
            "quarantined,total,started_at,updated_at,schema_version) VALUES "
            "('ing006-test','agent_event',1,2,'completed',NULL,NULL,0,0,0,0,0,1,1,1)"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="schema lineage"):
        command.downgrade(config, "0013_ing005_capture_privacy")
