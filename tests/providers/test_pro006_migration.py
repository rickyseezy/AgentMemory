"""PRO-006 durable scheduling schema and downgrade-safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


def _configuration(database: Path) -> Config:
    root = Path(__file__).resolve().parents[2]
    migrations = root / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def test_pro006_schema_installs_queue_rate_batch_result_and_operation_authority(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pro006-empty.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0040_pro007_provider_resilience",
        )
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
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        work_fks = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(
                "PRAGMA foreign_key_list('provider_work_items')"
            ).fetchall()
        }
    assert {
        "provider_work_items",
        "provider_scheduling_operations",
        "provider_scheduler_state",
        "provider_rate_states",
        "provider_batches",
        "provider_batch_items",
        "provider_item_results",
    } <= tables
    assert {
        "trg_provider_batches_immutable_delete",
        "trg_provider_batch_items_immutable_update",
        "trg_provider_item_results_immutable_delete",
        "trg_provider_work_identity_closed_update",
    } <= triggers
    assert {
        "ix_provider_work_dispatch",
        "ix_provider_work_partition",
        "uq_provider_work_operation",
    } <= indexes
    assert {
        ("brains", "brain_id", "id"),
        ("provider_profiles", "profile_id", "id"),
        ("embedding_spaces", "space_id", "id"),
    } <= work_fks

    command.downgrade(configuration, "0038_pro005_provider_routing")
    command.upgrade(configuration, "head")


def test_pro006_downgrade_refuses_to_destroy_scheduling_history(tmp_path: Path) -> None:
    database = tmp_path / "pro006-history.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO provider_scheduler_state(profile_id,dispatch_cursor,updated_at,"
            "schema_version) VALUES ('018f0000-0000-7000-8000-000000000999',0,0,1)"
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(configuration, "0038_pro005_provider_routing")
