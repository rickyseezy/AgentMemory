"""ING-004 relational priority scheduler and immutable DLQ migration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


def migration_config(tmp_path: Path) -> tuple[Config, str]:
    database_path = tmp_path / "migration.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    return configuration, f"sqlite:///{database_path}"


@pytest.mark.migration
def test_ing004_migration_extends_one_job_ledger_with_strict_dlq_evidence(tmp_path: Path) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0012_ing004_backpressure_dlq")
    engine = create_engine(database_url)
    try:
        schema = inspect(engine)
        assert {
            "job_authorizations",
            "dead_letters",
            "dead_letter_replays",
            "scheduler_state",
            "scheduler_alerts",
        }.issubset(schema.get_table_names())
        assert {"priority_class", "last_error_code", "parent_job_id"}.issubset(
            {column["name"] for column in schema.get_columns("jobs")}
        )
        checks = " ".join(str(item["sqltext"]) for item in schema.get_check_constraints("jobs"))
        assert "dead_lettered" in checks
        assert all(value in checks for value in ("interactive", "capture", "background"))
        assert tuple(schema.get_pk_constraint("scheduler_state")["constrained_columns"]) == (
            "singleton_id",
        )
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT dispatch_cursor FROM scheduler_state WHERE singleton_id=1")
                ).scalar_one()
                == 0
            )
        command.downgrade(configuration, "0011_ing003_ordered_replay")
        assert "dead_letters" not in inspect(engine).get_table_names()
        command.upgrade(configuration, "0012_ing004_backpressure_dlq")
    finally:
        engine.dispose()


@pytest.mark.migration
def test_ing004_constraints_reject_unsafe_dlq_and_downgrade_refuses_history(
    tmp_path: Path,
) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0012_ing004_backpressure_dlq")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO scheduler_alerts "
                    "(id,metric,threshold_percent,observed_value,observed_limit,created_at,"
                    "schema_version) VALUES ('alert-1','queue_pending',70,140,200,1,1)"
                )
            )
        with engine.begin() as connection, pytest.raises(IntegrityError):
            connection.execute(
                text(
                    "INSERT INTO scheduler_alerts "
                    "(id,metric,threshold_percent,observed_value,observed_limit,created_at,"
                    "schema_version) VALUES ('alert-2','secret_payload',70,1,1,1,1)"
                )
            )
        with pytest.raises(RuntimeError, match="downgrade refused"):
            command.downgrade(configuration, "0011_ing003_ordered_replay")
    finally:
        engine.dispose()
