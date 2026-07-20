"""ING-003 relational causal-order and shadow-replay migration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def migration_config(tmp_path: Path) -> tuple[Config, str]:
    database_path = tmp_path / "migration.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    return configuration, f"sqlite:///{database_path}"


@pytest.mark.migration
def test_ing003_migration_adds_watermarks_gaps_recorded_inputs_and_shadow_replay(
    tmp_path: Path,
) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0011_ing003_ordered_replay")
    engine = create_engine(database_url)
    try:
        schema = inspect(engine)
        assert {
            "ordered_projection_history",
            "ordered_replay_required_events",
            "ordered_replay_runs",
            "ordered_replay_sources",
            "ordered_replay_shadow_history",
            "ordered_replay_shadow_states",
            "projection_order_gaps",
            "projection_order_watermarks",
            "recorded_reduction_inputs",
        }.issubset(schema.get_table_names())
        assert tuple(
            schema.get_pk_constraint("projection_order_watermarks")["constrained_columns"]
        ) == ("projection_name", "brain_id", "ordering_key")
        assert tuple(schema.get_pk_constraint("projection_order_gaps")["constrained_columns"]) == (
            "projection_name",
            "brain_id",
            "ordering_key",
            "blocking_event_id",
        )
        replay_unique = {
            tuple(item["column_names"])
            for item in schema.get_unique_constraints("ordered_replay_runs")
        }
        assert ("brain_id", "projection_name", "projection_generation") in replay_unique
        source_unique = {
            tuple(item["column_names"])
            for item in schema.get_unique_constraints("ordered_replay_sources")
        }
        assert ("operation_id", "source_ordinal") in source_unique
        outbox_checks = " ".join(
            str(item["sqltext"]) for item in schema.get_check_constraints("outbox_messages")
        )
        inbox_checks = " ".join(
            str(item["sqltext"]) for item in schema.get_check_constraints("inbox_receipts")
        )
        assert "replay_required" in outbox_checks
        assert "replay_required" in inbox_checks
        command.downgrade(configuration, "0010_ing002_idempotent_delivery")
        assert "projection_order_watermarks" not in inspect(engine).get_table_names()
        command.upgrade(configuration, "0011_ing003_ordered_replay")
    finally:
        engine.dispose()


@pytest.mark.migration
def test_ing003_constraints_and_downgrade_preserve_ordering_evidence(tmp_path: Path) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0011_ing003_ordered_replay")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO brains "
                    "(id,normalized_name,display_name,trust_class,status,version,created_at,"
                    "updated_at,schema_version) VALUES "
                    "('018f0000-0000-7000-8000-000000000001','brain','Brain','personal',"
                    "'active',1,1,1,1)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO projection_order_watermarks "
                    "(projection_name,brain_id,ordering_key,applied_sequence,state_sha256,"
                    "last_event_id,lease_owner,lease_event_id,lease_sequence,lease_until,"
                    "created_at,updated_at,schema_version) VALUES "
                    "('projection','018f0000-0000-7000-8000-000000000001',"
                    "'018f0000-0000-7000-8000-000000000002',0,:digest,NULL,NULL,NULL,NULL,NULL,"
                    "1,1,1)"
                ),
                {"digest": bytes(32)},
            )
        with pytest.raises(RuntimeError, match="downgrade refused"):
            command.downgrade(configuration, "0010_ing002_idempotent_delivery")
    finally:
        engine.dispose()
