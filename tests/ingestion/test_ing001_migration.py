"""ING-001 relational expand/rollback and legacy backfill tests."""

from __future__ import annotations

import hashlib
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
def test_ing001_migration_backfills_dispatch_integrity_and_round_trips(tmp_path: Path) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0008_adp003_adapter_capabilities")
    engine = create_engine(database_url)
    payload = '{"legacy":true}'
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO brains "
                    "(id,normalized_name,display_name,trust_class,status,version,created_at,"
                    "updated_at,schema_version) VALUES "
                    "('brain-legacy','legacy','Legacy','personal','active',1,1,1,1)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO agent_events "
                    "(event_id,brain_id,type,payload_hash,classification,occurred_at,ingested_at,"
                    "schema_version) VALUES "
                    "('event-legacy','brain-legacy','legacy',:digest,'internal',1,1,1)"
                ),
                {"digest": b"a" * 32},
            )
            connection.execute(
                text(
                    "INSERT INTO outbox_messages "
                    "(id,source_event_id,topic,message_key,payload,status,created_at,"
                    "schema_version) "
                    "VALUES ('message-legacy','event-legacy','legacy','key',:payload,'ready',7,1)"
                ),
                {"payload": payload},
            )
        command.upgrade(configuration, "0009_ing001_durable_processing")
        upgraded = inspect(engine)
        assert {"artifacts", "event_projection_receipts", "ingestion_repair_alerts"}.issubset(
            upgraded.get_table_names()
        )
        assert {"payload_sha256", "lease_owner", "not_before", "attempts"}.issubset(
            {item["name"] for item in upgraded.get_columns("outbox_messages")}
        )
        with engine.connect() as connection:
            row = connection.execute(
                text("SELECT payload_sha256,not_before FROM outbox_messages")
            ).one()
            assert row[0] == hashlib.sha256(payload.encode()).digest()
            assert row[1] == 7
        command.downgrade(configuration, "0008_adp003_adapter_capabilities")
        assert "artifacts" not in inspect(engine).get_table_names()
        command.upgrade(configuration, "0009_ing001_durable_processing")
    finally:
        engine.dispose()


@pytest.mark.migration
def test_ing001_downgrade_refuses_terminal_state(tmp_path: Path) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0009_ing001_durable_processing")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO brains "
                    "(id,normalized_name,display_name,trust_class,status,version,created_at,"
                    "updated_at,schema_version) VALUES "
                    "('brain','brain','Brain','personal','active',1,1,1,1)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO artifacts "
                    "(id,brain_id,sha256,media_type,byte_length,encryption_key_ref,blob_uri,"
                    "classification,created_at,updated_at,schema_version) VALUES "
                    "('artifact','brain',:digest,'application/json',1,'key',:uri,'internal',1,1,1)"
                ),
                {"digest": b"a" * 32, "uri": f"cas://sha256/{'61' * 32}"},
            )
        with pytest.raises(RuntimeError, match="downgrade refused"):
            command.downgrade(configuration, "0008_adp003_adapter_capabilities")
    finally:
        engine.dispose()
