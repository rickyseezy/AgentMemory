"""ING-002 relational idempotency schema migration tests."""

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
def test_ing002_migration_adds_every_unique_idempotency_level_and_backfills_jobs(
    tmp_path: Path,
) -> None:
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
                    "('brain-legacy','legacy','Legacy','personal','active',1,1,1,1)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO jobs "
                    "(id,brain_id,kind,idempotency_key,state,attempts,lease_owner,lease_until,"
                    "next_attempt_at,created_at,updated_at,schema_version) VALUES "
                    "('job-1','brain-legacy','index','same-key','queued',0,NULL,NULL,1,1,1,1)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO jobs "
                    "(id,brain_id,kind,idempotency_key,state,attempts,lease_owner,lease_until,"
                    "next_attempt_at,created_at,updated_at,schema_version) VALUES "
                    "('job-2','brain-legacy','extract','completed-key','succeeded',1,NULL,NULL,"
                    "1,1,7,1)"
                )
            )
        command.upgrade(configuration, "0010_ing002_idempotent_delivery")
        schema = inspect(engine)
        assert {
            "command_receipts",
            "idempotency_conflicts",
            "inbox_receipts",
            "projection_idempotency_receipts",
            "provider_operation_results",
        }.issubset(schema.get_table_names())
        assert {"input_ref", "request_sha256", "result_sha256", "completed_at"}.issubset(
            {column["name"] for column in schema.get_columns("jobs")}
        )
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT request_sha256 FROM jobs WHERE id='job-1'")
                ).scalar_one()
                == hashlib.sha256(b"index\x00same-key").digest()
            )
            succeeded = connection.execute(
                text("SELECT request_sha256,result_sha256,completed_at FROM jobs WHERE id='job-2'")
            ).one()
            assert tuple(succeeded) == (
                hashlib.sha256(b"extract\x00completed-key").digest(),
                hashlib.sha256(b"legacy-succeeded\x00extract\x00completed-key").digest(),
                7,
            )
        command.downgrade(configuration, "0009_ing001_durable_processing")
        assert "inbox_receipts" not in inspect(engine).get_table_names()
        command.upgrade(configuration, "0010_ing002_idempotent_delivery")
    finally:
        engine.dispose()


@pytest.mark.migration
def test_ing002_unique_constraints_and_downgrade_refuse_canonical_receipts(tmp_path: Path) -> None:
    configuration, database_url = migration_config(tmp_path)
    command.upgrade(configuration, "0010_ing002_idempotent_delivery")
    engine = create_engine(database_url)
    try:
        schema = inspect(engine)
        event_primary = tuple(schema.get_pk_constraint("agent_events")["constrained_columns"])
        event_order_unique = {
            tuple(item["column_names"])
            for item in schema.get_unique_constraints("agent_event_envelopes")
        }
        command_primary = tuple(schema.get_pk_constraint("command_receipts")["constrained_columns"])
        inbox_primary = tuple(schema.get_pk_constraint("inbox_receipts")["constrained_columns"])
        inbox_unique = {
            tuple(item["column_names"]) for item in schema.get_unique_constraints("inbox_receipts")
        }
        job_unique = {tuple(item["column_names"]) for item in schema.get_unique_constraints("jobs")}
        provider_primary = tuple(
            schema.get_pk_constraint("provider_operation_results")["constrained_columns"]
        )
        provider_unique = {
            tuple(item["column_names"])
            for item in schema.get_unique_constraints("provider_operation_results")
        }
        projection_primary = tuple(
            schema.get_pk_constraint("projection_idempotency_receipts")["constrained_columns"]
        )
        projection_unique = {
            tuple(item["column_names"])
            for item in schema.get_unique_constraints("projection_idempotency_receipts")
        }
        assert event_primary == ("event_id",)
        assert ("ordering_key", "sequence") in event_order_unique
        assert command_primary == ("command_name", "idempotency_key")
        assert inbox_primary == ("consumer", "message_id")
        assert ("consumer", "idempotency_key") in inbox_unique
        assert ("kind", "idempotency_key") in job_unique
        assert provider_primary == ("profile_id", "idempotency_key")
        assert ("operation_id",) in provider_unique
        assert ("cache_key_sha256",) in provider_unique
        assert projection_primary == ("projection_name", "idempotency_key")
        assert (
            "projection_name",
            "source_message_id",
            "projection_generation",
        ) in projection_unique
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
                    "INSERT INTO command_receipts "
                    "(command_name,idempotency_key,brain_id,request_sha256,result_sha256,"
                    "completed_at,created_at,schema_version) VALUES "
                    "('test','key','brain',:request,:result,1,1,1)"
                ),
                {"request": b"a" * 32, "result": b"b" * 32},
            )
        with pytest.raises(RuntimeError, match="downgrade refused"):
            command.downgrade(configuration, "0009_ing001_durable_processing")
    finally:
        engine.dispose()
