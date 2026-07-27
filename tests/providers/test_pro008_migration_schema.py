"""PRO-008 migration, pointer, dual-write, and evidence schema tests."""

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


def test_pro008_schema_installs_all_live_migration_authority(tmp_path: Path) -> None:
    database = tmp_path / "pro008-empty.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0043_pro010_provider_observability",
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
        migration_fks = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(
                "PRAGMA foreign_key_list('embedding_generation_migrations')"
            ).fetchall()
        }
    assert {
        "embedding_generation_migrations",
        "embedding_migration_operations",
        "active_embedding_generations",
        "embedding_generation_write_routes",
        "embedding_migration_evidence",
        "embedding_migration_activations",
    } <= tables
    assert {
        "trg_embedding_generation_migrations_closed_update",
        "trg_embedding_generation_migrations_immutable_delete",
        "trg_embedding_migration_operations_immutable_update",
        "trg_embedding_migration_evidence_immutable_delete",
        "trg_embedding_migration_activations_immutable_update",
        "trg_active_embedding_generations_closed_update",
        "trg_embedding_generation_write_routes_closed_update",
    } <= triggers
    assert "ix_embedding_migration_brain_state" in indexes
    assert {
        ("embedding_index_generations", "source_generation_id", "id"),
        ("embedding_index_generations", "target_generation_id", "id"),
        ("embedding_spaces", "source_space_id", "id"),
        ("embedding_spaces", "target_space_id", "id"),
    } <= migration_fks

    command.downgrade(configuration, "0040_pro007_provider_resilience")
    command.upgrade(configuration, "head")


@pytest.mark.parametrize(
    "authority",
    [
        "embedding_generation_migrations",
        "active_embedding_generations",
        "embedding_generation_write_routes",
    ],
)
def test_pro008_downgrade_refuses_any_live_migration_authority(
    tmp_path: Path,
    authority: str,
) -> None:
    database = tmp_path / f"pro008-{authority}.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        if authority == "embedding_generation_migrations":
            connection.execute(
                "INSERT INTO embedding_generation_migrations "
                "(id,brain_id,source_space_id,source_generation_id,"
                "source_space_fingerprint,target_space_id,target_generation_id,"
                "target_space_fingerprint,source_watermark,backfill_cursor,"
                "catchup_watermark,catchup_cursor,state,validation_digest,"
                "rollback_until,source_retired_at,source_deleted_at,version,"
                "created_at,updated_at,schema_version) VALUES "
                "(?,?,?,?,?,?,?,?,0,0,0,0,'planned',NULL,NULL,NULL,NULL,1,0,0,1)",
                (
                    "018f0000-0000-7000-8000-000000000801",
                    "018f0000-0000-7000-8000-000000000001",
                    "018f0000-0000-7000-8000-000000000501",
                    "018f0000-0000-7000-8000-000000000111",
                    bytes(32),
                    "018f0000-0000-7000-8000-000000000502",
                    "018f0000-0000-7000-8000-000000000112",
                    bytes(32),
                ),
            )
        elif authority == "active_embedding_generations":
            connection.execute(
                "INSERT INTO active_embedding_generations "
                "(brain_id,purpose,space_id,generation_id,version,updated_at,schema_version) "
                "VALUES (?,?,?,?,1,0,1)",
                (
                    "018f0000-0000-7000-8000-000000000001",
                    "retrieval_document",
                    "018f0000-0000-7000-8000-000000000501",
                    "018f0000-0000-7000-8000-000000000111",
                ),
            )
        else:
            connection.execute(
                "INSERT INTO embedding_generation_write_routes "
                "(brain_id,source_space_id,primary_space_id,primary_space_fingerprint,"
                "primary_generation_id,secondary_space_id,secondary_space_fingerprint,"
                "secondary_generation_id,migration_id,version,updated_at,schema_version) "
                "VALUES (?,?,?,?,?,NULL,NULL,NULL,NULL,1,0,1)",
                (
                    "018f0000-0000-7000-8000-000000000001",
                    "018f0000-0000-7000-8000-000000000501",
                    "018f0000-0000-7000-8000-000000000501",
                    bytes(32),
                    "018f0000-0000-7000-8000-000000000111",
                ),
            )
        connection.commit()
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(configuration, "0040_pro007_provider_resilience")
