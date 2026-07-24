"""PRO-004 canonical embedding-space migration contract tests."""

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


def test_pro004_schema_installs_closed_constraints_triggers_and_empty_downgrade(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pro004-empty.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0041_pro008_embedding_migrations",
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
        space_fingerprint_columns = tuple(
            str(row[2])
            for row in connection.execute(
                "PRAGMA index_info('uq_embedding_space_brain_fingerprint')"
            ).fetchall()
        )
        generation_foreign_keys = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(
                "PRAGMA foreign_key_list('embedding_index_generations')"
            ).fetchall()
        }
    assert {
        "embedding_spaces",
        "embedding_index_generations",
        "embedding_generation_operations",
    } <= tables
    assert {
        "trg_embedding_spaces_immutable_update",
        "trg_embedding_spaces_immutable_delete",
        "trg_embedding_index_generations_closed_update",
        "trg_embedding_index_generations_immutable_delete",
        "trg_embedding_generation_operations_immutable_delete",
    } <= triggers
    assert {
        "uq_embedding_space_brain_fingerprint",
        "uq_embedding_generation_brain_space",
        "uq_embedding_generation_label",
        "uq_embedding_generation_vector_index",
    } <= indexes
    assert space_fingerprint_columns == ("brain_id", "immutable_fingerprint")
    assert ("embedding_spaces", "space_id", "id") in generation_foreign_keys

    command.downgrade(configuration, "0036_pro003_capability_attestations")
    command.upgrade(configuration, "head")


def test_pro004_downgrade_refuses_to_discard_canonical_space_history(tmp_path: Path) -> None:
    database = tmp_path / "pro004-history.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "INSERT INTO embedding_spaces("
            "id,brain_id,immutable_fingerprint,profile_id,capability_attestation_id,descriptor_json,"
            "adapter_digest,model_revision,dimension,dtype,normalization,similarity,purpose,"
            "created_at,schema_version"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "018f0000-0000-7000-8000-000000000101",
                "018f0000-0000-7000-8000-000000000100",
                "1" * 64,
                "018f0000-0000-7000-8000-000000000102",
                "2" * 64,
                b"{}",
                "3" * 64,
                "revision",
                2,
                "float32",
                "l2",
                "cosine",
                "retrieval_document",
                1,
                1,
            ),
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="PRO-004 downgrade refused"):
        command.downgrade(configuration, "0036_pro003_capability_attestations")
