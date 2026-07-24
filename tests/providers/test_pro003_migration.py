"""PRO-003 capability-attestation migration contract tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from alembic import command
from alembic.config import Config


def _configuration(database: Path) -> Config:
    root = Path(__file__).resolve().parents[2]
    migrations = root / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def test_pro003_empty_schema_installs_indexes_triggers_and_downgrades_cleanly(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pro003-empty.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        head = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        assert head == ("0041_pro008_embedding_migrations",)
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(provider_capability_attestations)")
        }
        assert columns == {
            "attestation_id",
            "profile_id",
            "adapter_digest",
            "endpoint_fingerprint",
            "configuration_digest",
            "suite_digest",
            "canary_digest",
            "validation_digest",
            "validated_batches",
            "recorded_at",
            "schema_version",
        }
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE 'trg_provider_capability_attestations_%'"
            )
        }
        assert triggers == {
            "trg_provider_capability_attestations_immutable_delete",
            "trg_provider_capability_attestations_immutable_update",
        }
    command.downgrade(configuration, "0035_pf005_mcp_sessions")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "provider_capability_attestations" not in tables
