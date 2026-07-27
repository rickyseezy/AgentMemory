"""PRO-005 append-only provider-routing migration contract tests."""

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


def test_pro005_schema_installs_immutable_authority_evidence_and_empty_downgrade(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pro005-empty.sqlite3"
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
        rule_foreign_keys = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(
                "PRAGMA foreign_key_list('provider_route_rules')"
            ).fetchall()
        }
    assert {
        "provider_routing_policies",
        "provider_route_rules",
        "provider_repository_route_restrictions",
        "provider_routing_operations",
        "provider_route_decisions",
    } <= tables
    assert {
        "trg_provider_routing_policies_immutable_update",
        "trg_provider_route_rules_immutable_delete",
        "trg_provider_repository_route_restrictions_immutable_update",
        "trg_provider_routing_operations_immutable_delete",
        "trg_provider_route_decisions_immutable_update",
    } <= triggers
    assert {
        ("provider_profile_revisions", "profile_id", "profile_id"),
        ("provider_profile_revisions", "profile_version", "version"),
    } <= rule_foreign_keys

    command.downgrade(configuration, "0037_pro004_embedding_spaces")
    command.upgrade(configuration, "head")
