"""GRA-002 relational migration and rollback-safety tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from alembic import command

from tests.identity.test_checkout_observation_sqlite import (
    _migration_config,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.migration
def test_gra002_migration_round_trips_before_evidence(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, "0020_mem006_session_briefing")
    command.upgrade(configuration, "0021_gra002_evidence_assertions")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0021_gra002_evidence_assertions",
        )
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'assertion_%'"
            )
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE 'assertion_%_no_%'"
            )
        }
    assert tables == {
        "assertion_candidates",
        "assertion_evidence_revocations",
        "assertion_evidence_snapshots",
        "assertion_evidence_sources",
        "assertion_lifecycle",
        "assertion_operations",
    }
    assert len(triggers) == 14
    command.downgrade(configuration, "0020_mem006_session_briefing")
    command.upgrade(configuration, "head")
