"""PF-003 relational registry migration and downgrade safety tests."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from alembic import command

from tests.providers.test_pro001_sqlite_profiles import _alembic

if TYPE_CHECKING:
    from pathlib import Path


def test_pf003_migration_is_strict_immutable_and_downgrade_safe(tmp_path: Path) -> None:
    database = tmp_path / "adapter-extensions.sqlite3"
    configuration = _alembic(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0037_pro004_embedding_spaces",
        )
        _seed_authority(connection)
        connection.execute(
            "INSERT INTO adapter_extension_registrations "
            "(registration_id,brain_id,actor_id,grant_id,adapter_id,adapter_version,"
            "adapter_kind,package_digest,manifest_digest,evidence_digest,registration_digest,"
            "manifest_json,evidence_json,state,registered_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "018f0000-0000-7000-8000-000000000321",
                "018f0000-0000-7000-8000-000000000322",
                "018f0000-0000-7000-8000-000000000323",
                "018f0000-0000-7000-8000-000000000324",
                "external-agent",
                "1.0.0",
                "agent",
                "a" * 64,
                "b" * 64,
                "c" * 64,
                "d" * 64,
                b'{"schema_version":1}',
                b'{"negotiated_protocol":"1.0"}',
                "active",
                1,
            ),
        )
        connection.execute(
            "INSERT INTO adapter_extension_operations "
            "(operation_id,request_digest,registration_id,completed_at) VALUES (?,?,?,?)",
            (
                "register-1",
                "e" * 64,
                "018f0000-0000-7000-8000-000000000321",
                1,
            ),
        )
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError, match="immutable adapter extension evidence"):
            connection.execute("UPDATE adapter_extension_registrations SET state='disabled'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO adapter_extension_registrations "
                "(registration_id,brain_id,actor_id,grant_id,adapter_id,adapter_version,"
                "adapter_kind,package_digest,manifest_digest,evidence_digest,registration_digest,"
                "manifest_json,evidence_json,state,registered_at) VALUES "
                "('bad','bad','bad','bad','bad','latest','other','bad','bad','bad','bad','[]','[]',"
                "'active',1)"
            )
    with pytest.raises(RuntimeError, match="PF-003 downgrade refused"):
        command.downgrade(configuration, "0033_pro002_custom_adapters")


def test_pf003_empty_migration_downgrades_cleanly(tmp_path: Path) -> None:
    database = tmp_path / "empty.sqlite3"
    configuration = _alembic(database)
    command.upgrade(configuration, "0034_pf003_adapter_extensions")
    command.downgrade(configuration, "0033_pro002_custom_adapters")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "adapter_extension_registrations" not in tables
    assert "adapter_extension_operations" not in tables


def _seed_authority(connection: sqlite3.Connection) -> None:
    connection.execute(
        "INSERT INTO brains (id,normalized_name,display_name,created_at,updated_at) "
        "VALUES (?,?,?,?,?)",
        ("018f0000-0000-7000-8000-000000000322", "test", "Test", 1, 1),
    )
    connection.execute(
        "INSERT INTO principals (id,local_subject_digest,type,created_at,updated_at) "
        "VALUES (?,?,?,?,?)",
        ("018f0000-0000-7000-8000-000000000323", bytes.fromhex("f" * 64), "owner", 1, 1),
    )
    connection.execute(
        "INSERT INTO scope_grants "
        "(id,principal_id,role,brain_id,valid_from,created_at,updated_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            "018f0000-0000-7000-8000-000000000324",
            "018f0000-0000-7000-8000-000000000323",
            "owner",
            "018f0000-0000-7000-8000-000000000322",
            1,
            1,
            1,
        ),
    )
