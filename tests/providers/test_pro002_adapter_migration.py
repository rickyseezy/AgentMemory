"""PRO-002 canonical custom-adapter persistence constraints."""

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


def test_pro002_adapter_schema_is_strict_append_only_and_downgrade_safe(tmp_path: Path) -> None:
    database = tmp_path / "provider-adapters.sqlite3"
    configuration = _alembic(database)
    command.upgrade(configuration, "head")
    digest = "a" * 64
    with closing(sqlite3.connect(database)) as connection:
        head = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        assert head == ("0040_pro007_provider_resilience",)
        connection.execute(
            "INSERT INTO provider_adapters "
            "(id,protocol_version,package_digest,signature,manifest_digest,plan_digest,"
            "attestation_digest,transport,capabilities,evidence_json,runtime_id,status,"
            "installed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "python-reference",
                1,
                digest,
                "b" * 64,
                "c" * 64,
                "d" * 64,
                "e" * 64,
                "framed_stdio",
                b'["embed_documents","cancel","shutdown"]',
                b'{"cyclonedx":"f","spdx":"f","provenance":"f","vulnerability":"f"}',
                "custom-provider-runtime",
                "active",
                1,
            ),
        )
        connection.execute(
            "INSERT INTO provider_adapter_installations "
            "(operation_id,adapter_id,request_digest,manifest_digest,plan_digest,"
            "attestation_digest,runtime_id,completed_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "install-1",
                "python-reference",
                "f" * 64,
                "c" * 64,
                "d" * 64,
                "e" * 64,
                "custom-provider-runtime",
                1,
            ),
        )
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError, match="immutable provider adapter evidence"):
            connection.execute("UPDATE provider_adapter_installations SET runtime_id='substituted'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO provider_adapters "
                "(id,protocol_version,package_digest,signature,manifest_digest,plan_digest,"
                "attestation_digest,transport,capabilities,evidence_json,runtime_id,status,"
                "installed_at) VALUES "
                "('invalid',2,'mutable','bad','bad','bad','bad','http','[]','{}','x','active',1)"
            )
    with pytest.raises(RuntimeError, match="PRO-002 downgrade refused"):
        command.downgrade(configuration, "0032_pro001_provider_profiles")


def test_pro002_empty_schema_downgrades_cleanly(tmp_path: Path) -> None:
    database = tmp_path / "empty.sqlite3"
    configuration = _alembic(database)
    command.upgrade(configuration, "0033_pro002_custom_adapters")
    command.downgrade(configuration, "0032_pro001_provider_profiles")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "provider_adapters" not in tables
    assert "provider_adapter_installations" not in tables
