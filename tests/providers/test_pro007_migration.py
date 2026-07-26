"""PRO-007 durable equivalence, circuit, attempt, and failure schema tests."""

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


def test_pro007_schema_installs_all_durable_resilience_authority(tmp_path: Path) -> None:
    database = tmp_path / "pro007-empty.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0042_pro009_provider_containment",
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
        endpoint_fks = {
            (str(row[2]), str(row[3]), str(row[4]))
            for row in connection.execute(
                "PRAGMA foreign_key_list('provider_equivalent_endpoints')"
            ).fetchall()
        }
        unique_set_coordinates = {
            tuple(
                str(column[2])
                for column in connection.execute(f"PRAGMA index_info('{index[1]!s}')").fetchall()
            )
            for index in connection.execute(
                "PRAGMA index_list('provider_equivalent_endpoint_sets')"
            ).fetchall()
            if bool(index[2])
        }
    assert {
        "provider_equivalent_endpoint_sets",
        "provider_equivalent_endpoints",
        "provider_equivalence_operations",
        "provider_endpoint_circuits",
        "provider_dispatch_attempts",
        "provider_operation_failures",
    } <= tables
    assert {
        "trg_provider_equivalent_endpoint_sets_immutable_update",
        "trg_provider_equivalent_endpoints_immutable_delete",
        "trg_provider_equivalence_operations_immutable_update",
        "trg_provider_dispatch_attempts_immutable_update",
        "trg_provider_operation_failures_immutable_delete",
    } <= triggers
    assert {
        "ix_provider_equivalent_endpoint_lookup",
        "ix_provider_endpoint_circuit_state",
        "ix_provider_dispatch_operation",
        "ix_provider_operation_failure_brain",
    } <= indexes
    assert {
        ("provider_equivalent_endpoint_sets", "set_id", "set_id"),
        (
            "provider_capability_attestations",
            "capability_attestation_id",
            "attestation_id",
        ),
        ("provider_profile_revisions", "profile_id", "profile_id"),
    } <= endpoint_fks
    assert (
        "primary_profile_id",
        "primary_profile_version",
        "space_id",
    ) in unique_set_coordinates

    command.downgrade(configuration, "0039_pro006_provider_scheduling")
    command.upgrade(configuration, "head")


@pytest.mark.parametrize(
    "authority",
    ["provider_dispatch_attempts", "provider_endpoint_circuits"],
)
def test_pro007_downgrade_refuses_to_destroy_any_resilience_evidence(
    tmp_path: Path,
    authority: str,
) -> None:
    database = tmp_path / f"pro007-{authority}.sqlite3"
    configuration = _configuration(database)
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        if authority == "provider_endpoint_circuits":
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "INSERT INTO provider_endpoint_circuits "
                "(endpoint_fingerprint,profile_id,profile_version,"
                "endpoint_attestation_digest,state,consecutive_failures,"
                "window_started_at,open_until,probe_in_flight,version,updated_at,"
                "schema_version) VALUES "
                "(?, '018f0000-0000-7000-8000-000000000999',1,?,'closed',"
                "0,NULL,NULL,0,0,0,1)",
                ("b" * 64, bytes(32)),
            )
        else:
            connection.execute(
                "INSERT INTO provider_dispatch_attempts "
                "(fact_id,operation_key_sha256,endpoint_fingerprint,"
                "endpoint_attestation_digest,attempt,fallback_ordinal,outcome_code,"
                "occurred_at,schema_version) VALUES (?,?,?,?,1,0,'started',0,1)",
                (bytes(32), bytes(32), "a" * 64, bytes(32)),
            )
        connection.commit()
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(configuration, "0039_pro006_provider_scheduling")
