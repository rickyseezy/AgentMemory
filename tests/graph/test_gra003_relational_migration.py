"""GRA-003 relational projection-work and immutable-evidence migration tests."""

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

_HEAD = "0022_gra003_materialized_assertion_edges"


@pytest.mark.migration
def test_gra003_relational_migration_installs_constrained_durable_state(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (_HEAD,)
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'assertion_edge_%'"
            )
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name LIKE 'assertion_edge_%_no_%'"
            )
        }
    assert tables == {
        "assertion_edge_integrity_findings",
        "assertion_edge_integrity_repairs",
        "assertion_edge_projection_jobs",
        "assertion_edge_projection_receipts",
    }
    assert len(triggers) == 6
    command.downgrade(configuration, "0021_gra002_evidence_assertions")
    command.upgrade(configuration, "head")


@pytest.mark.migration
def test_gra003_relational_migration_rejects_invalid_job_and_evidence_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "constraints.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO assertion_edge_projection_jobs "
                "(source_event_id,assertion_id,brain_id,principal_id,scope_fingerprint,"
                "project_id,repository_id,checkout_id,classification,aggregate_version,"
                "event_type,event_digest,state,attempts,not_before,lease_owner,lease_until,"
                "last_error_code,created_at,updated_at,completed_at,schema_version) VALUES "
                "('event-1','assertion-1','brain-1','principal-1',zeroblob(32),'project-1',"
                "'repository-1',NULL,'internal',1,'AssertionDisputed',zeroblob(32),'ready',"
                "0,1,NULL,NULL,NULL,1,1,NULL,1)"
            )
        connection.execute(
            "INSERT INTO assertion_edge_projection_jobs "
            "(source_event_id,assertion_id,brain_id,principal_id,scope_fingerprint,"
            "project_id,repository_id,checkout_id,classification,aggregate_version,"
            "event_type,event_digest,state,attempts,not_before,lease_owner,lease_until,"
            "last_error_code,created_at,updated_at,completed_at,schema_version) VALUES "
            "('event-1','assertion-1','brain-1','principal-1',zeroblob(32),'project-1',"
            "'repository-1',NULL,'internal',1,'AssertionActivated',zeroblob(32),'ready',"
            "0,1,NULL,NULL,NULL,1,1,NULL,1)"
        )
        with pytest.raises(sqlite3.IntegrityError, match="binding is immutable"):
            connection.execute(
                "UPDATE assertion_edge_projection_jobs SET project_id='project-2' "
                "WHERE source_event_id='event-1'"
            )
        connection.execute(
            "INSERT INTO assertion_edge_projection_receipts "
            "(source_event_id,assertion_id,brain_id,generation_id,projection_digest,"
            "projection_status,aggregate_version,completed_at,schema_version) VALUES "
            "('event-1','assertion-1','brain-1',randomblob(32),randomblob(32),'active',1,1,1)"
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE assertion_edge_projection_receipts SET completed_at=2 "
                "WHERE source_event_id='event-1'"
            )


@pytest.mark.migration
def test_gra003_relational_migration_refuses_evidence_bearing_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "downgrade.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO assertion_edge_integrity_findings "
            "(finding_id,brain_id,principal_id,scope_fingerprint,generation_id,assertion_id,"
            "kind,expected_digest,actual_digest,detected_at,schema_version) VALUES "
            "('finding-1','brain-1','principal-1',randomblob(32),randomblob(32),'assertion-1',"
            "'orphan',NULL,randomblob(32),1,1)"
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(configuration, "0021_gra002_evidence_assertions")
