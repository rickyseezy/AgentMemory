"""GRA-004 immutable VCS and evidence-anchor relational migration tests."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING

import pytest
from alembic import command
from sqlalchemy import text

from agentmemory.identity.adapters.outbound.sqlite_checkout_observation import (
    SqliteCheckoutObservationUnitOfWorkFactory,
)
from agentmemory.identity.adapters.outbound.uuid7_identity import SystemUuid7IdentityGenerator
from agentmemory.identity.application.commands.observe_checkout import ObserveCheckoutHandler
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from tests.core.support import BRAIN_ID, FixedClock
from tests.graph.test_gra002_sqlite_assertions import (
    ARTIFACT_BYTES,
    ARTIFACT_EVENT_ID,
    ARTIFACT_EVIDENCE_ID,
    ARTIFACT_ID,
    NOW,
    _seed_sources,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    PROJECT_ID,
    REPOSITORY_ID,
    _migration_config,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _command as checkout_command,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _seed_roots as seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

_HEAD = "0023_gra004_temporal_revision_truth"
_PREVIOUS = "0022_gra003_materialized_assertion_edges"


@pytest.mark.migration
def test_gra004_migration_installs_immutable_revision_authority(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (_HEAD,)
        expected = {
            "assertion_evidence_revision_anchors",
            "vcs_commit_parents",
            "vcs_commits",
            "vcs_evidence_impacts",
            "vcs_ref_observations",
            "vcs_revision_batches",
        }
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND (name LIKE 'vcs_%' OR name='assertion_evidence_revision_anchors')"
            )
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND (name LIKE 'vcs_%_no_%' "
                "OR name LIKE 'assertion_evidence_revision_anchors_no_%')"
            )
        }
    assert tables == expected
    assert len(triggers) == 2 * len(expected)
    command.downgrade(configuration, _PREVIOUS)
    command.upgrade(configuration, "head")


@pytest.mark.migration
def test_gra004_migration_enforces_batch_bounds_and_append_only_state(tmp_path: Path) -> None:
    database = tmp_path / "constraints.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        statement = (
            "INSERT INTO vcs_revision_batches "
            "(operation_id,brain_id,principal_id,repository_id,scope_fingerprint,batch_digest,"
            "source_digest,node_count,ref_count,impact_count,observed_at,schema_version) VALUES "
            "(?,?,?,?,?,randomblob(32),randomblob(32),?,?,?,?,1)"
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                statement,
                ("empty", "brain", "principal", "repository", bytes(32), 0, 0, 0, 1),
            )
        connection.execute(
            statement,
            ("batch-1", "brain", "principal", "repository", bytes(32), 1, 0, 0, 1),
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE vcs_revision_batches SET observed_at=2 WHERE operation_id='batch-1'"
            )


@pytest.mark.migration
def test_gra004_migration_refuses_evidence_bearing_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "downgrade.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute(
            "INSERT INTO vcs_revision_batches "
            "(operation_id,brain_id,principal_id,repository_id,scope_fingerprint,batch_digest,"
            "source_digest,node_count,ref_count,impact_count,observed_at,schema_version) VALUES "
            "('batch-1','brain','principal','repository',zeroblob(32),randomblob(32),"
            "randomblob(32),1,0,0,1,1)"
        )
        connection.commit()
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(configuration, _PREVIOUS)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_gra004_migration_backfills_existing_capture_time_revision(tmp_path: Path) -> None:
    database = tmp_path / "backfill.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, _PREVIOUS)
    store = SqliteCoreStore.create(
        database,
        SqliteRuntimePolicy(minimum_version=(3, 0, 0), required_compile_options=frozenset()),
    )
    try:
        await seed_roots(store)
        checkout = await ObserveCheckoutHandler(
            SqliteCheckoutObservationUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
        ).execute(checkout_command("observe-pre-gra004", "pre-gra004"))
        await _seed_sources(store)
        registered = round(NOW.timestamp() * 1_000_000)
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO assertion_evidence_sources "
                    "(evidence_id,brain_id,project_id,repository_id,checkout_id,classification,"
                    "kind,event_id,artifact_id,span_start,span_end,source_digest,occurred_at,"
                    "registered_at,schema_version) VALUES "
                    "(:evidence,:brain,:project,:repository,:checkout,'internal','artifact',"
                    ":event,:artifact,NULL,NULL,:digest,:occurred,:registered,1)"
                ),
                {
                    "evidence": ARTIFACT_EVIDENCE_ID,
                    "brain": BRAIN_ID,
                    "project": PROJECT_ID.value,
                    "repository": REPOSITORY_ID.value,
                    "checkout": checkout.checkout_id.value,
                    "event": ARTIFACT_EVENT_ID,
                    "artifact": ARTIFACT_ID,
                    "digest": hashlib.sha256(ARTIFACT_BYTES).digest(),
                    "occurred": registered - 2,
                    "registered": registered,
                },
            )
    finally:
        await store.close()
    command.upgrade(configuration, _HEAD)
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT checkout_id,commit_sha,branch_at_capture,anchored_at "
            "FROM assertion_evidence_revision_anchors WHERE evidence_id=?",
            (ARTIFACT_EVIDENCE_ID,),
        ).fetchone()
    assert row == (checkout.checkout_id.value, "a" * 40, "main", registered)
