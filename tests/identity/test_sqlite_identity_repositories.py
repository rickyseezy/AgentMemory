"""ID-001 real SQLite identity repository and authorization contract tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from agentmemory.identity.adapters.outbound.sqlite_identity import (
    SqliteCheckoutRepository,
    SqliteIdentityAuthorizationPolicy,
    SqliteProjectRepository,
    SqliteRepositoryIdentityRepository,
)
from agentmemory.identity.domain.errors import IdentityAuthorizationError, IdentityConflictError
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    IdentityCandidate,
    ProjectManifest,
    StableId,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    NOW,
    OWNER_ID,
    FixedClock,
    bootstrap_request,
    migrated_store,
)

if TYPE_CHECKING:
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHECKOUT_ID = StableId("018f0000-0000-7000-8000-000000000030")


def test_id001_migration_upgrades_downgrades_and_reapplies_from_pf002(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    command.upgrade(configuration, "0002_pf002_projection_rebuild")
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {
            "devices",
            "projects",
            "repositories",
            "repository_fingerprints",
            "project_repositories",
            "checkouts",
            "checkout_aliases",
        } <= tables
    command.downgrade(configuration, "0002_pf002_projection_rebuild")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "projects" not in tables
        assert "projection_rebuilds" in tables
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0002_pf002_projection_rebuild",
        )
    command.upgrade(configuration, "head")


def _fingerprint(seed: str) -> Fingerprint:
    return Fingerprint.from_bytes(seed.encode())


def _device() -> DeviceIdentity:
    return DeviceIdentity(
        DEVICE_ID,
        _fingerprint("device"),
        _fingerprint("volume"),
        _fingerprint("path"),
        verified=True,
    )


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    timestamp = int(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO devices "
                "(id, device_fingerprint, status, created_at, updated_at, schema_version) "
                "VALUES (:id, :fingerprint, 'verified', :now, :now, 1)"
            ),
            {
                "id": DEVICE_ID.value,
                "fingerprint": bytes.fromhex(_fingerprint("device").value),
                "now": timestamp,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO projects "
                "(id, brain_id, name, manifest_key, status, version, created_at, updated_at, "
                "schema_version) VALUES (:id, :brain, 'AgentMemory', :key, 'active', 1, "
                ":now, :now, 1)"
            ),
            {
                "id": PROJECT_ID.value,
                "brain": BRAIN_ID,
                "key": bytes.fromhex(_fingerprint("manifest").value),
                "now": timestamp,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO repositories "
                "(id, brain_id, vcs_type, root_fingerprint, primary_remote_fingerprint, status, "
                "created_at, updated_at, schema_version) VALUES "
                "(:id, :brain, 'git', :root, :remote, 'active', :now, :now, 1)"
            ),
            {
                "id": REPOSITORY_ID.value,
                "brain": BRAIN_ID,
                "root": bytes.fromhex(_fingerprint("root").value),
                "remote": bytes.fromhex(_fingerprint("remote").value),
                "now": timestamp,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO repository_fingerprints "
                "(brain_id, repository_id, algorithm, fingerprint, evidence_json, active, "
                "created_at, updated_at, schema_version) VALUES "
                "(:brain, :repository, 'GitRepositoryFingerprintV1', :fingerprint, '{}', 1, "
                ":now, :now, 1)"
            ),
            {
                "brain": BRAIN_ID,
                "repository": REPOSITORY_ID.value,
                "fingerprint": bytes.fromhex(_fingerprint("repository").value),
                "now": timestamp,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO project_repositories "
                "(project_id, repository_id, relation_type, created_at, updated_at, "
                "schema_version) "
                "VALUES (:project, :repository, 'primary', :now, :now, 1)"
            ),
            {"project": PROJECT_ID.value, "repository": REPOSITORY_ID.value, "now": timestamp},
        )
        await connection.execute(
            text(
                "INSERT INTO checkouts "
                "(id, brain_id, repository_id, device_id, canonical_path_hash, "
                "checkout_fingerprint, worktree_id, branch, head_commit, last_seen_at, status, "
                "created_at, updated_at, schema_version) VALUES "
                "(:id, :brain, :repository, :device, :path, :checkout, :worktree, 'main', "
                "'abc123', :now, 'active', :now, :now, 1)"
            ),
            {
                "id": CHECKOUT_ID.value,
                "brain": BRAIN_ID,
                "repository": REPOSITORY_ID.value,
                "device": DEVICE_ID.value,
                "path": bytes.fromhex(_fingerprint("path").value),
                "checkout": bytes.fromhex(_fingerprint("checkout").value),
                "worktree": bytes.fromhex(_fingerprint("worktree").value),
                "now": timestamp,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO checkout_aliases "
                "(checkout_id, brain_id, path_fingerprint, continuity_fingerprint, approved, "
                "first_seen_at, last_seen_at, schema_version) VALUES "
                "(:checkout, :brain, :path, NULL, 1, :now, :now, 1)"
            ),
            {
                "checkout": CHECKOUT_ID.value,
                "brain": BRAIN_ID,
                "path": bytes.fromhex(_fingerprint("path").value),
                "now": timestamp,
            },
        )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_sqlite_identity_repositories_resolve_manifest_checkout_and_repository(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        projects = SqliteProjectRepository(store.engine)
        checkouts = SqliteCheckoutRepository(store.engine)
        repositories = SqliteRepositoryIdentityRepository(store.engine)
        expected = IdentityCandidate(PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID)

        assert await checkouts.find_by_observation(
            StableId(BRAIN_ID),
            _device(),
            _fingerprint("checkout"),
        ) == (expected,)
        assert await checkouts.find_approved_heuristic(
            StableId(BRAIN_ID),
            _device(),
            None,
        ) == (expected,)
        assert await repositories.find_by_fingerprint(
            StableId(BRAIN_ID),
            _fingerprint("repository"),
        ) == (REPOSITORY_ID,)
        project_only = IdentityCandidate(PROJECT_ID, REPOSITORY_ID, None)
        assert await projects.resolve_manifest(
            StableId(BRAIN_ID),
            ProjectManifest(1, PROJECT_ID, REPOSITORY_ID),
            _fingerprint("repository"),
        ) == (project_only,)
        with pytest.raises(IdentityConflictError):
            await projects.resolve_manifest(
                StableId(BRAIN_ID),
                ProjectManifest(1, PROJECT_ID, REPOSITORY_ID),
                _fingerprint("fork"),
            )
        assert await projects.find_by_repository(StableId(BRAIN_ID), (REPOSITORY_ID,)) == (
            project_only,
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_sqlite_identity_authorization_is_exact_and_revocation_is_immediate(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        policy = SqliteIdentityAuthorizationPolicy(store.engine)
        await policy.authorize_resolution(
            StableId(BRAIN_ID),
            StableId(OWNER_ID),
            StableId(GRANT_ID),
        )
        with pytest.raises(IdentityAuthorizationError):
            await policy.authorize_resolution(
                StableId(BRAIN_ID),
                StableId("018f0000-0000-7000-8000-000000000099"),
                StableId(GRANT_ID),
            )
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_from = 9223372036854775807"),
            )
        with pytest.raises(IdentityAuthorizationError):
            await policy.authorize_resolution(
                StableId(BRAIN_ID),
                StableId(OWNER_ID),
                StableId(GRANT_ID),
            )
        async with store.engine.begin() as connection:
            await connection.execute(text("UPDATE scope_grants SET valid_from = 0"))
            await connection.execute(
                text("UPDATE principals SET status = 'revoked' WHERE id = :actor"),
                {"actor": OWNER_ID},
            )
        with pytest.raises(IdentityAuthorizationError):
            await policy.authorize_resolution(
                StableId(BRAIN_ID),
                StableId(OWNER_ID),
                StableId(GRANT_ID),
            )
    finally:
        await store.close()
