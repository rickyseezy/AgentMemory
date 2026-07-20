"""ID-002 real SQLite migration, concurrency, and append-only integration tests."""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.identity.adapters.outbound.sqlite_checkout_observation import (
    SqliteCheckoutObservationUnitOfWorkFactory,
)
from agentmemory.identity.adapters.outbound.sqlite_identity import SqliteCheckoutRepository
from agentmemory.identity.adapters.outbound.uuid7_identity import SystemUuid7IdentityGenerator
from agentmemory.identity.application.commands.observe_checkout import (
    ObserveCheckoutCommand,
    ObserveCheckoutHandler,
)
from agentmemory.identity.domain.checkout import CheckoutAggregate
from agentmemory.identity.domain.errors import IdentityConflictError
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    IdentityCandidate,
    StableId,
    VcsIdentity,
    VcsType,
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
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")


def _fingerprint(seed: str) -> Fingerprint:
    return Fingerprint.from_bytes(seed.encode())


def _device(path: str, file_id: str = "file-a") -> DeviceIdentity:
    return DeviceIdentity(
        device_id=DEVICE_ID,
        device_fingerprint=_fingerprint("device"),
        volume_fingerprint=_fingerprint("volume"),
        path_fingerprint=_fingerprint(path),
        verified=True,
        logical_path_fingerprint=_fingerprint(f"logical-{path}"),
        file_fingerprint=_fingerprint(file_id),
    )


def _vcs(
    checkout: str,
    worktree: str = "worktree-a",
    common: str = "common-a",
) -> VcsIdentity:
    return VcsIdentity(
        vcs_type=VcsType.GIT,
        repository_fingerprint=_fingerprint("repository"),
        checkout_fingerprint=_fingerprint(checkout),
        worktree_fingerprint=_fingerprint(worktree),
        repository_lookup_approved=True,
        common_directory_fingerprint=_fingerprint(common),
        branch="main",
        head_commit="a" * 40,
        remote_fingerprints=(_fingerprint("origin"),),
        dirty_digest=_fingerprint("clean"),
    )


def _command(  # noqa: PLR0913 -- Fixture exposes every independent continuity axis.
    operation_id: str,
    path: str,
    *,
    file_id: str = "file-a",
    checkout: str = "checkout-a",
    worktree: str = "worktree-a",
    common: str = "common-a",
    expected_version: int | None = None,
) -> ObserveCheckoutCommand:
    return ObserveCheckoutCommand(
        operation_id=operation_id,
        brain_id=StableId(BRAIN_ID),
        actor_id=StableId(OWNER_ID),
        grant_id=StableId(GRANT_ID),
        repository_id=REPOSITORY_ID,
        device=_device(path, file_id),
        vcs=_vcs(checkout, worktree, common),
        expected_version=expected_version,
    )


def _migration_config(database: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def test_id002_migration_is_reversible_before_canonical_observations(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _migration_config(database)
    command.upgrade(configuration, "0003_id001_workspace_identity")
    command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0004_id002_checkout_observation",
        )
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(domain_events)")}
        assert {"aggregate_type", "aggregate_version", "correlation_id"} <= columns
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='checkout_observations'"
        ).fetchone() == (1,)
    command.downgrade(configuration, "0003_id001_workspace_identity")
    command.upgrade(configuration, "head")


async def _seed_roots(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    now = int(NOW.timestamp() * 1_000_000)
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
                "now": now,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO projects "
                "(id, brain_id, name, manifest_key, status, version, created_at, updated_at, "
                "schema_version) VALUES "
                "(:id, :brain, 'AgentMemory', :manifest, 'active', 1, :now, :now, 1)"
            ),
            {
                "id": PROJECT_ID.value,
                "brain": BRAIN_ID,
                "manifest": bytes.fromhex(_fingerprint("manifest").value),
                "now": now,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO repositories "
                "(id, brain_id, vcs_type, root_fingerprint, primary_remote_fingerprint, "
                "status, created_at, updated_at, schema_version) VALUES "
                "(:id, :brain, 'git', :root, NULL, 'active', :now, :now, 1)"
            ),
            {
                "id": REPOSITORY_ID.value,
                "brain": BRAIN_ID,
                "root": bytes.fromhex(_fingerprint("root").value),
                "now": now,
            },
        )
        await connection.execute(
            text(
                "INSERT INTO project_repositories "
                "(project_id, repository_id, relation_type, created_at, updated_at, "
                "schema_version) VALUES (:project, :repository, 'primary', :now, :now, 1)"
            ),
            {
                "project": PROJECT_ID.value,
                "repository": REPOSITORY_ID.value,
                "now": now,
            },
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_move_clone_worktree_and_append_only_history(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed_roots(store)
        handler = ObserveCheckoutHandler(
            SqliteCheckoutObservationUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
        )
        with pytest.raises(IdentityConflictError):
            await handler.execute(
                replace(
                    _command("wrong-repository", "path-a"),
                    repository_id=StableId("018f0000-0000-7000-8000-000000000099"),
                )
            )
        created = await handler.execute(_command("observe-1", "path-a"))
        assert await SqliteCheckoutRepository(store.engine).find_by_observation(
            StableId(BRAIN_ID),
            _device("unseen-moved-path"),
            _fingerprint("unrelated-checkout"),
        ) == (IdentityCandidate(PROJECT_ID, REPOSITORY_ID, created.checkout_id),)
        moved = await handler.execute(_command("observe-2", "path-b", checkout="checkout-moved"))
        retried = await handler.execute(_command("observe-2", "path-b", checkout="checkout-moved"))
        clone = await handler.execute(
            _command(
                "observe-3",
                "clone",
                file_id="clone-file",
                checkout="clone-checkout",
                worktree="clone-worktree",
                common="clone-common",
            )
        )
        worktree = await handler.execute(
            _command(
                "observe-4",
                "linked",
                file_id="linked-file",
                checkout="linked-checkout",
                worktree="linked-worktree",
            )
        )
        assert created.checkout_id == moved.checkout_id == retried.checkout_id
        assert clone.checkout_id != created.checkout_id
        assert worktree.checkout_id not in {created.checkout_id, clone.checkout_id}
        assert clone.current.repository_id == worktree.current.repository_id == REPOSITORY_ID
        async with store.engine.connect() as connection:
            observation_rows = (
                await connection.execute(
                    text(
                        "SELECT operation_id, aggregate_version FROM checkout_observations "
                        "ORDER BY operation_id"
                    )
                )
            ).all()
            observations = [(str(row[0]), int(row[1])) for row in observation_rows]
            assert observations == [
                ("observe-1", 1),
                ("observe-2", 2),
                ("observe-3", 1),
                ("observe-4", 1),
            ]
            event_types = (
                (
                    await connection.execute(
                        text(
                            "SELECT event_type FROM domain_events "
                            "WHERE aggregate_type = 'checkout' ORDER BY sequence"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert event_types == [
                "CheckoutObserved",
                "CheckoutMoved",
                "CheckoutObserved",
                "CheckoutObserved",
            ]
        with pytest.raises(SQLAlchemyError, match="append-only"):
            async with store.engine.begin() as connection:
                await connection.execute(text("DELETE FROM checkout_observations"))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_stale_observation_has_one_winner(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed_roots(store)
        handler = ObserveCheckoutHandler(
            SqliteCheckoutObservationUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
        )
        created = await handler.execute(_command("observe-1", "path-a"))
        results = await asyncio.gather(
            handler.execute(_command("observe-2", "path-b", expected_version=1)),
            handler.execute(_command("observe-3", "path-c", expected_version=1)),
            return_exceptions=True,
        )
        assert sum(isinstance(result, CheckoutAggregate) for result in results) == 1
        assert sum(isinstance(result, IdentityConflictError) for result in results) == 1
        assert created.version == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_id002_downgrade_refuses_to_delete_canonical_events(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed_roots(store)
        handler = ObserveCheckoutHandler(
            SqliteCheckoutObservationUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
        )
        await handler.execute(_command("observe-1", "path-a"))
    finally:
        await store.close()
    configuration = _migration_config(tmp_path / "agentmemory.sqlite3")
    with pytest.raises(RuntimeError, match="downgrade refused"):
        command.downgrade(configuration, "0003_id001_workspace_identity")
