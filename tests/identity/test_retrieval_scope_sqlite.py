"""ID-004 real SQLite grant and bounded related-project graph tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import text

from agentmemory.identity.adapters.outbound.sqlite_retrieval_scope import (
    SqliteRelatedProjectGraph,
    SqliteRetrievalScopeAuthorizationRepository,
)
from agentmemory.identity.domain.errors import IdentityAuthorizationError
from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.identity.domain.value_objects import StableId
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

P1 = StableId("018f0000-0000-7000-8000-000000000010")
P2 = StableId("018f0000-0000-7000-8000-000000000011")
P3 = StableId("018f0000-0000-7000-8000-000000000012")
R1 = StableId("018f0000-0000-7000-8000-000000000020")
R2 = StableId("018f0000-0000-7000-8000-000000000021")
R3 = StableId("018f0000-0000-7000-8000-000000000022")


def _config(database: Path) -> Config:
    root = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(root / "alembic.ini"))
    configuration.set_main_option("script_location", str(root))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def test_id004_migration_expands_grants_and_round_trips(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _config(database)
    alembic_command.upgrade(configuration, "0005_id003_repository_topology")
    alembic_command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0006_id004_retrieval_scope",
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scope_grants)")}
        assert {"project_id", "repository_id", "version"} <= columns
    alembic_command.downgrade(configuration, "0005_id003_repository_topology")
    alembic_command.upgrade(configuration, "head")


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    now = int(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        for project, name in ((P1, "one"), (P2, "two"), (P3, "three")):
            await connection.execute(
                text(
                    "INSERT INTO projects (id,brain_id,name,manifest_key,status,version,"
                    "created_at,updated_at,schema_version) VALUES "
                    "(:id,:brain,:name,:key,'active',1,:now,:now,1)"
                ),
                {
                    "id": project.value,
                    "brain": BRAIN_ID,
                    "name": name,
                    "key": bytes(name.ljust(32, "x"), "utf-8")[:32],
                    "now": now,
                },
            )
        for repository, seed in ((R1, b"1"), (R2, b"2"), (R3, b"3")):
            await connection.execute(
                text(
                    "INSERT INTO repositories (id,brain_id,vcs_type,root_fingerprint,"
                    "primary_remote_fingerprint,status,created_at,updated_at,schema_version) "
                    "VALUES (:id,:brain,'git',:root,NULL,'active',:now,:now,1)"
                ),
                {"id": repository.value, "brain": BRAIN_ID, "root": seed * 32, "now": now},
            )
        for project, repository in ((P1, R1), (P2, R2), (P3, R3)):
            await connection.execute(
                text(
                    "INSERT INTO project_repositories (project_id,repository_id,relation_type,"
                    "created_at,updated_at,schema_version) VALUES "
                    "(:project,:repository,'primary',:now,:now,1)"
                ),
                {"project": project.value, "repository": repository.value, "now": now},
            )
        for index, (subject, target) in enumerate(((R1, R2), (R2, R3)), 1):
            await connection.execute(
                text(
                    "INSERT INTO repository_topology_links "
                    "(id,brain_id,subject_type,subject_id,relation_type,target_type,target_id,"
                    "component_root_fingerprint,status,valid_from,valid_to,version,created_at,"
                    "updated_at,schema_version) VALUES "
                    "(:id,:brain,'repository',:subject,'contains_repository','repository',"
                    ":target,NULL,'active',:now,NULL,1,:now,:now,1)"
                ),
                {
                    "id": f"018f0000-0000-7000-8000-00000000004{index}",
                    "brain": BRAIN_ID,
                    "subject": subject.value,
                    "target": target.value,
                    "now": now,
                },
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_snapshot_is_brain_scoped_and_grant_version_changes_on_revocation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        repository = SqliteRetrievalScopeAuthorizationRepository(store.engine)
        first = await repository.snapshot(
            StableId(BRAIN_ID),
            StableId(OWNER_ID),
            StableId(GRANT_ID),
            int(NOW.timestamp() * 1_000_000),
        )
        assert first.grants[0].role is RetrievalRole.OWNER
        assert {item.project_id for item in first.bindings} == {P1, P2, P3}
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE scope_grants SET version = version + 1, project_id = :project "
                    "WHERE id = :id"
                ),
                {"project": P1.value, "id": GRANT_ID},
            )
        narrowed = await repository.snapshot(
            StableId(BRAIN_ID),
            StableId(OWNER_ID),
            StableId(GRANT_ID),
            int(NOW.timestamp() * 1_000_000),
        )
        assert tuple(item.project_id for item in narrowed.bindings) == (P1,)
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE scope_grants SET version = version + 1, valid_to = :now WHERE id = :id"
                ),
                {"now": int(NOW.timestamp() * 1_000_000) + 1, "id": GRANT_ID},
            )
        with pytest.raises(IdentityAuthorizationError):
            await repository.snapshot(
                StableId(BRAIN_ID),
                StableId(OWNER_ID),
                StableId(GRANT_ID),
                int(NOW.timestamp() * 1_000_000) + 2,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_graph_is_cycle_safe_bounded_and_intersects_allowed_projects(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        graph = SqliteRelatedProjectGraph(store.engine)
        one_hop = await graph.expand(StableId(BRAIN_ID), P1, (P1, P2, P3), 1, 10)
        two_hops = await graph.expand(StableId(BRAIN_ID), P1, (P1, P2, P3), 3, 2)
        restricted = await graph.expand(StableId(BRAIN_ID), P1, (P1, P3), 3, 10)
        assert tuple(item.project_id for item in one_hop) == (P2,)
        assert tuple(item.project_id for item in two_hops) == (P2, P3)
        assert restricted == ()
    finally:
        await store.close()
