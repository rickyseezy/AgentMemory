"""ID-003 real SQLite migration, history, correction, and concurrency tests."""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.identity.adapters.outbound.sqlite_repository_topology import (
    SqliteRepositoryLinkUnitOfWorkFactory,
    SqliteRepositoryTopologyReadRepository,
)
from agentmemory.identity.adapters.outbound.uuid7_identity import SystemUuid7IdentityGenerator
from agentmemory.identity.application.commands.confirm_repository_link import (
    ConfirmRepositoryLinkCommand,
    ConfirmRepositoryLinkHandler,
)
from agentmemory.identity.domain.errors import IdentityConflictError
from agentmemory.identity.domain.topology import (
    ProjectRepositoryLink,
    RepositoryRelationType,
    RepositoryTopologyCandidate,
    TopologyConfirmationSource,
    TopologyEndpointType,
    TopologyEvidence,
    TopologyEvidenceKind,
    TopologyEvidenceStrength,
)
from agentmemory.identity.domain.value_objects import Fingerprint, StableId
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

PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
PROJECT_TWO_ID = StableId("018f0000-0000-7000-8000-000000000011")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHILD_ID = StableId("018f0000-0000-7000-8000-000000000021")


def _migration_config(database: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def test_id003_migration_upgrades_downgrades_and_reapplies(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _migration_config(database)
    alembic_command.upgrade(configuration, "0004_id002_checkout_observation")
    alembic_command.upgrade(configuration, "head")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0005_id003_repository_topology",
        )
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {
            "repository_topology_links",
            "repository_topology_link_history",
        } <= tables
    alembic_command.downgrade(configuration, "0004_id002_checkout_observation")
    alembic_command.upgrade(configuration, "head")


def _fingerprint(seed: str) -> Fingerprint:
    return Fingerprint.from_bytes(seed.encode())


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    timestamp = int(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        for project_id, name in (
            (PROJECT_ID, "frontend"),
            (PROJECT_TWO_ID, "backend"),
        ):
            await connection.execute(
                text(
                    "INSERT INTO projects "
                    "(id, brain_id, name, manifest_key, status, version, created_at, updated_at, "
                    "schema_version) VALUES (:id, :brain, :name, :manifest, 'active', 1, "
                    ":now, :now, 1)"
                ),
                {
                    "id": project_id.value,
                    "brain": BRAIN_ID,
                    "name": name,
                    "manifest": bytes.fromhex(_fingerprint(name).value),
                    "now": timestamp,
                },
            )
        for repository_id, seed in (
            (REPOSITORY_ID, "root"),
            (CHILD_ID, "child"),
        ):
            await connection.execute(
                text(
                    "INSERT INTO repositories "
                    "(id, brain_id, vcs_type, root_fingerprint, primary_remote_fingerprint, "
                    "status, created_at, updated_at, schema_version) VALUES "
                    "(:id, :brain, 'git', :root, NULL, 'active', :now, :now, 1)"
                ),
                {
                    "id": repository_id.value,
                    "brain": BRAIN_ID,
                    "root": bytes.fromhex(_fingerprint(seed).value),
                    "now": timestamp,
                },
            )


def _candidate(  # noqa: PLR0913 -- Fixture exposes independent topology axes.
    *,
    relation: RepositoryRelationType = RepositoryRelationType.CONTAINS_REPOSITORY,
    subject_type: TopologyEndpointType = TopologyEndpointType.REPOSITORY,
    subject_id: StableId = REPOSITORY_ID,
    target_id: StableId = CHILD_ID,
    component: Fingerprint | None = None,
    evidence_seed: str = "nested",
) -> RepositoryTopologyCandidate:
    kind = (
        TopologyEvidenceKind.PROJECT_MANIFEST
        if relation is RepositoryRelationType.PROJECT_USES_REPOSITORY
        else TopologyEvidenceKind.NESTED_GIT_MARKER
    )
    strength = (
        TopologyEvidenceStrength.DETERMINISTIC_MANIFEST
        if relation is RepositoryRelationType.PROJECT_USES_REPOSITORY
        else TopologyEvidenceStrength.DETERMINISTIC_VCS
    )
    return RepositoryTopologyCandidate(
        StableId(BRAIN_ID),
        subject_type,
        subject_id,
        relation,
        TopologyEndpointType.REPOSITORY,
        target_id,
        component,
        (TopologyEvidence(_fingerprint(evidence_seed), kind, strength),),
    )


@dataclass(slots=True)
class _MutableClock:
    instant: datetime = datetime(2026, 7, 20, 12, tzinfo=UTC)

    def now(self) -> datetime:
        return self.instant


def _command(
    operation_id: str,
    candidate: RepositoryTopologyCandidate,
    *,
    link_id: StableId | None = None,
    expected_version: int | None = None,
    reason: str | None = None,
) -> ConfirmRepositoryLinkCommand:
    source = (
        TopologyConfirmationSource.DETERMINISTIC_MANIFEST
        if candidate.relation_type is RepositoryRelationType.PROJECT_USES_REPOSITORY
        else TopologyConfirmationSource.DETERMINISTIC_VCS
    )
    return ConfirmRepositoryLinkCommand(
        operation_id,
        StableId(BRAIN_ID),
        StableId(OWNER_ID),
        StableId(GRANT_ID),
        candidate,
        source,
        link_id,
        expected_version,
        reason,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_confirmation_is_idempotent_and_history_is_append_only(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        handler = ConfirmRepositoryLinkHandler(
            SqliteRepositoryLinkUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
            FixedClock(),
        )
        created = await handler.execute(_command("confirm-1", _candidate()))
        replayed = await handler.execute(_command("confirm-1", _candidate()))
        assert replayed == created
        assert created.subject_id != created.target_id
        async with store.engine.connect() as connection:
            event = (
                await connection.execute(
                    text(
                        "SELECT event_type FROM domain_events "
                        "WHERE aggregate_type = 'project_repository_link'"
                    )
                )
            ).scalar_one()
            history_count = (
                await connection.execute(
                    text("SELECT COUNT(*) FROM repository_topology_link_history")
                )
            ).scalar_one()
        assert event == "RepositoryLinkConfirmed"
        assert history_count == 1
        with pytest.raises(SQLAlchemyError, match="append-only"):
            async with store.engine.begin() as connection:
                await connection.execute(text("DELETE FROM repository_topology_link_history"))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_user_correction_preserves_versions_and_uses_cas(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    clock = _MutableClock()
    try:
        await _seed(store)
        handler = ConfirmRepositoryLinkHandler(
            SqliteRepositoryLinkUnitOfWorkFactory(store, clock),
            SystemUuid7IdentityGenerator(),
            clock,
        )
        created = await handler.execute(_command("confirm-1", _candidate()))
        clock.instant += timedelta(seconds=1)
        corrected_candidate = _candidate(
            relation=RepositoryRelationType.SUBMODULE_OF,
            evidence_seed="gitlink",
        )
        correction = _command(
            "correct-1",
            corrected_candidate,
            link_id=created.link_id,
            expected_version=1,
            reason="user_verified_submodule",
        )
        correction = ConfirmRepositoryLinkCommand(
            correction.operation_id,
            correction.brain_id,
            correction.actor_id,
            correction.grant_id,
            correction.candidate,
            TopologyConfirmationSource.USER,
            correction.link_id,
            correction.expected_version,
            correction.correction_reason,
        )
        corrected = await handler.execute(correction)
        assert corrected.version == 2
        assert tuple(item.relation_type for item in corrected.history) == (
            RepositoryRelationType.CONTAINS_REPOSITORY,
            RepositoryRelationType.SUBMODULE_OF,
        )
        with pytest.raises(IdentityConflictError):
            await handler.execute(
                _command(
                    "correct-stale",
                    corrected_candidate,
                    link_id=created.link_id,
                    expected_version=1,
                    reason="stale_correction",
                )
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_monorepo_projects_share_repository_with_separate_component_scope(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        handler = ConfirmRepositoryLinkHandler(
            SqliteRepositoryLinkUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
            FixedClock(),
        )
        first = _candidate(
            relation=RepositoryRelationType.PROJECT_USES_REPOSITORY,
            subject_type=TopologyEndpointType.PROJECT,
            subject_id=PROJECT_ID,
            target_id=REPOSITORY_ID,
            component=_fingerprint("packages/frontend"),
            evidence_seed="frontend-manifest",
        )
        second = _candidate(
            relation=RepositoryRelationType.PROJECT_USES_REPOSITORY,
            subject_type=TopologyEndpointType.PROJECT,
            subject_id=PROJECT_TWO_ID,
            target_id=REPOSITORY_ID,
            component=_fingerprint("packages/backend"),
            evidence_seed="backend-manifest",
        )
        frontend, backend = await asyncio.gather(
            handler.execute(_command("confirm-frontend", first)),
            handler.execute(_command("confirm-backend", second)),
        )
        assert frontend.target_id == backend.target_id == REPOSITORY_ID
        assert frontend.component_root_fingerprint != backend.component_root_fingerprint
        async with store.engine.connect() as connection:
            roles = (
                (
                    await connection.execute(
                        text(
                            "SELECT project_id, relation_type FROM project_repositories "
                            "ORDER BY project_id"
                        )
                    )
                )
                .tuples()
                .all()
            )
        assert roles == [
            (PROJECT_ID.value, "component"),
            (PROJECT_TWO_ID.value, "component"),
        ]
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_duplicate_link_has_one_winner_and_endpoint_validation_is_exact(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        reader = SqliteRepositoryTopologyReadRepository(store.engine)
        await reader.require_candidate(_candidate())
        with pytest.raises(IdentityConflictError):
            await reader.require_candidate(
                _candidate(target_id=StableId("018f0000-0000-7000-8000-000000000099"))
            )
        handler = ConfirmRepositoryLinkHandler(
            SqliteRepositoryLinkUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
            FixedClock(),
        )
        results = await asyncio.gather(
            handler.execute(_command("confirm-a", _candidate())),
            handler.execute(_command("confirm-b", _candidate())),
            return_exceptions=True,
        )
        assert sum(isinstance(result, ProjectRepositoryLink) for result in results) == 1
        assert sum(isinstance(result, IdentityConflictError) for result in results) == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_id003_downgrade_refuses_canonical_link_loss(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        await ConfirmRepositoryLinkHandler(
            SqliteRepositoryLinkUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
            FixedClock(),
        ).execute(_command("confirm-1", _candidate()))
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="downgrade refused"):
        alembic_command.downgrade(
            _migration_config(tmp_path / "agentmemory.sqlite3"),
            "0004_id002_checkout_observation",
        )
