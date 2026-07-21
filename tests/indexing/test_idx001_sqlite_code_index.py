"""IDX-001 real migration and SQLite code-index repository integration tests."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.indexing.adapters.outbound.sqlite_code_index import (
    SqliteCodeIndexRepository,
)
from agentmemory.indexing.application.code_index import (
    FindCodeEntitiesHandler,
    FindCodeEntitiesQuery,
    IndexRepositorySnapshotCommand,
    IndexRepositorySnapshotHandler,
)
from agentmemory.indexing.domain.code_entities import LanguageTier
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
)
from agentmemory.indexing.domain.ports import (
    ParsedDefinition,
    ParsedSource,
    ParserDescriptor,
    SourceArtifact,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from tests.core.support import (
    BRAIN_ID,
    NOW,
    OWNER_ID,
    FixedClock,
    bootstrap_request,
    migrated_store,
)

if TYPE_CHECKING:
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
SOURCE = b"def hello():\r\n    return 'caf\xc3\xa9'\r\n"


def _configuration(database: Path) -> Config:
    root = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(root / "alembic.ini"))
    configuration.set_main_option("script_location", str(root))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


def test_idx001_migration_round_trips_empty_database_and_refuses_history_loss(
    tmp_path: Path,
) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _configuration(database)
    alembic_command.upgrade(configuration, "0025_gra006_graph_integrity")
    alembic_command.upgrade(configuration, "0026_idx001_code_entities")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {
            "source_snapshots",
            "source_files",
            "file_revisions",
            "code_symbols",
            "symbol_revisions",
            "symbol_occurrences",
            "parse_failures",
        } <= tables
    alembic_command.downgrade(configuration, "0025_gra006_graph_integrity")
    alembic_command.upgrade(configuration, "head")


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_sqlite_repository_exact_replay_search_and_immutability(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        repository = SqliteCodeIndexRepository(store, FixedClock())
        handler = IndexRepositorySnapshotHandler(
            _Source((SourceArtifact("src/main.py", SOURCE),)), _Plugin(), repository
        )
        command = _command(_scope("indexing.snapshot"))
        first = await handler.execute(command)
        replay = await handler.execute(command)
        assert replay == first

        files = await repository.list_files(_scope("indexing.search"), first.snapshot.id)
        assert len(files) == 1
        assert files[0].file.relative_path == "src/main.py"
        assert files[0].revision.byte_length == len(SOURCE)
        assert len(files[0].symbol_revisions) == 1
        hits = await FindCodeEntitiesHandler(repository).execute(
            FindCodeEntitiesQuery(_scope("indexing.search"), first.snapshot.id, "HELLO")
        )
        assert len(hits) == 1
        assert hits[0].display_name == "hello"

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable"):
                await connection.execute(text("UPDATE source_files SET relative_path='changed.py'"))
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="IDX-001 source history"):
        alembic_command.downgrade(
            _configuration(tmp_path / "agentmemory.sqlite3"),
            "0025_gra006_graph_integrity",
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_repository_rejects_conflicting_replay_and_revoked_authority(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _seed(store)
        repository = SqliteCodeIndexRepository(store, FixedClock())
        scope = _scope("indexing.snapshot")
        handler = IndexRepositorySnapshotHandler(
            _Source((SourceArtifact("main.py", SOURCE),)), _Plugin(), repository
        )
        command = _command(scope)
        result = await handler.execute(command)
        with pytest.raises(IndexingConflictError):
            await handler.execute(replace(command, working_digest="e" * 64))

        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:now"),
                {"now": round((NOW + timedelta(microseconds=1)).timestamp() * 1_000_000)},
            )
        revoked_repository = SqliteCodeIndexRepository(
            store, FixedClock(NOW + timedelta(seconds=1))
        )
        with pytest.raises(IndexingAuthorizationError):
            await revoked_repository.list_files(_scope("indexing.search"), result.snapshot.id)
    finally:
        await store.close()


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    now = round(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects(id,brain_id,name,manifest_key,status,version,created_at,"
                "updated_at,schema_version) VALUES(:id,:brain,'Index',:key,'active',1,:now,"
                ":now,1)"
            ),
            {"id": PROJECT_ID, "brain": BRAIN_ID, "key": b"i" * 32, "now": now},
        )
        await connection.execute(
            text(
                "INSERT INTO repositories(id,brain_id,vcs_type,root_fingerprint,"
                "primary_remote_fingerprint,status,created_at,updated_at,schema_version) "
                "VALUES(:id,:brain,'git',:root,NULL,'active',:now,:now,1)"
            ),
            {"id": REPOSITORY_ID, "brain": BRAIN_ID, "root": b"r" * 32, "now": now},
        )
        await connection.execute(
            text(
                "INSERT INTO project_repositories(project_id,repository_id,relation_type,"
                "created_at,updated_at,schema_version) VALUES(:project,:repository,'primary',"
                ":now,:now,1)"
            ),
            {"project": PROJECT_ID, "repository": REPOSITORY_ID, "now": now},
        )


def _scope(action: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(OWNER_ID),
        role=RetrievalRole.OWNER,
        mode=RetrievalScopeMode.CURRENT,
        members=(
            ScopeMember(
                StableId(PROJECT_ID),
                (StableId(REPOSITORY_ID),),
                (),
            ),
        ),
        classification_ceiling=Classification.LOCAL_ONLY,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="code_indexing",
    )


def _command(scope: AuthorizedScope) -> IndexRepositorySnapshotCommand:
    return IndexRepositorySnapshotCommand("idx-operation-1", scope, "abc123", "d" * 64, NOW)


@dataclass(frozen=True, slots=True)
class _Source:
    values: tuple[SourceArtifact, ...]

    async def read(self, scope: AuthorizedScope) -> tuple[SourceArtifact, ...]:
        del scope
        return self.values


class _Plugin:
    _descriptor = ParserDescriptor(
        "python", LanguageTier.PRECISE, "test-parser-1", "grammar-1", "a" * 64
    )

    def detect(self, relative_path: str, content: bytes) -> str | None:
        del relative_path, content
        return "python"

    def describe(self, language: str) -> ParserDescriptor:
        assert language == "python"
        return self._descriptor

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        assert language == "python"
        del relative_path, content
        definition = ParsedDefinition(
            "python:src/main.py:function:hello",
            "hello",
            "function",
            4,
            9,
            0,
            4,
            0,
            9,
        )
        return ParsedSource(
            "python",
            self._descriptor.parser_version,
            self._descriptor.grammar_revision,
            self._descriptor.query_pack_digest,
            0,
            (definition,),
            (),
        )
