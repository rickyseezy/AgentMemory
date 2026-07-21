"""IDX-001 append-only SQLite source and semantic evidence repository."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.indexing.domain.code_entities import (
    CodeSymbol,
    FileRevision,
    IndexedFile,
    LanguageTier,
    OccurrenceRole,
    ParseFailure,
    ParseStatus,
    SemanticPriority,
    SemanticSource,
    SourceFile,
    SourceSnapshot,
    SourceSpan,
    SymbolKind,
    SymbolOccurrence,
    SymbolRevision,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_ACTION = "code index repository action is not authorized"
_ERR_AUTHORIZATION = "code index repository scope is not authorized"
_ERR_CONFLICT = "code index evidence conflicts with immutable history"
_ERR_STORAGE = "code index storage is unavailable"
_WRITE_ACTIONS = frozenset({"indexing.snapshot", "indexing.scip.import"})
_READ_ACTIONS = frozenset({"indexing.search"})
_WRITE_ROLES = frozenset({"owner", "admin", "editor", "worker"})
_READ_ROLES = frozenset({"owner", "admin", "editor", "reader", "auditor", "worker"})


class SqliteCodeIndexRepository:
    """Store immutable snapshots/file revisions and all semantic provenance."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical single-writer store and trusted authorization clock."""
        self._store = store
        self._clock = clock

    async def start_snapshot(
        self, scope: AuthorizedScope, operation_id: str, snapshot: SourceSnapshot
    ) -> SourceSnapshot:
        """Insert or exactly replay one scope-bound repository snapshot."""
        _require_action(scope, _WRITE_ACTIONS)
        _unauthorized_if(
            condition=snapshot.brain_id != scope.brain_id.value
            or snapshot.project_id not in {item.value for item in scope.project_ids}
            or snapshot.repository_id not in {item.value for item in scope.repository_ids}
        )
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(
                    connection,
                    scope,
                    snapshot.project_id,
                    snapshot.repository_id,
                    self._clock.now(),
                    write=True,
                )
                row = (
                    (
                        await connection.execute(
                            text("SELECT * FROM source_snapshots WHERE operation_id=:operation"),
                            {"operation": operation_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    stored = _snapshot(row)
                    _conflict_if(
                        condition=stored != snapshot
                        or bytes(row["scope_fingerprint"]).hex() != scope.scope_fingerprint
                    )
                    return stored
                await connection.execute(
                    text(
                        "INSERT INTO source_snapshots(id,operation_id,brain_id,project_id,"
                        "repository_id,principal_id,scope_fingerprint,commit_id,working_digest,"
                        "created_at) VALUES(:id,:operation,:brain,:project,:repository,:principal,"
                        ":scope,:commit,:working,:created)"
                    ),
                    {
                        "id": snapshot.id,
                        "operation": operation_id,
                        "brain": snapshot.brain_id,
                        "project": snapshot.project_id,
                        "repository": snapshot.repository_id,
                        "principal": scope.principal_id.value,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "commit": snapshot.commit_id,
                        "working": bytes.fromhex(snapshot.working_digest),
                        "created": _micros(snapshot.created_at),
                    },
                )
                return snapshot
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def save_file(self, scope: AuthorizedScope, indexed: IndexedFile) -> IndexedFile:
        """Atomically append or exactly replay one independently parsed file."""
        _require_action(scope, _WRITE_ACTIONS)
        try:
            async with _write_transaction(self._store) as connection:
                snapshot = await _snapshot_row(connection, indexed.revision.snapshot_id)
                _unauthorized_if(
                    condition=snapshot is None
                    or str(snapshot["repository_id"]) != indexed.file.repository_id
                )
                snapshot = cast("RowMapping", snapshot)
                await _authorize(
                    connection,
                    scope,
                    str(snapshot["project_id"]),
                    indexed.file.repository_id,
                    self._clock.now(),
                    write=True,
                )
                await _insert_file(connection, indexed.file)
                await _insert_revision(connection, indexed.revision)
                for symbol in indexed.symbols:
                    await _insert_symbol(connection, symbol)
                for revision in indexed.symbol_revisions:
                    await _insert_symbol_revision(connection, revision)
                for occurrence in indexed.occurrences:
                    await _insert_occurrence(connection, occurrence)
                for failure in indexed.failures:
                    await _insert_failure(connection, failure)
                return indexed
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def merge_precise_evidence(
        self,
        scope: AuthorizedScope,
        file_revision_id: str,
        symbols: tuple[CodeSymbol, ...],
        revisions: tuple[SymbolRevision, ...],
        occurrences: tuple[SymbolOccurrence, ...],
    ) -> None:
        """Append precise evidence while preserving every lower-priority row."""
        _require_action(scope, _WRITE_ACTIONS)
        try:
            async with _write_transaction(self._store) as connection:
                resolved_scope = await _file_revision_scope(connection, file_revision_id)
                _unauthorized_if(condition=resolved_scope is None)
                project_id, repository_id = cast("tuple[str, str]", resolved_scope)
                await _authorize(
                    connection,
                    scope,
                    project_id,
                    repository_id,
                    self._clock.now(),
                    write=True,
                )
                _unauthorized_if(
                    condition=any(item.repository_id != repository_id for item in symbols)
                )
                _conflict_if(
                    condition=any(item.file_revision_id != file_revision_id for item in revisions)
                    or any(item.file_revision_id != file_revision_id for item in occurrences)
                )
                for symbol in symbols:
                    await _insert_symbol(connection, symbol)
                for revision in revisions:
                    await _insert_symbol_revision(connection, revision)
                for occurrence in occurrences:
                    await _insert_occurrence(connection, occurrence)
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def list_files(self, scope: AuthorizedScope, snapshot_id: str) -> tuple[IndexedFile, ...]:
        """Load one authorized snapshot with all retained provenance."""
        _require_action(scope, _READ_ACTIONS)
        try:
            async with self._store.engine.connect() as connection:
                snapshot = await _snapshot_row(connection, snapshot_id)
                if snapshot is None:
                    return ()
                repository_id = str(snapshot["repository_id"])
                await _authorize(
                    connection,
                    scope,
                    str(snapshot["project_id"]),
                    repository_id,
                    self._clock.now(),
                    write=False,
                )
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT revision.*, source_file.repository_id,"
                                "source_file.relative_path FROM file_revisions AS revision "
                                "JOIN source_files AS source_file "
                                "ON source_file.id=revision.file_id "
                                "WHERE revision.snapshot_id=:snapshot "
                                "ORDER BY source_file.relative_path"
                            ),
                            {"snapshot": snapshot_id},
                        )
                    )
                    .mappings()
                    .all()
                )
                indexed_files = [await _indexed_file(connection, row) for row in rows]
                return tuple(indexed_files)
        except IndexingAuthorizationError, IndexingConflictError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


async def _insert_file(connection: AsyncConnection, item: SourceFile) -> None:
    await _insert_exact(
        connection,
        "source_files",
        {"id": item.id, "repository_id": item.repository_id, "relative_path": item.relative_path},
    )


async def _insert_revision(connection: AsyncConnection, item: FileRevision) -> None:
    await _insert_exact(
        connection,
        "file_revisions",
        {
            "id": item.id,
            "file_id": item.file_id,
            "snapshot_id": item.snapshot_id,
            "content_digest": bytes.fromhex(item.content_digest),
            "byte_length": item.byte_length,
            "language": item.language,
            "language_tier": item.language_tier.value,
            "parser_version": item.parser_version,
            "grammar_revision": item.grammar_revision,
            "query_pack_digest": bytes.fromhex(item.query_pack_digest),
            "status": item.status.value,
            "error_count": item.error_count,
        },
    )


async def _insert_symbol(connection: AsyncConnection, item: CodeSymbol) -> None:
    await _insert_exact(
        connection,
        "code_symbols",
        {
            "id": item.id,
            "repository_id": item.repository_id,
            "stable_key": item.stable_key,
            "display_name": item.display_name,
            "kind": item.kind.value,
        },
    )


async def _insert_symbol_revision(connection: AsyncConnection, item: SymbolRevision) -> None:
    await _insert_exact(connection, "symbol_revisions", _semantic_values(item, None))


async def _insert_occurrence(connection: AsyncConnection, item: SymbolOccurrence) -> None:
    await _insert_exact(connection, "symbol_occurrences", _semantic_values(item, item.role.value))


async def _insert_failure(connection: AsyncConnection, item: ParseFailure) -> None:
    await _insert_exact(
        connection,
        "parse_failures",
        {
            "id": item.id,
            "file_revision_id": item.file_revision_id,
            "language": item.language,
            "parser_version": item.parser_version,
            "error_code": item.error_code,
            "recoverable": item.recoverable,
        },
    )


def _semantic_values(
    item: SymbolRevision | SymbolOccurrence, role: str | None
) -> dict[str, object]:
    values: dict[str, object] = {
        "id": item.id,
        "file_revision_id": item.file_revision_id,
        "symbol_id": item.symbol_id if isinstance(item, SymbolRevision) else item.target_symbol_id,
        "start_byte": item.span.start_byte,
        "end_byte": item.span.end_byte,
        "start_line": item.span.start_line,
        "start_column": item.span.start_column,
        "end_line": item.span.end_line,
        "end_column": item.span.end_column,
        "source": item.source.value,
        "priority": int(item.priority),
        "source_identity": item.source_identity,
    }
    if role is not None:
        values["role"] = role
    return values


_TABLE_COLUMNS = {
    "source_files": ("id", "repository_id", "relative_path"),
    "file_revisions": (
        "id",
        "file_id",
        "snapshot_id",
        "content_digest",
        "byte_length",
        "language",
        "language_tier",
        "parser_version",
        "grammar_revision",
        "query_pack_digest",
        "status",
        "error_count",
    ),
    "code_symbols": ("id", "repository_id", "stable_key", "display_name", "kind"),
    "symbol_revisions": (
        "id",
        "file_revision_id",
        "symbol_id",
        "start_byte",
        "end_byte",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "source",
        "priority",
        "source_identity",
    ),
    "symbol_occurrences": (
        "id",
        "file_revision_id",
        "symbol_id",
        "role",
        "start_byte",
        "end_byte",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "source",
        "priority",
        "source_identity",
    ),
    "parse_failures": (
        "id",
        "file_revision_id",
        "language",
        "parser_version",
        "error_code",
        "recoverable",
    ),
}

_SELECT_BY_ID = {
    table: text(
        f"SELECT {','.join(columns)} FROM {table} WHERE id=:id"  # noqa: S608  # nosec B608
    )
    for table, columns in _TABLE_COLUMNS.items()
}
_INSERT_BY_ID = {
    table: text(
        f"INSERT INTO {table}({','.join(columns)}) "  # nosec B608
        f"VALUES({','.join(f':{column}' for column in columns)})"
    )
    for table, columns in _TABLE_COLUMNS.items()
}


async def _insert_exact(
    connection: AsyncConnection, table: str, values: Mapping[str, object]
) -> None:
    columns = _TABLE_COLUMNS[table]
    row = (
        (await connection.execute(_SELECT_BY_ID[table], {"id": values["id"]}))
        .mappings()
        .one_or_none()
    )
    if row is not None:
        if any(row[column] != values[column] for column in columns):
            raise IndexingConflictError(_ERR_CONFLICT)
        return
    await connection.execute(_INSERT_BY_ID[table], dict(values))


async def _indexed_file(connection: AsyncConnection, row: RowMapping) -> IndexedFile:
    revision = _file_revision(row)
    semantic_symbols = (
        (
            await connection.execute(
                text(
                    "SELECT DISTINCT symbol.* FROM code_symbols AS symbol "
                    "JOIN (SELECT symbol_id FROM symbol_revisions "
                    "WHERE file_revision_id=:revision UNION SELECT symbol_id "
                    "FROM symbol_occurrences WHERE file_revision_id=:revision) AS used "
                    "ON used.symbol_id=symbol.id ORDER BY symbol.id"
                ),
                {"revision": revision.id},
            )
        )
        .mappings()
        .all()
    )
    revision_rows = (
        (
            await connection.execute(
                text("SELECT * FROM symbol_revisions WHERE file_revision_id=:revision ORDER BY id"),
                {"revision": revision.id},
            )
        )
        .mappings()
        .all()
    )
    occurrence_rows = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM symbol_occurrences WHERE file_revision_id=:revision ORDER BY id"
                ),
                {"revision": revision.id},
            )
        )
        .mappings()
        .all()
    )
    failure_rows = (
        (
            await connection.execute(
                text("SELECT * FROM parse_failures WHERE file_revision_id=:revision ORDER BY id"),
                {"revision": revision.id},
            )
        )
        .mappings()
        .all()
    )
    return IndexedFile(
        SourceFile(str(row["file_id"]), str(row["repository_id"]), str(row["relative_path"])),
        revision,
        tuple(_symbol(item) for item in semantic_symbols),
        tuple(_symbol_revision(item) for item in revision_rows),
        tuple(_occurrence(item) for item in occurrence_rows),
        tuple(_failure(item) for item in failure_rows),
    )


def _snapshot(row: RowMapping) -> SourceSnapshot:
    return SourceSnapshot(
        str(row["id"]),
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        None if row["commit_id"] is None else str(row["commit_id"]),
        bytes(row["working_digest"]).hex(),
        _datetime(int(row["created_at"])),
    )


def _file_revision(row: RowMapping) -> FileRevision:
    return FileRevision(
        str(row["id"]),
        str(row["file_id"]),
        str(row["snapshot_id"]),
        bytes(row["content_digest"]).hex(),
        int(row["byte_length"]),
        str(row["language"]),
        LanguageTier(str(row["language_tier"])),
        str(row["parser_version"]),
        str(row["grammar_revision"]),
        bytes(row["query_pack_digest"]).hex(),
        ParseStatus(str(row["status"])),
        int(row["error_count"]),
    )


def _symbol(row: RowMapping) -> CodeSymbol:
    return CodeSymbol(
        str(row["id"]),
        str(row["repository_id"]),
        str(row["stable_key"]),
        str(row["display_name"]),
        SymbolKind(str(row["kind"])),
    )


def _source_span(row: RowMapping) -> SourceSpan:
    return SourceSpan(
        *(
            int(row[name])
            for name in (
                "start_byte",
                "end_byte",
                "start_line",
                "start_column",
                "end_line",
                "end_column",
            )
        )
    )


def _symbol_revision(row: RowMapping) -> SymbolRevision:
    return SymbolRevision(
        str(row["id"]),
        str(row["symbol_id"]),
        str(row["file_revision_id"]),
        _source_span(row),
        SemanticSource(str(row["source"])),
        SemanticPriority(int(row["priority"])),
        str(row["source_identity"]),
    )


def _occurrence(row: RowMapping) -> SymbolOccurrence:
    return SymbolOccurrence(
        str(row["id"]),
        str(row["file_revision_id"]),
        str(row["symbol_id"]),
        OccurrenceRole(str(row["role"])),
        _source_span(row),
        SemanticSource(str(row["source"])),
        SemanticPriority(int(row["priority"])),
        str(row["source_identity"]),
    )


def _failure(row: RowMapping) -> ParseFailure:
    return ParseFailure(
        str(row["id"]),
        str(row["file_revision_id"]),
        str(row["language"]),
        str(row["parser_version"]),
        str(row["error_code"]),
        bool(row["recoverable"]),
    )


async def _snapshot_row(connection: AsyncConnection, snapshot_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM source_snapshots WHERE id=:id"), {"id": snapshot_id}
            )
        )
        .mappings()
        .one_or_none()
    )


async def _file_revision_scope(
    connection: AsyncConnection, revision_id: str
) -> tuple[str, str] | None:
    row = (
        await connection.execute(
            text(
                "SELECT snapshot.project_id,snapshot.repository_id "
                "FROM file_revisions AS revision "
                "JOIN source_snapshots AS snapshot ON snapshot.id=revision.snapshot_id "
                "WHERE revision.id=:id"
            ),
            {"id": revision_id},
        )
    ).one_or_none()
    return None if row is None else (str(row[0]), str(row[1]))


async def _authorize(  # noqa: PLR0913 -- Authority binds the complete repository scope.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    project_id: str,
    repository_id: str,
    now: datetime,
    *,
    write: bool,
) -> None:
    allowed = _WRITE_ROLES if write else _READ_ROLES
    if (
        scope.role.value not in allowed
        or project_id not in {item.value for item in scope.project_ids}
        or repository_id not in {item.value for item in scope.repository_ids}
    ):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    project = (
        await connection.execute(
            text(
                "SELECT project.id FROM repositories AS repository "
                "JOIN project_repositories AS binding "
                "ON binding.repository_id=repository.id "
                "JOIN projects AS project ON project.id=binding.project_id "
                "WHERE repository.id=:repository AND project.id=:project "
                "AND repository.status='active' "
                "AND project.status='active' AND project.brain_id=:brain "
                "AND EXISTS(SELECT 1 FROM scope_grants AS grant_row "
                "WHERE grant_row.principal_id=:principal "
                "AND grant_row.brain_id=:brain AND grant_row.role=:role "
                "AND grant_row.valid_from<=:now "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) "
                "AND (grant_row.project_id IS NULL OR grant_row.project_id=project.id) "
                "AND (grant_row.repository_id IS NULL "
                "OR grant_row.repository_id=repository.id))"
            ),
            {
                "repository": repository_id,
                "project": project_id,
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
                "role": scope.role.value,
                "now": _micros(now),
            },
        )
    ).scalar_one_or_none()
    _unauthorized_if(condition=project is None)


def _require_action(scope: AuthorizedScope, allowed: frozenset[str]) -> None:
    if scope.action not in allowed:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _unauthorized_if(*, condition: bool) -> None:
    if condition:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _conflict_if(*, condition: bool) -> None:
    if condition:
        raise IndexingConflictError(_ERR_CONFLICT)


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, UTC)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    await store.write_lock.acquire()
    connection: AsyncConnection | None = None
    try:
        connection = await store.engine.connect()
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        yield connection
        await connection.commit()
    except BaseException:
        if connection is not None:
            await connection.rollback()
        raise
    finally:
        if connection is not None:
            await connection.close()
        store.write_lock.release()
