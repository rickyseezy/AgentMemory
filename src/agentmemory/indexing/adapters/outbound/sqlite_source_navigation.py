"""IDX-007 authorized SQLite semantic-evidence lookup adapter."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.indexing.adapters.outbound.policy_visibility import policy_visible_sql
from agentmemory.indexing.domain.code_entities import (
    OccurrenceRole,
    SemanticSource,
    SourceSpan,
    SymbolKind,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.source_navigation import (
    SourceEvidence,
    SourceEvidenceKind,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection
    from sqlalchemy.sql.elements import TextClause

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERR_ACTION = "source navigation repository action is not authorized"
_ERR_AUTHORIZATION = "source navigation repository scope is not authorized"
_ERR_STORAGE = "source navigation repository is unavailable"
_READ_ROLES = frozenset({"owner", "admin", "editor", "reader", "auditor", "worker"})

_BASE_SELECT = (
    "SELECT :kind AS evidence_kind,evidence.id AS evidence_id,snapshot.brain_id,"
    "snapshot.project_id,snapshot.repository_id,snapshot.id AS snapshot_id,"
    "snapshot.commit_id,revision.file_id AS source_file_id,revision.id AS file_revision_id,"
    "COALESCE((SELECT binding.relative_path FROM snapshot_file_bindings AS binding "
    "WHERE binding.snapshot_id=revision.snapshot_id "
    "AND binding.source_file_id=revision.file_id "
    "AND binding.file_revision_id=revision.id),source_file.relative_path) AS relative_path,"
    "symbol.id AS symbol_id,symbol.stable_key,symbol.display_name,symbol.kind AS symbol_kind,"
    ":role_expression AS occurrence_role,evidence.start_byte,evidence.end_byte,"
    "evidence.start_line,evidence.start_column,evidence.end_line,evidence.end_column,"
    "revision.content_digest,revision.byte_length,revision.parser_version,"
    "revision.grammar_revision,revision.query_pack_digest,evidence.source AS semantic_source "
    "FROM {evidence_table} AS evidence "
    "JOIN file_revisions AS revision ON revision.id=evidence.file_revision_id "
    "JOIN source_snapshots AS snapshot ON snapshot.id=revision.snapshot_id "
    "JOIN source_files AS source_file ON source_file.id=revision.file_id "
    "JOIN code_symbols AS symbol ON symbol.id=evidence.symbol_id "
    "WHERE evidence.id=:evidence_id AND "
)


def _select_sql(table: str, kind: str, role_expression: str) -> TextClause:
    path = (
        "COALESCE((SELECT visible_binding.relative_path FROM snapshot_file_bindings "
        "AS visible_binding WHERE visible_binding.snapshot_id=revision.snapshot_id "
        "AND visible_binding.source_file_id=revision.file_id "
        "AND visible_binding.file_revision_id=revision.id),source_file.relative_path)"
    )
    statement = _BASE_SELECT.replace("{evidence_table}", table).replace(
        ":role_expression", role_expression
    )
    statement += policy_visible_sql("snapshot.repository_id", path)
    return text(statement).bindparams(kind=kind)


_SELECT_DEFINITION = _select_sql("symbol_revisions", "definition", "NULL")
_SELECT_OCCURRENCE = _select_sql("symbol_occurrences", "occurrence", "evidence.role")


class SqliteSourceEvidenceRepository:
    """Resolve one immutable symbol/occurrence evidence under current authority."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical database and trusted authorization clock."""
        self._store = store
        self._clock = clock

    async def get(self, scope: AuthorizedScope, evidence_id: str) -> SourceEvidence | None:
        """Hide missing/policy-revoked evidence and reject stale grants before release."""
        if scope.action != "indexing.source.navigate":
            raise IndexingAuthorizationError(_ERR_ACTION)
        if _DIGEST.fullmatch(evidence_id) is None or set(evidence_id) == {"0"}:
            raise IndexingValidationError(_ERR_STORAGE)
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (await connection.execute(_SELECT_DEFINITION, {"evidence_id": evidence_id}))
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    row = (
                        (await connection.execute(_SELECT_OCCURRENCE, {"evidence_id": evidence_id}))
                        .mappings()
                        .one_or_none()
                    )
                if row is None:
                    return None
                await _authorize(connection, scope, row, self._clock.now())
                return _evidence(row)
        except IndexingAuthorizationError, IndexingValidationError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


async def _authorize(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    row: RowMapping,
    now: datetime,
) -> None:
    project_id = str(row["project_id"])
    repository_id = str(row["repository_id"])
    if (
        scope.role.value not in _READ_ROLES
        or str(row["brain_id"]) != scope.brain_id.value
        or project_id not in {item.value for item in scope.project_ids}
        or repository_id not in {item.value for item in scope.repository_ids}
    ):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    result = await connection.execute(
        text(
            "SELECT 1 FROM repositories AS repository "
            "JOIN project_repositories AS binding ON binding.repository_id=repository.id "
            "JOIN projects AS project ON project.id=binding.project_id "
            "WHERE repository.id=:repository AND project.id=:project "
            "AND repository.status='active' AND project.status='active' "
            "AND project.brain_id=:brain AND EXISTS(SELECT 1 FROM scope_grants AS grant_row "
            "WHERE grant_row.principal_id=:principal AND grant_row.brain_id=:brain "
            "AND grant_row.role=:role AND grant_row.valid_from<=:now "
            "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) "
            "AND (grant_row.project_id IS NULL OR grant_row.project_id=project.id) "
            "AND (grant_row.repository_id IS NULL OR grant_row.repository_id=repository.id))"
        ),
        {
            "repository": repository_id,
            "project": project_id,
            "brain": scope.brain_id.value,
            "principal": scope.principal_id.value,
            "role": scope.role.value,
            "now": round(now.timestamp() * 1_000_000),
        },
    )
    if result.scalar_one_or_none() is None:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _evidence(row: RowMapping) -> SourceEvidence:
    role = None if row["occurrence_role"] is None else OccurrenceRole(str(row["occurrence_role"]))
    return SourceEvidence(
        evidence_id=str(row["evidence_id"]),
        kind=SourceEvidenceKind(str(row["evidence_kind"])),
        brain_id=str(row["brain_id"]),
        project_id=str(row["project_id"]),
        repository_id=str(row["repository_id"]),
        snapshot_id=str(row["snapshot_id"]),
        commit_id=None if row["commit_id"] is None else str(row["commit_id"]),
        source_file_id=str(row["source_file_id"]),
        file_revision_id=str(row["file_revision_id"]),
        relative_path=str(row["relative_path"]),
        symbol_id=str(row["symbol_id"]),
        symbol_stable_key=str(row["stable_key"]),
        symbol_display_name=str(row["display_name"]),
        symbol_kind=SymbolKind(str(row["symbol_kind"])),
        occurrence_role=role,
        span=SourceSpan(
            int(row["start_byte"]),
            int(row["end_byte"]),
            int(row["start_line"]),
            int(row["start_column"]),
            int(row["end_line"]),
            int(row["end_column"]),
        ),
        content_digest=_blob(row["content_digest"]).hex(),
        byte_length=int(row["byte_length"]),
        parser_version=str(row["parser_version"]),
        grammar_revision=str(row["grammar_revision"]),
        query_pack_digest=_blob(row["query_pack_digest"]).hex(),
        semantic_source=SemanticSource(str(row["semantic_source"])),
    )


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, bytearray):
        return bytes(value)
    raise IndexingValidationError(_ERR_STORAGE)
