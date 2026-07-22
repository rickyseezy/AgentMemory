"""PF-005 encrypted checkpoint source for the durable IDX-002 pipeline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.incremental import (
    IndexRevisionContext,
    VcsDelta,
    VcsDeltaKind,
)
from agentmemory.indexing.domain.incremental_ports import (
    RepositoryInspection,
    RepositoryManifestEntry,
)
from agentmemory.indexing.domain.ports import SourceArtifact
from agentmemory.operations.domain.errors import OperationError

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping

    from agentmemory.indexing.domain.incremental import PriorIndexedUnit
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.adapters.outbound.workspace_checkpoint_ingestion import (
        SqlitePreparedWorkspaceChangeRepository,
    )

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERR_AUTHORIZATION = "checkpoint source repository is not authorized"
_ERR_INTEGRITY = "checkpoint source failed integrity verification"
_ERR_UNAVAILABLE = "checkpoint source is unavailable"
_GENERATED_PARTS = frozenset({".generated", "dist", "gen", "generated", "node_modules", "vendor"})


@dataclass(frozen=True, slots=True)
class SqliteCheckpointIncrementalRepositorySource:
    """Reconstruct complete manifests and decrypt only exact planned artifacts."""

    store: SqliteCoreStore
    preparations: SqlitePreparedWorkspaceChangeRepository

    async def inspect(
        self,
        repository_id: str,
        base_commit_id: str | None,
        target_commit_id: str | None,
        previous: tuple[PriorIndexedUnit, ...],
    ) -> RepositoryInspection:
        """Overlay ordered sanitized checkpoints into a complete repository manifest."""
        del base_commit_id
        target = _target(target_commit_id)
        try:
            async with self.store.engine.connect() as connection:
                target_row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT b.batch_sequence,b.partial,s.repository_id FROM "
                                "mcp_workspace_checkpoint_batches b JOIN mcp_session_credentials s "
                                "ON s.session_id=b.session_id WHERE b.batch_digest=:target"
                            ),
                            {"target": bytes.fromhex(target)},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                target_row = _require_target_row(target_row, repository_id)
                sequence = _integer(target_row["batch_sequence"])
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT c.*,b.batch_sequence FROM "
                                "mcp_workspace_checkpoint_changes c JOIN "
                                "mcp_workspace_checkpoint_batches b ON "
                                "b.batch_digest=c.batch_digest WHERE "
                                "c.repository_id=:repository AND b.batch_sequence<=:sequence "
                                "ORDER BY b.batch_sequence,c.ordinal"
                            ),
                            {"repository": repository_id, "sequence": sequence},
                        )
                    )
                    .mappings()
                    .all()
                )
        except (
            IndexingAuthorizationError,
            IndexingUnavailableError,
            IndexingValidationError,
        ):
            raise
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise IndexingUnavailableError(_ERR_UNAVAILABLE) from error
        target_rows = tuple(row for row in rows if _integer(row["batch_sequence"]) == sequence)
        if target_rows and any(str(row["repository_id"]) != repository_id for row in target_rows):
            raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
        current: dict[str, RepositoryManifestEntry] = {}
        for row in rows:
            path = _text(row, "relative_path")
            if str(row["disposition"]) != "event" or bool(_integer(row["deleted"])):
                current.pop(path, None)
                continue
            digest = _blob(row, "sanitized_sha256", 32).hex()
            size = _integer(row["sanitized_size"])
            current[path] = RepositoryManifestEntry(path, digest, size, _generated(path))
        entries = tuple(current[path] for path in sorted(current))
        deltas = _target_deltas(target_rows, previous, current)
        working_digest = hashlib.sha256(
            json.dumps(
                {
                    "files": [
                        {
                            "generated": entry.generated,
                            "path": entry.relative_path,
                            "sha256": entry.content_digest,
                            "size": entry.byte_length,
                        }
                        for entry in entries
                    ],
                    "partial": bool(_integer(target_row["partial"])),
                    "schema_version": 1,
                    "target": target,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        return RepositoryInspection(
            target,
            working_digest,
            entries,
            deltas,
            IndexRevisionContext.WORKTREE,
        )

    async def read(
        self,
        repository_id: str,
        target_commit_id: str | None,
        relative_path: str,
        expected_digest: str,
        revision_context: IndexRevisionContext,
    ) -> SourceArtifact:
        """Decrypt the latest exact sanitized artifact visible at the target checkpoint."""
        target = _target(target_commit_id)
        if (
            revision_context is not IndexRevisionContext.WORKTREE
            or _DIGEST.fullmatch(expected_digest) is None
        ):
            raise IndexingValidationError(_ERR_INTEGRITY)
        try:
            async with self.store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT c.*,b.batch_sequence FROM "
                                "mcp_workspace_checkpoint_changes c JOIN "
                                "mcp_workspace_checkpoint_batches b ON "
                                "b.batch_digest=c.batch_digest JOIN "
                                "mcp_workspace_checkpoint_batches target ON "
                                "target.batch_digest=:target WHERE "
                                "c.repository_id=:repository AND c.relative_path=:path AND "
                                "b.batch_sequence<=target.batch_sequence ORDER BY "
                                "b.batch_sequence DESC,c.ordinal DESC LIMIT 1"
                            ),
                            {
                                "target": bytes.fromhex(target),
                                "repository": repository_id,
                                "path": relative_path,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
            row = _require_source_row(row, repository_id)
            prepared = await self.preparations.load_by_identity(
                _blob(row, "batch_digest", 32).hex(),
                _integer(row["ordinal"]),
            )
        except IndexingAuthorizationError, IndexingValidationError:
            raise
        except OperationError as error:
            raise IndexingUnavailableError(_ERR_UNAVAILABLE) from error
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise IndexingUnavailableError(_ERR_UNAVAILABLE) from error
        content = prepared.artifact_content
        if (
            content is None
            or prepared.repository_id != repository_id
            or prepared.relative_path != relative_path
            or hashlib.sha256(content).hexdigest() != expected_digest
        ):
            raise IndexingValidationError(_ERR_INTEGRITY)
        return SourceArtifact(relative_path, content)


def _target(value: str | None) -> str:
    if value is None or _DIGEST.fullmatch(value) is None:
        raise IndexingValidationError(_ERR_INTEGRITY)
    return value


def _require_target_row(row: RowMapping | None, repository_id: str) -> RowMapping:
    if row is None:
        raise IndexingUnavailableError(_ERR_UNAVAILABLE)
    if str(row["repository_id"]) != repository_id:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    return row


def _require_source_row(row: RowMapping | None, repository_id: str) -> RowMapping:
    if (
        row is None
        or str(row["repository_id"]) != repository_id
        or str(row["disposition"]) != "event"
        or bool(_integer(row["deleted"]))
    ):
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)
    return row


def _target_deltas(
    rows: tuple[RowMapping, ...],
    previous: tuple[PriorIndexedUnit, ...],
    current: dict[str, RepositoryManifestEntry],
) -> tuple[VcsDelta, ...]:
    prior = {item.relative_path: item for item in previous}
    deltas: dict[str, VcsDelta] = {}
    for row in rows:
        path = _text(row, "relative_path")
        included = str(row["disposition"]) == "event" and not bool(_integer(row["deleted"]))
        if not included:
            if path in prior:
                deltas[path] = VcsDelta(VcsDeltaKind.DELETE, path)
            continue
        kind = VcsDeltaKind.ADD if path not in prior else VcsDeltaKind.MODIFY
        if path in prior and prior[path].content_digest == current[path].content_digest:
            continue
        deltas[path] = VcsDelta(kind, path)
    return tuple(deltas[path] for path in sorted(deltas))


def _generated(path: str) -> bool:
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    return any(part in _GENERATED_PARTS for part in parts) or path.endswith(
        (".generated.go", ".g.cs", ".min.js")
    )


def _blob(row: RowMapping, key: str, length: int | None = None) -> bytes:
    value = row[key]
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise ValueError
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value


def _text(row: RowMapping, key: str) -> str:
    value = row[key]
    if not isinstance(value, str) or not value:
        raise ValueError
    return value
