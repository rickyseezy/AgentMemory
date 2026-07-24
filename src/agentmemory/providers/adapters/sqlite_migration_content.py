"""Canonical SQLite content replay source for PRO-008 generation migration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.providers.domain.errors import (
    EmbeddingMigrationConflictError,
    EmbeddingMigrationDependencyError,
    EmbeddingMigrationValidationError,
)
from agentmemory.providers.domain.migration import (
    MigrationContent,
    MigrationContentPage,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import RowMapping

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted", "local_only"})
_ERR_BOUNDS = "canonical embedding replay bounds are invalid"
_ERR_INTEGRITY = "canonical embedding content is malformed"
_ERR_STORAGE = "canonical embedding content is unavailable"
_MAX_PAGE_SIZE = 4_096
_LATEST_QUERY = (
    "SELECT COALESCE(MAX(sequence),0) FROM domain_events "
    "WHERE brain_id=:brain AND payload_json IS NOT NULL AND event_id IS NOT NULL "
    "AND target_type IS NOT NULL AND target_id_hash IS NOT NULL"
)
_PAGE_QUERY = (
    "SELECT sequence,event_id,payload_hash,payload_json FROM domain_events "
    "WHERE brain_id=:brain AND sequence>:after AND sequence<=:through "
    "AND payload_json IS NOT NULL AND event_id IS NOT NULL "
    "AND target_type IS NOT NULL AND target_id_hash IS NOT NULL "
    "ORDER BY sequence LIMIT :limit"
)


class SqliteCanonicalEmbeddingContentSource:
    """Read content-addressed canonical projection inputs at a stable watermark."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical relational event authority."""
        self._store = store

    async def latest_watermark(self, brain_id: str) -> int:
        """Return the latest eligible committed canonical sequence for one Brain."""
        try:
            async with self._store.engine.connect() as connection:
                value = (
                    await connection.execute(
                        text(_LATEST_QUERY),
                        {"brain": brain_id},
                    )
                ).scalar_one()
            return int(value)
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error

    async def read_page(
        self,
        brain_id: str,
        after_sequence: int,
        through_sequence: int,
        limit: int,
    ) -> MigrationContentPage:
        """Read strictly ordered local content references, never prior vectors."""
        if (
            after_sequence < 0
            or through_sequence < after_sequence
            or not 1 <= limit <= _MAX_PAGE_SIZE
        ):
            raise EmbeddingMigrationValidationError(_ERR_BOUNDS)
        try:
            async with self._store.engine.connect() as connection:
                rows = (
                    (
                        await connection.execute(
                            text(_PAGE_QUERY),
                            {
                                "after": after_sequence,
                                "brain": brain_id,
                                "limit": limit,
                                "through": through_sequence,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
            records = tuple(_record(row) for row in rows)
            complete = len(records) < limit
            next_cursor = through_sequence if complete else records[-1].sequence
            return MigrationContentPage(records, next_cursor, complete)
        except (
            EmbeddingMigrationValidationError,
            EmbeddingMigrationConflictError,
        ):
            raise
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error


def _record(row: RowMapping) -> MigrationContent:
    classification = _classification(str(row["payload_json"]))
    event_id = str(row["event_id"])
    return MigrationContent(
        sequence=int(row["sequence"]),
        source_entity_id=event_id,
        source_content_hash=_blob(row["payload_hash"]).hex(),
        content_ref=f"sqlite://domain-events/{event_id}",
        classification=classification,
    )


def _classification(payload: str) -> str:
    """Extract only the closed classification token without returning content."""
    value = json.loads(payload).get("classification")
    return str(value) if value in _CLASSIFICATIONS else "internal"


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise TypeError
