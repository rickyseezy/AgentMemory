"""Ordered idempotent Cypher 25 migrations for PF-001 readiness state."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from neo4j import Query

from agentmemory.operations.adapters.outbound.neo4j_graph import VECTOR_INDEX_NAME

if TYPE_CHECKING:
    from pathlib import Path

    from neo4j import AsyncDriver

_MIGRATION_FILE = "0001_pf001_core_schema.cypher"
_MAX_MIGRATION_BYTES = 64 * 1024
_EXPECTED_STATEMENTS = 4
_MIGRATION_SHA256 = "657a2675d0646c4ec2d664f51a74b1da38e7253c7038529e112d31d64dec824b"


async def migrate_neo4j(driver: AsyncDriver, database: str, directory: Path) -> None:
    """Apply the signed on-disk migration bundle and await the vector index."""
    for statement in _load_migration(directory):
        await driver.execute_query(
            # Digest pinning above promotes this on-disk statement to trusted query text.
            Query(statement),  # pyright: ignore[reportArgumentType]
            database_=database,
        )
    await driver.execute_query(
        "CYPHER 25 CALL db.awaitIndex($index_name, 300)",
        index_name=VECTOR_INDEX_NAME,
        database_=database,
    )


def _load_migration(directory: Path) -> tuple[str, ...]:
    path = directory / _MIGRATION_FILE
    payload = path.read_bytes()
    if (
        not payload
        or len(payload) > _MAX_MIGRATION_BYTES
        or hashlib.sha256(payload).hexdigest() != _MIGRATION_SHA256
    ):
        msg = "signed Neo4j migration bundle failed its size or digest integrity policy"
        raise RuntimeError(msg)
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        msg = "signed Neo4j migration bundle is not UTF-8"
        raise RuntimeError(msg) from error
    statements_source = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("//")
    )
    statements = tuple(
        statement.strip() for statement in statements_source.split(";") if statement.strip()
    )
    if len(statements) != _EXPECTED_STATEMENTS or any(
        not statement.startswith("CYPHER 25\n") for statement in statements
    ):
        msg = "signed Neo4j migration bundle has an invalid grammar"
        raise RuntimeError(msg)
    return statements
