"""Ordered idempotent Cypher 25 migrations for PF-001 readiness state."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from neo4j import Query

from agentmemory.operations.adapters.outbound.neo4j_graph import VECTOR_INDEX_NAME

if TYPE_CHECKING:
    from pathlib import Path

    from neo4j import AsyncDriver

_MAX_MIGRATION_BYTES = 64 * 1024
_MIGRATIONS = (
    (
        "0001_pf001_core_schema.cypher",
        4,
        "657a2675d0646c4ec2d664f51a74b1da38e7253c7038529e112d31d64dec824b",
    ),
    (
        "0002_pf002_projection_schema.cypher",
        4,
        "ebaffd862afc8833b1c3bca1ccf7cb084a0682cbfb222b8e6ddba430a5d8f465",
    ),
    (
        "0003_gra001_brain_scoped_schema.cypher",
        54,
        "f3e2b2370d682132157b4f0129b26403be2f46836dd3386cdc89c4848faf6ed8",
    ),
    (
        "0004_gra003_materialized_edge_indexes.cypher",
        8,
        "7c584d5179398f7de2ad91b4757535d6415d1d4e4c511da707bd888688413d9f",
    ),
)


async def migrate_neo4j(driver: AsyncDriver, database: str, directory: Path) -> None:
    """Apply the signed on-disk migration bundle and await the vector index."""
    for filename, expected_statements, expected_digest in _MIGRATIONS:
        for statement in _load_migration(
            directory,
            filename,
            expected_statements,
            expected_digest,
        ):
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


def _load_migration(
    directory: Path,
    filename: str,
    expected_statements: int,
    expected_digest: str,
) -> tuple[str, ...]:
    path = directory / filename
    try:
        payload = path.read_bytes()
    except OSError as error:
        msg = "signed Neo4j migration bundle failed its size or digest integrity policy"
        raise RuntimeError(msg) from error
    if (
        not payload
        or len(payload) > _MAX_MIGRATION_BYTES
        or hashlib.sha256(payload).hexdigest() != expected_digest
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
    if len(statements) != expected_statements or any(
        not statement.startswith("CYPHER 25\n") for statement in statements
    ):
        msg = "signed Neo4j migration bundle has an invalid grammar"
        raise RuntimeError(msg)
    return statements
