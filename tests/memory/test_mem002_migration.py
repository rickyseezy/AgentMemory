"""MEM-002 provenance backfill, projection source, and rollback tests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from tests.core.support import write_secret
from tests.memory.test_mem002_sqlite_repository import (
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)


def _config(database: Path) -> Config:
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    config = Config(str(migrations / "alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


def _store(database: Path) -> SqliteCoreStore:
    return SqliteCoreStore.create(
        database,
        SqliteRuntimePolicy(
            minimum_version=(3, 0, 0),
            required_compile_options=frozenset(),
        ),
    )


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_upgrade_backfills_legacy_provenance_and_memory_projected_replay_source(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    config = _config(database)
    command.upgrade(config, "0015_mem001_memory_consolidation")
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = _store(database)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
    finally:
        await store.close()

    with closing(sqlite3.connect(database)) as connection:
        current = json.loads(
            connection.execute(
                "SELECT provenance_json FROM memory_revisions WHERE memory_id=?",
                (memory_id,),
            ).fetchone()[0]
        )
        legacy = {
            "created_by_event": current["created_by_event"],
            "evidence_ids": current["evidence_ids"],
            "extractor": current["extractor"],
            "promotion_policy_version": current["promotion_policy_version"],
            "source_task_id": current["source_task_id"],
            "evidence_watermark_sha256": current["evidence_watermark_sha256"],
        }
        event = json.loads(
            connection.execute(
                "SELECT event_json FROM domain_events WHERE aggregate_id=?",
                (memory_id,),
            ).fetchone()[0]
        )
        event["provenance"] = legacy
        connection.execute(
            "UPDATE memory_revisions SET provenance_json=?,schema_version=1 WHERE memory_id=?",
            (_canonical(legacy), memory_id),
        )
        connection.execute(
            "UPDATE domain_events SET projection_type=NULL,stable_id=NULL,target_type=NULL,"
            "target_id_hash=NULL,payload_json=NULL,payload_hash=NULL,source_digest=NULL,"
            "event_type='MemoryActivated',event_json=?,schema_version=1 WHERE aggregate_id=?",
            (_canonical(event), memory_id),
        )
        connection.commit()

    command.upgrade(config, "0016_mem002_memory_provenance")
    with closing(sqlite3.connect(database)) as connection:
        connection.row_factory = sqlite3.Row
        revision = connection.execute(
            "SELECT provenance_json,schema_version FROM memory_revisions WHERE memory_id=?",
            (memory_id,),
        ).fetchone()
        provenance = json.loads(revision["provenance_json"])
        assert set(provenance) == {
            "actor_id",
            "agent_id",
            "content_sha256",
            "created_by_event",
            "evidence_ids",
            "evidence_watermark_sha256",
            "extractor",
            "extractor_input_sha256",
            "promotion_policy_version",
            "source_task_id",
        }
        assert provenance["actor_id"] == commit.actor_id
        assert provenance["agent_id"] == commit.extractor.extractor_id
        assert provenance["extractor_input_sha256"] == commit.extractor_input_sha256
        assert revision["schema_version"] == 2

        projected = connection.execute(
            "SELECT * FROM domain_events WHERE aggregate_id=?",
            (memory_id,),
        ).fetchone()
        assert projected["event_type"] == "MemoryProjected"
        assert projected["projection_type"] == "graph"
        assert projected["stable_id"] == memory_id
        assert projected["target_type"] == "memory"
        assert projected["target_id_hash"] == hashlib.sha256(memory_id.encode()).digest()
        assert (
            projected["payload_hash"] == hashlib.sha256(projected["payload_json"].encode()).digest()
        )
        assert json.loads(projected["event_json"])["provenance"] == provenance
        assert projected["payload_json"] == projected["event_json"]
        assert len(projected["source_digest"]) == 32
        assert projected["schema_version"] == 2
        with pytest.raises(sqlite3.IntegrityError, match="memory provenance is immutable"):
            connection.execute(
                "UPDATE memory_revisions SET provenance_json='{}' WHERE memory_id=?",
                (memory_id,),
            )

    with pytest.raises(RuntimeError, match="MEM-002 downgrade refused"):
        command.downgrade(config, "0015_mem001_memory_consolidation")


@pytest.mark.migration
def test_empty_mem002_schema_can_downgrade_without_leaving_guards(tmp_path: Path) -> None:
    database = tmp_path / "empty.sqlite3"
    config = _config(database)
    command.upgrade(config, "0016_mem002_memory_provenance")
    command.downgrade(config, "0015_mem001_memory_consolidation")
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "0015_mem001_memory_consolidation",
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' "
            "AND name='memory_revision_provenance_no_update'"
        ).fetchone() == (0,)
