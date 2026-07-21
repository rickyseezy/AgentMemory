"""MEM-004 SQLite correction, history, authorization, and concurrency acceptance tests."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.memory.adapters.outbound.sqlite_correction import (
    SqliteMemoryCorrectionRepository,
    SqliteMemoryCorrectionUnitOfWorkFactory,
)
from agentmemory.memory.adapters.outbound.sqlite_provenance import SqliteMemoryRepository
from agentmemory.memory.application.correct_memory import CorrectMemoryCommand, CorrectMemoryHandler
from agentmemory.memory.domain.consolidation import MemoryScope, MemoryStatus
from agentmemory.memory.domain.correction import CorrectionRelation, MemoryPrecedencePolicy
from agentmemory.memory.domain.errors import MemoryConflictError, MemoryEvidenceNotFoundError
from tests.core.support import migrated_store, write_secret
from tests.memory.test_mem001_consolidation_domain import EVENT_ONE, NOW
from tests.memory.test_mem002_sqlite_repository import (
    _access,  # pyright: ignore[reportPrivateUsage]
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.memory.domain.consolidation import ConsolidationCommit
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

OPERATION_ID = "018f0000-0000-7000-8000-000000000551"
SECOND_OPERATION_ID = "018f0000-0000-7000-8000-000000000552"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000553"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000554"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000555"
OTHER_CHECKOUT_ID = "018f0000-0000-7000-8000-000000000556"
SECOND_CORRELATION_ID = "018f0000-0000-7000-8000-000000000557"
WRONG_ID = "018f0000-0000-7000-8000-000000000999"


class _Clock:
    def now(self) -> datetime:
        return NOW + timedelta(seconds=10)


class _LaterClock:
    def now(self) -> datetime:
        return NOW + timedelta(seconds=20)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_equal_scope_correction_is_atomic_replayable_audited_and_historical(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory = commit.memories[0]
        repository = SqliteMemoryCorrectionRepository(store)
        handler = _handler(store, repository)
        command = _command(commit, memory.memory_id, evidence_ids=(EVENT_ONE,))

        result, replay = await asyncio.gather(handler.execute(command), handler.execute(command))
        history = await repository.history_authorized(
            memory.memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            NOW + timedelta(seconds=10),
        )
        historical = await SqliteMemoryRepository(store).explain_authorized(
            _access(
                commit,
                memory_id=memory.memory_id,
            )
        )
        async with store.engine.connect() as connection:
            source = (
                (
                    await connection.execute(
                        text(
                            "SELECT status,aggregate_version,recorded_to FROM memories WHERE id=:id"
                        ),
                        {"id": memory.memory_id},
                    )
                )
                .mappings()
                .one()
            )
            correction = (
                (await connection.execute(text("SELECT * FROM memory_corrections")))
                .mappings()
                .one()
            )
            event = (
                (
                    await connection.execute(
                        text("SELECT * FROM domain_events WHERE event_id=:id"),
                        {"id": OPERATION_ID},
                    )
                )
                .mappings()
                .one()
            )
            evidence_count = (
                await connection.execute(text("SELECT COUNT(*) FROM memory_correction_evidence"))
            ).scalar_one()
            outbox_topic = (
                await connection.execute(
                    text("SELECT topic FROM outbox_messages WHERE topic='memory.corrected.v1'")
                )
            ).scalar_one()
            audit_action = (
                await connection.execute(
                    text("SELECT action FROM audit_events WHERE action='memory.corrected'")
                )
            ).scalar_one()
    finally:
        await store.close()

    assert replay == result
    assert result.relation is CorrectionRelation.CONTRADICTS
    assert source["status"] == "disputed"
    assert source["aggregate_version"] == 2
    assert source["recorded_to"] is not None
    assert correction["id"] == OPERATION_ID
    assert correction["source_assertion_id"] == memory.memory_id
    assert correction["relation"] == "contradicts"
    assert evidence_count == 1
    assert event["event_type"] == "MemoryCorrected"
    assert event["projection_type"] == "graph"
    assert json.loads(str(event["event_json"]))["relationship"]["type"] == "CONTRADICTS"
    assert outbox_topic == "memory.corrected.v1"
    assert audit_action == "memory.corrected"
    assert historical is not None
    assert historical.memory.status is MemoryStatus.DISPUTED
    assert history is not None
    assert history.root.statement == memory.statement
    assert tuple(item.assertion_id for item in history.corrections) == (OPERATION_ID,)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_narrower_correction_governs_only_declared_scope_and_keeps_source_applicable(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory = commit.memories[0]
        repository = SqliteMemoryCorrectionRepository(store)
        scope = replace(commit.scope, checkout_id=CHECKOUT_ID)
        result = await _handler(store, repository).execute(
            _command(commit, memory.memory_id, scope=scope)
        )
        history = await repository.history_authorized(
            memory.memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            NOW + timedelta(seconds=10),
        )
        assert history is not None
        inside = MemoryPrecedencePolicy().resolve(
            history.root,
            history.corrections,
            scope,
            valid_at=NOW + timedelta(seconds=10),
            recorded_at=NOW + timedelta(seconds=10),
        )
        outside = MemoryPrecedencePolicy().resolve(
            history.root,
            history.corrections,
            replace(commit.scope, checkout_id=OTHER_CHECKOUT_ID),
            valid_at=NOW + timedelta(seconds=10),
            recorded_at=NOW + timedelta(seconds=10),
        )
        source = await repository.load_authorized(
            memory.memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            NOW + timedelta(seconds=10),
        )
    finally:
        await store.close()

    assert result.source_status is MemoryStatus.DISPUTED
    assert source is not None
    assert source.recorded_to is None
    assert inside.assertion_id == OPERATION_ID
    assert outside.assertion_id == memory.memory_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_stale_and_unauthorized_corrections_fail_without_disclosing_target(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
        repository = SqliteMemoryCorrectionRepository(store)
        handler = _handler(store, repository)
        await handler.execute(_command(commit, memory_id))

        with pytest.raises(MemoryConflictError):
            await handler.execute(
                replace(
                    _command(commit, memory_id),
                    operation_id=SECOND_OPERATION_ID,
                    expected_version=1,
                )
            )
        base = _command(commit, memory_id)
        invalid_commands = (
            replace(base, operation_id=SECOND_OPERATION_ID, actor_id=WRONG_ID),
            replace(base, operation_id=SECOND_OPERATION_ID, grant_id=WRONG_ID),
            replace(
                base,
                operation_id=SECOND_OPERATION_ID,
                brain_id=WRONG_ID,
                scope=replace(commit.scope, brain_id=WRONG_ID),
            ),
        )
        for invalid in invalid_commands:
            with pytest.raises(MemoryEvidenceNotFoundError):
                await handler.execute(invalid)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_correction_chain_closes_prior_assertion_and_resolves_latest_state(
    tmp_path: Path,
) -> None:
    store, key_file = _store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
        repository = SqliteMemoryCorrectionRepository(store)
        await _handler(store, repository).execute(_command(commit, memory_id))
        second = replace(
            _command(commit, OPERATION_ID),
            operation_id=SECOND_OPERATION_ID,
            assertion_id=OPERATION_ID,
            expected_version=1,
            statement="Projection rebuilds use copy-on-write generations.",
            correlation_id=SECOND_CORRELATION_ID,
            requested_at=NOW + timedelta(seconds=11),
        )
        result = await CorrectMemoryHandler(
            repository,
            SqliteMemoryCorrectionUnitOfWorkFactory(store),
            MemoryPrecedencePolicy(),
            _LaterClock(),
        ).execute(second)
        history = await repository.history_authorized(
            memory_id,
            commit.scope.brain_id,
            commit.actor_id,
            commit.grant_id,
            NOW + timedelta(seconds=20),
        )
        assert history is not None
        selected = MemoryPrecedencePolicy().resolve(
            history.root,
            history.corrections,
            commit.scope,
            valid_at=NOW + timedelta(seconds=20),
            recorded_at=NOW + timedelta(seconds=20),
        )
    finally:
        await store.close()

    assert result.source_assertion_id == OPERATION_ID
    assert tuple(item.status for item in history.corrections) == (
        MemoryStatus.SUPERSEDED,
        MemoryStatus.ACTIVE,
    )
    assert history.corrections[0].recorded_to == NOW + timedelta(seconds=20)
    assert selected.assertion_id == SECOND_OPERATION_ID


def _store(tmp_path: Path) -> tuple[SqliteCoreStore, Path]:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    return migrated_store(tmp_path), key_file


def _handler(
    store: SqliteCoreStore,
    repository: SqliteMemoryCorrectionRepository,
) -> CorrectMemoryHandler:
    return CorrectMemoryHandler(
        repository,
        SqliteMemoryCorrectionUnitOfWorkFactory(store),
        MemoryPrecedencePolicy(),
        _Clock(),
    )


def _command(
    commit: ConsolidationCommit,
    memory_id: str,
    *,
    scope: MemoryScope | None = None,
    evidence_ids: tuple[str, ...] = (),
) -> CorrectMemoryCommand:
    return CorrectMemoryCommand(
        OPERATION_ID,
        commit.actor_id,
        commit.grant_id,
        commit.scope.brain_id,
        CORRELATION_ID,
        CAUSATION_ID,
        memory_id,
        1,
        "Projection rebuilds do not use immutable shadow generations.",
        scope or commit.scope,
        NOW,
        None,
        "user_correction",
        evidence_ids,
        NOW + timedelta(seconds=5),
        NOW + timedelta(minutes=1),
    )
