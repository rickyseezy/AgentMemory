"""MEM-006 SQLite memory, revision, authorization, and event integration tests."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, cast
from uuid import UUID

import pytest
from sqlalchemy import text

from agentmemory.identity.adapters.outbound.sqlite_checkout_observation import (
    SqliteCheckoutObservationUnitOfWorkFactory,
)
from agentmemory.identity.adapters.outbound.uuid7_identity import SystemUuid7IdentityGenerator
from agentmemory.identity.application.commands.observe_checkout import ObserveCheckoutHandler
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.retrieval.adapters.outbound.sqlite_briefing import (
    SqliteCodeRevisionQuery,
    SqliteContextInjectionRepository,
    SqliteMemoryBriefingRepository,
)
from agentmemory.retrieval.adapters.outbound.sqlite_briefing import (
    _memory_item as map_memory_item,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.retrieval.application.start_session_briefing import (
    DeterministicBriefingRetrievalPipeline,
    StartSessionBriefingHandler,
)
from agentmemory.retrieval.domain.continuity import (
    BriefingBudget,
    BriefingStatus,
    ContextInjectedEvent,
    ProcedureEnvironment,
    StartSessionBriefingQuery,
)
from agentmemory.retrieval.domain.errors import (
    RetrievalAuthorizationError,
    RetrievalConflictError,
    RetrievalDependencyError,
    RetrievalIntegrityError,
    RetrievalValidationError,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.identity.test_checkout_observation_sqlite import (
    _command as checkout_command,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _seed_roots as seed_checkout_roots,  # pyright: ignore[reportPrivateUsage]
)
from tests.memory.test_mem001_consolidation_domain import NOW
from tests.memory.test_mem002_sqlite_repository import (
    _persist_memory,  # pyright: ignore[reportPrivateUsage]
)
from tests.retrieval.support import (
    FakeCodeRevisionQuery,
    FakeContinuityRepository,
    FakeProcedureRepository,
)
from tests.retrieval.support import (
    scope as default_scope,
)

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.engine import RowMapping

    from agentmemory.memory.domain.consolidation import ConsolidationCommit

EVENT_ID = "018f0000-0000-7000-8000-000000000721"
RETRY_EVENT_ID = "018f0000-0000-7000-8000-000000000723"
OPERATION_ID = "018f0000-0000-7000-8000-000000000722"
COLLISION_OPERATION_ID = "018f0000-0000-7000-8000-000000000724"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_memory_source_and_context_event_are_authorized_atomic_and_content_free(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        authorized = _scope(commit)
        identities = iter((UUID(EVENT_ID), UUID(RETRY_EVENT_ID)))
        handler = StartSessionBriefingHandler(
            FakeContinuityRepository(()),
            SqliteMemoryBriefingRepository(store.engine, FixedClock(NOW + timedelta(seconds=10))),
            FakeCodeRevisionQuery(),
            DeterministicBriefingRetrievalPipeline.production(),
            FakeProcedureRepository(()),
            SqliteContextInjectionRepository(store.engine),
            lambda: next(identities),
        )
        query = _query(authorized)

        first = await handler.execute(query)
        replay = await handler.execute(query)

        async with store.engine.connect() as connection:
            receipt = (
                await connection.execute(
                    text(
                        "SELECT selected_json,status,event_sha256 FROM session_briefing_receipts "
                        "WHERE operation_id=:operation"
                    ),
                    {"operation": OPERATION_ID},
                )
            ).one()
            event = (
                await connection.execute(
                    text(
                        "SELECT event_type,event_json FROM domain_events "
                        "WHERE aggregate_type='session_briefing'"
                    )
                )
            ).one()
            receipt_count = int(
                (
                    await connection.execute(text("SELECT COUNT(*) FROM session_briefing_receipts"))
                ).scalar_one()
            )
    finally:
        await store.close()

    assert first == replay
    assert first.status is BriefingStatus.READY
    assert first.context_event_id == EVENT_ID
    assert [item.source_memory_id for item in first.items] == [commit.memories[0].memory_id]
    assert receipt_count == 1
    assert receipt[1] == "ready"
    assert len(receipt[2]) == 32
    assert event[0] == "ContextInjected"
    selected = json.loads(str(receipt[0]))
    event_document = json.loads(str(event[1]))
    assert selected[0]["item_id"].startswith("memory:")
    assert "statement" not in str(receipt[0]).lower()
    assert "content" not in event_document


@pytest.mark.asyncio
@pytest.mark.integration
async def test_divergent_briefing_operation_reuse_conflicts(tmp_path: Path) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        handler = StartSessionBriefingHandler(
            FakeContinuityRepository(()),
            SqliteMemoryBriefingRepository(store.engine, FixedClock(NOW + timedelta(seconds=10))),
            FakeCodeRevisionQuery(),
            DeterministicBriefingRetrievalPipeline.production(),
            FakeProcedureRepository(()),
            SqliteContextInjectionRepository(store.engine),
            lambda: UUID(EVENT_ID),
        )
        query = _query(_scope(commit))
        await handler.execute(query)

        with pytest.raises(RetrievalConflictError):
            await handler.execute(replace(query, budget=BriefingBudget(1_300, 12, 20_480)))
        with pytest.raises(RetrievalConflictError):
            await handler.execute(replace(query, operation_id=COLLISION_OPERATION_ID))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_code_revision_query_reads_only_latest_explicit_checkout(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_checkout_roots(store)
        observed = await ObserveCheckoutHandler(
            SqliteCheckoutObservationUnitOfWorkFactory(store, FixedClock()),
            SystemUuid7IdentityGenerator(),
        ).execute(checkout_command("mem006-observe", "workspace"))
        base = _checkout_scope(observed.checkout_id.value)

        revisions = await SqliteCodeRevisionQuery(store.engine, FixedClock()).current_revisions(
            base
        )
    finally:
        await store.close()

    assert len(revisions) == 1
    assert revisions[0].checkout_id == observed.checkout_id.value
    assert revisions[0].branch_name == "main"
    assert revisions[0].commit_sha == "a" * 40


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.privacy
async def test_revoked_grant_hides_memory_and_blocks_context_event_atomically(
    tmp_path: Path,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        authorized = _scope(commit)
        clock = FixedClock(NOW + timedelta(seconds=10))
        memories = SqliteMemoryBriefingRepository(store.engine, clock)
        assert len(await memories.list_items(authorized, 10)) == 1
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE scope_grants SET valid_to=:revoked "
                    "WHERE brain_id=:brain AND principal_id=:principal"
                ),
                {
                    "brain": authorized.brain_id.value,
                    "principal": authorized.principal_id.value,
                    "revoked": round((NOW + timedelta(seconds=5)).timestamp() * 1_000_000),
                },
            )
        assert await memories.list_items(authorized, 10) == ()
        handler = StartSessionBriefingHandler(
            FakeContinuityRepository(()),
            memories,
            FakeCodeRevisionQuery(),
            DeterministicBriefingRetrievalPipeline.production(),
            FakeProcedureRepository(()),
            SqliteContextInjectionRepository(store.engine),
            lambda: UUID(EVENT_ID),
        )
        with pytest.raises(RetrievalAuthorizationError):
            await handler.execute(_query(authorized))
        async with store.engine.connect() as connection:
            receipt_count = int(
                (
                    await connection.execute(text("SELECT COUNT(*) FROM session_briefing_receipts"))
                ).scalar_one()
            )
    finally:
        await store.close()

    assert receipt_count == 0


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("content", "[]"),
        ("content", '{"extra":true,"statement":"value"}'),
        ("content", '{"statement":1}'),
        ("evidence", ""),
    ],
)
async def test_malformed_memory_projection_fails_closed(
    tmp_path: Path,
    mutation: str,
    value: str,
) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        async with store.engine.begin() as connection:
            if mutation == "evidence":
                await connection.execute(text("DELETE FROM memory_evidence"))
            elif mutation == "content":
                await connection.execute(
                    text("UPDATE memory_revisions SET content_json=:value"),
                    {"value": value},
                )
        repository = SqliteMemoryBriefingRepository(
            store.engine,
            FixedClock(NOW + timedelta(seconds=10)),
        )
        with pytest.raises(RetrievalIntegrityError):
            await repository.list_items(_scope(commit), 10)
    finally:
        await store.close()


@pytest.mark.parametrize(
    "provenance",
    ["[]", '{"extractor":[]}', '{"extractor":{}}'],
)
def test_malformed_memory_provenance_mapping_fails_closed(provenance: str) -> None:
    row: dict[str, object] = {
        "brain_id": "018f0000-0000-7000-8000-000000000004",
        "checkout_id": None,
        "classification": "internal",
        "content_json": '{"statement":"value"}',
        "current_revision": 1,
        "evidence_json": '["018f0000-0000-7000-8000-000000000101"]',
        "id": "018f0000-0000-7000-8000-000000000704",
        "memory_class": "decision",
        "project_id": "018f0000-0000-7000-8000-000000000010",
        "provenance_json": provenance,
        "recorded_from": round(NOW.timestamp() * 1_000_000),
        "repository_id": "018f0000-0000-7000-8000-000000000020",
        "source_task_id": "018f0000-0000-7000-8000-000000000703",
        "valid_from": round(NOW.timestamp() * 1_000_000),
    }
    with pytest.raises(RetrievalIntegrityError):
        map_memory_item(cast("RowMapping", row))


@pytest.mark.asyncio
async def test_briefing_sqlite_adapters_validate_bounds_scope_and_storage_failure(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    authorized = default_scope()
    memory = SqliteMemoryBriefingRepository(store.engine, FixedClock())
    revisions = SqliteCodeRevisionQuery(store.engine, FixedClock())
    recorder = SqliteContextInjectionRepository(store.engine)
    query = _query(authorized)
    briefing = DeterministicBriefingRetrievalPipeline.production().select(query, (), (), (), ())
    event = ContextInjectedEvent.create(EVENT_ID, query, briefing)

    with pytest.raises(RetrievalValidationError):
        await memory.list_items(authorized, 0)
    assert await revisions.current_revisions(authorized) == ()
    with pytest.raises(RetrievalAuthorizationError):
        await recorder.record(_scope_mismatch(), event)

    await store.close()
    (tmp_path / "agentmemory.sqlite3").unlink()
    with pytest.raises(RetrievalDependencyError):
        await memory.list_items(authorized, 10)
    with pytest.raises(RetrievalDependencyError):
        await revisions.current_revisions(_checkout_scope(EVENT_ID))
    with pytest.raises(RetrievalDependencyError):
        await recorder.record(authorized, event)
    await store.close()


def _scope(commit: ConsolidationCommit) -> AuthorizedScope:
    checkout_ids = () if commit.scope.checkout_id is None else (StableId(commit.scope.checkout_id),)
    return AuthorizedScope.create(
        brain_id=StableId(commit.scope.brain_id),
        principal_id=StableId(commit.actor_id),
        role=RetrievalRole.OWNER,
        mode=RetrievalScopeMode.CURRENT,
        members=(
            ScopeMember(
                StableId(commit.scope.project_id),
                (StableId(commit.scope.repository_id),),
                checkout_ids,
            ),
        ),
        classification_ceiling=Classification.LOCAL_ONLY,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action="memory.recall",
        purpose="interactive_recall",
    )


def _checkout_scope(checkout_id: str) -> AuthorizedScope:
    authorized = default_scope()
    member = authorized.members[0]
    return replace(
        authorized,
        members=(
            ScopeMember(
                member.project_id,
                member.repository_ids,
                (StableId(checkout_id),),
            ),
        ),
    )


def _scope_mismatch() -> AuthorizedScope:
    authorized = default_scope()
    return AuthorizedScope.create(
        brain_id=authorized.brain_id,
        principal_id=StableId("018f0000-0000-7000-8000-000000000725"),
        role=authorized.role,
        mode=authorized.mode,
        members=authorized.members,
        classification_ceiling=authorized.classification_ceiling,
        temporal_scope=authorized.temporal_scope,
        grant_version=authorized.grant_version,
        policy_version=authorized.policy_version,
        security_epoch=authorized.security_epoch,
        action=authorized.action,
        purpose=authorized.purpose,
    )


def _query(authorized: AuthorizedScope) -> StartSessionBriefingQuery:
    return StartSessionBriefingQuery(
        authorized,
        BriefingBudget(),
        ProcedureEnvironment("darwin", ("mcp",)),
        OPERATION_ID,
        NOW + timedelta(seconds=10),
    )
