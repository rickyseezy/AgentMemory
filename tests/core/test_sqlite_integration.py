"""Real Alembic/SQLite repository, UoW, and readiness integration tests."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.operations.adapters.outbound.readiness_status import SqliteReadinessStatusQuery
from agentmemory.operations.adapters.outbound.sqlite_checks import (
    SqliteActiveBrainResolver,
    SqliteReadinessChecks,
    SqliteSemanticSmokeStore,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import (
    SqliteCoreUnitOfWork,
    SqliteUnitOfWorkFactory,
)
from agentmemory.operations.application.commands.active_release import (
    ActiveReleaseTransactionHandler,
)
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.domain.bootstrap import BootstrapDisposition
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from tests.core.support import (
    BRAIN_ID,
    FixedClock,
    active_pointer,
    binding,
    bootstrap_request,
    digest,
    migrated_store,
    receipt,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


async def _bootstrap(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_real_migration_and_bootstrap_are_atomic_and_idempotent(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        handler = BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock()))
        first = await handler.execute(bootstrap_request())
        second = await handler.execute(bootstrap_request("bootstrap-retry"))
        assert first.disposition is BootstrapDisposition.CREATED
        assert second.disposition is BootstrapDisposition.ALREADY_INITIALIZED
        async with store.engine.connect() as connection:
            assert (await connection.execute(text("SELECT COUNT(*) FROM brains"))).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM principals"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM scope_grants"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM audit_events"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one() == "0001_pf001_core"
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_bootstrap_conflict_and_uncommitted_uow_roll_back(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        changed = replace(bootstrap_request("conflict"), release_digest=digest("other-release"))
        with pytest.raises(OperationError) as raised:
            await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
                changed
            )
        assert raised.value.code is ErrorCode.CONFLICT

        unit_of_work = SqliteCoreUnitOfWork(store, FixedClock())
        async with unit_of_work:
            await unit_of_work.receipts.add(receipt())
        assert await SqliteReadinessStatusQuery(store).latest() is None
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_receipt_repository_is_idempotent_and_status_detects_corruption(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        value = receipt()
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(value)
            await unit_of_work.receipts.add(value)
            await unit_of_work.commit()
        assert await SqliteReadinessStatusQuery(store).latest() == value
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE readiness_receipts SET record_json = record_json || ' '")
            )
        with pytest.raises(OperationError) as raised:
            await SqliteReadinessStatusQuery(store).latest()
        assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_release_stage_commit_and_exact_mirror_are_durable_and_idempotent(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        readiness_receipt = receipt()
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(readiness_receipt)
            await unit_of_work.commit()
        pointer = active_pointer(readiness_receipt)
        handler = ActiveReleaseTransactionHandler(factory)
        first = await handler.stage(readiness_receipt.binding.operation_id, pointer)
        replay = await handler.stage(readiness_receipt.binding.operation_id, pointer)
        assert not first.already_staged
        assert replay.already_staged
        assert replay.stage_digest == first.stage_digest
        assert (
            await handler.commit(
                readiness_receipt.binding.operation_id,
                first.stage_digest,
                pointer,
            )
            == pointer.pointer_digest
        )
        assert (
            await handler.commit(
                readiness_receipt.binding.operation_id,
                first.stage_digest,
                pointer,
            )
            == pointer.pointer_digest
        )
        assert await handler.matches(pointer)
        async with store.engine.connect() as connection:
            stage = (
                await connection.execute(
                    text(
                        "SELECT state, pointer_digest FROM active_release_stages "
                        "WHERE operation_id = :operation_id"
                    ),
                    {"operation_id": readiness_receipt.binding.operation_id.value},
                )
            ).one()
            mirror = (
                await connection.execute(
                    text(
                        "SELECT active_release_digest, active_data_generation "
                        "FROM installation_state "
                        "WHERE singleton_key = 'local'"
                    )
                )
            ).one()
        assert stage[0] == "committed"
        assert stage[1].hex() == pointer.pointer_digest.value
        assert mirror[0].hex() == pointer.pointer_digest.value
        assert mirror[1] == pointer.generation_id.value
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_release_rejects_missing_readiness_wrong_stage_and_mirror_tamper(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        pointer = active_pointer()
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        handler = ActiveReleaseTransactionHandler(factory)
        with pytest.raises(OperationError) as missing:
            await handler.stage(binding().operation_id, pointer)
        assert missing.value.code is ErrorCode.CONFLICT
        readiness_receipt = receipt()
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(readiness_receipt)
            await unit_of_work.commit()
        stage = await handler.stage(readiness_receipt.binding.operation_id, pointer)
        with pytest.raises(OperationError) as wrong_stage:
            await handler.commit(
                readiness_receipt.binding.operation_id,
                digest("wrong-stage"),
                pointer,
            )
        assert wrong_stage.value.code is ErrorCode.CONFLICT
        await handler.commit(readiness_receipt.binding.operation_id, stage.stage_digest, pointer)
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE active_release_pointers SET pointer_record_json = "
                    "pointer_record_json || ' ' WHERE singleton_key = 'local'"
                )
            )
        with pytest.raises(OperationError) as tampered:
            await handler.matches(pointer)
        assert tampered.value.code is ErrorCode.INTEGRITY_VIOLATION
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_release_rejects_missing_stage_foreign_binding_and_stage_equivocation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        readiness_receipt = receipt()
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(readiness_receipt)
            await unit_of_work.commit()
        handler = ActiveReleaseTransactionHandler(factory)
        pointer = active_pointer(readiness_receipt)
        with pytest.raises(OperationError) as absent:
            await handler.commit(
                readiness_receipt.binding.operation_id,
                digest("unstaged"),
                pointer,
            )
        assert absent.value.code is ErrorCode.CONFLICT
        with pytest.raises(OperationError) as foreign_installation:
            await handler.stage(
                readiness_receipt.binding.operation_id,
                active_pointer(
                    readiness_receipt,
                    installation_id="018f0000-0000-7000-8000-000000000099",
                ),
            )
        assert foreign_installation.value.code is ErrorCode.CONFLICT
        with pytest.raises(OperationError) as foreign_release:
            await handler.stage(
                readiness_receipt.binding.operation_id,
                active_pointer(readiness_receipt, release_id="v2.0.0"),
            )
        assert foreign_release.value.code is ErrorCode.CONFLICT
        await handler.stage(readiness_receipt.binding.operation_id, pointer)
        with pytest.raises(OperationError) as equivocation:
            await handler.stage(
                readiness_receipt.binding.operation_id,
                active_pointer(readiness_receipt, resource_inventory_version=10),
            )
        assert equivocation.value.code is ErrorCode.CONFLICT
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_release_rejects_rollback_and_broken_redundant_mirrors(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        first_receipt = receipt()
        second_receipt = receipt(binding("install-0002"))
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(first_receipt)
            await unit_of_work.receipts.add(second_receipt)
            await unit_of_work.commit()
        handler = ActiveReleaseTransactionHandler(factory)
        pointer = active_pointer(first_receipt)
        stage = await handler.stage(first_receipt.binding.operation_id, pointer)
        await handler.commit(first_receipt.binding.operation_id, stage.stage_digest, pointer)
        with pytest.raises(OperationError) as rollback:
            await handler.stage(
                second_receipt.binding.operation_id,
                active_pointer(second_receipt, release_sequence=6),
            )
        assert rollback.value.code is ErrorCode.CONFLICT
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE installation_state SET active_release_digest = :digest "
                    "WHERE singleton_key = 'local'"
                ),
                {"digest": bytes.fromhex(digest("corrupt-mirror").value)},
            )
        with pytest.raises(OperationError) as disagreement:
            await handler.matches(pointer)
        assert disagreement.value.code is ErrorCode.INTEGRITY_VIOLATION
        async with store.engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM installation_state WHERE singleton_key = 'local'")
            )
        with pytest.raises(OperationError) as absent:
            await handler.matches(pointer)
        assert absent.value.code is ErrorCode.INTEGRITY_VIOLATION
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_release_commit_rolls_back_when_installation_mirror_disappears(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        readiness_receipt = receipt()
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(readiness_receipt)
            await unit_of_work.commit()
        handler = ActiveReleaseTransactionHandler(factory)
        pointer = active_pointer(readiness_receipt)
        stage = await handler.stage(readiness_receipt.binding.operation_id, pointer)
        async with store.engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM installation_state WHERE singleton_key = 'local'")
            )
        with pytest.raises(OperationError) as raised:
            await handler.commit(
                readiness_receipt.binding.operation_id,
                stage.stage_digest,
                pointer,
            )
        assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM active_release_pointers"))
            ).scalar_one() == 0
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_release_rejects_non_object_and_structurally_inconsistent_pointer_mirror(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        readiness_receipt = receipt()
        factory = SqliteUnitOfWorkFactory(store, FixedClock())
        async with factory() as unit_of_work:
            await unit_of_work.receipts.add(readiness_receipt)
            await unit_of_work.commit()
        handler = ActiveReleaseTransactionHandler(factory)
        pointer = active_pointer(readiness_receipt)
        stage = await handler.stage(readiness_receipt.binding.operation_id, pointer)
        await handler.commit(readiness_receipt.binding.operation_id, stage.stage_digest, pointer)
        for statement in (
            "UPDATE active_release_pointers SET pointer_record_json = '[]'",
            "UPDATE active_release_pointers SET pointer_record_json = :record, "
            "release_sequence = '999'",
        ):
            async with store.engine.begin() as connection:
                parameters = {
                    "record": json.dumps(
                        pointer.record(),
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                }
                await connection.execute(text(statement), parameters)
            with pytest.raises(OperationError) as raised:
                await handler.matches(pointer)
            assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_every_concrete_sqlite_readiness_capability_executes_live(tmp_path: Path) -> None:
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    state.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    store = migrated_store(state)
    try:
        await _bootstrap(store)
        checks = SqliteReadinessChecks(store, FixedClock(), state, artifacts)
        readiness_binding = binding()
        assert (await checks.sqlite_integrity(readiness_binding)).startswith("sqlite:")
        assert await checks.migration_head(readiness_binding) == "alembic:0001_pf001_core"
        assert await checks.writable_volumes(readiness_binding) == "state:durable;artifacts:durable"
        assert (await checks.audit_append(readiness_binding)).startswith("audit:")
        assert (await checks.audit_append(readiness_binding)).startswith("audit:")
        assert (await checks.deletion_guard(readiness_binding)).endswith(":excluded")
        assert await checks.expired_lease_recovery(readiness_binding) == (
            "expired_lease:queued:attempt_2"
        )
        assert (await SqliteActiveBrainResolver(store).get()).value == BRAIN_ID
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_semantic_canonical_write_is_idempotent_conflict_safe_and_cleaned(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await _bootstrap(store)
        canonical = SqliteSemanticSmokeStore(store, FixedClock())
        readiness_binding = binding()
        first = await canonical.write(readiness_binding, "canary", "persistent memory")
        second = await canonical.write(readiness_binding, "canary", "persistent memory")
        assert first == second
        with pytest.raises(OperationError) as raised:
            await canonical.write(readiness_binding, "canary", "different")
        assert raised.value.code is ErrorCode.CONFLICT
        await canonical.delete(readiness_binding, "canary")
        async with store.engine.connect() as connection:
            statements = (
                "SELECT COUNT(*) FROM agent_events",
                "SELECT COUNT(*) FROM outbox_messages",
                "SELECT COUNT(*) FROM smoke_memories",
            )
            for statement in statements:
                count = (await connection.execute(text(statement))).scalar_one()
                assert count == 0
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_policy_observation_reports_live_pragmas(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        observation = await store.observe_and_enforce_policy()
        assert observation.journal_mode == "wal"
        assert observation.synchronous == 2
        assert observation.foreign_keys == 1
        assert observation.busy_timeout >= 5_000
        assert observation.secure_delete == 1
        assert observation.trusted_schema == 0
        async with store.engine.connect() as first, store.engine.connect() as second:
            for connection in (first, second):
                assert (await connection.exec_driver_sql("PRAGMA foreign_keys")).scalar_one() == 1
                assert (await connection.exec_driver_sql("PRAGMA synchronous")).scalar_one() == 2
                assert (await connection.exec_driver_sql("PRAGMA trusted_schema")).scalar_one() == 0
    finally:
        await store.close()
