# pyright: reportPrivateUsage=false
"""MEM-001 SQLite tamper, transaction, and bounded-query boundary tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.envelope_crypto import SqliteWrappedBrainKeyProvider
from agentmemory.ingestion.adapters.outbound.sqlite_schema_evolution import (
    SqliteCanonicalEventSourceReader,
)
from agentmemory.memory.adapters.outbound import sqlite_consolidation as sqlite_memory
from agentmemory.memory.adapters.outbound.sqlite_consolidation import (
    SqliteMemoryConsolidationReceiptQuery,
    SqliteMemoryConsolidationUnitOfWorkFactory,
    SqliteTaskEvidenceQuery,
)
from agentmemory.memory.domain.consolidation import (
    ConsolidationCommit,
    MemoryCandidateBatch,
    MemoryPromotionPolicy,
    MemoryScope,
    consolidation_idempotency_key,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import BRAIN_ID, NOW, PROJECT_ID, REPOSITORY_ID
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority
from tests.memory.test_mem001_consolidation_boundaries import _commit
from tests.memory.test_mem001_consolidation_domain import (
    EVENT_TWO,
    TASK_ID,
    candidate_document,
    extractor,
)
from tests.memory.test_mem001_sqlite_consolidation import _capture_task_events

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.engine import RowMapping

    from agentmemory.memory.domain.consolidation import JsonValue
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


def _scope() -> MemoryScope:
    return MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)


async def _database_commit(store: SqliteCoreStore, key_file: Path) -> ConsolidationCommit:
    query = SqliteTaskEvidenceQuery(
        store,
        SqliteCanonicalEventSourceReader(
            store,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        ),
    )
    source = await query.load(TASK_ID, EVENT_TWO, _scope(), 256, 1024 * 1024)
    assert source is not None
    identity = extractor()
    candidate = MemoryCandidateBatch.decode(
        candidate_document(source),
        source.extractor_input_sha256,
    ).candidates[0]
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    memory = candidate.activate(decision, source, identity, NOW + timedelta(seconds=2))
    original = _commit()
    return replace(
        original,
        idempotency_key=consolidation_idempotency_key(
            TASK_ID,
            source.watermark_sha256,
            identity.fingerprint,
        ),
        evidence_watermark_sha256=source.watermark_sha256,
        extractor_input_sha256=source.extractor_input_sha256,
        memories=(memory,),
    )


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"data": {}, "dataref": {}},
        {"dataref": "not-an-object"},
        {"dataref": {"uri": "cas://sha256/a", "content_sha256": "a", "size_bytes": 1}},
        {
            "content_sha256": "a" * 64,
            "dataref": {
                "uri": f"cas://sha256/{'a' * 64}",
                "content_sha256": "a" * 64,
                "size_bytes": 0,
            },
        },
        {
            "content_sha256": "b" * 64,
            "dataref": {
                "uri": f"cas://sha256/{'a' * 64}",
                "content_sha256": "a" * 64,
                "size_bytes": 1,
            },
        },
        {
            "content_sha256": "a" * 64,
            "dataref": {
                "uri": f"cas://sha256/{'a' * 64}",
                "content_sha256": "a" * 64,
                "size_bytes": 1,
                "unknown": True,
            },
        },
    ],
)
def test_event_payload_rejects_ambiguous_or_unbound_artifact_references(
    document: dict[str, JsonValue],
) -> None:
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._event_payload(document)


def test_event_payload_accepts_hash_bound_inline_and_artifact_metadata() -> None:
    assert sqlite_memory._event_payload({"data": {"a": 1}}) == b'{"a":1}'
    digest = "a" * 64
    reference: dict[str, JsonValue] = {
        "content_sha256": digest,
        "dataref": {
            "uri": f"cas://sha256/{digest}",
            "content_sha256": digest,
            "size_bytes": 42,
        },
    }
    assert json.loads(sqlite_memory._event_payload(reference)) == {"dataref": reference["dataref"]}


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b'{"a":1,"a":2}',
        b'{"value":NaN}',
    ],
)
def test_strict_persisted_json_rejects_invalid_duplicate_nonfinite_or_nonobject(raw: bytes) -> None:
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._strict_object(raw)


def test_sqlite_mapping_helpers_reject_type_confusion_and_accept_driver_binary_types() -> None:
    assert sqlite_memory._bytes(b"a") == b"a"
    assert sqlite_memory._bytes(bytearray(b"b")) == b"b"
    assert sqlite_memory._bytes(memoryview(b"c")) == b"c"
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._bytes("not-binary")
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._string({"field": 1}, "field")
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._integer({"field": True}, "field")
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._canonical_json({"invalid": {1, 2}})


def test_persisted_receipt_authentication_rejects_shape_hash_and_canonicalization_tampering() -> (
    None
):
    result = _commit().result
    result_json = sqlite_memory._result_json(result)
    row: dict[str, object] = {
        "result_json": result_json,
        "result_sha256": bytes.fromhex(result.result_sha256),
    }
    assert sqlite_memory._result(cast("RowMapping", row), result.idempotency_key) == result

    malformed = dict(row)
    malformed["result_json"] = result_json.replace('"memory_ids":[', '"memory_ids":"')
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._result(cast("RowMapping", malformed), result.idempotency_key)
    missing = dict(row)
    missing["result_json"] = "{}"
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._result(cast("RowMapping", missing), result.idempotency_key)
    wrong_hash = dict(row)
    wrong_hash["result_sha256"] = b"x" * 32
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._result(cast("RowMapping", wrong_hash), result.idempotency_key)
    noncanonical = dict(row)
    noncanonical["result_json"] = result_json.replace("{", "{ ", 1)
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._result(cast("RowMapping", noncanonical), result.idempotency_key)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_query_enforces_item_byte_and_terminal_scope_bounds(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        keys = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
        query = SqliteTaskEvidenceQuery(store, SqliteCanonicalEventSourceReader(store, keys))
        assert await query.load(TASK_ID, EVENT_TWO, _scope(), 256, 1024 * 1024) is None
        await _capture_task_events(store, key_file)
        for maximum_items, maximum_bytes in ((0, 1), (257, 1), (1, 0), (1, 1024 * 1024 + 1)):
            with pytest.raises(MemoryValidationError):
                await query.load(TASK_ID, EVENT_TWO, _scope(), maximum_items, maximum_bytes)
        with pytest.raises(MemoryValidationError) as count:
            await query.load(TASK_ID, EVENT_TWO, _scope(), 1, 1024 * 1024)
        assert count.value.code_for("evidence") == "count_exceeded"
        with pytest.raises(MemoryValidationError) as size:
            await query.load(TASK_ID, EVENT_TWO, _scope(), 256, 1)
        assert size.value.code_for("evidence") == "bytes_exceeded"
        other = MemoryScope(
            BRAIN_ID,
            PROJECT_ID,
            "018f0000-0000-7000-8000-000000000021",
            None,
        )
        assert await query.load(TASK_ID, EVENT_TWO, other, 256, 1024 * 1024) is None
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unit_of_work_rolls_back_uncommitted_stages_and_rejects_divergent_identity(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        factory = SqliteMemoryConsolidationUnitOfWorkFactory(store)
        commit = await _database_commit(store, key_file)

        class ForcedRollbackError(RuntimeError):
            pass

        async def force_rollback() -> None:
            async with factory() as unit:
                await unit.repository.add(commit)
                raise ForcedRollbackError

        with pytest.raises(ForcedRollbackError):
            await force_rollback()
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM memory_consolidations"))
            ).scalar_one() == 0

        async with factory() as unit:
            await unit.repository.add(commit)
            await unit.repository.add(commit)
            divergent = replace(commit, memories=())
            with pytest.raises(MemoryConflictError):
                await unit.repository.add(divergent)
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM memory_consolidations"))
            ).scalar_one() == 0
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unit_of_work_commits_once_and_receipt_query_rejects_invalid_digest(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        factory = SqliteMemoryConsolidationUnitOfWorkFactory(store)
        commit = await _database_commit(store, key_file)
        unit = factory()
        async with unit:
            await unit.repository.add(commit)
            await unit.commit()
            with pytest.raises(MemoryIntegrityError):
                await unit.commit()
        receipts = SqliteMemoryConsolidationReceiptQuery(store)
        assert await receipts.get(commit.idempotency_key) == commit.result
        for invalid in ("zz", "a", "A" * 64, "0" * 64):
            with pytest.raises(MemoryValidationError):
                await receipts.get(invalid)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_unopened_unit_of_work_fails_closed() -> None:
    class Store:
        pass

    unit = sqlite_memory._SqliteMemoryConsolidationUnitOfWork(cast("SqliteCoreStore", Store()))
    with pytest.raises(MemoryIntegrityError):
        await unit.commit()
    with pytest.raises(MemoryIntegrityError):
        await unit.__aexit__(None, None, None)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_tampered_receipt_is_never_returned_as_idempotency_success(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        commit = await _database_commit(store, key_file)
        async with SqliteMemoryConsolidationUnitOfWorkFactory(store)() as unit:
            await unit.repository.add(commit)
            await unit.commit()
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE memory_consolidations SET result_sha256=:digest "
                    "WHERE idempotency_key=:key"
                ),
                {"digest": b"x" * 32, "key": bytes.fromhex(commit.idempotency_key)},
            )
        with pytest.raises(MemoryIntegrityError):
            await SqliteMemoryConsolidationReceiptQuery(store).get(commit.idempotency_key)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_task_evidence_rejects_decrypted_envelope_coordinate_tampering(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        reader = SqliteCanonicalEventSourceReader(
            store,
            SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
        )
        raw = await reader.read("018f0000-0000-7000-8000-000000000301")
        async with store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text("SELECT * FROM event_task_lineage ORDER BY event_id LIMIT 1")
                    )
                )
                .mappings()
                .one()
            )
        tampered = raw.replace(BRAIN_ID.encode(), b"018f0000-0000-7000-8000-000000000099")
        forged_row = dict(row)
        forged_row["canonical_event_sha256"] = hashlib.sha256(tampered).digest()
        with pytest.raises(MemoryIntegrityError):
            sqlite_memory._task_evidence(
                cast("RowMapping", forged_row), tampered, TASK_ID, _scope()
            )
    finally:
        await store.close()


def test_microsecond_conversion_preserves_required_precision() -> None:
    assert sqlite_memory._micros(NOW + timedelta(microseconds=7)) - sqlite_memory._micros(NOW) == 7
