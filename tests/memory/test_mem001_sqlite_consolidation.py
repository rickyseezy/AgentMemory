"""MEM-001 indexed task evidence and atomic SQLite persistence tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAgentEventUnitOfWorkFactory,
)
from agentmemory.ingestion.adapters.outbound.sqlite_schema_evolution import (
    SqliteCanonicalEventSourceReader,
)
from agentmemory.ingestion.application.append_agent_event import (
    AppendAgentEventCommand,
    AppendAgentEventHandler,
)
from agentmemory.ingestion.domain.agent_event import (
    AgentEventData,
    CaptureCapability,
    EventFamily,
    ResolvedAgentEventIdentity,
)
from agentmemory.ingestion.domain.capture import AdmittedAgentEvent
from agentmemory.memory.adapters.outbound.sqlite_consolidation import (
    SqliteMemoryConsolidationAccessPolicy,
    SqliteMemoryConsolidationReceiptQuery,
    SqliteMemoryConsolidationUnitOfWorkFactory,
    SqliteTaskEvidenceQuery,
)
from agentmemory.memory.application.consolidate_task import (
    ConsolidateTaskCommand,
    ConsolidateTaskHandler,
)
from agentmemory.memory.domain.consolidation import (
    ExtractorResponse,
    MemoryPromotionPolicy,
    MemoryScope,
)
from agentmemory.memory.domain.errors import MemoryAuthorizationError, MemoryIntegrityError
from tests.core.support import GRANT_ID, OWNER_ID, FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    NOW,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    event,
    privacy_result,
)
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority
from tests.memory.test_mem001_consolidation_domain import (
    EVENT_ONE,
    EVENT_TWO,
    TASK_ID,
    candidate_document,
    extractor,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.memory.domain.consolidation import ExtractorRequest
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


@dataclass(slots=True)
class DeterministicExtractor:
    output: bytes
    calls: int = 0

    async def extract(self, request: ExtractorRequest) -> ExtractorResponse:
        self.calls += 1
        return ExtractorResponse(
            request.operation_id,
            request.idempotency_key,
            request.task_id,
            request.input_sha256,
            request.extractor,
            self.output,
            hashlib.sha256(self.output).hexdigest(),
        )


def _task_event(
    event_id: str,
    event_type: EventFamily,
    sequence: int,
    payload: bytes,
) -> AgentEvent:
    source = event(event_id=event_id, sequence=sequence)
    return replace(
        source,
        event_type=event_type,
        subject=f"task/{TASK_ID}",
        occurred_at=NOW + timedelta(seconds=sequence),
        dataschema=event_type.dataschema,
        provenance=replace(source.provenance, task_id=TASK_ID),
        capture_capabilities=(CaptureCapability.TASK_LIFECYCLE,),
        payload=AgentEventData(payload, hashlib.sha256(payload).hexdigest()),
    )


async def _capture_task_events(store: SqliteCoreStore, key_file: Path) -> None:
    keys = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
    appender = AppendAgentEventHandler(
        CanonicalAgentEventEncoder(),
        AesGcmAgentEventEncryptor(keys),
        SqliteAgentEventUnitOfWorkFactory(store, FixedClock(NOW)),
    )
    identity = ResolvedAgentEventIdentity(
        BRAIN_ID,
        PRINCIPAL_ID,
        PROJECT_ID,
        REPOSITORY_ID,
        None,
    )
    events = (
        _task_event(
            EVENT_ONE,
            EventFamily.TASK_CHECKPOINTED,
            1,
            b'{"summary":"first checkpoint"}',
        ),
        _task_event(
            EVENT_TWO,
            EventFamily.TASK_COMPLETED,
            2,
            b'{"summary":"projection rebuild completed"}',
        ),
    )
    for item in events:
        if item.payload is None:
            raise AssertionError
        admitted = AdmittedAgentEvent(
            item,
            identity,
            NOW + timedelta(seconds=10),
            0,
            privacy_result(item.payload.value),
        )
        await appender.execute(AppendAgentEventCommand(admitted))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_task_lineage_query_and_consolidation_commit_are_atomic_and_idempotent(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    keys = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
    reader = SqliteCanonicalEventSourceReader(store, keys)
    scope = MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        query = SqliteTaskEvidenceQuery(store, reader)
        source = await query.load(TASK_ID, EVENT_TWO, scope, 256, 1024 * 1024)
        assert source is not None
        assert tuple(item.event_id for item in source.evidence) == (EVENT_ONE, EVENT_TWO)
        original = await reader.read(EVENT_TWO)

        extractor_adapter = DeterministicExtractor(candidate_document(source))
        receipts = SqliteMemoryConsolidationReceiptQuery(store)
        use_case = ConsolidateTaskHandler(
            query,
            extractor_adapter,
            SqliteMemoryConsolidationAccessPolicy(store),
            receipts,
            SqliteMemoryConsolidationUnitOfWorkFactory(store),
            MemoryPromotionPolicy.production(),
            FixedClock(NOW + timedelta(seconds=20)),
        )
        request = ConsolidateTaskCommand(
            "mem001-sqlite",
            OWNER_ID,
            GRANT_ID,
            "018f0000-0000-7000-8000-000000000401",
            "018f0000-0000-7000-8000-000000000402",
            TASK_ID,
            EVENT_TWO,
            scope,
            extractor(),
            NOW + timedelta(seconds=19),
            NOW + timedelta(minutes=5),
        )
        first = await use_case.execute(request)
        retry = await use_case.execute(request)
        assert retry == first
        assert first.promoted == 1
        assert extractor_adapter.calls == 1
        assert await reader.read(EVENT_TWO) == original

        async with store.engine.connect() as connection:
            counts = {
                table: (
                    await connection.execute(text(f"SELECT COUNT(*) FROM {table}"))  # noqa: S608
                ).scalar_one()
                for table in (
                    "agent_events",
                    "event_task_lineage",
                    "memory_consolidations",
                    "memories",
                    "memory_revisions",
                    "memory_evidence",
                    "memory_candidate_rejections",
                )
            }
            assert counts == {
                "agent_events": 2,
                "event_task_lineage": 2,
                "memory_consolidations": 1,
                "memories": 1,
                "memory_revisions": 1,
                "memory_evidence": 2,
                "memory_candidate_rejections": 0,
            }
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM domain_events WHERE aggregate_type='memory'")
                )
            ).scalar_one() == 1
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM outbox_messages WHERE topic='memory.consolidated.v1'"
                    )
                )
            ).scalar_one() == 1
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_events WHERE action='memory.task_consolidated'"
                    )
                )
            ).scalar_one() == 1
            result = await receipts.get(first.idempotency_key)
            assert result == first
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_task_evidence_query_fails_closed_on_lineage_tampering(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE event_task_lineage SET canonical_event_sha256=:digest "
                    "WHERE event_id=:event_id"
                ),
                {"digest": b"x" * 32, "event_id": EVENT_ONE},
            )
        query = SqliteTaskEvidenceQuery(
            store,
            SqliteCanonicalEventSourceReader(
                store,
                SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
            ),
        )
        with pytest.raises(MemoryIntegrityError):
            await query.load(
                TASK_ID,
                EVENT_TWO,
                MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
                256,
                1024 * 1024,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_rejected_claim_persists_only_hashes_and_content_free_reason(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        scope = MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)
        query = SqliteTaskEvidenceQuery(
            store,
            SqliteCanonicalEventSourceReader(
                store,
                SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)),
            ),
        )
        source = await query.load(TASK_ID, EVENT_TWO, scope, 256, 1024 * 1024)
        assert source is not None
        invented = "018f0000-0000-7000-8000-000000000399"
        use_case = ConsolidateTaskHandler(
            query,
            DeterministicExtractor(candidate_document(source, evidence_ids=[invented])),
            SqliteMemoryConsolidationAccessPolicy(store),
            SqliteMemoryConsolidationReceiptQuery(store),
            SqliteMemoryConsolidationUnitOfWorkFactory(store),
            MemoryPromotionPolicy.production(),
            FixedClock(NOW + timedelta(seconds=20)),
        )
        result = await use_case.execute(
            ConsolidateTaskCommand(
                "mem001-rejection",
                OWNER_ID,
                GRANT_ID,
                "018f0000-0000-7000-8000-000000000411",
                "018f0000-0000-7000-8000-000000000412",
                TASK_ID,
                EVENT_TWO,
                scope,
                extractor(),
                NOW + timedelta(seconds=19),
                NOW + timedelta(minutes=5),
            )
        )
        assert (result.promoted, result.rejected) == (0, 1)
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT candidate_key_sha256,content_hash,reason_code "
                        "FROM memory_candidate_rejections"
                    )
                )
            ).one()
            assert len(row.candidate_key_sha256) == 32
            assert len(row.content_hash) == 32
            assert row.reason_code == "unsupported_evidence"
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM memories"))
            ).scalar_one() == 0
            assert "Projection rebuilds" not in str(tuple(row))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_revoked_or_read_only_grant_denies_before_task_content_is_read(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await _capture_task_events(store, key_file)
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET role='reader' WHERE id=:grant"),
                {"grant": GRANT_ID},
            )

        class FailingReader:
            async def read(self, event_id: str) -> bytes:
                del event_id
                raise AssertionError

        query = SqliteTaskEvidenceQuery(store, FailingReader())
        source = MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)
        extractor_adapter = DeterministicExtractor(b"{}")
        use_case = ConsolidateTaskHandler(
            query,
            extractor_adapter,
            SqliteMemoryConsolidationAccessPolicy(store),
            SqliteMemoryConsolidationReceiptQuery(store),
            SqliteMemoryConsolidationUnitOfWorkFactory(store),
            MemoryPromotionPolicy.production(),
            FixedClock(NOW + timedelta(seconds=20)),
        )
        with pytest.raises(MemoryAuthorizationError):
            await use_case.execute(
                ConsolidateTaskCommand(
                    "mem001-forbidden",
                    OWNER_ID,
                    GRANT_ID,
                    "018f0000-0000-7000-8000-000000000421",
                    "018f0000-0000-7000-8000-000000000422",
                    TASK_ID,
                    EVENT_TWO,
                    source,
                    extractor(),
                    NOW + timedelta(seconds=19),
                    NOW + timedelta(minutes=5),
                )
            )
        assert extractor_adapter.calls == 0
    finally:
        await store.close()
