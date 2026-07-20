"""ADP-006 real encrypted canonical-event continuity integration tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.payload_reader import InlineOnlyPayloadReader
from agentmemory.ingestion.adapters.outbound.sqlite_capabilities import (
    SqliteAdapterCapabilityUnitOfWorkFactory,
    SystemIngestionIdentityGenerator,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAdapterCapabilityRegistry,
    SqliteAgentEventScopeResolver,
    SqliteAgentEventUnitOfWorkFactory,
)
from agentmemory.ingestion.adapters.outbound.sqlite_privacy import (
    SqliteCapturePolicyDecisionRepository,
    SqliteCapturePolicyRepository,
)
from agentmemory.ingestion.application.adapter_capabilities import (
    RegisterAgentAdapterCommand,
    RegisterAgentAdapterHandler,
)
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
from agentmemory.ingestion.application.capture_agent_event import CaptureAgentEventHandler
from agentmemory.ingestion.application.privacy import CapturePolicyPipeline
from agentmemory.ingestion.domain.adapter_capability import AdapterCapabilityManifest
from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.retrieval.adapters.outbound.sqlite_continuity import (
    SqliteContinuityReadRepository,
)
from agentmemory.retrieval.domain.continuity import ContinuityKind
from agentmemory.retrieval.domain.errors import RetrievalIntegrityError
from tests.core.support import FixedClock, bootstrap_request, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    CORRELATION_ID,
    DIGEST,
    EVENT_ID,
    NOW,
    ORDERING_KEY,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    SESSION_ID,
)
from tests.ingestion.capability_support import complete_availability
from tests.retrieval.support import scope

if TYPE_CHECKING:
    from pathlib import Path

_ITEMS = (
    ("fact-api", "fact", "The frontend consumes the user API."),
    ("decision-auth", "decision", "Keep auth in the shared client."),
    ("change-client", "change", "Updated the generated user client."),
    ("failure-timeout", "failure", "The integration test timed out."),
    ("next-contract", "next_step", "Verify against the contract fixture."),
)


def _descriptor() -> AdapterCapabilityManifest:
    return AdapterCapabilityManifest.create(
        adapter_id="agentmemory.claude-code",
        adapter_version="1.0.0",
        adapter_digest=DIGEST,
        schema_major=1,
        supported_families=(EventFamily.TASK_CHECKPOINTED,),
        evidence_availability=complete_availability(task_lifecycle=CaptureMethod.NATIVE),
    )


def _event() -> AgentEvent:
    payload = json.dumps(
        {
            "continuity": {
                "items": [
                    {"content": content, "kind": kind, "semantic_id": semantic_id}
                    for semantic_id, kind, content in _ITEMS
                ],
                "schema_version": 1,
            }
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    descriptor = _descriptor()
    return AgentEvent.create(
        specversion="1.0",
        event_id=EVENT_ID,
        source="urn:agentmemory:adapter:agentmemory.claude-code",
        event_type=EventFamily.TASK_CHECKPOINTED,
        subject=f"session/{SESSION_ID}",
        occurred_at=NOW,
        datacontenttype="application/json",
        dataschema=EventFamily.TASK_CHECKPOINTED.dataschema,
        identity=AgentEventIdentity(
            BRAIN_ID,
            PRINCIPAL_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            None,
            "main",
            "a" * 40,
        ),
        provenance=AgentEventProvenance(
            "claude_code",
            descriptor.adapter_id,
            descriptor.adapter_version,
            descriptor.adapter_digest,
            "claude-sonnet",
            SESSION_ID,
            None,
            None,
            None,
            descriptor.manifest_sha256,
            CaptureMethod.NATIVE,
            DIGEST,
        ),
        correlation_id=CORRELATION_ID,
        causation_id=None,
        ordering_key=ORDERING_KEY,
        sequence=1,
        classification=Classification.INTERNAL,
        retention_policy_id="default",
        capture_capabilities=(CaptureCapability.TASK_LIFECYCLE,),
        payload=AgentEventData(payload, hashlib.sha256(payload).hexdigest()),
        payload_reference=None,
    )


async def _seed(store: object) -> None:
    from agentmemory.operations.adapters.outbound.sqlite_store import (  # noqa: PLC0415
        SqliteCoreStore,
    )

    assert isinstance(store, SqliteCoreStore)
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    now = round(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects "
                "(id,brain_id,name,manifest_key,status,version,created_at,updated_at,"
                "schema_version) "
                "VALUES (:id,:brain,'AgentMemory',:key,'active',1,:now,:now,1)"
            ),
            {"id": PROJECT_ID, "brain": BRAIN_ID, "key": b"p" * 32, "now": now},
        )
        await connection.execute(
            text(
                "INSERT INTO repositories "
                "(id,brain_id,vcs_type,root_fingerprint,primary_remote_fingerprint,status,"
                "created_at,updated_at,schema_version) VALUES "
                "(:id,:brain,'git',:root,NULL,'active',:now,:now,1)"
            ),
            {"id": REPOSITORY_ID, "brain": BRAIN_ID, "root": b"r" * 32, "now": now},
        )
        await connection.execute(
            text(
                "INSERT INTO project_repositories "
                "(project_id,repository_id,relation_type,created_at,updated_at,schema_version) "
                "VALUES (:project,:repository,'primary',:now,:now,1)"
            ),
            {"project": PROJECT_ID, "repository": REPOSITORY_ID, "now": now},
        )
    identities = SystemIngestionIdentityGenerator()
    await RegisterAgentAdapterHandler(
        SqliteAdapterCapabilityUnitOfWorkFactory(store, FixedClock(NOW), identities),
        identities,
        FixedClock(NOW),
    ).execute(RegisterAgentAdapterCommand("register-adp006", _descriptor()))


async def _capture(store: object, key_file: Path) -> SqliteWrappedBrainKeyProvider:
    from agentmemory.operations.adapters.outbound.sqlite_store import (  # noqa: PLC0415
        SqliteCoreStore,
    )

    assert isinstance(store, SqliteCoreStore)
    clock = FixedClock(NOW)
    keys = SqliteWrappedBrainKeyProvider(store, key_file, clock)
    handler = CaptureAgentEventHandler(
        SqliteAdapterCapabilityRegistry(store.engine),
        SqliteAgentEventScopeResolver(store.engine, clock),
        InlineOnlyPayloadReader(),
        CapturePolicyPipeline(SqliteCapturePolicyRepository(store)),
        SqliteCapturePolicyDecisionRepository(store),
        AppendAgentEventHandler(
            CanonicalAgentEventEncoder(),
            AesGcmAgentEventEncryptor(keys),
            SqliteAgentEventUnitOfWorkFactory(store, clock),
        ),
        clock,
    )
    await handler.execute(_event())
    return keys


@pytest.mark.asyncio
@pytest.mark.integration
async def test_reads_all_semantics_from_encrypted_canonical_event_with_provenance(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await _seed(store)
        keys = await _capture(store, key_file)
        items = await SqliteContinuityReadRepository(
            store.engine, keys, FixedClock(NOW)
        ).list_items(scope(), 200)
        assert {(item.kind.value, item.content) for item in items} == {
            (kind, content) for _, kind, content in _ITEMS
        }
        assert {item.kind for item in items} == set(ContinuityKind)
        assert all(item.provenance.producer_host == "claude_code" for item in items)
        assert all(item.provenance.model_id == "claude-sonnet" for item in items)
        assert all(item.evidence_event_id == EVENT_ID for item in items)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_tombstone_and_revocation_exclude_content_before_decryption_result(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await _seed(store)
        keys = await _capture(store, key_file)
        repository = SqliteContinuityReadRepository(store.engine, keys, FixedClock(NOW))
        now = round(NOW.timestamp() * 1_000_000)
        deleted_id = f"{EVENT_ID}:2"
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO deletion_tombstones "
                    "(id,brain_id,target_type,target_id_hash,effective_at,purge_state,"
                    "restore_guard_version,created_at,schema_version) VALUES "
                    "(:id,:brain,'continuity_item',:hash,:now,'tombstoned',1,:now,1)"
                ),
                {
                    "id": "018f0000-0000-7000-8000-000000000901",
                    "brain": BRAIN_ID,
                    "hash": hashlib.sha256(deleted_id.encode()).digest(),
                    "now": now,
                },
            )
        items = await repository.list_items(scope(), 200)
        assert deleted_id not in {item.item_id for item in items}
        assert len(items) == 4
        async with store.engine.begin() as connection:
            await connection.execute(text("UPDATE scope_grants SET valid_to=:now"), {"now": now})
        assert await repository.list_items(scope(), 200) == ()
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_authenticated_ciphertext_tamper_fails_closed(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await _seed(store)
        keys = await _capture(store, key_file)
        async with store.engine.begin() as connection:
            ciphertext = bytearray(
                (
                    await connection.execute(
                        text("SELECT ciphertext FROM agent_event_envelopes WHERE event_id=:id"),
                        {"id": EVENT_ID},
                    )
                ).scalar_one()
            )
            ciphertext[0] ^= 1
            await connection.execute(
                text("UPDATE agent_event_envelopes SET ciphertext=:value WHERE event_id=:id"),
                {"value": bytes(ciphertext), "id": EVENT_ID},
            )
        with pytest.raises(RetrievalIntegrityError):
            await SqliteContinuityReadRepository(store.engine, keys, FixedClock(NOW)).list_items(
                scope(), 200
            )
    finally:
        await store.close()


def test_reference_clock_is_utc() -> None:
    assert datetime.fromtimestamp(NOW.timestamp(), tz=UTC) == NOW
