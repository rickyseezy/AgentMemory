"""ING-006 encrypted SQLite view and resumable checkpoint integration tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
    decrypt_agent_event,
)
from agentmemory.ingestion.adapters.outbound.sqlite_schema_evolution import (
    SqliteCanonicalEventSourceReader,
    SqliteEventSchemaMigrationRepository,
)
from agentmemory.ingestion.application.schema_evolution import (
    EventUpcasterRegistry,
    EvolveEventSchemaHandler,
    ResumeEventSchemaMigrationHandler,
)
from agentmemory.ingestion.domain.capture import EncryptedAgentEvent
from agentmemory.ingestion.domain.schema_evolution import (
    EventSchemaKey,
    JsonValue,
    SchemaMigrationState,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import BRAIN_ID, EVENT_ID, NOW, event
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class AgentEventV1ToV2:
    """Fixture transform representing a new internal view without wire-history rewrite."""

    source: EventSchemaKey = field(default_factory=lambda: EventSchemaKey("agent_event", 1, 1))
    target: EventSchemaKey = field(default_factory=lambda: EventSchemaKey("agent_event", 1, 2))
    upcaster_id: str = "agent_event.v1_to_v2"
    known_source_fields: frozenset[str] = frozenset()

    def transform(self, fields: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        result = dict(fields)
        result["internal_schema_revision"] = 2
        return result


@pytest.mark.asyncio
@pytest.mark.integration
async def test_schema_migration_decrypts_original_and_stores_only_encrypted_derived_view(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    keys = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
    try:
        await seed_capture_authority(store)
        await capture_handler(store, key_file).execute(event())
        async with store.engine.connect() as connection:
            canonical_sha = (
                await connection.execute(
                    text(
                        "SELECT canonical_sha256 FROM agent_event_envelopes "
                        "WHERE event_id=:event_id"
                    ),
                    {"event_id": EVENT_ID},
                )
            ).scalar_one()
            lineage = (
                await connection.execute(
                    text(
                        "SELECT schema_family,schema_major,event_schema_version,"
                        "original_canonical_sha256 FROM event_schema_sources "
                        "WHERE event_id=:event_id"
                    ),
                    {"event_id": EVENT_ID},
                )
            ).one()
            assert lineage[:3] == ("agent_event", 1, 1)
            assert lineage[3] == canonical_sha
        repository = SqliteEventSchemaMigrationRepository(
            store,
            SqliteCanonicalEventSourceReader(store, keys),
            AesGcmAgentEventEncryptor(keys),
            FixedClock(NOW),
        )
        target = EventSchemaKey("agent_event", 1, 2)
        progress = await ResumeEventSchemaMigrationHandler(
            repository,
            EvolveEventSchemaHandler(EventUpcasterRegistry((target,), (AgentEventV1ToV2(),))),
        ).execute("ing006-upcast", target, 100)
        assert progress.state is SchemaMigrationState.COMPLETED
        assert progress.upcasted == 1
        async with store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT v.*,e.brain_id,e.classification FROM event_schema_views v "
                            "JOIN agent_events e ON e.event_id=v.event_id "
                            "WHERE v.event_id=:event_id"
                        ),
                        {"event_id": EVENT_ID},
                    )
                )
                .mappings()
                .one()
            )
        ciphertext = bytes(row["ciphertext"])
        assert b"internal_schema_revision" not in ciphertext
        encrypted = EncryptedAgentEvent(
            int(row["envelope_version"]),
            str(row["algorithm"]),
            str(row["brain_key_id"]),
            str(row["data_key_id"]),
            bytes(row["payload_nonce"]),
            ciphertext,
            bytes(row["wrapped_data_key_nonce"]),
            bytes(row["wrapped_data_key"]),
            bytes(row["aad_sha256"]).hex(),
            bytes(row["derived_sha256"]).hex(),
        )
        plaintext = decrypt_agent_event(
            encrypted,
            await keys.current(BRAIN_ID),
            event_id=EVENT_ID,
            brain_id=BRAIN_ID,
            classification=str(row["classification"]),
        )
        document = json.loads(plaintext)
        assert document["internal_schema_revision"] == 2
        assert document["id"] == EVENT_ID
        assert bytes(row["original_sha256"]) == canonical_sha
    finally:
        await store.close()
