"""ADP-002 real migration, identity resolution, key, and atomic capture tests."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING
from uuid import uuid7

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
from agentmemory.ingestion.application.adapter_capabilities import (
    RegisterAgentAdapterCommand,
    RegisterAgentAdapterHandler,
)
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
from agentmemory.ingestion.application.capture_agent_event import CaptureAgentEventHandler
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionConflictError, IngestionDependencyError
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from tests.core.support import FixedClock, bootstrap_request, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    EVENT_ID,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
    descriptor,
    event,
)

if TYPE_CHECKING:
    from multiprocessing.connection import Connection


async def _seed_capture_authority(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    configured = descriptor()
    now = round(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO projects "
                "(id, brain_id, name, manifest_key, status, version, created_at, updated_at, "
                "schema_version) VALUES (:id, :brain, 'AgentMemory', :key, 'active', 1, "
                ":now, :now, 1)"
            ),
            {"id": PROJECT_ID, "brain": BRAIN_ID, "key": b"p" * 32, "now": now},
        )
        await connection.execute(
            text(
                "INSERT INTO repositories "
                "(id, brain_id, vcs_type, root_fingerprint, primary_remote_fingerprint, status, "
                "created_at, updated_at, schema_version) VALUES "
                "(:id, :brain, 'git', :root, NULL, 'active', :now, :now, 1)"
            ),
            {"id": REPOSITORY_ID, "brain": BRAIN_ID, "root": b"r" * 32, "now": now},
        )
        await connection.execute(
            text(
                "INSERT INTO project_repositories "
                "(project_id, repository_id, relation_type, created_at, updated_at, "
                "schema_version) VALUES (:project, :repository, 'primary', :now, :now, 1)"
            ),
            {"project": PROJECT_ID, "repository": REPOSITORY_ID, "now": now},
        )
    identities = SystemIngestionIdentityGenerator()
    await RegisterAgentAdapterHandler(
        SqliteAdapterCapabilityUnitOfWorkFactory(
            store,
            FixedClock(NOW),
            identities,
        ),
        identities,
        FixedClock(NOW),
    ).execute(RegisterAgentAdapterCommand("test-adp002-register", configured))


def _handler(store: SqliteCoreStore, key_file: Path) -> CaptureAgentEventHandler:
    clock = FixedClock(NOW)
    return CaptureAgentEventHandler(
        SqliteAdapterCapabilityRegistry(store.engine),
        SqliteAgentEventScopeResolver(store.engine, clock),
        InlineOnlyPayloadReader(),
        AppendAgentEventHandler(
            CanonicalAgentEventEncoder(),
            AesGcmAgentEventEncryptor(SqliteWrappedBrainKeyProvider(store, key_file, clock)),
            SqliteAgentEventUnitOfWorkFactory(store, clock),
        ),
        clock,
    )


def _append_then_exit(database_path: str, key_path: str, sender: Connection) -> None:
    async def execute() -> None:
        store = SqliteCoreStore.create(
            Path(database_path),
            SqliteRuntimePolicy((3, 0, 0), frozenset()),
        )
        result = await _handler(store, Path(key_path)).execute(event())
        sender.send(result.disposition.value)
        sender.close()
        os._exit(0)

    asyncio.run(execute())


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_event_envelope_outbox_and_audit_commit_atomically_and_retry_exactly(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await _seed_capture_authority(store)
        handler = _handler(store, key_file)
        first = await handler.execute(event())
        retry = await handler.execute(event())
        assert first.disposition is AppendDisposition.ACCEPTED
        assert retry.disposition is AppendDisposition.DUPLICATE
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM agent_events"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM agent_event_envelopes"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM outbox_messages"))
            ).scalar_one() == 1
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM audit_events WHERE action='agent_event.appended'")
                )
            ).scalar_one() == 1
            ciphertext = (
                await connection.execute(text("SELECT ciphertext FROM agent_event_envelopes"))
            ).scalar_one()
            assert b"secret" not in ciphertext
            provenance = (
                await connection.execute(
                    text(
                        "SELECT adapter_id, adapter_version, adapter_digest, "
                        "capability_manifest_sha256, capture_method "
                        "FROM agent_event_envelopes"
                    )
                )
            ).one()
            configured = descriptor()
            assert tuple(provenance) == (
                configured.adapter_id,
                configured.adapter_version,
                bytes.fromhex(configured.adapter_digest),
                bytes.fromhex(configured.manifest_sha256),
                "native",
            )
            wrapped_brain_key = (
                await connection.execute(text("SELECT ciphertext FROM brain_encryption_keys"))
            ).scalar_one()
            assert b"i" * 32 not in wrapped_brain_key
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_same_order_sequence_with_different_event_is_rejected_without_partial_facts(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await _seed_capture_authority(store)
        handler = _handler(store, key_file)
        await handler.execute(event())
        with pytest.raises(IngestionConflictError):
            await handler.execute(
                event(event_id="018f0000-0000-7000-8000-000000000102", sequence=1)
            )
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM agent_events"))
            ).scalar_one() == 1
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM outbox_messages"))
            ).scalar_one() == 1
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM audit_events WHERE action='agent_event.appended'")
                )
            ).scalar_one() == 1
            assert (
                await connection.execute(
                    text("SELECT event_id FROM agent_events WHERE event_id=:id"),
                    {"id": EVENT_ID},
                )
            ).scalar_one() == EVENT_ID
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_brain_key_provider_rejects_unknown_scope_and_wrapper_tamper(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    provider = SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW))
    try:
        await _seed_capture_authority(store)
        with pytest.raises(IngestionDependencyError, match="scope is unavailable"):
            await provider.current("018f0000-0000-7000-8000-000000000999")
        await provider.current(BRAIN_ID)
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE brain_encryption_keys SET aad_sha256 = :tampered"),
                {"tampered": b"x" * 32},
            )
        with pytest.raises(IngestionDependencyError, match="integrity failed"):
            await provider.current(BRAIN_ID)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.load
async def test_real_encrypted_full_durability_append_p95_is_below_50ms(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await _seed_capture_authority(store)
        handler = _handler(store, key_file)
        durations: list[float] = []
        for sequence in range(1, 101):
            source = replace(event(), event_id=str(uuid7()), sequence=sequence)
            started = perf_counter()
            await handler.execute(source)
            durations.append((perf_counter() - started) * 1_000)
        durations.sort()
        p95 = durations[94]
        assert p95 < 50
    finally:
        await store.close()


@pytest.mark.integration
@pytest.mark.resilience
def test_process_exit_immediately_after_ack_preserves_event_and_outbox(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    asyncio.run(_seed_capture_authority(store))
    asyncio.run(store.close())
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_append_then_exit,
        args=(str(tmp_path / "agentmemory.sqlite3"), str(key_file), sender),
    )
    process.start()
    sender.close()
    assert receiver.recv() == AppendDisposition.ACCEPTED.value
    process.join(timeout=10)
    assert process.exitcode == 0
    with closing(sqlite3.connect(tmp_path / "agentmemory.sqlite3")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM agent_events").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM outbox_messages").fetchone() == (1,)
