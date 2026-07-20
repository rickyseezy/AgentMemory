"""ING-001 begin/write/commit failure injection and no-ACK guarantees."""

from __future__ import annotations

import asyncio
import multiprocessing
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Self, cast

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import SqliteAgentEventUnitOfWork
from agentmemory.ingestion.application.append_agent_event import (
    AppendAgentEventCommand,
    AppendAgentEventHandler,
)
from agentmemory.ingestion.domain.agent_event import ResolvedAgentEventIdentity
from agentmemory.ingestion.domain.capture import (
    AdmittedAgentEvent,
    AppendAgentEventResult,
    AppendDisposition,
    EncryptedAgentEvent,
)
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    EVENT_ID,
    NOW,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    event,
)
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority

if TYPE_CHECKING:
    from multiprocessing.connection import Connection

    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.ports import AgentEventUnitOfWorkFactory

_ERR_ARTIFACT = "artifact unavailable"
_ERR_WRITE = "write unavailable"
_ERR_OUTBOX = "outbox unavailable"
_ERR_AUDIT = "audit unavailable"
_ERR_BEGIN = "begin unavailable"
_ERR_COMMIT = "durable commit failed"


def _pause_after(sender: Connection, phase: str) -> None:
    sender.send(phase)
    sender.close()
    threading.Event().wait()


def _append_with_kill_boundary(
    database_path: str,
    key_path: str,
    phase: str,
    sender: Connection,
) -> None:
    async def execute() -> None:
        store = SqliteCoreStore.create(
            Path(database_path),
            SqliteRuntimePolicy((3, 0, 0), frozenset()),
        )
        clock = FixedClock(NOW)
        source = admitted()
        canonical = CanonicalAgentEventEncoder().encode(source.event)
        encrypted = await AesGcmAgentEventEncryptor(
            SqliteWrappedBrainKeyProvider(store, Path(key_path), clock)
        ).encrypt(
            event_id=source.event.event_id,
            brain_id=source.identity.brain_id,
            classification=source.event.classification.value,
            plaintext=canonical,
        )
        unit = SqliteAgentEventUnitOfWork(store, clock)
        async with unit:
            if phase == "begin":
                _pause_after(sender, phase)
            artifact_id = await unit.artifacts.ensure_reference(source, encrypted)
            await unit.events.append(source, encrypted, artifact_id)
            if phase == "write":
                _pause_after(sender, phase)
            await unit.outbox.enqueue(source)
            await unit.audit.append_agent_event(source, encrypted)
            if phase == "commit":
                _pause_after(sender, phase)
            await unit.commit()
            if phase == "ack":
                _pause_after(sender, phase)

    asyncio.run(execute())


class _Encoder:
    def encode(self, event: AgentEvent) -> bytes:
        del event
        return b"canonical"


class _Encryptor:
    async def encrypt(self, **values: object) -> EncryptedAgentEvent:
        del values
        return EncryptedAgentEvent(
            1,
            "AES-256-GCM",
            "brain:v1",
            "018f0000-0000-7000-8000-000000000777",
            b"n" * 12,
            b"c" * 17,
            b"w" * 12,
            b"d" * 48,
            "a" * 64,
            "b" * 64,
        )


def admitted() -> AdmittedAgentEvent:
    return AdmittedAgentEvent(
        event(),
        ResolvedAgentEventIdentity(
            BRAIN_ID,
            PRINCIPAL_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            None,
        ),
        NOW,
        0,
    )


@dataclass
class _Artifacts:
    fail: bool

    async def ensure_reference(self, source: object, encrypted: object) -> None:
        del source, encrypted
        if self.fail:
            raise IngestionDependencyError(_ERR_ARTIFACT)


@dataclass
class _Events:
    fail: bool

    async def append(
        self,
        source: object,
        encrypted: object,
        artifact_id: str | None,
    ) -> AppendAgentEventResult:
        del source, encrypted, artifact_id
        if self.fail:
            raise IngestionDependencyError(_ERR_WRITE)
        return AppendAgentEventResult(EVENT_ID, AppendDisposition.ACCEPTED, 1)


@dataclass
class _Outbox:
    fail: bool

    async def enqueue(self, source: object) -> None:
        del source
        if self.fail:
            raise IngestionDependencyError(_ERR_OUTBOX)


@dataclass
class _Audit:
    fail: bool

    async def append_agent_event(self, source: object, encrypted: object) -> None:
        del source, encrypted
        if self.fail:
            raise IngestionDependencyError(_ERR_AUDIT)


class _UnitOfWork:
    def __init__(self, fail_at: str) -> None:
        self.fail_at = fail_at
        self.artifacts = _Artifacts(fail_at == "artifact")
        self.events = _Events(fail_at == "event_write")
        self.outbox = _Outbox(fail_at == "outbox_write")
        self.audit = _Audit(fail_at == "audit_write")
        self.committed = False

    async def __aenter__(self) -> Self:
        if self.fail_at == "begin":
            raise IngestionDependencyError(_ERR_BEGIN)
        return self

    async def __aexit__(self, *values: object) -> None:
        del values

    async def commit(self) -> None:
        if self.fail_at in {"commit", "fsync", "disk_full"}:
            raise IngestionDependencyError(_ERR_COMMIT)
        self.committed = True


@dataclass
class _Factory:
    unit: _UnitOfWork

    def __call__(self) -> _UnitOfWork:
        return self.unit


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fail_at",
    [
        "begin",
        "artifact",
        "event_write",
        "outbox_write",
        "audit_write",
        "commit",
        "fsync",
        "disk_full",
    ],
)
async def test_no_ack_is_constructed_before_every_durable_boundary(fail_at: str) -> None:
    unit = _UnitOfWork(fail_at)
    factory = cast("AgentEventUnitOfWorkFactory", _Factory(unit))
    handler = AppendAgentEventHandler(_Encoder(), _Encryptor(), factory)
    with pytest.raises(IngestionDependencyError):
        await handler.execute(AppendAgentEventCommand(admitted()))
    assert not unit.committed


@pytest.mark.asyncio
@pytest.mark.integration
async def test_partial_sql_write_failure_rolls_back_event_artifact_outbox_and_audit(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        async with store.engine.begin() as connection:
            await connection.exec_driver_sql(
                "CREATE TRIGGER ing001_fail_outbox BEFORE INSERT ON outbox_messages "
                "BEGIN SELECT RAISE(ABORT, 'simulated disk write failure'); END"
            )
        with pytest.raises(IngestionDependencyError, match="durable enqueue failed") as raised:
            await capture_handler(store, key_file).execute(event())
        assert "simulated" not in str(raised.value)
        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM agent_events),"
                        "(SELECT COUNT(*) FROM agent_event_envelopes),"
                        "(SELECT COUNT(*) FROM artifacts),"
                        "(SELECT COUNT(*) FROM outbox_messages),"
                        "(SELECT COUNT(*) FROM audit_events WHERE action='agent_event.appended')"
                    )
                )
            ).one()
            assert tuple(counts) == (0, 0, 0, 0, 0)
    finally:
        await store.close()


@pytest.mark.integration
@pytest.mark.resilience
@pytest.mark.parametrize(
    ("phase", "expected_count", "retry_disposition"),
    [
        ("begin", 0, AppendDisposition.ACCEPTED),
        ("write", 0, AppendDisposition.ACCEPTED),
        ("commit", 0, AppendDisposition.ACCEPTED),
        ("ack", 1, AppendDisposition.DUPLICATE),
    ],
)
def test_process_kill_at_each_ack_boundary_is_recoverable_and_retry_safe(
    tmp_path: Path,
    phase: str,
    expected_count: int,
    retry_disposition: AppendDisposition,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    asyncio.run(seed_capture_authority(store))
    asyncio.run(store.close())
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_append_with_kill_boundary,
        args=(str(tmp_path / "agentmemory.sqlite3"), str(key_file), phase, sender),
    )
    process.start()
    sender.close()
    assert receiver.poll(10)
    assert receiver.recv() == phase
    process.terminate()
    process.join(timeout=10)
    assert process.exitcode is not None
    with closing(sqlite3.connect(tmp_path / "agentmemory.sqlite3")) as connection:
        statements = (
            "SELECT COUNT(*) FROM agent_events",
            "SELECT COUNT(*) FROM agent_event_envelopes",
            "SELECT COUNT(*) FROM outbox_messages",
        )
        for statement in statements:
            assert connection.execute(statement).fetchone() == (expected_count,)

    restarted = SqliteCoreStore.create(
        tmp_path / "agentmemory.sqlite3",
        SqliteRuntimePolicy((3, 0, 0), frozenset()),
    )
    try:
        retry = asyncio.run(capture_handler(restarted, key_file).execute(event()))
        assert retry.disposition is retry_disposition
    finally:
        asyncio.run(restarted.close())
