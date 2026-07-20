"""ADP-002 bounded spool, timeout, forbidden-work, and latency tests."""

from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING

import httpx
import pytest

from agentmemory.ingestion.adapters.host_capture import (
    AgentEventCaptureHook,
    CaptureStatus,
    HookCaptureResult,
    HttpAgentEventIpcClient,
)
from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.adapters.outbound.offline_spool import (
    EncryptedSqliteSpool,
    SpoolCapacityError,
)
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from tests.core.support import write_secret
from tests.ingestion.adp002_support import EVENT_ID, event

if TYPE_CHECKING:
    from pathlib import Path


def _spool(tmp_path: Path, *, records: int = 10) -> EncryptedSqliteSpool:
    tmp_path.chmod(0o700)
    key = tmp_path / "spool-key"
    write_secret(key, b"s" * 32)
    spool = EncryptedSqliteSpool(
        tmp_path / "events.sqlite3",
        key,
        maximum_records=records,
        maximum_bytes=128 * 1024,
    )
    spool.initialize()
    return spool


def test_spool_is_encrypted_bounded_idempotent_and_order_preserving(tmp_path: Path) -> None:
    spool = _spool(tmp_path, records=2)
    first = b'{"private":"first"}'
    second = b'{"private":"second"}'
    assert spool.enqueue(EVENT_ID, "order-a", 2, second)
    assert spool.enqueue("018f0000-0000-7000-8000-000000000102", "order-a", 1, first)
    assert not spool.enqueue(EVENT_ID, "order-a", 2, second)
    with pytest.raises(SpoolCapacityError):
        spool.enqueue("018f0000-0000-7000-8000-000000000103", "order-b", 1, b"third")
    pending = spool.pending()
    assert [item.sequence for item in pending] == [1, 2]
    assert [item.canonical_event for item in pending] == [first, second]
    with closing(sqlite3.connect(tmp_path / "events.sqlite3")) as connection:
        ciphertext = b"".join(
            row[0] for row in connection.execute("SELECT ciphertext FROM spool_events")
        )
    assert b"private" not in ciphertext
    assert spool.acknowledge((pending[0].event_id,)) == 1
    assert [item.event_id for item in spool.pending()] == [EVENT_ID]


def test_spool_rejects_invalid_bounds_empty_events_and_conflicting_retry(tmp_path: Path) -> None:
    key = tmp_path / "spool-key"
    write_secret(key, b"s" * 32)
    with pytest.raises(ValueError, match="positive"):
        EncryptedSqliteSpool(tmp_path / "bad.sqlite3", key, maximum_records=0)
    spool = _spool(tmp_path)
    with pytest.raises(ValueError, match="must not be empty"):
        spool.enqueue(EVENT_ID, "order-a", 1, b"")
    assert spool.enqueue(EVENT_ID, "order-a", 1, b"first")
    with pytest.raises(IngestionDependencyError, match="identity conflicted"):
        spool.enqueue(EVENT_ID, "order-a", 1, b"other")
    with pytest.raises(ValueError, match="batch size"):
        spool.pending(0)
    assert spool.acknowledge(()) == 0
    with pytest.raises(ValueError, match="at most 100"):
        spool.acknowledge(tuple(str(index) for index in range(101)))


def test_spool_rejects_symlink_and_authenticated_metadata_tamper(tmp_path: Path) -> None:
    key = tmp_path / "spool-key"
    write_secret(key, b"s" * 32)
    target = tmp_path / "target.sqlite3"
    target.touch()
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(IngestionDependencyError, match="path is unsafe"):
        EncryptedSqliteSpool(link, key).initialize()
    spool = _spool(tmp_path)
    spool.enqueue(EVENT_ID, "order-a", 1, b"private")
    with closing(sqlite3.connect(tmp_path / "events.sqlite3")) as connection:
        connection.execute("UPDATE spool_events SET aad_sha256 = ?", (b"x" * 32,))
        connection.commit()
    with pytest.raises(IngestionDependencyError, match="integrity failed"):
        spool.pending()


class _PassRedactor:
    def __init__(self) -> None:
        self.calls = 0

    def redact(self, canonical_event: bytes) -> bytes:
        self.calls += 1
        return canonical_event


class _FailingRedactor:
    def redact(self, canonical_event: bytes) -> bytes:
        del canonical_event
        message = "redactor unavailable"
        raise IngestionDependencyError(message)


@dataclass
class _Ipc:
    disposition: AppendDisposition = AppendDisposition.ACCEPTED
    delay_seconds: float = 0
    calls: int = 0

    async def append(self, canonical_event: bytes) -> AppendDisposition:
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        assert canonical_event
        return self.disposition


@pytest.mark.asyncio
@pytest.mark.load
async def test_healthy_hook_p95_is_below_published_50ms_profile(tmp_path: Path) -> None:
    redactor = _PassRedactor()
    ipc = _Ipc()
    hook = AgentEventCaptureHook(redactor, ipc, _spool(tmp_path))
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    durations: list[float] = []
    for _ in range(200):
        started = perf_counter()
        result = await hook.capture(raw)
        durations.append((perf_counter() - started) * 1_000)
        assert result.status is CaptureStatus.ACCEPTED
    durations.sort()
    p95 = durations[round(len(durations) * 0.95) - 1]
    assert p95 < 50
    assert redactor.calls == 200
    assert ipc.calls == 200


@pytest.mark.asyncio
@pytest.mark.resilience
async def test_timeout_returns_control_with_durable_deferred_status(tmp_path: Path) -> None:
    spool = _spool(tmp_path)
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    hook = AgentEventCaptureHook(
        _PassRedactor(),
        _Ipc(delay_seconds=0.1),
        spool,
        ipc_timeout_seconds=0.001,
    )
    started = perf_counter()
    result = await hook.capture(raw)
    elapsed = perf_counter() - started
    assert result.status is CaptureStatus.DEFERRED
    assert elapsed < 0.05
    assert spool.pending()[0].event_id == EVENT_ID


@pytest.mark.asyncio
async def test_ignored_policy_result_is_terminal_and_never_spooled(tmp_path: Path) -> None:
    spool = _spool(tmp_path)
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    result = await AgentEventCaptureHook(
        _PassRedactor(),
        _Ipc(AppendDisposition.IGNORED),
        spool,
    ).capture(raw)
    assert result == HookCaptureResult(EVENT_ID, CaptureStatus.IGNORED)
    assert spool.pending() == ()


@pytest.mark.asyncio
@pytest.mark.load
async def test_concurrent_hooks_share_capture_dependencies_without_reordering(
    tmp_path: Path,
) -> None:
    ipc = _Ipc()
    hook = AgentEventCaptureHook(_PassRedactor(), ipc, _spool(tmp_path))
    raw = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    results = await asyncio.gather(*(hook.capture(raw) for _ in range(64)))
    assert all(result.status is CaptureStatus.ACCEPTED for result in results)
    assert ipc.calls == 64


@pytest.mark.asyncio
async def test_invalid_event_never_reaches_ipc_or_spool(tmp_path: Path) -> None:
    ipc = _Ipc()
    spool = _spool(tmp_path)
    result = await AgentEventCaptureHook(_PassRedactor(), ipc, spool).capture(b"not-json")
    assert result.status is CaptureStatus.INVALID
    assert ipc.calls == 0
    assert spool.pending() == ()


@pytest.mark.asyncio
async def test_redactor_dependency_failure_returns_safe_status(tmp_path: Path) -> None:
    ipc = _Ipc()
    result = await AgentEventCaptureHook(_FailingRedactor(), ipc, _spool(tmp_path)).capture(
        b"private"
    )
    assert result == HookCaptureResult(None, CaptureStatus.SPOOL_UNAVAILABLE)
    assert ipc.calls == 0


@pytest.mark.asyncio
async def test_http_ipc_reuses_client_and_validates_safe_response() -> None:
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201, json={"status": "accepted"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        ipc = HttpAgentEventIpcClient(
            client,
            "http://127.0.0.1:9411/v1/agent-events:append",
            "a" * 64,
        )
        assert await ipc.append(b"first") is AppendDisposition.ACCEPTED
        assert await ipc.append(b"second") is AppendDisposition.ACCEPTED
    assert len(requests) == 2
    assert {request.headers["authorization"] for request in requests} == {f"Bearer {'a' * 64}"}


@pytest.mark.asyncio
async def test_http_ipc_accepts_terminal_ignored_policy_receipt() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(201, json={"status": "ignored"})
        )
    ) as client:
        ipc = HttpAgentEventIpcClient(
            client,
            "http://127.0.0.1:9411/v1/agent-events:append",
            "a" * 64,
        )
        assert await ipc.append(b"event") is AppendDisposition.IGNORED


@pytest.mark.asyncio
async def test_http_ipc_rejects_non_loopback_route_and_malformed_status() -> None:
    invalid_endpoints = (
        "https://127.0.0.1:9411/v1/agent-events:append",
        "http://example.com:9411/v1/agent-events:append",
        "http://localhost:9411/v1/agent-events:append",
        "http://user@127.0.0.1:9411/v1/agent-events:append",
        "http://127.0.0.1:9411/other",
        "http://127.0.0.1:9411/v1/agent-events:append?redirect=1",
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={})),
    ) as client:
        for endpoint in invalid_endpoints:
            with pytest.raises(ValueError, match="fixed loopback"):
                HttpAgentEventIpcClient(client, endpoint, "a" * 64)
        ipc = HttpAgentEventIpcClient(
            client,
            "http://127.0.0.1:9411/v1/agent-events:append",
            "a" * 64,
        )
        with pytest.raises(TypeError, match="invalid status"):
            await ipc.append(b"event")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"status": "deferred"})
        ),
    ) as client:
        ipc = HttpAgentEventIpcClient(
            client,
            "http://[::1]:9411/v1/agent-events:append",
            "a" * 64,
        )
        with pytest.raises(TypeError, match="non-durable status"):
            await ipc.append(b"event")
