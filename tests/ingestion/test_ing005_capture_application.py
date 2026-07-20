"""ING-005 in-memory capture boundary and privacy decision tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.ingestion.application.capture_agent_event import (
    CaptureAgentEventHandler,
    read_payload_bytes,
    source_path_for_policy,
)
from agentmemory.ingestion.application.privacy import CapturePolicyPipeline
from agentmemory.ingestion.domain.agent_event import (
    AgentEventData,
    CaptureCapability,
    EventFamily,
    PayloadReference,
    ResolvedAgentEventIdentity,
)
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.privacy import (
    CapturePolicy,
    CapturePolicyResult,
    SensitiveAction,
)
from tests.core.support import FixedClock
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    EVENT_ID,
    NOW,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    descriptor,
    event,
)
from tests.ingestion.capability_support import registered

if TYPE_CHECKING:
    from agentmemory.ingestion.application.append_agent_event import (
        AppendAgentEventCommand,
        AppendAgentEventHandler,
    )
    from agentmemory.ingestion.domain.adapter_capability import RegisteredAdapterCapabilities
    from agentmemory.ingestion.domain.agent_event import (
        AgentEvent,
        AgentEventIdentity,
        AgentEventProvenance,
    )


_SECRET = b'{"token":"sk-abcdefghijklmnopqrstuvwxyz123456"}'
_SANITIZED = b'{"token":"[REDACTED:SECRET]"}'


class _Capabilities:
    async def get(
        self,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
    ) -> RegisteredAdapterCapabilities:
        configured = descriptor()
        assert (adapter_id, adapter_version, adapter_digest) == (
            configured.adapter_id,
            configured.adapter_version,
            configured.adapter_digest,
        )
        return registered(configured, observed_at=NOW)


class _Scope:
    async def resolve(
        self,
        claim: AgentEventIdentity,
        provenance: AgentEventProvenance,
    ) -> ResolvedAgentEventIdentity:
        del claim, provenance
        return ResolvedAgentEventIdentity(
            BRAIN_ID,
            PRINCIPAL_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            None,
        )


class _Reader:
    async def read(self, reference: PayloadReference) -> bytes:
        assert reference.size_bytes == len(_SECRET)
        return _SECRET


class _Policies:
    def __init__(self, action: SensitiveAction = SensitiveAction.REDACT) -> None:
        self.policy = replace(
            CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID),
            secret_action=action,
        )

    async def resolve(
        self,
        brain_id: str,
        repository_id: str | None,
        version: int | None,
    ) -> CapturePolicy:
        assert (brain_id, repository_id, version) == (BRAIN_ID, REPOSITORY_ID, None)
        return self.policy


class _Decisions:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, str, CapturePolicyResult, int]] = []

    async def record(
        self,
        event_id: str,
        brain_id: str,
        principal_id: str,
        result: CapturePolicyResult,
        decided_at_microseconds: int,
    ) -> None:
        self.records.append((event_id, brain_id, principal_id, result, decided_at_microseconds))


class _Appender:
    def __init__(self) -> None:
        self.commands: list[AppendAgentEventCommand] = []

    async def execute(self, command: AppendAgentEventCommand) -> AppendAgentEventResult:
        self.commands.append(command)
        return AppendAgentEventResult(EVENT_ID, AppendDisposition.ACCEPTED, 42, 0)


def _handler(action: SensitiveAction) -> tuple[CaptureAgentEventHandler, _Decisions, _Appender]:
    decisions = _Decisions()
    appender = _Appender()
    handler = CaptureAgentEventHandler(
        _Capabilities(),
        _Scope(),
        _Reader(),
        CapturePolicyPipeline(_Policies(action)),
        decisions,
        cast("AppendAgentEventHandler", appender),
        FixedClock(NOW),
    )
    return handler, decisions, appender


def _secret_event() -> AgentEvent:
    return replace(
        event(),
        payload=AgentEventData(_SECRET, hashlib.sha256(_SECRET).hexdigest()),
    )


@pytest.mark.asyncio
async def test_capture_appends_only_the_sanitized_event_and_atomic_privacy_receipt() -> None:
    handler, decisions, appender = _handler(SensitiveAction.REDACT)
    result = await handler.execute(_secret_event())
    assert result.disposition is AppendDisposition.ACCEPTED
    assert decisions.records == []
    assert len(appender.commands) == 1
    admitted = appender.commands[0].admitted
    assert admitted.event.payload is not None
    assert admitted.event.payload.value == _SANITIZED
    assert admitted.event.payload_reference is None
    assert admitted.privacy is not None
    assert admitted.privacy.payload == _SANITIZED


@pytest.mark.asyncio
async def test_capture_exclusion_records_only_decision_and_returns_terminal_ignored() -> None:
    handler, decisions, appender = _handler(SensitiveAction.EXCLUDE)
    result = await handler.execute(_secret_event())
    assert result == AppendAgentEventResult(
        EVENT_ID,
        AppendDisposition.IGNORED,
        round(NOW.timestamp() * 1_000_000),
        0,
    )
    assert appender.commands == []
    assert len(decisions.records) == 1
    event_id, brain_id, principal_id, privacy, decided_at = decisions.records[0]
    assert (event_id, brain_id, principal_id, decided_at) == (
        EVENT_ID,
        BRAIN_ID,
        PRINCIPAL_ID,
        round(NOW.timestamp() * 1_000_000),
    )
    assert privacy.payload is None


@pytest.mark.asyncio
async def test_payload_reader_handles_inline_and_referenced_content() -> None:
    inline = event()
    if inline.payload is None:
        raise AssertionError
    assert await read_payload_bytes(inline, _Reader()) == inline.payload.value
    digest = hashlib.sha256(_SECRET).hexdigest()
    referenced = replace(
        inline,
        payload=None,
        payload_reference=PayloadReference(f"cas://sha256/{digest}", digest, len(_SECRET)),
    )
    assert await read_payload_bytes(referenced, _Reader()) == _SECRET


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (None, "session/fixture"),
        (b"[]", "session/fixture"),
        (b'{"path":"src/current.py"}', "src/current.py"),
        (b'{"new_path":"src/new.py","path":1}', "src/new.py"),
        (b'{"old_path":"src/old.py"}', "src/old.py"),
        (b'{"status":"unknown"}', "session/fixture"),
    ],
)
def test_file_source_path_uses_closed_precedence_or_subject(
    payload: bytes | None,
    expected: str,
) -> None:
    source = replace(
        event(),
        event_type=EventFamily.FILE_CHANGED,
        dataschema=EventFamily.FILE_CHANGED.dataschema,
        subject="session/fixture",
        capture_capabilities=(CaptureCapability.FILE_OBSERVATION,),
        payload=(
            None
            if payload is None
            else AgentEventData(payload, hashlib.sha256(payload).hexdigest())
        ),
        payload_reference=(
            PayloadReference(
                f"cas://sha256/{hashlib.sha256(_SECRET).hexdigest()}",
                hashlib.sha256(_SECRET).hexdigest(),
                len(_SECRET),
            )
            if payload is None
            else None
        ),
    )
    assert source_path_for_policy(source) == expected


def test_non_file_event_has_no_policy_source_path() -> None:
    assert source_path_for_policy(event()) is None
