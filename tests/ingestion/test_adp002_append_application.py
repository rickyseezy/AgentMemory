"""ADP-002 command transaction and ACK semantics tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

import pytest

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
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    EVENT_ID,
    NOW,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    event,
)

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.ingestion.domain.ports import AgentEventRepository, AgentEventUnitOfWork


class _Encoder:
    def encode(self, event: object) -> bytes:
        del event
        return b"canonical"


class _Encryptor:
    async def encrypt(self, **kwargs: object) -> EncryptedAgentEvent:
        assert kwargs["plaintext"] == b"canonical"
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


class _Repository:
    def __init__(self, disposition: AppendDisposition) -> None:
        self.disposition = disposition

    async def append(self, admitted: object, encrypted: object) -> AppendAgentEventResult:
        del admitted, encrypted
        return AppendAgentEventResult(EVENT_ID, self.disposition, 42)


class _UnitOfWork:
    def __init__(self, disposition: AppendDisposition) -> None:
        self.events: AgentEventRepository = _Repository(disposition)
        self.commits = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, exc, traceback
        return None

    async def commit(self) -> None:
        self.commits += 1


@dataclass
class _Factory:
    current: _UnitOfWork

    def __call__(self) -> AgentEventUnitOfWork:
        return self.current


def _admitted() -> AdmittedAgentEvent:
    return AdmittedAgentEvent(
        event(),
        ResolvedAgentEventIdentity(BRAIN_ID, PRINCIPAL_ID, PROJECT_ID, REPOSITORY_ID, None),
        NOW,
        0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("disposition", "commits"),
    [(AppendDisposition.ACCEPTED, 1), (AppendDisposition.DUPLICATE, 0)],
)
async def test_ack_occurs_only_after_new_event_commit(
    disposition: AppendDisposition,
    commits: int,
) -> None:
    uow = _UnitOfWork(disposition)
    handler = AppendAgentEventHandler(_Encoder(), _Encryptor(), _Factory(uow))
    result = await handler.execute(AppendAgentEventCommand(_admitted()))
    assert result.disposition is disposition
    assert uow.commits == commits
