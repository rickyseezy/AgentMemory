"""PF-005 scoped session credential authentication tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from agentmemory.operations.adapters.inbound.session_authentication import (
    SessionCredentialAuthenticator,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSession,
    McpSessionRegistration,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    INSTALLATION_ID,
    NOW,
    OWNER_ID,
    FixedClock,
    digest,
)

_SESSION = Uuid7Id("019f4d50-4154-7902-b2a0-7c164ae2549f")
_SECRET = bytes(range(32))


@pytest.mark.asyncio
@pytest.mark.security
async def test_pf005_session_authenticator_hashes_secret_and_returns_only_exact_scope() -> None:
    session = McpSession.register(_registration())
    repository = _AuthorizationRepository(session)
    authenticator = SessionCredentialAuthenticator(repository, FixedClock())
    resolved = await authenticator.authenticate(f"Bearer {_SECRET.hex()}", _SESSION.value)
    assert resolved is session
    assert repository.observed_digest == Sha256Digest.from_bytes(_SECRET)


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    ("authorization", "session_id"),
    [
        (None, _SESSION.value),
        ("Bearer invalid", _SESSION.value),
        (f"Bearer {_SECRET.hex()}", "foreign"),
        (f"Bearer {bytes(reversed(_SECRET)).hex()}", _SESSION.value),
    ],
)
async def test_pf005_session_authenticator_denies_malformed_foreign_and_wrong_secrets(
    authorization: str | None,
    session_id: str,
) -> None:
    authenticator = SessionCredentialAuthenticator(
        _AuthorizationRepository(McpSession.register(_registration())),
        FixedClock(),
    )
    with pytest.raises(OperationError) as raised:
        await authenticator.authenticate(authorization, session_id)
    assert raised.value.code is ErrorCode.UNAUTHENTICATED


@dataclass(slots=True)
class _AuthorizationRepository:
    session: McpSession
    observed_digest: Sha256Digest | None = None

    async def authorize(
        self,
        digest: Sha256Digest,
        session_id: Uuid7Id,
        now: datetime,
    ) -> McpSession | None:
        del now
        self.observed_digest = digest
        if (
            digest != self.session.registration.credential_digest
            or session_id != self.session.registration.session_id
        ):
            return None
        return self.session


def _registration() -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=_SESSION,
        installation_id=Uuid7Id(INSTALLATION_ID),
        brain_id=Uuid7Id(BRAIN_ID),
        actor_id=Uuid7Id(OWNER_ID),
        grant_id=Uuid7Id(GRANT_ID),
        agent_id="codex",
        workspace_fingerprint=digest("workspace"),
        device_identity="dev:1",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=1,
        credential_digest=Sha256Digest.from_bytes(_SECRET),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
