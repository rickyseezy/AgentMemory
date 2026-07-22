"""PF-005 scoped bearer authentication for the transient MCP bridge."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.operations.domain.mcp_session import McpSession
    from agentmemory.shared.clock import Clock

_BEARER_PATTERN = re.compile(r"^Bearer ([0-9a-f]{64})$")
_SECRET_BYTES = 32


class SessionAuthorizationPort(Protocol):
    """Resolve one current hash-only session credential scope."""

    async def authorize(
        self,
        digest: Sha256Digest,
        session_id: Uuid7Id,
        now: datetime,
    ) -> McpSession | None:
        """Return current scope or no authority."""
        ...


@dataclass(frozen=True, slots=True)
class SessionCredentialAuthenticator:
    """Hash a presented session secret and enforce current scope and epoch."""

    repository: SessionAuthorizationPort
    clock: Clock

    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        """Return authenticated session scope or one indistinguishable denial."""
        matched = _BEARER_PATTERN.fullmatch(authorization or "")
        try:
            identifier = Uuid7Id(session_id)
            secret = bytearray.fromhex(matched.group(1) if matched is not None else "")
        except ValueError as error:
            raise _unauthenticated() from error
        try:
            if len(secret) != _SECRET_BYTES:
                raise _unauthenticated()
            digest = Sha256Digest(hashlib.sha256(secret).hexdigest())
            session = await self.repository.authorize(digest, identifier, self.clock.now())
            if session is None:
                raise _unauthenticated()
            return session
        finally:
            secret[:] = bytes(len(secret))


def _unauthenticated() -> OperationError:
    return OperationError(ErrorCode.UNAUTHENTICATED, "session authentication is required")
