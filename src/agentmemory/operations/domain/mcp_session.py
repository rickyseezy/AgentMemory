"""PF-005 short-lived credential and heartbeat session aggregate."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.value_objects import (
    Sha256Digest,
    Uuid7Id,
    require_utc_microseconds,
)

_MAX_CREDENTIAL_TTL: Final = timedelta(hours=12)
_MAX_LEASE: Final = timedelta(seconds=120)
_AGENT_ID = re.compile(r"^[a-z0-9_.-]{1,64}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_IDENTITY_LENGTH: Final = 512


class McpSessionState(StrEnum):
    """Closed durable PF-005 session lifecycle."""

    REGISTERED = "registered"
    ACTIVE = "active"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"


class McpGitCoverage(StrEnum):
    """Whether the selected workspace mount contains the resolved Git metadata."""

    NONE = "none"
    PARTIAL = "partial"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class McpSessionRegistration:
    """Hash-only authority registered by the root-authenticated launcher."""

    session_id: Uuid7Id
    installation_id: Uuid7Id
    brain_id: Uuid7Id
    actor_id: Uuid7Id
    grant_id: Uuid7Id
    agent_id: str
    workspace_fingerprint: Sha256Digest
    device_identity: str
    git_repository_id: str | None
    git_worktree_id: str | None
    git_coverage: McpGitCoverage
    security_epoch: int
    credential_digest: Sha256Digest
    issued_at: datetime
    expires_at: datetime
    project_id: Uuid7Id | None = None
    repository_id: Uuid7Id | None = None
    checkout_id: Uuid7Id | None = None

    def __post_init__(self) -> None:
        """Require canonical bounded authority and a maximum twelve-hour lifetime."""
        issued = require_utc_microseconds(self.issued_at)
        expires = require_utc_microseconds(self.expires_at)
        if (
            _AGENT_ID.fullmatch(self.agent_id) is None
            or not _valid_identity(self.device_identity)
            or not _valid_git_scope(
                self.git_repository_id,
                self.git_worktree_id,
                self.git_coverage,
            )
            or isinstance(self.security_epoch, bool)
            or self.security_epoch < 1
            or expires <= issued
            or expires - issued > _MAX_CREDENTIAL_TTL
            or ((self.project_id is None) != (self.repository_id is None))
            or (self.checkout_id is not None and self.repository_id is None)
        ):
            message = "MCP session registration is invalid"
            raise DomainValidationError(message)
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)


@dataclass(frozen=True, slots=True)
class McpWorkspaceScope:
    """Canonical existing Project/Repository/Checkout selected by Core."""

    project_id: Uuid7Id
    repository_id: Uuid7Id
    checkout_id: Uuid7Id | None


def _valid_identity(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= _MAX_IDENTITY_LENGTH
        and not any(character in value for character in "\x00\r\n")
    )


def _valid_git_scope(
    repository_id: str | None,
    worktree_id: str | None,
    coverage: McpGitCoverage,
) -> bool:
    values = (repository_id, worktree_id)
    if any(value is not None and not _valid_identity(value) for value in values):
        return False
    if coverage is McpGitCoverage.NONE:
        return values == (None, None)
    return (
        repository_id is not None
        and worktree_id is not None
        and _DIGEST.fullmatch(repository_id) is not None
        and _DIGEST.fullmatch(worktree_id) is not None
    )


@dataclass(frozen=True, slots=True)
class McpSession:
    """One durable session lease and terminal outcome."""

    registration: McpSessionRegistration
    state: McpSessionState
    lease_duration: timedelta | None
    lease_expires_at: datetime | None
    last_heartbeat_at: datetime | None
    revoked_at: datetime | None
    finished_at: datetime | None
    revision: int

    def __post_init__(self) -> None:
        """Reject impossible restored aggregate combinations."""
        if self.revision < 0:
            message = "MCP session revision is invalid"
            raise DomainValidationError(message)
        for value in (
            self.lease_expires_at,
            self.last_heartbeat_at,
            self.revoked_at,
            self.finished_at,
        ):
            if value is not None:
                require_utc_microseconds(value)
        if self.state is McpSessionState.REGISTERED:
            valid = (
                self.lease_duration is None
                and self.lease_expires_at is None
                and self.last_heartbeat_at is None
                and self.finished_at is None
            )
        elif self.state is McpSessionState.ACTIVE:
            valid = (
                self.lease_duration is not None
                and timedelta(0) < self.lease_duration <= _MAX_LEASE
                and self.lease_expires_at is not None
                and self.last_heartbeat_at is not None
                and self.finished_at is None
            )
        else:
            valid = (
                self.lease_duration is not None
                and timedelta(0) < self.lease_duration <= _MAX_LEASE
                and self.lease_expires_at is not None
                and self.last_heartbeat_at is not None
                and self.finished_at is not None
            )
        ordered = (
            (
                self.last_heartbeat_at is None
                or self.last_heartbeat_at >= self.registration.issued_at
            )
            and (self.revoked_at is None or self.revoked_at >= self.registration.issued_at)
            and (
                self.finished_at is None
                or (
                    self.last_heartbeat_at is not None
                    and self.finished_at >= self.last_heartbeat_at
                )
            )
        )
        if not valid or not ordered:
            message = "MCP session state is inconsistent"
            raise DomainValidationError(message)

    @classmethod
    def register(cls, registration: McpSessionRegistration) -> McpSession:
        """Create the initial non-runnable credential authority."""
        return cls(registration, McpSessionState.REGISTERED, None, None, None, None, None, 0)

    def begin(self, now: datetime, lease: timedelta) -> McpSession:
        """Activate a registered session with a bounded heartbeat lease."""
        timestamp = require_utc_microseconds(now)
        if (
            self.state is McpSessionState.ACTIVE
            and self.revoked_at is None
            and self.last_heartbeat_at == timestamp
            and self.lease_duration == lease
        ):
            return self
        if (
            self.state is not McpSessionState.REGISTERED
            or self.revoked_at is not None
            or not timedelta(0) < lease <= _MAX_LEASE
        ):
            message = "MCP session cannot begin"
            raise DomainValidationError(message)
        if timestamp < self.registration.issued_at or timestamp >= self.registration.expires_at:
            message = "MCP session credential is not current"
            raise DomainValidationError(message)
        return replace(
            self,
            state=McpSessionState.ACTIVE,
            lease_duration=lease,
            lease_expires_at=timestamp + lease,
            last_heartbeat_at=timestamp,
            revision=self.revision + 1,
        )

    def heartbeat(self, now: datetime) -> McpSession:
        """Renew an active, unrevoked lease without exceeding credential expiry."""
        timestamp = require_utc_microseconds(now)
        if (
            self.state is McpSessionState.ACTIVE
            and self.revoked_at is None
            and self.last_heartbeat_at == timestamp
        ):
            return self
        if (
            self.state is not McpSessionState.ACTIVE
            or self.revoked_at is not None
            or self.lease_duration is None
            or self.last_heartbeat_at is None
            or timestamp < self.last_heartbeat_at
            or timestamp >= self.registration.expires_at
        ):
            message = "MCP session heartbeat is invalid"
            raise DomainValidationError(message)
        return replace(
            self,
            last_heartbeat_at=timestamp,
            lease_expires_at=min(timestamp + self.lease_duration, self.registration.expires_at),
            revision=self.revision + 1,
        )

    def revoke(self, now: datetime) -> McpSession:
        """Make the credential unusable; exact replay is idempotent."""
        timestamp = require_utc_microseconds(now)
        if self.revoked_at is not None:
            if self.revoked_at != timestamp:
                message = "MCP session revocation diverged"
                raise DomainValidationError(message)
            return self
        if timestamp < self.registration.issued_at:
            message = "MCP session revocation time is invalid"
            raise DomainValidationError(message)
        return replace(self, revoked_at=timestamp, revision=self.revision + 1)

    def finish(self, state: McpSessionState, now: datetime) -> McpSession:
        """Record only completed or interrupted as terminal outcomes."""
        timestamp = require_utc_microseconds(now)
        if self.state in {McpSessionState.COMPLETED, McpSessionState.INTERRUPTED}:
            if self.state is state and self.finished_at == timestamp:
                return self
            message = "MCP session terminal outcome diverged"
            raise DomainValidationError(message)
        if self.state is not McpSessionState.ACTIVE or state not in {
            McpSessionState.COMPLETED,
            McpSessionState.INTERRUPTED,
        }:
            message = "MCP session terminal transition is invalid"
            raise DomainValidationError(message)
        if self.last_heartbeat_at is None or timestamp < self.last_heartbeat_at:
            message = "MCP session finish time is invalid"
            raise DomainValidationError(message)
        return replace(self, state=state, finished_at=timestamp, revision=self.revision + 1)

    def expired(self, now: datetime) -> bool:
        """Report an active session whose lease or credential has expired."""
        timestamp = require_utc_microseconds(now)
        return (
            self.state is McpSessionState.ACTIVE
            and self.lease_expires_at is not None
            and (timestamp >= self.lease_expires_at or timestamp >= self.registration.expires_at)
        )

    def interrupt_if_expired(self, now: datetime) -> McpSession:
        """Atomically revoke and interrupt only an expired active session."""
        timestamp = require_utc_microseconds(now)
        if not self.expired(timestamp):
            message = "MCP session lease is not expired"
            raise DomainValidationError(message)
        return replace(
            self,
            state=McpSessionState.INTERRUPTED,
            revoked_at=self.revoked_at or timestamp,
            finished_at=timestamp,
            revision=self.revision + 1,
        )
