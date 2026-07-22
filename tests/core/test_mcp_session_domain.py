"""PF-005 session credential and lease domain acceptance tests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSession,
    McpSessionRegistration,
    McpSessionState,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
    WorkspaceCheckpointIngestionResult,
)

NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
SESSION = Uuid7Id("019d2b4e-7a10-7def-8abc-0123456789ab")
INSTALLATION = Uuid7Id("019d2b4e-7a11-7def-8abc-0123456789ab")
DIGEST = Sha256Digest("b" * 64)
WORKSPACE = Sha256Digest("a" * 64)


def test_pf005_session_lifecycle_is_closed_monotonic_and_revocable() -> None:
    registration = _registration()
    session = McpSession.register(registration)
    assert session.state is McpSessionState.REGISTERED
    assert session.revision == 0

    active = session.begin(NOW, timedelta(seconds=120))
    assert active.begin(NOW, timedelta(seconds=120)) is active
    assert active.state is McpSessionState.ACTIVE
    assert active.lease_expires_at == NOW + timedelta(seconds=120)
    heartbeat = active.heartbeat(NOW + timedelta(seconds=30))
    assert heartbeat.heartbeat(NOW + timedelta(seconds=30)) is heartbeat
    assert heartbeat.last_heartbeat_at == NOW + timedelta(seconds=30)
    assert heartbeat.lease_expires_at == NOW + timedelta(seconds=150)

    revoked = heartbeat.revoke(NOW + timedelta(seconds=31))
    assert revoked.revoked_at == NOW + timedelta(seconds=31)
    assert revoked.revoke(NOW + timedelta(seconds=31)) == revoked
    finished = revoked.finish(McpSessionState.COMPLETED, NOW + timedelta(seconds=32))
    assert finished.state is McpSessionState.COMPLETED
    assert finished.finished_at == NOW + timedelta(seconds=32)
    assert finished.finish(McpSessionState.COMPLETED, NOW + timedelta(seconds=32)) == finished


def test_pf005_expired_active_session_becomes_interrupted_never_completed() -> None:
    active = McpSession.register(_registration()).begin(NOW, timedelta(seconds=120))
    assert not active.expired(NOW + timedelta(seconds=119))
    assert active.expired(NOW + timedelta(seconds=120))
    interrupted = active.interrupt_if_expired(NOW + timedelta(seconds=120))
    assert interrupted.state is McpSessionState.INTERRUPTED
    assert interrupted.revoked_at == NOW + timedelta(seconds=120)
    assert interrupted.finished_at == NOW + timedelta(seconds=120)


RegistrationMutation = Callable[[McpSessionRegistration], McpSessionRegistration]


def _invalid_authority_mutations() -> tuple[RegistrationMutation, ...]:
    return (
        lambda registration: replace(registration, agent_id="Codex;rm"),
        lambda registration: replace(registration, security_epoch=0),
        lambda registration: replace(registration, issued_at=NOW.replace(tzinfo=None)),
        lambda registration: replace(
            registration,
            expires_at=NOW + timedelta(hours=12, microseconds=1),
        ),
    )


@pytest.mark.parametrize("mutation", _invalid_authority_mutations())
def test_pf005_registration_rejects_invalid_or_overlong_authority(
    mutation: RegistrationMutation,
) -> None:
    with pytest.raises(DomainValidationError):
        mutation(_registration())


def test_pf005_session_rejects_backward_time_invalid_transition_and_post_revoke_heartbeat() -> None:
    active = McpSession.register(_registration()).begin(NOW, timedelta(seconds=120))
    with pytest.raises(DomainValidationError):
        active.heartbeat(NOW - timedelta(microseconds=1))
    revoked = active.revoke(NOW + timedelta(seconds=1))
    with pytest.raises(DomainValidationError):
        revoked.heartbeat(NOW + timedelta(seconds=2))
    registered_revoked = McpSession.register(_registration()).revoke(NOW)
    with pytest.raises(DomainValidationError):
        registered_revoked.begin(NOW, timedelta(seconds=120))
    completed = active.finish(McpSessionState.COMPLETED, NOW + timedelta(seconds=1))
    with pytest.raises(DomainValidationError):
        completed.finish(McpSessionState.INTERRUPTED, NOW + timedelta(seconds=2))
    with pytest.raises(DomainValidationError):
        replace(active, revision=-1)


def test_pf005_session_rejects_all_temporal_and_terminal_divergence() -> None:
    registered = McpSession.register(_registration())
    with pytest.raises(DomainValidationError, match="credential is not current"):
        registered.begin(NOW - timedelta(microseconds=1), timedelta(seconds=1))
    active = registered.begin(NOW, timedelta(seconds=120))
    with pytest.raises(DomainValidationError, match="revocation diverged"):
        active.revoke(NOW).revoke(NOW + timedelta(microseconds=1))
    with pytest.raises(DomainValidationError, match="revocation time"):
        active.revoke(NOW - timedelta(microseconds=1))
    with pytest.raises(DomainValidationError, match="terminal transition"):
        active.finish(McpSessionState.ACTIVE, NOW)
    with pytest.raises(DomainValidationError, match="finish time"):
        active.heartbeat(NOW + timedelta(seconds=1)).finish(
            McpSessionState.INTERRUPTED,
            NOW,
        )
    with pytest.raises(DomainValidationError, match="not expired"):
        active.interrupt_if_expired(NOW + timedelta(seconds=119))


def _invalid_scope_mutations() -> tuple[RegistrationMutation, ...]:
    return (
        lambda registration: replace(registration, device_identity=""),
        lambda registration: replace(registration, device_identity="device\nforeign"),
        lambda registration: replace(registration, git_repository_id="not-a-digest"),
        lambda registration: replace(registration, git_coverage=McpGitCoverage.PARTIAL),
        lambda registration: replace(
            registration,
            project_id=Uuid7Id("019d2b4e-7a15-7def-8abc-0123456789ab"),
        ),
        lambda registration: replace(
            registration,
            checkout_id=Uuid7Id("019d2b4e-7a16-7def-8abc-0123456789ab"),
        ),
    )


@pytest.mark.parametrize("mutation", _invalid_scope_mutations())
def test_pf005_registration_rejects_incomplete_identity_and_scope_pairs(
    mutation: RegistrationMutation,
) -> None:
    with pytest.raises(DomainValidationError):
        mutation(_registration())


def test_pf005_registration_accepts_complete_git_and_workspace_scope() -> None:
    git_digest = "c" * 64
    registration = replace(
        _registration(),
        git_repository_id=git_digest,
        git_worktree_id="d" * 64,
        git_coverage=McpGitCoverage.COMPLETE,
        project_id=Uuid7Id("019d2b4e-7a15-7def-8abc-0123456789ab"),
        repository_id=Uuid7Id("019d2b4e-7a16-7def-8abc-0123456789ab"),
        checkout_id=Uuid7Id("019d2b4e-7a17-7def-8abc-0123456789ab"),
    )
    assert registration.git_repository_id == git_digest


@pytest.mark.parametrize(
    "path",
    ["", "/absolute", "../escape", "a//b", "a\\b", "a\nforeign", "a" * 4097],
)
def test_pf005_checkpoint_change_rejects_unsafe_relative_paths(path: str) -> None:
    with pytest.raises(DomainValidationError):
        WorkspaceCheckpointChange(
            relative_path=path,
            sha256=_sha(b"content"),
            content=b"content",
            deleted=False,
        )


def test_pf005_checkpoint_contract_rejects_content_order_digest_and_count_divergence() -> None:
    with pytest.raises(DomainValidationError):
        WorkspaceCheckpointChange(
            relative_path="large",
            sha256=_sha(b""),
            content=b"x" * (2 * 1024 * 1024 + 1),
            deleted=False,
        )
    with pytest.raises(DomainValidationError):
        WorkspaceCheckpointChange(
            relative_path="deleted",
            sha256=_sha(b"content"),
            content=b"content",
            deleted=True,
        )
    with pytest.raises(DomainValidationError):
        WorkspaceCheckpointChange(
            relative_path="changed",
            sha256=_sha(b"other"),
            content=b"content",
            deleted=False,
        )

    first = WorkspaceCheckpointChange(
        relative_path="b", sha256=_sha(b"b"), content=b"b", deleted=False
    )
    second = WorkspaceCheckpointChange(
        relative_path="a", sha256=_sha(b"a"), content=b"a", deleted=False
    )
    with pytest.raises(DomainValidationError, match="paths"):
        _checkpoint((first, second))
    with pytest.raises(DomainValidationError, match="paths"):
        _checkpoint((second, second))
    with pytest.raises(DomainValidationError, match="digest"):
        WorkspaceCheckpointBatch(
            session_id=SESSION,
            workspace_fingerprint=WORKSPACE,
            batch_digest=DIGEST,
            partial=False,
            changes=(),
        )
    with pytest.raises(DomainValidationError, match="too many"):
        WorkspaceCheckpointBatch(
            session_id=SESSION,
            workspace_fingerprint=WORKSPACE,
            batch_digest=DIGEST,
            partial=False,
            changes=(second,) * 10_001,
        )
    for count in (-1, True, 10_001):
        with pytest.raises(DomainValidationError, match="ingestion result"):
            WorkspaceCheckpointIngestionResult(DIGEST, count)


def _sha(content: bytes) -> Sha256Digest:
    return Sha256Digest(hashlib.sha256(content).hexdigest())


def _checkpoint(
    changes: tuple[WorkspaceCheckpointChange, ...],
) -> WorkspaceCheckpointBatch:
    document = {
        "session_id": SESSION.value,
        "workspace_fingerprint": WORKSPACE.value,
        "batch_digest": "",
        "partial": False,
        "changes": [change.document() for change in changes],
    }
    canonical = json.dumps(document, separators=(",", ":")).encode()
    return WorkspaceCheckpointBatch(
        session_id=SESSION,
        workspace_fingerprint=WORKSPACE,
        batch_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        partial=False,
        changes=changes,
    )


def _registration() -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=SESSION,
        installation_id=INSTALLATION,
        brain_id=Uuid7Id("019d2b4e-7a12-7def-8abc-0123456789ab"),
        actor_id=Uuid7Id("019d2b4e-7a13-7def-8abc-0123456789ab"),
        grant_id=Uuid7Id("019d2b4e-7a14-7def-8abc-0123456789ab"),
        agent_id="codex",
        workspace_fingerprint=WORKSPACE,
        device_identity="dev:1",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=7,
        credential_digest=DIGEST,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=12),
    )
