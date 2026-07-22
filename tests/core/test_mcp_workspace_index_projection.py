"""PF-005 automatic checkpoint indexing projection tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.operations.adapters.outbound.workspace_checkpoint_indexing import (
    WorkspaceCheckpointIndexProjection,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import McpGitCoverage, McpSessionRegistration
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import WorkspaceCheckpointBatch
from tests.core.support import FixedClock
from tests.retrieval.support import scope

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.indexing.application.incremental_index import StartIndexRunCommand
    from agentmemory.indexing.domain.incremental import IndexRun

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)
_SESSION = Uuid7Id("019d2b4e-7a10-7def-8abc-0123456789ab")
_REPOSITORY = Uuid7Id("019d2b4e-7a16-7def-8abc-0123456789ab")


@dataclass(slots=True)
class _Resolver:
    error: Exception | None = None
    query: ResolveRetrievalScopeQuery | None = None

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        self.query = query
        if self.error is not None:
            raise self.error
        authorized = scope()
        return RetrievalScopeResolution(
            authorized,
            ScopeExplanation(authorized.mode, ("current:project",)),
        )


@dataclass(frozen=True, slots=True)
class _Ack:
    operation_id: str
    repository_id: str
    target_commit_id: str | None


@dataclass(slots=True)
class _Starter:
    error: Exception | None = None
    divergent: bool = False
    command: StartIndexRunCommand | None = None

    async def execute(self, command: StartIndexRunCommand) -> IndexRun:
        self.command = command
        if self.error is not None:
            raise self.error
        acknowledgement = _Ack(
            "foreign" if self.divergent else command.operation_id,
            _REPOSITORY.value,
            command.target_commit_id,
        )
        return cast("IndexRun", acknowledgement)


@pytest.mark.asyncio
async def test_pf005_projection_queues_exact_checkpoint_under_current_scope() -> None:
    resolver = _Resolver()
    starter = _Starter()
    batch = _batch()
    registration = replace(
        _registration(),
        checkout_id=Uuid7Id("019d2b4e-7a17-7def-8abc-0123456789ab"),
    )
    await WorkspaceCheckpointIndexProjection(
        resolver,
        starter,
        FixedClock(_NOW),
    ).project(batch, registration)

    assert resolver.query is not None
    assert resolver.query.current_checkout_id is not None
    assert starter.command is not None
    assert starter.command.target_commit_id == batch.batch_digest.value
    assert starter.command.include_generated is False
    assert starter.command.scope.action == "indexing.run.start"
    assert starter.command.scope.purpose == "automatic_indexing"


@pytest.mark.asyncio
async def test_pf005_projection_requires_canonical_workspace_and_exact_acknowledgement() -> None:
    projection = WorkspaceCheckpointIndexProjection(_Resolver(), _Starter(), FixedClock(_NOW))
    with pytest.raises(OperationError) as absent:
        await projection.project(
            _batch(),
            replace(_registration(), project_id=None, repository_id=None),
        )
    assert absent.value.code is ErrorCode.DEPENDENCY_UNAVAILABLE
    assert absent.value.retryable

    divergent = WorkspaceCheckpointIndexProjection(
        _Resolver(),
        _Starter(divergent=True),
        FixedClock(_NOW),
    )
    with pytest.raises(OperationError) as acknowledgement:
        await divergent.project(_batch(), _registration())
    assert acknowledgement.value.code is ErrorCode.INTEGRITY_VIOLATION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (IdentityAuthorizationError("private"), ErrorCode.FORBIDDEN),
        (IndexingAuthorizationError("private"), ErrorCode.FORBIDDEN),
        (IdentityConflictError("private"), ErrorCode.CONFLICT),
        (IndexingConflictError("private"), ErrorCode.CONFLICT),
        (IdentityDependencyError("private"), ErrorCode.DEPENDENCY_UNAVAILABLE),
        (IndexingUnavailableError("private"), ErrorCode.DEPENDENCY_UNAVAILABLE),
        (IdentityValidationError("private"), ErrorCode.INTEGRITY_VIOLATION),
        (IndexingValidationError("private"), ErrorCode.INTEGRITY_VIOLATION),
    ],
)
async def test_pf005_projection_maps_dependency_taxonomy_without_leaking_content(
    failure: Exception,
    expected: ErrorCode,
) -> None:
    projection = WorkspaceCheckpointIndexProjection(
        _Resolver(error=failure),
        _Starter(),
        FixedClock(_NOW),
    )
    with pytest.raises(OperationError) as raised:
        await projection.project(_batch(), _registration())
    assert raised.value.code is expected
    assert "private" not in str(raised.value)
    assert raised.value.retryable is (expected is ErrorCode.DEPENDENCY_UNAVAILABLE)


@pytest.mark.asyncio
async def test_pf005_projection_preserves_already_safe_operation_failures() -> None:
    expected = OperationError(ErrorCode.CAPACITY_EXHAUSTED, "safe", retryable=True)
    projection = WorkspaceCheckpointIndexProjection(
        _Resolver(error=expected),
        _Starter(),
        FixedClock(_NOW),
    )
    with pytest.raises(OperationError) as raised:
        await projection.project(_batch(), _registration())
    assert raised.value is expected


def _digest(value: str) -> Sha256Digest:
    return Sha256Digest(hashlib.sha256(value.encode()).hexdigest())


def _batch() -> WorkspaceCheckpointBatch:
    fingerprint = _digest("workspace")
    canonical = json.dumps(
        {
            "session_id": _SESSION.value,
            "workspace_fingerprint": fingerprint.value,
            "batch_digest": "",
            "partial": False,
            "changes": [],
        },
        separators=(",", ":"),
    ).encode()
    return WorkspaceCheckpointBatch(
        session_id=_SESSION,
        workspace_fingerprint=fingerprint,
        batch_digest=Sha256Digest(hashlib.sha256(canonical).hexdigest()),
        partial=False,
        changes=(),
    )


def _registration() -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=_SESSION,
        installation_id=Uuid7Id("019d2b4e-7a11-7def-8abc-0123456789ab"),
        brain_id=Uuid7Id("019d2b4e-7a12-7def-8abc-0123456789ab"),
        actor_id=Uuid7Id("019d2b4e-7a13-7def-8abc-0123456789ab"),
        grant_id=Uuid7Id("019d2b4e-7a14-7def-8abc-0123456789ab"),
        agent_id="codex",
        workspace_fingerprint=_digest("workspace"),
        device_identity="dev:1",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=7,
        credential_digest=_digest("credential"),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(hours=12),
        project_id=Uuid7Id("019d2b4e-7a15-7def-8abc-0123456789ab"),
        repository_id=_REPOSITORY,
    )
