"""PF-005 projection adapter that queues sanitized checkpoints into IDX-002."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeQuery,
)
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, RetrievalScopeMode
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.indexing.application.incremental_index import StartIndexRunCommand
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution
    from agentmemory.indexing.domain.incremental import IndexRun
    from agentmemory.operations.domain.mcp_session import McpSessionRegistration
    from agentmemory.operations.domain.workspace_checkpoint import WorkspaceCheckpointBatch
    from agentmemory.shared.clock import Clock


class _ScopeResolver(Protocol):
    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Resolve current canonical authority."""
        ...


class _StartIndexRun(Protocol):
    async def execute(self, command: StartIndexRunCommand) -> IndexRun:
        """Durably queue or replay one exact index run."""
        ...


@dataclass(frozen=True, slots=True)
class WorkspaceCheckpointIndexProjection:
    """Turn one ingested batch into one authorization-bound durable index run."""

    scopes: _ScopeResolver
    start: _StartIndexRun
    clock: Clock

    async def project(
        self,
        batch: WorkspaceCheckpointBatch,
        registration: McpSessionRegistration,
    ) -> None:
        """Queue the exact checkpoint manifest before its ingestion receipt is appended."""
        if registration.project_id is None or registration.repository_id is None:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace index scope is unavailable",
                retryable=True,
            )
        now = self.clock.now()
        operation_id = f"pf005-index-{batch.batch_digest.value}"
        try:
            resolution = await self.scopes.execute(
                ResolveRetrievalScopeQuery(
                    operation_id,
                    StableId(registration.brain_id.value),
                    StableId(registration.actor_id.value),
                    StableId(registration.grant_id.value),
                    RetrievalScopeMode.CURRENT,
                    StableId(registration.project_id.value),
                    StableId(registration.repository_id.value),
                    (
                        None
                        if registration.checkout_id is None
                        else StableId(registration.checkout_id.value)
                    ),
                    (),
                    _microseconds(now),
                )
            )
            resolved = resolution.scope
            scope = AuthorizedScope.create(
                brain_id=resolved.brain_id,
                principal_id=resolved.principal_id,
                role=resolved.role,
                mode=resolved.mode,
                members=resolved.members,
                classification_ceiling=resolved.classification_ceiling,
                temporal_scope=resolved.temporal_scope,
                grant_version=resolved.grant_version,
                policy_version=resolved.policy_version,
                security_epoch=resolved.security_epoch,
                action="indexing.run.start",
                purpose="automatic_indexing",
            )
            run = await self.start.execute(
                StartIndexRunCommand(
                    operation_id,
                    scope,
                    batch.batch_digest.value,
                    include_generated=False,
                    detected_at=now,
                )
            )
            _require_ack(
                run,
                operation_id,
                registration.repository_id.value,
                batch.batch_digest.value,
            )
        except OperationError:
            raise
        except (IdentityAuthorizationError, IndexingAuthorizationError) as error:
            raise OperationError(
                ErrorCode.FORBIDDEN,
                "workspace index is not authorized",
            ) from error
        except (IdentityConflictError, IndexingConflictError) as error:
            raise OperationError(
                ErrorCode.CONFLICT,
                "workspace index conflicted",
            ) from error
        except (IdentityDependencyError, IndexingUnavailableError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace indexing is unavailable",
                retryable=True,
            ) from error
        except (IdentityValidationError, IndexingValidationError) as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "workspace index input is invalid",
            ) from error


def _microseconds(value: datetime) -> int:
    return int(value.timestamp()) * 1_000_000 + value.microsecond


def _require_ack(
    run: IndexRun,
    operation: str,
    repository: str,
    target: str,
) -> None:
    if (
        run.operation_id != operation
        or run.repository_id != repository
        or run.target_commit_id != target
    ):
        raise OperationError(
            ErrorCode.INTEGRITY_VIOLATION,
            "workspace index acknowledgement is invalid",
        )
