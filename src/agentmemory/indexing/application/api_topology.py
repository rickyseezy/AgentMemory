"""IDX-004 topology extraction, registration, and cross-project linking use cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.api_topology import ApiTopologyLinkPolicy
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.api_topology import (
        ApiTopologyCandidateBatch,
        ApiTopologyLinkDecision,
        ApiTopologySourceArtifact,
        EndpointCandidate,
    )
    from agentmemory.indexing.domain.api_topology_ports import (
        ApiTopologyPluginPort,
        ApiTopologyRepository,
        ConsumesAssertionPort,
        TopologyEvidenceLineagePort,
    )

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERR_ACTION = "API topology action is not authorized"
_ERR_CONFLICT = "API topology command conflicts with durable state"
_ERR_PLUGIN = "API topology plugin does not support the artifact"
_ERR_SCOPE = "API topology candidate is outside authorized scope"


@dataclass(frozen=True, slots=True)
class RegisterApiTopologyBatchCommand:
    """Append one complete plugin result for an immutable source revision."""

    operation_id: str
    scope: AuthorizedScope
    batch: ApiTopologyCandidateBatch
    registered_at: datetime

    def __post_init__(self) -> None:
        """Validate operation identity, UTC time, and exact candidate scope membership."""
        _operation(self.operation_id)
        _utc(self.registered_at)
        _authorize_batch(self.scope, self.batch)


@dataclass(frozen=True, slots=True)
class RegisterApiTopologyBatchHandler:
    """Persist complete candidates so an empty batch can represent removal."""

    repository: ApiTopologyRepository

    async def execute(self, command: RegisterApiTopologyBatchCommand) -> ApiTopologyCandidateBatch:
        """Exactly replay or append one source-revision candidate batch."""
        _require_action(command.scope, "indexing.api_topology.register")
        existing = await self.repository.find_batch_by_operation(
            command.scope, command.operation_id
        )
        if existing is not None:
            if existing.digest != command.batch.digest:
                raise IndexingConflictError(_ERR_CONFLICT)
            return existing
        return await self.repository.register_batch(
            command.scope,
            command.operation_id,
            command.batch,
            command.registered_at,
        )


@dataclass(frozen=True, slots=True)
class ExtractAndRegisterApiTopologyCommand:
    """Run one selected deterministic plugin then persist its complete output."""

    operation_id: str
    scope: AuthorizedScope
    artifact: ApiTopologySourceArtifact
    registered_at: datetime

    def __post_init__(self) -> None:
        """Validate command and exact source evidence authority."""
        _operation(self.operation_id)
        _utc(self.registered_at)
        evidence = self.artifact.evidence
        if not _scope_contains(self.scope, evidence.project_id, evidence.repository_id):
            raise IndexingAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class ExtractAndRegisterApiTopologyHandler:
    """Select exactly one owning parser and delegate canonical persistence."""

    plugins: tuple[ApiTopologyPluginPort, ...]
    registration: RegisterApiTopologyBatchHandler

    async def execute(
        self, command: ExtractAndRegisterApiTopologyCommand
    ) -> ApiTopologyCandidateBatch:
        """Extract deterministically and register without retaining raw artifact bytes."""
        _require_action(command.scope, "indexing.api_topology.register")
        selected = tuple(
            plugin
            for plugin in self.plugins
            if plugin.supports(command.artifact.evidence.relative_path)
        )
        if len(selected) != 1:
            raise IndexingValidationError(_ERR_PLUGIN)
        batch = selected[0].extract(command.artifact)
        return await self.registration.execute(
            RegisterApiTopologyBatchCommand(
                command.operation_id,
                command.scope,
                batch,
                command.registered_at,
            )
        )


@dataclass(frozen=True, slots=True)
class LinkApiTopologyCommand:
    """Link one client call across every explicitly authorized project and repository."""

    operation_id: str
    scope: AuthorizedScope
    client_call_id: str
    linked_at: datetime

    def __post_init__(self) -> None:
        """Require stable command identity, candidate identity, UTC, and a non-empty scope."""
        _operation(self.operation_id)
        if _DIGEST.fullmatch(self.client_call_id) is None:
            raise IndexingValidationError(_ERR_CONFLICT)
        _utc(self.linked_at)
        if not self.scope.members:
            raise IndexingAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class LinkApiTopologyHandler:
    """Apply deterministic precedence, materialize assertions, and register stale lineage."""

    repository: ApiTopologyRepository
    assertions: ConsumesAssertionPort
    lineage: TopologyEvidenceLineagePort

    async def execute(self, command: LinkApiTopologyCommand) -> ApiTopologyLinkDecision:
        """Exactly replay or link one client call with complete evidence and qualification."""
        _require_action(command.scope, "indexing.api_topology.link")
        replay = await self.repository.find_link_decision(command.scope, command.operation_id)
        if replay is not None:
            if replay.client_call_id != command.client_call_id:
                raise IndexingConflictError(_ERR_CONFLICT)
            return replay
        client, endpoints, contracts, ownership = await self.repository.load_link_universe(
            command.scope,
            command.client_call_id,
            command.linked_at,
        )
        decision = ApiTopologyLinkPolicy.link(client, endpoints, contracts, ownership)
        endpoint_by_id: dict[str, EndpointCandidate] = {item.id: item for item in endpoints}
        assertion_ids: list[str] = []
        for match in decision.matches:
            endpoint = endpoint_by_id[match.endpoint_id]
            assertion_id = await self.assertions.record(
                command.scope,
                match,
                command.linked_at,
            )
            assertion_ids.append(assertion_id)
            await self.lineage.register(
                command.scope,
                f"{command.operation_id}:client:{match.rank}",
                client.evidence.source_revision_context_id,
                client.evidence.source_semantic_id,
                client.evidence.evidence_id,
                assertion_id,
                command.linked_at,
            )
            await self.lineage.register(
                command.scope,
                f"{command.operation_id}:server:{match.rank}",
                endpoint.evidence.source_revision_context_id,
                endpoint.evidence.source_semantic_id,
                endpoint.evidence.evidence_id,
                assertion_id,
                command.linked_at,
            )
        return await self.repository.record_link_decision(
            command.scope,
            command.operation_id,
            decision,
            tuple(assertion_ids),
            command.linked_at,
        )


def _authorize_batch(scope: AuthorizedScope, batch: ApiTopologyCandidateBatch) -> None:
    for candidate in batch.candidates:
        evidence = candidate.evidence
        if evidence.brain_id != scope.brain_id.value or not _scope_contains(
            scope, evidence.project_id, evidence.repository_id
        ):
            raise IndexingAuthorizationError(_ERR_SCOPE)


def _scope_contains(scope: AuthorizedScope, project_id: str, repository_id: str) -> bool:
    return any(
        member.project_id.value == project_id
        and repository_id in {value.value for value in member.repository_ids}
        for member in scope.members
    )


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _operation(value: str) -> None:
    if _OPERATION.fullmatch(value) is None:
        raise IndexingValidationError(_ERR_CONFLICT)


def _utc(value: datetime) -> None:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise IndexingValidationError(_ERR_CONFLICT)
