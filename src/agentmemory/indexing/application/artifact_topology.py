"""IDX-005 deterministic artifact topology use cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.artifact_topology import (
        ArtifactTopologyBatch,
        ArtifactTopologySnapshot,
        ArtifactTopologySourceArtifact,
        TopologyCandidate,
        TopologyRelationCandidate,
        UnknownTopologyEvidence,
    )
    from agentmemory.indexing.domain.artifact_topology_ports import (
        ArtifactParserPort,
        ArtifactTopologyLineagePort,
        ArtifactTopologyProjectionPort,
        ArtifactTopologyRepository,
    )

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ERR_ACTION = "artifact topology action is not authorized"
_ERR_CONFLICT = "artifact topology command conflicts with durable state"
_ERR_PLUGIN = "artifact topology parser does not exclusively support the artifact"
_ERR_SCOPE = "artifact topology evidence is outside authorized scope"


@dataclass(frozen=True, slots=True)
class RegisterArtifactTopologyBatchCommand:
    """Register and project one complete deterministic parser output."""

    operation_id: str
    scope: AuthorizedScope
    batch: ArtifactTopologyBatch
    registered_at: datetime

    def __post_init__(self) -> None:
        """Validate operation, time, and exact batch authority."""
        _operation(self.operation_id)
        _utc(self.registered_at)
        _authorize_batch(self.scope, self.batch)


@dataclass(frozen=True, slots=True)
class RegisterArtifactTopologyBatchHandler:
    """Append canonical observations then idempotently project graph truth and lineage."""

    repository: ArtifactTopologyRepository
    projection: ArtifactTopologyProjectionPort
    lineage: ArtifactTopologyLineagePort

    async def execute(self, command: RegisterArtifactTopologyBatchCommand) -> ArtifactTopologyBatch:
        """Exactly replay persistence and projection while preserving append-only history."""
        _require_action(command.scope, "indexing.artifact_topology.register")
        existing = await self.repository.find_batch_by_operation(
            command.scope, command.operation_id
        )
        if existing is not None and existing.digest != command.batch.digest:
            raise IndexingConflictError(_ERR_CONFLICT)
        batch = existing or await self.repository.register_batch(
            command.scope,
            command.operation_id,
            command.batch,
            command.registered_at,
        )
        assertion_ids = await self.projection.project(
            command.scope,
            command.operation_id,
            batch,
            command.registered_at,
        )
        if len(assertion_ids) != len(batch.relations):
            raise IndexingConflictError(_ERR_CONFLICT)
        for rank, (relation, assertion_id) in enumerate(
            zip(batch.relations, assertion_ids, strict=True), start=1
        ):
            await self.lineage.register(
                command.scope,
                f"{command.operation_id}:relation:{rank}",
                relation,
                assertion_id,
                command.registered_at,
            )
        return batch


@dataclass(frozen=True, slots=True)
class ExtractAndRegisterArtifactTopologyCommand:
    """Select one deterministic parser for an authorized ephemeral artifact."""

    operation_id: str
    scope: AuthorizedScope
    artifact: ArtifactTopologySourceArtifact
    registered_at: datetime

    def __post_init__(self) -> None:
        """Reject ambient scope and invalid operation/time before parsing bytes."""
        _operation(self.operation_id)
        _utc(self.registered_at)
        evidence = self.artifact.evidence
        if evidence.brain_id != self.scope.brain_id.value or not _scope_contains(
            self.scope, evidence.project_id, evidence.repository_id
        ):
            raise IndexingAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class ExtractAndRegisterArtifactTopologyHandler:
    """Run deterministic parsing before any optional enrichment boundary."""

    parsers: tuple[ArtifactParserPort, ...]
    registration: RegisterArtifactTopologyBatchHandler

    async def execute(
        self, command: ExtractAndRegisterArtifactTopologyCommand
    ) -> ArtifactTopologyBatch:
        """Parse and persist without retaining source bytes or invoking an ungoverned model."""
        _require_action(command.scope, "indexing.artifact_topology.register")
        selected = tuple(
            parser
            for parser in self.parsers
            if parser.supports(command.artifact.evidence.relative_path)
        )
        if len(selected) != 1:
            raise IndexingValidationError(_ERR_PLUGIN)
        batch = selected[0].parse(command.artifact)
        return await self.registration.execute(
            RegisterArtifactTopologyBatchCommand(
                command.operation_id,
                command.scope,
                batch,
                command.registered_at,
            )
        )


@dataclass(frozen=True, slots=True)
class QueryArtifactTopologyCommand:
    """Read the complete authorized latest-per-source topology at a temporal cutoff."""

    scope: AuthorizedScope
    cutoff: datetime

    def __post_init__(self) -> None:
        """Require explicit non-empty scope and UTC cutoff."""
        _utc(self.cutoff)
        if not self.scope.members:
            raise IndexingAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class QueryArtifactTopologyHandler:
    """Return temporal topology without collapsing conflicting environment observations."""

    repository: ArtifactTopologyRepository

    async def execute(self, command: QueryArtifactTopologyCommand) -> ArtifactTopologySnapshot:
        """Authorize before querying the repository."""
        _require_action(command.scope, "indexing.artifact_topology.read")
        return await self.repository.snapshot(command.scope, command.cutoff)


def _authorize_batch(scope: AuthorizedScope, batch: ArtifactTopologyBatch) -> None:
    observations: tuple[
        TopologyCandidate | TopologyRelationCandidate | UnknownTopologyEvidence, ...
    ] = (*batch.candidates, *batch.relations, *batch.unknown_evidence)
    for item in observations:
        evidence = item.evidence
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
