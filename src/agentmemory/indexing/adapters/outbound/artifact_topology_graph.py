"""IDX-005 adapters to canonical graph entities, assertions, receipts, and lineage."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
)
from agentmemory.graph.application.project_entity import (
    ProjectGraphEntityCommand,
    ProjectGraphEntityHandler,
)
from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionExtractor,
    AssertionPredicate,
    AssertionScope,
    AssertionTemporal,
)
from agentmemory.graph.domain.models import GraphClassification, GraphEntity, GraphEntityType
from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
from agentmemory.indexing.application.revision_history import (
    RegisterEvidenceLineageCommand,
    RegisterEvidenceLineageHandler,
)
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    TopologyCandidate,
    TopologyEntityKind,
    TopologyRelationCandidate,
    TopologyRelationKind,
)
from agentmemory.indexing.domain.errors import IndexingConflictError, IndexingUnavailableError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertion_ports import ScopedAssertionRepositoryFactory
    from agentmemory.graph.domain.ports import ScopedGraphRepositoryFactory
    from agentmemory.indexing.domain.revision_history_ports import SourceRevisionRepository
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_CONFLICT = "artifact topology projection conflicts with canonical state"
_ERR_STORAGE = "artifact topology projection storage is unavailable"
_PREDICATES = {
    TopologyRelationKind.DEPENDS_ON: AssertionPredicate.DEPENDS_ON,
    TopologyRelationKind.DEPLOYED_AS: AssertionPredicate.DEPLOYED_AS,
    TopologyRelationKind.PRODUCES: AssertionPredicate.PRODUCES,
    TopologyRelationKind.CONSUMES: AssertionPredicate.CONSUMES,
}
_ENTITY_TYPES = {
    TopologyEntityKind.PACKAGE: GraphEntityType.PACKAGE,
    TopologyEntityKind.CONTAINER_IMAGE: GraphEntityType.DEPLOYMENT,
    TopologyEntityKind.WORKLOAD: GraphEntityType.DEPLOYMENT,
    TopologyEntityKind.INFRASTRUCTURE_RESOURCE: GraphEntityType.DEPENDENCY,
    TopologyEntityKind.PIPELINE: GraphEntityType.PROCEDURE,
    TopologyEntityKind.ENVIRONMENT_REFERENCE: GraphEntityType.ENVIRONMENT,
    TopologyEntityKind.MESSAGE_CHANNEL: GraphEntityType.CONTRACT,
    TopologyEntityKind.EVENT_SCHEMA: GraphEntityType.CONTRACT,
    TopologyEntityKind.SERVICE: GraphEntityType.SERVICE,
}


@dataclass(frozen=True, slots=True)
class CanonicalArtifactTopologyProjection:
    """Project entities and activate exact deterministic artifact assertions idempotently."""

    store: SqliteCoreStore
    graph: ScopedGraphRepositoryFactory
    assertions: ScopedAssertionRepositoryFactory

    async def project(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        projected_at: datetime,
    ) -> tuple[str, ...]:
        """Project every candidate before relation assertions and append exact receipts."""
        graph_scope = _scope_for(scope, "graph.project")
        projector = ProjectGraphEntityHandler(self.graph)
        for candidate in batch.candidates:
            await projector.execute(
                ProjectGraphEntityCommand(graph_scope, _graph_entity(candidate, projected_at))
            )
        assertion_ids: list[str] = []
        for rank, relation in enumerate(batch.relations, start=1):
            existing = await self._receipt(relation.id)
            if existing is not None:
                assertion_ids.append(existing)
                continue
            assertion_id = await self._assertion(
                scope,
                f"{operation_id}:relation:{rank}",
                relation,
                projected_at,
            )
            await self._record_receipt(relation.id, assertion_id, operation_id, projected_at)
            assertion_ids.append(assertion_id)
        return tuple(assertion_ids)

    async def _assertion(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        relation: TopologyRelationCandidate,
        projected_at: datetime,
    ) -> str:
        assertion_id = _uuid7("artifact-topology-assertion.v1", relation.id)
        candidate = AssertionCandidate.create(
            candidate_id=assertion_id,
            subject_id=relation.subject_entity_id,
            predicate=_PREDICATES[relation.relation],
            object_id=relation.object_entity_id,
            scope=AssertionScope(
                relation.evidence.brain_id,
                relation.evidence.project_id,
                relation.evidence.repository_id,
                None,
                relation.evidence.classification,
            ),
            temporal=AssertionTemporal(
                relation.valid_from,
                relation.valid_to,
                projected_at,
                None,
            ),
            confidence=AssertionConfidence(9_800, 9_700, 9_800),
            extractor=AssertionExtractor(
                "artifact-topology-parser",
                "idx005-parsers-1.0.0",
                "deterministic",
                "local-v1",
            ),
            evidence_ids=(relation.evidence.evidence_id,),
        )
        proposed = await ProposeAssertionHandler(self.assertions).execute(
            ProposeAssertionCommand(
                _operation("artifact.propose", operation_id),
                _scope_for(scope, "graph.assertion.propose"),
                candidate,
            )
        )
        await ActivateAssertionHandler(self.assertions).execute(
            ActivateAssertionCommand(
                _operation("artifact.activate", operation_id),
                _uuid7("artifact-topology-activation.v1", relation.id),
                proposed.id,
                _scope_for(scope, "graph.assertion.activate"),
                projected_at,
            )
        )
        return proposed.id

    async def _receipt(self, relation_id: str) -> str | None:
        try:
            async with self.store.engine.connect() as connection:
                value = (
                    await connection.execute(
                        text(
                            "SELECT assertion_id FROM artifact_topology_projection_receipts "
                            "WHERE relation_id=:relation"
                        ),
                        {"relation": relation_id},
                    )
                ).scalar_one_or_none()
            return None if value is None else str(value)
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def _record_receipt(
        self,
        relation_id: str,
        assertion_id: str,
        operation_id: str,
        projected_at: datetime,
    ) -> None:
        try:
            async with self.store.write_lock, self.store.engine.begin() as connection:
                existing = (
                    (
                        await connection.execute(
                            text(
                                "SELECT assertion_id,operation_id FROM "
                                "artifact_topology_projection_receipts "
                                "WHERE relation_id=:relation"
                            ),
                            {"relation": relation_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    _conflict_if(str(existing["assertion_id"]) != assertion_id)
                    return
                await connection.execute(
                    text(
                        "INSERT INTO artifact_topology_projection_receipts"
                        "(relation_id,assertion_id,operation_id,projected_at,schema_version) "
                        "VALUES(:relation,:assertion,:operation,:projected,1)"
                    ),
                    {
                        "relation": relation_id,
                        "assertion": assertion_id,
                        "operation": operation_id,
                        "projected": _micros(projected_at),
                    },
                )
        except IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


@dataclass(frozen=True, slots=True)
class SourceRevisionArtifactTopologyLineage:
    """Delegate relation evidence lineage to the branch-aware IDX-003 repository."""

    repository: SourceRevisionRepository

    async def register(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        relation: TopologyRelationCandidate,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        """Append exact source-revision/evidence/assertion lineage."""
        return await RegisterEvidenceLineageHandler(self.repository).execute(
            RegisterEvidenceLineageCommand(
                _operation("artifact.lineage", operation_id),
                _scope_for(scope, "indexing.revision.lineage.register"),
                relation.evidence.source_revision_context_id,
                relation.evidence.evidence_id,
                assertion_id,
                registered_at,
            )
        )


def _graph_entity(candidate: TopologyCandidate, projected_at: datetime) -> GraphEntity:
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "kind": candidate.kind.value,
                "name": candidate.name,
                "version": candidate.version,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return GraphEntity.create(
        entity_id=candidate.entity_id,
        brain_id=candidate.evidence.brain_id,
        entity_type=_ENTITY_TYPES[candidate.kind],
        project_id=candidate.evidence.project_id,
        repository_id=candidate.evidence.repository_id,
        checkout_id=None,
        schema_version=1,
        created_at=candidate.evidence.observed_at,
        recorded_from=projected_at,
        recorded_to=None,
        classification=GraphClassification(candidate.evidence.classification),
        content_fingerprint=fingerprint,
    )


def _scope_for(scope: AuthorizedScope, action: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=scope.brain_id,
        principal_id=scope.principal_id,
        role=scope.role,
        mode=scope.mode,
        members=scope.members,
        classification_ceiling=scope.classification_ceiling,
        temporal_scope=scope.temporal_scope,
        grant_version=scope.grant_version,
        policy_version=scope.policy_version,
        security_epoch=scope.security_epoch,
        action=action,
        purpose=scope.purpose,
    )


def _operation(prefix: str, value: str) -> str:
    digest = hashlib.sha256(f"{prefix}\0{value}".encode()).hexdigest()
    return f"{prefix}.{digest}"


def _uuid7(namespace: str, value: str) -> str:
    raw = bytearray(hashlib.sha256(f"{namespace}\0{value}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(raw)))


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _conflict_if(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise IndexingConflictError(_ERR_CONFLICT)
