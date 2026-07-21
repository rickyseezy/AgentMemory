"""IDX-004 adapters from topology matches to canonical graph truth and stale lineage."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import text

from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
)
from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionExtractor,
    AssertionPredicate,
    AssertionScope,
    AssertionTemporal,
)
from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
from agentmemory.indexing.application.revision_history import (
    RegisterEvidenceLineageCommand,
    RegisterEvidenceLineageHandler,
)
from agentmemory.indexing.domain.api_topology import (
    ApiMatchDisposition,
    ApiMatchRule,
    ApiTopologyMatch,
)
from agentmemory.indexing.domain.errors import IndexingConflictError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertion_ports import ScopedAssertionRepositoryFactory
    from agentmemory.indexing.domain.revision_history_ports import SourceRevisionRepository
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_INTEGRITY = "API topology assertion evidence is unavailable"


@dataclass(frozen=True, slots=True)
class SqliteConsumesAssertionAdapter:
    """Propose every qualified match and activate only deterministic confirmed matches."""

    store: SqliteCoreStore
    repositories: ScopedAssertionRepositoryFactory

    async def record(
        self,
        scope: AuthorizedScope,
        match: ApiTopologyMatch,
        occurred_at: datetime,
    ) -> str:
        """Materialize a canonical CONSUMES assertion with exact client/server evidence."""
        coordinates = await self._client_scope(match.client_call_id)
        assertion_id = _uuid7_from_digest("api-topology-assertion.v1", match.id)
        candidate = AssertionCandidate.create(
            candidate_id=assertion_id,
            subject_id=match.client_entity_id,
            predicate=AssertionPredicate.CONSUMES,
            object_id=match.endpoint_entity_id,
            scope=AssertionScope(*coordinates),
            temporal=AssertionTemporal(occurred_at, None, occurred_at, None),
            confidence=AssertionConfidence(
                match.confidence_basis_points,
                _rule_reliability(match.rule),
                match.confidence_basis_points,
            ),
            extractor=AssertionExtractor(
                "api-topology-linker",
                match.rule_version,
                "deterministic",
                "local-v1",
            ),
            evidence_ids=match.supporting_evidence_ids,
        )
        proposed = await ProposeAssertionHandler(self.repositories).execute(
            ProposeAssertionCommand(
                _operation("topology.propose", match.id),
                _scope_for(scope, "graph.assertion.propose"),
                candidate,
            )
        )
        if match.disposition is ApiMatchDisposition.CONFIRMED:
            await ActivateAssertionHandler(self.repositories).execute(
                ActivateAssertionCommand(
                    _operation("topology.activate", match.id),
                    _uuid7_from_digest("api-topology-activation-event.v1", match.id),
                    proposed.id,
                    _scope_for(scope, "graph.assertion.activate"),
                    occurred_at,
                )
            )
        return proposed.id

    async def _client_scope(self, candidate_id: str) -> tuple[str, str, str, None, str]:
        async with self.store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT batch.brain_id,batch.project_id,batch.repository_id,"
                            "candidate.classification FROM api_topology_client_call_candidates "
                            "AS candidate JOIN api_topology_candidate_batches AS batch "
                            "ON batch.batch_id=candidate.batch_id WHERE candidate.candidate_id=:id"
                        ),
                        {"id": candidate_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise IndexingConflictError(_ERR_INTEGRITY)
        return (
            str(row["brain_id"]),
            str(row["project_id"]),
            str(row["repository_id"]),
            None,
            str(row["classification"]),
        )


@dataclass(frozen=True, slots=True)
class SourceRevisionTopologyLineageAdapter:
    """Delegate exact source/evidence/assertion lineage to the branch-aware IDX-003 store."""

    repository: SourceRevisionRepository

    async def register(  # noqa: PLR0913 -- Exact lineage coordinates are security-relevant.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        source_revision_context_id: str,
        source_semantic_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        """Append lineage with a bounded operation identity and an action-bound scope."""
        del source_semantic_id
        return await RegisterEvidenceLineageHandler(self.repository).execute(
            RegisterEvidenceLineageCommand(
                _operation("topology.lineage", operation_id),
                _scope_for(scope, "indexing.revision.lineage.register"),
                source_revision_context_id,
                evidence_id,
                assertion_id,
                registered_at,
            )
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


def _rule_reliability(rule: ApiMatchRule) -> int:
    return {
        ApiMatchRule.CONTRACT_OPERATION: 9_700,
        ApiMatchRule.GENERATED_CLIENT_SYMBOL: 9_200,
        ApiMatchRule.SERVICE_BASE_URL: 8_400,
        ApiMatchRule.HEURISTIC_PATH: 7_200,
    }[rule]


def _operation(prefix: str, value: str) -> str:
    digest = hashlib.sha256(f"{prefix}\0{value}".encode()).hexdigest()
    return f"{prefix}.{digest}"


def _uuid7_from_digest(namespace: str, value: str) -> str:
    raw = bytearray(hashlib.sha256(f"{namespace}\0{value}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(raw)))
