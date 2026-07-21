"""GRA-004 bitemporal assertion query and revision-observation use cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphIntegrityError
from agentmemory.graph.domain.models import stable_graph_id
from agentmemory.graph.domain.temporal_truth import (
    RevisionEvidencePolicy,
    TemporalAssertionCriteria,
    TemporalAssertionExplanation,
    TemporalAssertionResult,
    TemporalTruthMode,
    TruthCurrency,
    TruthTemporalScope,
    VcsRevisionBatch,
    validate_predicates,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertions import AssertionPredicate
    from agentmemory.graph.domain.temporal_truth import RevisionEvidenceProof
    from agentmemory.graph.domain.temporal_truth_ports import (
        TemporalAssertionRepository,
        VcsRevisionBatchRepository,
        VcsRevisionPort,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_MAX_RESULTS = 1_000
_ERR_ACTION = "temporal truth action is not authorized"
_ERR_QUERY = "temporal truth query is invalid"
_ERR_SCOPE = "temporal truth query is outside authorized scope"


@dataclass(frozen=True, slots=True)
class QueryTemporalAssertionsQuery:
    """A bounded canonical truth query with explicit temporal semantics."""

    scope: AuthorizedScope
    temporal: TruthTemporalScope
    assertion_id: str | None = None
    subject_id: str | None = None
    predicates: tuple[AssertionPredicate, ...] = ()
    limit: int = 100

    def __post_init__(self) -> None:
        """Validate identifiers, closed filters, bounds, and revision membership."""
        for value in (self.assertion_id, self.subject_id):
            if value is not None:
                stable_graph_id(value)
        validate_predicates(self.predicates)
        if not 1 <= self.limit <= _MAX_RESULTS:
            raise GraphIntegrityError(_ERR_QUERY)
        if self.temporal.revision is not None:
            repositories = {item.value for item in self.scope.repository_ids}
            if self.temporal.revision.repository_id not in repositories:
                raise GraphAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class QueryTemporalAssertionsHandler:
    """Select bitemporal authority, then apply immutable revision reachability."""

    assertions: TemporalAssertionRepository
    revisions: VcsRevisionPort

    async def execute(
        self,
        query: QueryTemporalAssertionsQuery,
        evaluated_at: datetime,
    ) -> tuple[TemporalAssertionResult, ...]:
        """Return only supported truth with non-ambiguous current/historical labels."""
        _require_action(query.scope, "graph.assertion.truth.query")
        valid_at, recorded_at = query.temporal.evaluation_times(evaluated_at)
        resolved = None
        if query.temporal.revision is not None:
            resolved = await self.revisions.resolve(
                query.scope,
                query.temporal.revision,
                recorded_at,
            )
        candidates = await self.assertions.query(
            query.scope,
            TemporalAssertionCriteria(
                query.assertion_id,
                query.subject_id,
                query.predicates,
                valid_at,
                recorded_at,
                query.limit,
            ),
        )
        results: list[TemporalAssertionResult] = []
        for candidate in candidates:
            if (
                query.temporal.mode is TemporalTruthMode.CURRENT
                and not candidate.currently_authoritative
            ):
                continue
            proofs: tuple[RevisionEvidenceProof, ...] = ()
            if resolved is not None:
                accumulated: list[RevisionEvidenceProof] = []
                for evidence, anchor in zip(
                    candidate.assertion.evidence,
                    candidate.evidence_anchors,
                    strict=True,
                ):
                    accumulated.append(
                        await self.revisions.prove(
                            query.scope,
                            evidence.evidence_id,
                            anchor,
                            resolved,
                            recorded_at,
                        )
                    )
                proofs = tuple(accumulated)
                if not RevisionEvidencePolicy.assertion_supported(proofs):
                    continue
            currency = (
                TruthCurrency.CURRENT
                if query.temporal.mode is TemporalTruthMode.CURRENT
                else TruthCurrency.HISTORICAL
            )
            explanation = TemporalAssertionExplanation(
                candidate.assertion.id,
                candidate.assertion.revision_id,
                candidate.lifecycle_event_id,
                currency,
                valid_at,
                recorded_at,
                candidate.currently_authoritative,
                resolved,
                proofs,
            )
            results.append(TemporalAssertionResult(candidate.assertion, explanation))
        if len(results) > query.limit:
            raise GraphIntegrityError(_ERR_QUERY)
        return tuple(results)


@dataclass(frozen=True, slots=True)
class RecordVcsRevisionBatchCommand:
    """Append one authorized VCS DAG/ref/lineage-impact observation."""

    scope: AuthorizedScope
    batch: VcsRevisionBatch

    def __post_init__(self) -> None:
        """Require exact Brain and Repository membership before adapter access."""
        if self.batch.brain_id != self.scope.brain_id.value:
            raise GraphAuthorizationError(_ERR_SCOPE)
        if self.batch.repository_id not in {item.value for item in self.scope.repository_ids}:
            raise GraphAuthorizationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class RecordVcsRevisionBatchHandler:
    """Persist immutable revision authority behind a narrow repository port."""

    repository: VcsRevisionBatchRepository

    async def execute(self, command: RecordVcsRevisionBatchCommand) -> str:
        """Authorize the closed internal action and append exactly once."""
        _require_action(command.scope, "graph.vcs.revision.record")
        digest = await self.repository.append(command.scope, command.batch)
        if digest != command.batch.digest:
            raise GraphIntegrityError(_ERR_QUERY)
        return digest


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)
