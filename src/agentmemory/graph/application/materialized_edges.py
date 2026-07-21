"""GRA-003 assertion-edge materialization, integrity, repair, and traversal use cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphIntegrityError
from agentmemory.graph.domain.materialized_edges import (
    EdgeIntegrityFindingKind,
    EdgeIntegrityPolicy,
    MaterializedAssertionEdge,
    TraversalEdgeExplanation,
)
from agentmemory.graph.domain.models import GraphRelationshipType, stable_graph_id

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.materialized_edge_ports import (
        CanonicalAssertionProjectionSource,
        MaterializedEdgeIntegrityJournal,
        ScopedMaterializedEdgeProjectionFactory,
    )
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_TRAVERSAL_EDGES = 1_000
_ERR_ACTION = "materialized edge action is not authorized"
_ERR_GENERATION = "materialized edge generation is invalid"
_ERR_INTEGRITY = "materialized edge projection does not match canonical assertion"
_ERR_SCOPE = "materialized edge is outside authorized scope"
_ERR_TRAVERSAL = "materialized edge traversal is invalid"


@dataclass(frozen=True, slots=True)
class MaterializeAssertionEdgeCommand:
    """Consume one assertion integration event into the active graph generation."""

    source_event_id: str
    assertion_id: str
    generation_id: str
    scope: AuthorizedScope

    def __post_init__(self) -> None:
        """Reject malformed event, assertion, and generation identities at the boundary."""
        stable_graph_id(self.source_event_id)
        stable_graph_id(self.assertion_id)
        _require_generation(self.generation_id)


@dataclass(frozen=True, slots=True)
class MaterializeAssertionEdgeHandler:
    """Re-read canonical state so delayed events cannot resurrect stale authority."""

    source: CanonicalAssertionProjectionSource
    projections: ScopedMaterializedEdgeProjectionFactory

    async def execute(self, command: MaterializeAssertionEdgeCommand) -> MaterializedAssertionEdge:
        """Project the latest canonical lifecycle state under current authorization."""
        _require_action(command.scope, "graph.assertion.materialize")
        assertion, latest_event_id, latest_occurred_at = await self.source.current_for_event(
            command.scope,
            command.source_event_id,
            command.assertion_id,
        )
        edge = MaterializedAssertionEdge.from_assertion(
            assertion,
            source_event_id=latest_event_id,
            generation_id=command.generation_id,
            projected_at=latest_occurred_at,
        )
        _require_scope(command.scope, edge)
        result = await self.projections.projection(command.scope).project(edge)
        if (
            result.assertion_id != edge.assertion_id
            or result.projection_digest != edge.projection_digest
        ):
            raise GraphIntegrityError(_ERR_INTEGRITY)
        return edge


@dataclass(frozen=True, slots=True)
class ValidateAssertionEdgesCommand:
    """Request a bidirectional canonical/projection integrity pass and repair."""

    generation_id: str
    checked_at: datetime
    scope: AuthorizedScope

    def __post_init__(self) -> None:
        """Require an exact immutable generation identity."""
        _require_generation(self.generation_id)


@dataclass(frozen=True, slots=True)
class ValidateAssertionEdgesHandler:
    """Quarantine or repair only edges named by deterministic integrity findings."""

    source: CanonicalAssertionProjectionSource
    projections: ScopedMaterializedEdgeProjectionFactory
    journal: MaterializedEdgeIntegrityJournal

    async def execute(
        self, command: ValidateAssertionEdgesCommand
    ) -> tuple[EdgeIntegrityFindingKind, ...]:
        """Run reverse checks, journal findings, and apply finding-specific repair."""
        _require_action(command.scope, "graph.assertion.edge.integrity")
        expected = await self.source.expected_edges(
            command.scope, command.generation_id, command.checked_at
        )
        projection = self.projections.projection(command.scope)
        actual = await projection.list_edges(command.generation_id)
        findings = EdgeIntegrityPolicy.evaluate(expected, actual, command.checked_at)
        await self.journal.record(command.scope, findings)
        expected_by_id = {edge.assertion_id: edge for edge in expected}
        for finding in findings:
            if finding.kind is EdgeIntegrityFindingKind.ORPHAN:
                await projection.quarantine(
                    finding.assertion_id,
                    finding.generation_id,
                    "orphan_assertion",
                    command.checked_at,
                )
            else:
                edge = expected_by_id.get(finding.assertion_id)
                if edge is None:
                    raise GraphIntegrityError(_ERR_INTEGRITY)
                if finding.kind is EdgeIntegrityFindingKind.MISMATCH:
                    await projection.quarantine(
                        finding.assertion_id,
                        finding.generation_id,
                        "projection_mismatch",
                        command.checked_at,
                    )
                result = await projection.project(edge)
                if result.projection_digest != edge.projection_digest:
                    raise GraphIntegrityError(_ERR_INTEGRITY)
            await self.journal.repaired(command.scope, finding, command.checked_at)
        return tuple(finding.kind for finding in findings)


@dataclass(frozen=True, slots=True)
class TraverseAssertionEdgesQuery:
    """Bounded direct-edge traversal with mandatory authority explanations."""

    subject_id: str
    relationship_types: tuple[GraphRelationshipType, ...]
    generation_id: str
    limit: int
    scope: AuthorizedScope

    def __post_init__(self) -> None:
        """Reject arbitrary relationship names and unbounded traversal."""
        stable_graph_id(self.subject_id)
        _require_generation(self.generation_id)
        if (
            not self.relationship_types
            or tuple(dict.fromkeys(self.relationship_types)) != self.relationship_types
            or any(not _is_relationship_type(item) for item in self.relationship_types)
            or not 1 <= self.limit <= _MAX_TRAVERSAL_EDGES
        ):
            raise GraphIntegrityError(_ERR_TRAVERSAL)


@dataclass(frozen=True, slots=True)
class TraverseAssertionEdgesHandler:
    """Return only authorized, explained, current direct-edge traversal results."""

    projections: ScopedMaterializedEdgeProjectionFactory

    async def execute(
        self, query: TraverseAssertionEdgesQuery
    ) -> tuple[TraversalEdgeExplanation, ...]:
        """Delegate one closed bounded query after checking action authority."""
        _require_action(query.scope, "graph.assertion.traverse")
        results = await self.projections.projection(query.scope).traverse(
            query.subject_id,
            query.relationship_types,
            query.generation_id,
            query.limit,
        )
        if len(results) > query.limit or any(
            item.subject_id != query.subject_id
            or item.relationship_type not in query.relationship_types
            or item.generation_id != query.generation_id
            for item in results
        ):
            raise GraphIntegrityError(_ERR_INTEGRITY)
        return results


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise GraphAuthorizationError(_ERR_ACTION)


def _require_scope(scope: AuthorizedScope, edge: MaterializedAssertionEdge) -> None:
    classifications = ("public", "internal", "confidential", "restricted", "local_only")
    ceiling = classifications.index(scope.classification_ceiling.value)
    member = next(
        (item for item in scope.members if item.project_id.value == edge.project_id),
        None,
    )
    if (
        edge.brain_id != scope.brain_id.value
        or member is None
        or edge.repository_id not in {item.value for item in member.repository_ids}
        or (
            edge.checkout_id is not None
            and member.checkout_ids
            and edge.checkout_id not in {item.value for item in member.checkout_ids}
        )
        or edge.classification.value not in classifications[: ceiling + 1]
    ):
        raise GraphAuthorizationError(_ERR_SCOPE)


def _require_generation(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise GraphIntegrityError(_ERR_GENERATION)


def _is_relationship_type(value: object) -> bool:
    return isinstance(value, GraphRelationshipType)
