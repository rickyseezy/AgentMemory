"""GRA-005 contradiction use-case orchestration tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.graph.application.contradictions import (
    DetectContradictionsCommand,
    DetectContradictionsHandler,
    EvaluateContradictionsHandler,
    EvaluateContradictionsQuery,
    ResolveContradictionCommand,
    ResolveContradictionHandler,
)
from agentmemory.graph.domain.assertions import AssertionPolarity
from agentmemory.graph.domain.contradictions import (
    Contradiction,
    ContradictionDecision,
    ContradictionDetector,
    ContradictionResolution,
    ContradictionResolutionOutcome,
    RetrievalAssertionCandidate,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphConflictError
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra005_contradiction_domain import (
    EVIDENCE_A,
    EVIDENCE_B,
    GRANT,
    LATER,
    LEFT,
    NOW,
    RIGHT,
    _claim,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import REPOSITORY_ID

if TYPE_CHECKING:
    from agentmemory.graph.domain.contradictions import ContradictionCandidate
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


@pytest.mark.asyncio
async def test_detect_authorizes_then_persists_deterministic_disputes() -> None:
    repository = _Repository(
        candidates=(
            _claim(LEFT),
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        )
    )
    command = DetectContradictionsCommand(
        "detect-1",
        _scope("graph.contradiction.detect"),
        REPOSITORY_ID.value,
        NOW,
    )
    result = await DetectContradictionsHandler(repository).execute(command)
    assert len(result) == 1
    assert repository.recorded == [(command.operation_id, REPOSITORY_ID.value, result)]

    with pytest.raises(GraphAuthorizationError):
        await DetectContradictionsHandler(repository).execute(
            replace(command, scope=_scope("graph.contradiction.query"))
        )

    with pytest.raises(GraphAuthorizationError, match="scope"):
        DetectContradictionsCommand(
            "detect-outside-scope",
            _scope("graph.contradiction.detect"),
            LEFT,
            NOW,
        )


@pytest.mark.asyncio
async def test_user_resolution_uses_current_principal_and_preserves_history() -> None:
    repository = _Repository(disputes=(_dispute(),))
    command = ResolveContradictionCommand(
        "resolve-1",
        _scope("graph.contradiction.resolve"),
        repository.disputes[0].id,
        GRANT,
        ContradictionResolutionOutcome.LEFT_ASSERTION,
        "user_confirmed",
        (EVIDENCE_A,),
        LATER,
    )
    result = await ResolveContradictionHandler(repository).execute(command)
    assert result.resolution is not None
    assert result.resolution.actor_id == command.scope.principal_id.value
    assert result.resolution.grant_id == GRANT
    assert repository.resolved[0][0] == "resolve-1"

    repository.disputes = ()
    with pytest.raises(GraphConflictError, match="not found"):
        await ResolveContradictionHandler(repository).execute(command)


@pytest.mark.asyncio
async def test_retrieval_policy_runs_after_fusion_and_cannot_be_overruled_by_rank() -> None:
    repository = _Repository(disputes=(_dispute(),))
    candidates = (
        RetrievalAssertionCandidate(LEFT, 10_000, authoritative=True),
        RetrievalAssertionCandidate(RIGHT, 1, authoritative=True),
    )
    result = await EvaluateContradictionsHandler(repository).execute(
        EvaluateContradictionsQuery(
            _scope("graph.contradiction.query"),
            candidates,
        )
    )
    assert result.decision is ContradictionDecision.UNKNOWN
    assert repository.queried == [(LEFT, RIGHT)]

    with pytest.raises(GraphConflictError, match="query"):
        EvaluateContradictionsQuery(_scope("graph.contradiction.query"), ())
    duplicate = RetrievalAssertionCandidate(LEFT, 1, authoritative=True)
    with pytest.raises(GraphConflictError, match="query"):
        EvaluateContradictionsQuery(
            _scope("graph.contradiction.query"),
            (duplicate, duplicate),
        )


def _dispute() -> Contradiction:
    return ContradictionDetector.detect(
        (
            _claim(LEFT),
            _claim(RIGHT, polarity=AssertionPolarity.NEGATIVE, evidence_id=EVIDENCE_B),
        ),
        NOW,
    )[0]


@dataclass
class _Repository:
    candidates: tuple[ContradictionCandidate, ...] = ()
    disputes: tuple[Contradiction, ...] = ()
    recorded: list[tuple[str, str, tuple[Contradiction, ...]]] = field(
        default_factory=list[tuple[str, str, tuple[Contradiction, ...]]]
    )
    resolved: list[tuple[str, Contradiction, ContradictionResolution]] = field(
        default_factory=list[tuple[str, Contradiction, ContradictionResolution]]
    )
    queried: list[tuple[str, ...]] = field(default_factory=list[tuple[str, ...]])

    async def detection_candidates(
        self, scope: AuthorizedScope, repository_id: str
    ) -> tuple[ContradictionCandidate, ...]:
        del scope, repository_id
        return self.candidates

    async def record_detection(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        repository_id: str,
        contradictions: tuple[Contradiction, ...],
    ) -> tuple[Contradiction, ...]:
        del scope
        self.recorded.append((operation_id, repository_id, contradictions))
        self.disputes = contradictions
        return contradictions

    async def get(self, scope: AuthorizedScope, contradiction_id: str) -> Contradiction | None:
        del scope
        return next((item for item in self.disputes if item.id == contradiction_id), None)

    async def resolve(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        contradiction: Contradiction,
        resolution: ContradictionResolution,
    ) -> Contradiction:
        del scope
        self.resolved.append((operation_id, contradiction, resolution))
        resolved = contradiction.resolve(resolution)
        self.disputes = tuple(
            resolved if item.id == contradiction.id else item for item in self.disputes
        )
        return resolved

    async def for_assertions(
        self, scope: AuthorizedScope, assertion_ids: tuple[str, ...]
    ) -> tuple[Contradiction, ...]:
        del scope
        self.queried.append(assertion_ids)
        return tuple(
            item
            for item in self.disputes
            if item.left_assertion_id in assertion_ids or item.right_assertion_id in assertion_ids
        )
