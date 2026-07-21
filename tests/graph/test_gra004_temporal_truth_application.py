"""GRA-004 application orchestration and historical-label tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.graph.application.temporal_truth import (
    QueryTemporalAssertionsHandler,
    QueryTemporalAssertionsQuery,
    RecordVcsRevisionBatchCommand,
    RecordVcsRevisionBatchHandler,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphIntegrityError
from agentmemory.graph.domain.temporal_truth import (
    EvidenceRevisionAnchor,
    ResolvedVcsRevision,
    RevisionApplicability,
    RevisionEvidenceProof,
    TemporalAssertionCandidate,
    TruthCurrency,
    TruthTemporalScope,
    VcsRevisionBatch,
    VcsRevisionSelector,
)
from tests.graph.test_gra003_materialized_edge_application import (
    ACTIVATED_EVENT_ID,
    ASSERTION_ID,
    REPOSITORY_ID,
    _active,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra003_materialized_edge_application import (
    EVIDENCE_ID as ASSERTION_EVIDENCE_ID,
)
from tests.graph.test_gra003_materialized_edge_application import (
    _scope as projection_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra004_temporal_truth_domain import (
    CHECKOUT_ID,
    MAIN,
    MERGE,
    NOW,
    _batch,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.graph.domain.temporal_truth import TemporalAssertionCriteria
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope


@pytest.mark.asyncio
async def test_current_query_returns_only_current_authority_with_current_label() -> None:
    candidate = _candidate(current=True)
    handler = QueryTemporalAssertionsHandler(_Assertions((candidate,)), _Revisions())
    results = await handler.execute(
        QueryTemporalAssertionsQuery(
            _scope("graph.assertion.truth.query"), TruthTemporalScope.current()
        ),
        NOW,
    )
    assert len(results) == 1
    assert results[0].explanation.currency is TruthCurrency.CURRENT
    assert results[0].explanation.currently_authoritative

    stale_current = QueryTemporalAssertionsHandler(
        _Assertions((_candidate(current=False),)),
        _Revisions(),
    )
    assert (
        await stale_current.execute(
            QueryTemporalAssertionsQuery(
                _scope("graph.assertion.truth.query"), TruthTemporalScope.current()
            ),
            NOW,
        )
        == ()
    )


@pytest.mark.asyncio
async def test_historical_revision_query_never_relabels_old_assertion_as_current() -> None:
    candidate = _candidate(current=False)
    revisions = _Revisions(applicability=RevisionApplicability.REACHABLE)
    recorded_at = NOW - timedelta(hours=1)
    temporal = TruthTemporalScope.historical(
        as_of_recorded=recorded_at,
        revision=VcsRevisionSelector(REPOSITORY_ID, branch_name="main"),
    )
    results = await QueryTemporalAssertionsHandler(_Assertions((candidate,)), revisions).execute(
        QueryTemporalAssertionsQuery(
            _scope("graph.assertion.truth.query"),
            temporal,
            assertion_id=ASSERTION_ID,
            limit=1,
        ),
        NOW,
    )
    assert len(results) == 1
    explanation = results[0].explanation
    assert explanation.currency is TruthCurrency.HISTORICAL
    assert not explanation.currently_authoritative
    assert explanation.recorded_at == recorded_at
    assert explanation.resolved_revision is not None
    assert explanation.resolved_revision.commit_sha == MERGE
    assert revisions.proved == [ASSERTION_EVIDENCE_ID]


@pytest.mark.asyncio
async def test_revision_query_excludes_assertion_when_all_evidence_is_stale_or_unreachable() -> (
    None
):
    for applicability in (RevisionApplicability.STALE, RevisionApplicability.UNREACHABLE):
        handler = QueryTemporalAssertionsHandler(
            _Assertions((_candidate(current=True),)),
            _Revisions(applicability=applicability),
        )
        results = await handler.execute(
            QueryTemporalAssertionsQuery(
                _scope("graph.assertion.truth.query"),
                TruthTemporalScope.historical(
                    revision=VcsRevisionSelector(REPOSITORY_ID, commit_sha=MERGE)
                ),
            ),
            NOW,
        )
        assert results == ()


@pytest.mark.asyncio
async def test_query_and_revision_recording_reject_wrong_actions_or_scope() -> None:
    handler = QueryTemporalAssertionsHandler(_Assertions(()), _Revisions())
    with pytest.raises(GraphAuthorizationError, match="action"):
        await handler.execute(
            QueryTemporalAssertionsQuery(_scope("graph.read"), TruthTemporalScope.current()),
            NOW,
        )
    with pytest.raises(GraphIntegrityError, match="query"):
        QueryTemporalAssertionsQuery(
            _scope("graph.assertion.truth.query"), TruthTemporalScope.current(), limit=0
        )

    repository = _BatchRepository()
    command = RecordVcsRevisionBatchCommand(_scope("graph.vcs.revision.record"), _batch())
    assert await RecordVcsRevisionBatchHandler(repository).execute(command) == _batch().digest
    assert repository.batches == [_batch().digest]
    with pytest.raises(GraphAuthorizationError, match="action"):
        await RecordVcsRevisionBatchHandler(repository).execute(
            RecordVcsRevisionBatchCommand(_scope("graph.read"), _batch())
        )


@dataclass(slots=True)
class _Assertions:
    candidates: tuple[TemporalAssertionCandidate, ...]

    async def query(
        self,
        scope: AuthorizedScope,
        criteria: TemporalAssertionCriteria,
    ) -> tuple[TemporalAssertionCandidate, ...]:
        del scope, criteria
        return self.candidates


@dataclass(slots=True)
class _Revisions:
    applicability: RevisionApplicability = RevisionApplicability.REACHABLE
    proved: list[str] = field(default_factory=list[str])

    async def resolve(
        self,
        scope: AuthorizedScope,
        selector: VcsRevisionSelector,
        recorded_at: datetime,
    ) -> ResolvedVcsRevision:
        del scope
        return ResolvedVcsRevision(
            selector,
            MERGE,
            "a" * 64,
            recorded_at,
            "b" * 64 if selector.branch_name is not None else None,
            force_pushed=False,
        )

    async def prove(
        self,
        scope: AuthorizedScope,
        evidence_id: str,
        anchor: EvidenceRevisionAnchor | None,
        resolved: ResolvedVcsRevision,
        recorded_at: datetime,
    ) -> RevisionEvidenceProof:
        del scope, anchor, recorded_at
        self.proved.append(evidence_id)
        invalidations = (MAIN,) if self.applicability is RevisionApplicability.STALE else ()
        commit = None if self.applicability is RevisionApplicability.UNVERSIONED else MAIN
        return RevisionEvidenceProof(
            evidence_id,
            self.applicability,
            commit,
            resolved.commit_sha,
            invalidations,
            resolved.graph_digest,
        )


@dataclass(slots=True)
class _BatchRepository:
    batches: list[str] = field(default_factory=list[str])

    async def append(self, scope: AuthorizedScope, batch: VcsRevisionBatch) -> str:
        del scope
        self.batches.append(batch.digest)
        return batch.digest


def _candidate(*, current: bool) -> TemporalAssertionCandidate:
    assertion = _active(CHECKOUT_ID)
    return TemporalAssertionCandidate(
        assertion,
        ACTIVATED_EVENT_ID,
        current,
        (
            EvidenceRevisionAnchor(
                ASSERTION_EVIDENCE_ID,
                REPOSITORY_ID,
                CHECKOUT_ID,
                MAIN,
                "main",
                NOW - timedelta(days=1),
            ),
        ),
    )


def _scope(action: str) -> AuthorizedScope:
    return projection_scope(action, (CHECKOUT_ID,))
