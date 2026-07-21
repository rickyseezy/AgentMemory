"""TDD specifications for IDX-003 revision lineage, replay, and history policy."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.application.revision_history import (
    ProcessSourceRevisionCommand,
    ProcessSourceRevisionHandler,
    QuerySourceRevisionHistoryHandler,
    QuerySourceRevisionHistoryQuery,
    SourceRevisionWorker,
)
from agentmemory.indexing.domain.errors import IndexingValidationError
from agentmemory.indexing.domain.revision_history import (
    CommitGraphAnswer,
    CommitGraphQueryKind,
    CommitGraphSnapshot,
    ReextractionAction,
    SourceRevisionApplicability,
    SourceRevisionChangeKind,
    SourceRevisionHistoryCandidate,
    SourceRevisionHistoryPolicy,
    SourceRevisionOutcome,
    SourceRevisionTransition,
    reextraction_job_id,
)
from agentmemory.indexing.domain.revision_history_ports import SourceRevisionWork
from tests.core.support import FixedClock
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
ROOT = "1" * 40
BASE = "2" * 40
MAIN = "3" * 40
FEATURE = "4" * 40
EVIDENCE = "018f0000-0000-7000-8000-000000000160"
ASSERTION = "018f0000-0000-7000-8000-000000000170"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _transition(  # noqa: PLR0913 -- Test builder exposes relevant transition axes.
    *,
    event: str = "event-1",
    commit: str = MAIN,
    kind: SourceRevisionChangeKind = SourceRevisionChangeKind.MODIFY,
    current_revision: str | None = None,
    current_content: str | None = None,
    reintroduced_from: str | None = None,
) -> SourceRevisionTransition:
    deleted = kind is SourceRevisionChangeKind.DELETE
    revision = None if deleted else current_revision or _digest(f"revision:{event}")
    content = None if deleted else current_content or _digest("content:new")
    return SourceRevisionTransition(
        _digest(event),
        _digest("run"),
        _digest("brain"),
        _digest("project"),
        _digest("repository"),
        _digest("file"),
        _digest("file"),
        _digest(f"snapshot:{event}"),
        _digest("snapshot:previous"),
        revision,
        _digest("revision:previous"),
        "src/service.py",
        None,
        commit,
        BASE,
        content,
        _digest("content:old"),
        kind,
        () if deleted else (_digest(f"semantic:{event}"),),
        (EVIDENCE,),
        (ASSERTION,),
        reintroduced_from,
        NOW,
    )


def test_identical_content_reintroduction_has_new_context_and_extraction_job() -> None:
    original = _transition(event="original", commit=BASE, kind=SourceRevisionChangeKind.ADD)
    reintroduced = _transition(
        event="reintroduced",
        commit=MAIN,
        kind=SourceRevisionChangeKind.REINTRODUCE,
        current_content=original.content_digest,
        reintroduced_from=original.context_id,
    )

    assert original.content_digest == reintroduced.content_digest
    assert original.context_id != reintroduced.context_id
    assert reintroduced.reintroduced_from_context_id == original.context_id
    assert reextraction_job_id(original.context_id, ReextractionAction.EXTRACT) != (
        reextraction_job_id(reintroduced.context_id, ReextractionAction.EXTRACT)
    )


def test_delete_and_reintroduction_shapes_fail_closed() -> None:
    deleted = _transition(kind=SourceRevisionChangeKind.DELETE)
    with pytest.raises(IndexingValidationError, match="transition is invalid"):
        replace(deleted, file_revision_id=_digest("unexpected"))
    with pytest.raises(IndexingValidationError, match="transition is invalid"):
        _transition(kind=SourceRevisionChangeKind.REINTRODUCE)


def test_graph_answers_are_watermark_replay_stable_and_shape_checked() -> None:
    first = CommitGraphAnswer(
        kind=CommitGraphQueryKind.ANCESTRY,
        left_commit_sha=BASE,
        right_commit_sha=MAIN,
        graph_digest=_digest("graph"),
        is_ancestor=True,
        merge_base_shas=(),
        answered_at=NOW,
    )
    replay = replace(first, answered_at=NOW + timedelta(seconds=10))

    assert first.id == replay.id
    with pytest.raises(IndexingValidationError, match="answer is invalid"):
        replace(first, merge_base_shas=(BASE,))
    merge_base = CommitGraphAnswer(
        CommitGraphQueryKind.MERGE_BASE,
        MAIN,
        FEATURE,
        first.graph_digest,
        None,
        (BASE,),
        NOW,
    )
    assert merge_base.merge_base_shas == (BASE,)


def test_history_policy_does_not_globally_stale_unaffected_branch() -> None:
    candidate = _candidate(BASE, invalidations=(MAIN,))

    assert (
        SourceRevisionHistoryPolicy.classify(candidate, ()) is SourceRevisionApplicability.CURRENT
    )
    assert (
        SourceRevisionHistoryPolicy.classify(candidate, (MAIN,))
        is SourceRevisionApplicability.STALE
    )
    deleted = replace(
        candidate,
        file_revision_id=None,
        content_digest=None,
        kind=SourceRevisionChangeKind.DELETE,
    )
    assert SourceRevisionHistoryPolicy.classify(deleted, ()) is SourceRevisionApplicability.DELETED


@dataclass(slots=True)
class _Graph:
    branch_tip: str = MAIN
    calls: list[tuple[str, str, str]] = field(default_factory=list[tuple[str, str, str]])

    async def pin_commit(
        self,
        brain_id: str,
        repository_id: str,
        commit_sha: str,
        recorded_at: datetime,
        answered_at: datetime,
    ) -> CommitGraphSnapshot:
        del answered_at
        return CommitGraphSnapshot(
            brain_id,
            repository_id,
            commit_sha,
            _digest(f"graph:{recorded_at.isoformat()}"),
            recorded_at,
        )

    async def pin_branch(
        self,
        brain_id: str,
        repository_id: str,
        branch_name: str,
        recorded_at: datetime,
        answered_at: datetime,
    ) -> CommitGraphSnapshot:
        del branch_name, answered_at
        pinned = self.branch_tip
        self.branch_tip = FEATURE
        return CommitGraphSnapshot(
            brain_id,
            repository_id,
            pinned,
            _digest(f"graph:{recorded_at.isoformat()}"),
            recorded_at,
            _digest("ref"),
        )

    async def ancestry(
        self,
        snapshot: CommitGraphSnapshot,
        ancestor_sha: str,
        descendant_sha: str,
        answered_at: datetime,
    ) -> CommitGraphAnswer:
        self.calls.append((ancestor_sha, descendant_sha, snapshot.target_commit_sha))
        reachable = {
            (BASE, MAIN),
            (MAIN, MAIN),
            (BASE, FEATURE),
            (FEATURE, FEATURE),
        }
        return CommitGraphAnswer(
            CommitGraphQueryKind.ANCESTRY,
            ancestor_sha,
            descendant_sha,
            snapshot.graph_digest,
            (ancestor_sha, descendant_sha) in reachable,
            (),
            answered_at,
        )

    async def merge_bases(
        self,
        snapshot: CommitGraphSnapshot,
        left_sha: str,
        right_sha: str,
        answered_at: datetime,
    ) -> CommitGraphAnswer:
        return CommitGraphAnswer(
            CommitGraphQueryKind.MERGE_BASE,
            left_sha,
            right_sha,
            snapshot.graph_digest,
            None,
            (BASE,),
            answered_at,
        )


@dataclass(slots=True)
class _Repository:
    work: SourceRevisionWork | None = None
    history: tuple[SourceRevisionHistoryCandidate, ...] = ()
    outcome: SourceRevisionOutcome | None = None

    async def claim_next(self, claimed_at: datetime) -> SourceRevisionWork | None:
        del claimed_at
        return self.work

    async def find_outcome(self, operation_id: str, event_id: str) -> SourceRevisionOutcome | None:
        del operation_id, event_id
        return self.outcome

    async def complete(
        self,
        work: SourceRevisionWork,
        snapshot: CommitGraphSnapshot,
        answers: tuple[CommitGraphAnswer, ...],
        processed_at: datetime,
    ) -> SourceRevisionOutcome:
        transition = work.transition
        result = SourceRevisionOutcome(
            work.operation_id,
            transition.event_id,
            transition.digest,
            transition.context_id,
            snapshot.graph_digest,
            tuple(sorted(item.id for item in answers)),
            reextraction_job_id(transition.context_id, ReextractionAction.EXTRACT),
            ReextractionAction.EXTRACT,
            len(transition.affected_evidence_ids),
            len(transition.affected_assertion_ids),
            processed_at,
        )
        self.outcome = result
        return result

    async def candidates(
        self,
        scope: AuthorizedScope,
        repository_id: str,
        relative_path: str,
        recorded_at: datetime,
        limit: int,
    ) -> tuple[SourceRevisionHistoryCandidate, ...]:
        del scope, repository_id, relative_path, recorded_at
        return self.history[:limit]

    async def register_lineage(  # noqa: PLR0913 -- Implements the production port.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        context_id: str,
        evidence_id: str,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        del scope, operation_id, context_id, evidence_id, assertion_id, registered_at
        return _digest("lineage")


@pytest.mark.asyncio
async def test_process_command_persists_ancestry_merge_base_and_replays() -> None:
    transition = _transition()
    work = SourceRevisionWork("process-revision-1", transition)
    graph = _Graph()
    repository = _Repository(work=work)
    handler = ProcessSourceRevisionHandler(graph, repository)
    command = ProcessSourceRevisionCommand(work.operation_id, work, NOW + timedelta(seconds=1))

    first = await handler.execute(command)
    replay = await handler.execute(command)

    assert replay is first
    assert len(first.graph_answer_ids) == 2
    assert graph.calls == [(BASE, MAIN, MAIN)]


@pytest.mark.asyncio
async def test_worker_claims_and_processes_one_committed_revision() -> None:
    work = SourceRevisionWork("process-worker-1", _transition())
    repository = _Repository(work=work)
    worker = SourceRevisionWorker(
        ProcessSourceRevisionHandler(_Graph(), repository),
        repository,
        FixedClock(NOW + timedelta(seconds=1)),
    )

    assert await worker.run_once()
    assert repository.outcome is not None


@pytest.mark.asyncio
async def test_history_query_pins_branch_before_concurrent_ref_change() -> None:
    graph = _Graph(branch_tip=MAIN)
    repository = _Repository(history=(_candidate(BASE, invalidations=(MAIN,)),))
    handler = QuerySourceRevisionHistoryHandler(
        graph,
        repository,
        FixedClock(NOW + timedelta(seconds=1)),
    )
    scope = _scope("indexing.revision.history.read")

    result = await handler.execute(
        QuerySourceRevisionHistoryQuery(
            scope,
            scope.repository_ids[0].value,
            "src/service.py",
            NOW,
            branch_name="main",
        )
    )

    assert graph.branch_tip == FEATURE
    assert len(result) == 1
    assert result[0].applicability is SourceRevisionApplicability.STALE
    assert all(target == MAIN and pinned == MAIN for _, target, pinned in graph.calls)


def _candidate(
    commit_sha: str, *, invalidations: tuple[str, ...]
) -> SourceRevisionHistoryCandidate:
    return SourceRevisionHistoryCandidate(
        _digest(f"context:{commit_sha}"),
        _digest("file"),
        _digest(f"revision:{commit_sha}"),
        _digest(f"snapshot:{commit_sha}"),
        "src/service.py",
        commit_sha,
        _digest(f"content:{commit_sha}"),
        SourceRevisionChangeKind.ADD,
        invalidations,
        (EVIDENCE,),
        (ASSERTION,),
        None,
        NOW,
    )
