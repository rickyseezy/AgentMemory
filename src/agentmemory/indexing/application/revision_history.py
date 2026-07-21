"""IDX-003 committed source processing and authorized historical queries."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.revision_history import (
    SourceRevisionHistoryEntry,
    SourceRevisionHistoryPolicy,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.revision_history import (
        CommitGraphAnswer,
        SourceRevisionOutcome,
    )
    from agentmemory.indexing.domain.revision_history_ports import (
        CommitGraphPort,
        SourceRevisionRepository,
        SourceRevisionWork,
    )
    from agentmemory.shared.clock import Clock

_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_BRANCH = 1_024
_MAX_RESULTS = 1_000
_ERR_ACTION = "source revision action is not authorized"
_ERR_QUERY = "source revision history query is invalid"
_ERR_REPLAY = "source revision processing conflicts with durable history"
_ERR_SCOPE = "source revision scope is invalid"


@dataclass(frozen=True, slots=True)
class ProcessSourceRevisionCommand:
    """Process one exact committed index event into ancestry-scoped history."""

    operation_id: str
    work: SourceRevisionWork
    processed_at: datetime

    def __post_init__(self) -> None:
        """Bind the command operation to the durably claimed work identity."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or self.operation_id != self.work.operation_id
        ):
            raise IndexingValidationError(_ERR_REPLAY)
        _utc(self.processed_at)


@dataclass(frozen=True, slots=True)
class ProcessSourceRevisionHandler:
    """Pin the commit graph, record ancestry decisions, then atomically process lineage."""

    graph: CommitGraphPort
    repository: SourceRevisionRepository

    async def execute(self, command: ProcessSourceRevisionCommand) -> SourceRevisionOutcome:
        """Exactly replay or process one committed changed/deleted source revision."""
        transition = command.work.transition
        existing = await self.repository.find_outcome(command.operation_id, transition.event_id)
        if existing is not None:
            return existing
        snapshot = await self.graph.pin_commit(
            transition.brain_id,
            transition.repository_id,
            transition.commit_sha,
            transition.occurred_at,
            command.processed_at,
        )
        answers: list[CommitGraphAnswer] = []
        if transition.base_commit_sha is not None:
            answers.append(
                await self.graph.ancestry(
                    snapshot,
                    transition.base_commit_sha,
                    transition.commit_sha,
                    command.processed_at,
                )
            )
            answers.append(
                await self.graph.merge_bases(
                    snapshot,
                    transition.base_commit_sha,
                    transition.commit_sha,
                    command.processed_at,
                )
            )
        return await self.repository.complete(
            command.work,
            snapshot,
            tuple(sorted(answers, key=lambda item: item.id)),
            command.processed_at,
        )


@dataclass(frozen=True, slots=True)
class SourceRevisionWorker:
    """Drain committed indexing events without competing with projection delivery."""

    handler: ProcessSourceRevisionHandler
    repository: SourceRevisionRepository
    clock: Clock

    async def run_once(self) -> bool:
        """Process one pending event and return whether work was available."""
        claimed_at = self.clock.now()
        work = await self.repository.claim_next(claimed_at)
        if work is None:
            return False
        await self.handler.execute(
            ProcessSourceRevisionCommand(work.operation_id, work, self.clock.now())
        )
        return True

    async def run(self, stop: asyncio.Event, *, idle_seconds: float = 0.1) -> None:
        """Drain committed source events until graceful shutdown."""
        while not stop.is_set():
            if not await self.run_once():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=idle_seconds)
                except TimeoutError:
                    continue


@dataclass(frozen=True, slots=True)
class QuerySourceRevisionHistoryQuery:
    """Authorized source-path history at one immutable commit or recorded branch view."""

    scope: AuthorizedScope
    repository_id: str
    relative_path: str
    recorded_at: datetime
    branch_name: str | None = None
    commit_sha: str | None = None
    include_stale: bool = True
    limit: int = 100

    def __post_init__(self) -> None:
        """Require one selector, exact repository membership, UTC, and bounded result count."""
        if (self.branch_name is None) == (self.commit_sha is None):
            raise IndexingValidationError(_ERR_QUERY)
        if self.branch_name is not None and (
            not self.branch_name
            or len(self.branch_name) > _MAX_BRANCH
            or any(character in self.branch_name for character in "\x00\r\n")
        ):
            raise IndexingValidationError(_ERR_QUERY)
        if self.commit_sha is not None and _COMMIT.fullmatch(self.commit_sha) is None:
            raise IndexingValidationError(_ERR_QUERY)
        if (
            self.repository_id not in {item.value for item in self.scope.repository_ids}
            or len(self.scope.project_ids) != 1
        ):
            raise IndexingAuthorizationError(_ERR_SCOPE)
        if not 1 <= self.limit <= _MAX_RESULTS:
            raise IndexingValidationError(_ERR_QUERY)
        _utc(self.recorded_at)


@dataclass(frozen=True, slots=True)
class QuerySourceRevisionHistoryHandler:
    """Resolve once, then classify every context against the same graph watermark."""

    graph: CommitGraphPort
    repository: SourceRevisionRepository
    clock: Clock

    async def execute(
        self, query: QuerySourceRevisionHistoryQuery
    ) -> tuple[SourceRevisionHistoryEntry, ...]:
        """Return reachable retained history with exact ancestry proof identities."""
        _require_action(query.scope, "indexing.revision.history.read")
        answered_at = self.clock.now()
        if query.commit_sha is not None:
            snapshot = await self.graph.pin_commit(
                query.scope.brain_id.value,
                query.repository_id,
                query.commit_sha,
                query.recorded_at,
                answered_at,
            )
        else:
            snapshot = await self.graph.pin_branch(
                query.scope.brain_id.value,
                query.repository_id,
                str(query.branch_name),
                query.recorded_at,
                answered_at,
            )
        candidates = await self.repository.candidates(
            query.scope,
            query.repository_id,
            query.relative_path,
            query.recorded_at,
            query.limit,
        )
        results: list[SourceRevisionHistoryEntry] = []
        for candidate in candidates:
            anchor = await self.graph.ancestry(
                snapshot,
                candidate.commit_sha,
                snapshot.target_commit_sha,
                answered_at,
            )
            if not anchor.is_ancestor:
                continue
            invalidation_answers = [
                await self.graph.ancestry(
                    snapshot,
                    commit_sha,
                    snapshot.target_commit_sha,
                    answered_at,
                )
                for commit_sha in candidate.invalidating_commit_shas
            ]
            reachable = tuple(
                sorted(
                    answer.left_commit_sha for answer in invalidation_answers if answer.is_ancestor
                )
            )
            applicability = SourceRevisionHistoryPolicy.classify(candidate, reachable)
            if not query.include_stale and applicability.value == "stale":
                continue
            answer_ids = tuple(sorted((anchor.id, *(item.id for item in invalidation_answers))))
            results.append(
                SourceRevisionHistoryEntry(
                    candidate,
                    applicability,
                    reachable,
                    snapshot.graph_digest,
                    answer_ids,
                )
            )
        return tuple(results[: query.limit])


@dataclass(frozen=True, slots=True)
class RegisterEvidenceLineageCommand:
    """Attach exact assertion evidence to one immutable source-revision context."""

    operation_id: str
    scope: AuthorizedScope
    context_id: str
    evidence_id: str
    assertion_id: str
    registered_at: datetime

    def __post_init__(self) -> None:
        """Reject malformed mutation identity before repository access."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            raise IndexingValidationError(_ERR_REPLAY)
        _utc(self.registered_at)


@dataclass(frozen=True, slots=True)
class RegisterEvidenceLineageHandler:
    """Authorize and append a source revision → evidence → assertion reverse edge."""

    repository: SourceRevisionRepository

    async def execute(self, command: RegisterEvidenceLineageCommand) -> str:
        """Append or exactly replay one evidence lineage registration."""
        _require_action(command.scope, "indexing.revision.lineage.register")
        return await self.repository.register_lineage(
            command.scope,
            command.operation_id,
            command.context_id,
            command.evidence_id,
            command.assertion_id,
            command.registered_at,
        )


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _utc(value: datetime) -> None:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise IndexingValidationError(_ERR_QUERY)
