"""IDX-003 source-revision lineage and pinned commit-graph decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast
from uuid import UUID

from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from datetime import datetime

_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_BRANCH = re.compile(r"^[^\x00\r\n]{1,1024}$")
_MAX_PATH_BYTES = 4_096
_MAX_IDS = 100_000
_UUID7 = 7
_ERR_ANSWER = "commit graph answer is invalid"
_ERR_HISTORY = "source revision history is invalid"
_ERR_TRANSITION = "source revision transition is invalid"


class CommitGraphQueryKind(StrEnum):
    """Closed graph questions whose exact answers are persisted for replay."""

    ANCESTRY = "ancestry"
    MERGE_BASE = "merge_base"


class SourceRevisionChangeKind(StrEnum):
    """Closed source-history transitions independent of VCS status spelling."""

    ADD = "add"
    MODIFY = "modify"
    RENAME = "rename"
    DELETE = "delete"
    REINTRODUCE = "reintroduce"


class SourceRevisionApplicability(StrEnum):
    """Relationship between one historical context and a selected revision."""

    CURRENT = "current"
    STALE = "stale"
    DELETED = "deleted"


class ReextractionAction(StrEnum):
    """Bounded follow-up work created by source-revision processing."""

    EXTRACT = "extract"
    RETRACT = "retract"


@dataclass(frozen=True, slots=True)
class CommitGraphSnapshot:
    """Immutable canonical commit-graph view used by every answer in one decision."""

    brain_id: str
    repository_id: str
    target_commit_sha: str
    graph_digest: str
    recorded_at: datetime
    resolved_ref_observation_id: str | None = None

    def __post_init__(self) -> None:
        """Require stable scope, commit, watermark, and optional ref proof."""
        _stable_id(self.brain_id, _ERR_ANSWER)
        _stable_id(self.repository_id, _ERR_ANSWER)
        _commit(self.target_commit_sha, _ERR_ANSWER)
        _digest(self.graph_digest, _ERR_ANSWER)
        _utc(self.recorded_at, _ERR_ANSWER)
        if self.resolved_ref_observation_id is not None:
            _digest(self.resolved_ref_observation_id, _ERR_ANSWER)


@dataclass(frozen=True, slots=True)
class CommitGraphAnswer:
    """Replay-stable ancestry or complete best-merge-base answer."""

    kind: CommitGraphQueryKind
    left_commit_sha: str
    right_commit_sha: str
    graph_digest: str
    is_ancestor: bool | None
    merge_base_shas: tuple[str, ...]
    answered_at: datetime

    def __post_init__(self) -> None:
        """Require a complete answer shape bound to one graph watermark."""
        _enum(self.kind, CommitGraphQueryKind, _ERR_ANSWER)
        _commit(self.left_commit_sha, _ERR_ANSWER)
        _commit(self.right_commit_sha, _ERR_ANSWER)
        _digest(self.graph_digest, _ERR_ANSWER)
        _utc(self.answered_at, _ERR_ANSWER)
        _sorted_commits(self.merge_base_shas, _ERR_ANSWER)
        if self.kind is CommitGraphQueryKind.ANCESTRY:
            if not isinstance(cast("object", self.is_ancestor), bool) or self.merge_base_shas:
                raise IndexingValidationError(_ERR_ANSWER)
        elif self.is_ancestor is not None or not self.merge_base_shas:
            raise IndexingValidationError(_ERR_ANSWER)

    @property
    def id(self) -> str:
        """Return exact query-and-answer identity for durable replay."""
        return _identity(
            "commit-graph-answer.v1",
            {
                "graph_digest": self.graph_digest,
                "is_ancestor": self.is_ancestor,
                "kind": self.kind.value,
                "left": self.left_commit_sha,
                "merge_bases": list(self.merge_base_shas),
                "right": self.right_commit_sha,
            },
        )


@dataclass(frozen=True, slots=True)
class SourceRevisionTransition:
    """One committed changed/deleted file and its exact reverse dependency closure."""

    event_id: str
    run_id: str
    brain_id: str
    project_id: str
    repository_id: str
    source_file_id: str
    previous_source_file_id: str | None
    snapshot_id: str
    previous_snapshot_id: str | None
    file_revision_id: str | None
    previous_file_revision_id: str | None
    relative_path: str
    previous_path: str | None
    commit_sha: str
    base_commit_sha: str | None
    content_digest: str | None
    previous_content_digest: str | None
    kind: SourceRevisionChangeKind
    current_semantic_ids: tuple[str, ...]
    affected_evidence_ids: tuple[str, ...]
    affected_assertion_ids: tuple[str, ...]
    reintroduced_from_context_id: str | None
    occurred_at: datetime

    def __post_init__(self) -> None:  # noqa: C901 -- Closed transition matrix is explicit.
        """Reject ambiguous lineage, unordered impacts, and false continuity."""
        for value in (
            self.event_id,
            self.run_id,
            self.source_file_id,
            self.snapshot_id,
        ):
            _digest(value, _ERR_TRANSITION)
        for value in (self.brain_id, self.project_id, self.repository_id):
            _stable_id(value, _ERR_TRANSITION)
        for optional_value in (
            self.previous_source_file_id,
            self.previous_snapshot_id,
            self.file_revision_id,
            self.previous_file_revision_id,
            self.content_digest,
            self.previous_content_digest,
            self.reintroduced_from_context_id,
        ):
            if optional_value is not None:
                _digest(optional_value, _ERR_TRANSITION)
        _path(self.relative_path)
        if self.previous_path is not None:
            _path(self.previous_path)
        _commit(self.commit_sha, _ERR_TRANSITION)
        if self.base_commit_sha is not None:
            _commit(self.base_commit_sha, _ERR_TRANSITION)
        _enum(self.kind, SourceRevisionChangeKind, _ERR_TRANSITION)
        _sorted_digests(self.current_semantic_ids, _ERR_TRANSITION)
        _sorted_graph_ids(self.affected_evidence_ids, _ERR_TRANSITION)
        _sorted_graph_ids(self.affected_assertion_ids, _ERR_TRANSITION)
        _utc(self.occurred_at, _ERR_TRANSITION)
        if any(
            len(values) > _MAX_IDS
            for values in (
                self.current_semantic_ids,
                self.affected_evidence_ids,
                self.affected_assertion_ids,
            )
        ):
            raise IndexingValidationError(_ERR_TRANSITION)
        deleted = self.kind is SourceRevisionChangeKind.DELETE
        if deleted != (self.file_revision_id is None and self.content_digest is None):
            raise IndexingValidationError(_ERR_TRANSITION)
        if deleted and self.current_semantic_ids:
            raise IndexingValidationError(_ERR_TRANSITION)
        if self.kind is SourceRevisionChangeKind.RENAME and (
            self.previous_path is None or self.previous_source_file_id is None
        ):
            raise IndexingValidationError(_ERR_TRANSITION)
        if self.kind is SourceRevisionChangeKind.REINTRODUCE and (
            self.reintroduced_from_context_id is None
            or self.file_revision_id is None
            or self.file_revision_id == self.previous_file_revision_id
        ):
            raise IndexingValidationError(_ERR_TRANSITION)
        if self.kind is not SourceRevisionChangeKind.REINTRODUCE and (
            self.reintroduced_from_context_id is not None
        ):
            raise IndexingValidationError(_ERR_TRANSITION)

    @property
    def context_id(self) -> str:
        """Create a context identity that cannot collapse identical bytes across commits."""
        return _identity(
            "source-revision-context.v1",
            {
                "commit_sha": self.commit_sha,
                "event_id": self.event_id,
                "file_revision_id": self.file_revision_id,
                "snapshot_id": self.snapshot_id,
                "source_file_id": self.source_file_id,
            },
        )

    @property
    def digest(self) -> str:
        """Bind every processing input and reverse dependency to one receipt."""
        return _identity(
            "source-revision-transition.v1",
            {
                "assertions": list(self.affected_assertion_ids),
                "base_commit_sha": self.base_commit_sha,
                "brain_id": self.brain_id,
                "commit_sha": self.commit_sha,
                "content_digest": self.content_digest,
                "context_id": self.context_id,
                "current_semantic_ids": list(self.current_semantic_ids),
                "event_id": self.event_id,
                "evidence": list(self.affected_evidence_ids),
                "kind": self.kind.value,
                "previous_content_digest": self.previous_content_digest,
                "previous_file_revision_id": self.previous_file_revision_id,
                "previous_path": self.previous_path,
                "previous_snapshot_id": self.previous_snapshot_id,
                "previous_source_file_id": self.previous_source_file_id,
                "project_id": self.project_id,
                "relative_path": self.relative_path,
                "repository_id": self.repository_id,
                "reintroduced_from": self.reintroduced_from_context_id,
                "run_id": self.run_id,
                "snapshot_id": self.snapshot_id,
                "source_file_id": self.source_file_id,
            },
        )


@dataclass(frozen=True, slots=True)
class SourceRevisionOutcome:
    """Durable result of processing one committed source transition."""

    operation_id: str
    event_id: str
    transition_digest: str
    context_id: str
    graph_digest: str
    graph_answer_ids: tuple[str, ...]
    reextraction_job_id: str
    action: ReextractionAction
    closed_evidence_count: int
    affected_assertion_count: int
    processed_at: datetime

    def __post_init__(self) -> None:
        """Require bounded counters and exact immutable receipt coordinates."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            raise IndexingValidationError(_ERR_TRANSITION)
        for value in (
            self.event_id,
            self.transition_digest,
            self.context_id,
            self.graph_digest,
            self.reextraction_job_id,
        ):
            _digest(value, _ERR_TRANSITION)
        _sorted_digests(self.graph_answer_ids, _ERR_TRANSITION)
        _enum(self.action, ReextractionAction, _ERR_TRANSITION)
        if (
            isinstance(cast("object", self.closed_evidence_count), bool)
            or not isinstance(cast("object", self.closed_evidence_count), int)
            or self.closed_evidence_count < 0
            or isinstance(cast("object", self.affected_assertion_count), bool)
            or not isinstance(cast("object", self.affected_assertion_count), int)
            or self.affected_assertion_count < 0
        ):
            raise IndexingValidationError(_ERR_TRANSITION)
        _utc(self.processed_at, _ERR_TRANSITION)


@dataclass(frozen=True, slots=True)
class SourceRevisionHistoryCandidate:
    """Authorized retained source context before commit-reachability classification."""

    context_id: str
    source_file_id: str
    file_revision_id: str | None
    snapshot_id: str
    relative_path: str
    commit_sha: str
    content_digest: str | None
    kind: SourceRevisionChangeKind
    invalidating_commit_shas: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    reintroduced_from_context_id: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        """Validate a content-free, deterministic retained history row."""
        for value in (self.context_id, self.source_file_id, self.snapshot_id):
            _digest(value, _ERR_HISTORY)
        for optional_value in (
            self.file_revision_id,
            self.content_digest,
            self.reintroduced_from_context_id,
        ):
            if optional_value is not None:
                _digest(optional_value, _ERR_HISTORY)
        _path(self.relative_path)
        _commit(self.commit_sha, _ERR_HISTORY)
        _enum(self.kind, SourceRevisionChangeKind, _ERR_HISTORY)
        _sorted_commits(self.invalidating_commit_shas, _ERR_HISTORY)
        _sorted_graph_ids(self.evidence_ids, _ERR_HISTORY)
        _sorted_graph_ids(self.assertion_ids, _ERR_HISTORY)
        _utc(self.observed_at, _ERR_HISTORY)


@dataclass(frozen=True, slots=True)
class SourceRevisionHistoryEntry:
    """One reachable historical source context with replayable graph evidence."""

    candidate: SourceRevisionHistoryCandidate
    applicability: SourceRevisionApplicability
    reachable_invalidating_commits: tuple[str, ...]
    graph_digest: str
    graph_answer_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Prevent current/stale/deleted labels from disagreeing with graph proof."""
        _enum(self.applicability, SourceRevisionApplicability, _ERR_HISTORY)
        _sorted_commits(self.reachable_invalidating_commits, _ERR_HISTORY)
        _digest(self.graph_digest, _ERR_HISTORY)
        _sorted_digests(self.graph_answer_ids, _ERR_HISTORY)
        if self.applicability is SourceRevisionApplicability.CURRENT and (
            self.reachable_invalidating_commits
            or self.candidate.kind is SourceRevisionChangeKind.DELETE
        ):
            raise IndexingValidationError(_ERR_HISTORY)
        if self.applicability is SourceRevisionApplicability.STALE and (
            not self.reachable_invalidating_commits
        ):
            raise IndexingValidationError(_ERR_HISTORY)
        if self.applicability is SourceRevisionApplicability.DELETED and (
            self.candidate.kind is not SourceRevisionChangeKind.DELETE
        ):
            raise IndexingValidationError(_ERR_HISTORY)


class SourceRevisionHistoryPolicy:
    """Classify a reachable context without using mutable branch labels."""

    @staticmethod
    def classify(
        candidate: SourceRevisionHistoryCandidate,
        reachable_invalidations: tuple[str, ...],
    ) -> SourceRevisionApplicability:
        """Return current, stale, or deletion-marker status for one target commit."""
        if candidate.kind is SourceRevisionChangeKind.DELETE:
            return SourceRevisionApplicability.DELETED
        if reachable_invalidations:
            return SourceRevisionApplicability.STALE
        return SourceRevisionApplicability.CURRENT


def reextraction_job_id(context_id: str, action: ReextractionAction) -> str:
    """Derive one follow-up job per new revision context, never per blob digest."""
    _digest(context_id, _ERR_TRANSITION)
    _enum(action, ReextractionAction, _ERR_TRANSITION)
    return _identity(
        "source-revision-reextraction.v1",
        {"action": action.value, "context_id": context_id},
    )


def _identity(namespace: str, document: dict[str, object]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{namespace}\0{encoded}".encode()).hexdigest()


def _path(value: str) -> None:
    if not value or len(value.encode()) > _MAX_PATH_BYTES or "\\" in value or "\x00" in value:
        raise IndexingValidationError(_ERR_HISTORY)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_HISTORY)


def _commit(value: object, error: str) -> None:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise IndexingValidationError(error)


def _digest(value: object, error: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise IndexingValidationError(error)


def _stable_id(value: str, error: str) -> None:
    if _DIGEST.fullmatch(value) is not None:
        return
    try:
        parsed = UUID(value)
    except ValueError as exception:
        raise IndexingValidationError(error) from exception
    if parsed.version != _UUID7 or str(parsed) != value:
        raise IndexingValidationError(error)


def _sorted_digests(values: tuple[str, ...], error: str) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(error)
    for value in values:
        _digest(value, error)


def _sorted_commits(values: tuple[str, ...], error: str) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(error)
    for value in values:
        _commit(value, error)


def _sorted_graph_ids(values: tuple[str, ...], error: str) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(error)
    for value in values:
        _stable_id(value, error)


def _enum(value: object, expected: type[StrEnum], error: str) -> None:
    if not isinstance(value, expected):
        raise IndexingValidationError(error)


def _utc(value: datetime, error: str) -> None:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise IndexingValidationError(error)
