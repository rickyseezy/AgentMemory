"""IDX-002 deterministic incremental plans, cache identities, and run lifecycle."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast
from uuid import UUID

from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from datetime import datetime

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._+-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ERR_CACHE = "incremental index cache identity is invalid"
_ERR_PLAN = "incremental index plan is invalid"
_ERR_RUN = "incremental index run is invalid"
_ERR_EVENT = "incremental projection event is invalid"
_MAX_PATH_BYTES = 4_096
_MAX_FILES = 1_000_000
_MAX_SEMANTIC_IDS = 100_000
_MAX_IDENTITY = 128
_UUID7_VERSION = 7


class VcsDeltaKind(StrEnum):
    """Closed VCS observations used to corroborate content-addressed planning."""

    ADD = "add"
    MODIFY = "modify"
    RENAME = "rename"
    COPY = "copy"
    DELETE = "delete"


class IndexOperationKind(StrEnum):
    """Closed operations required by the IDX-002 plan."""

    ADD = "add"
    MODIFY = "modify"
    RENAME = "rename"
    DELETE = "delete"
    REUSE = "reuse"


class IndexOperationReason(StrEnum):
    """Content-safe reason explaining why one unit is rebuilt or reused."""

    NEW_CONTENT = "new_content"
    CONTENT_CHANGED = "content_changed"
    FINGERPRINT_CHANGED = "fingerprint_changed"
    PATH_CHANGED = "path_changed"
    COPIED_CONTENT = "copied_content"
    CONTENT_DELETED = "content_deleted"
    GENERATED_EXCLUDED = "generated_excluded"
    CACHE_HIT = "cache_hit"


class IndexRunState(StrEnum):
    """Durable long-operation lifecycle exposed by the indexing API."""

    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class IndexFingerprint:
    """Every implementation/policy coordinate capable of changing extracted semantics."""

    plugin_version: str
    grammar_revision: str
    query_pack_digest: str
    extraction_config_digest: str
    privacy_policy_version: str

    def __post_init__(self) -> None:
        """Reject mutable, empty, or ambiguous cache coordinates."""
        for value in (self.plugin_version, self.grammar_revision, self.privacy_policy_version):
            if _VERSION.fullmatch(value) is None:
                raise IndexingValidationError(_ERR_CACHE)
        for value in (self.query_pack_digest, self.extraction_config_digest):
            _digest(value, _ERR_CACHE)

    @property
    def digest(self) -> str:
        """Return a canonical fingerprint independent of Python serialization details."""
        return _identity(
            "index-fingerprint.v1",
            {
                "extraction_config_digest": self.extraction_config_digest,
                "grammar_revision": self.grammar_revision,
                "plugin_version": self.plugin_version,
                "privacy_policy_version": self.privacy_policy_version,
                "query_pack_digest": self.query_pack_digest,
            },
        )

    def cache_key(self, relative_path: str, content_digest: str) -> str:
        """Bind cache reuse to exact bytes, path-sensitive semantics, parser, and policy."""
        _path(relative_path)
        _digest(content_digest, _ERR_CACHE)
        return _identity(
            "index-cache.v1",
            {
                "content_digest": content_digest,
                "extraction_config_digest": self.extraction_config_digest,
                "grammar_revision": self.grammar_revision,
                "path": relative_path,
                "plugin_version": self.plugin_version,
                "privacy_policy_version": self.privacy_policy_version,
                "query_pack_digest": self.query_pack_digest,
            },
        )


@dataclass(frozen=True, slots=True)
class PriorIndexedUnit:
    """Current authorized file binding from the previous completed snapshot."""

    relative_path: str
    source_file_id: str
    file_revision_id: str
    content_digest: str
    cache_key: str
    semantic_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require stable, sorted, content-free prior evidence."""
        _path(self.relative_path)
        for value in (
            self.source_file_id,
            self.file_revision_id,
            self.content_digest,
            self.cache_key,
        ):
            _digest(value, _ERR_PLAN)
        _sorted_digests(self.semantic_ids, _ERR_PLAN)


@dataclass(frozen=True, slots=True)
class CurrentIndexUnit:
    """Current repository manifest entry without retained source text."""

    relative_path: str
    content_digest: str
    byte_length: int
    cache_key: str
    generated: bool = False

    def __post_init__(self) -> None:
        """Validate the exact current content and policy classification."""
        _path(self.relative_path)
        _digest(self.content_digest, _ERR_PLAN)
        _digest(self.cache_key, _ERR_PLAN)
        if (
            isinstance(cast("object", self.byte_length), bool)
            or not isinstance(cast("object", self.byte_length), int)
            or self.byte_length < 0
            or not isinstance(cast("object", self.generated), bool)
        ):
            raise IndexingValidationError(_ERR_PLAN)


@dataclass(frozen=True, slots=True)
class VcsDelta:
    """One normalized Git change observation; hashes remain authoritative."""

    kind: VcsDeltaKind
    relative_path: str
    previous_path: str | None = None

    def __post_init__(self) -> None:
        """Require coherent old/new paths for each closed VCS status."""
        _enum(self.kind, VcsDeltaKind, _ERR_PLAN)
        _path(self.relative_path)
        if self.kind in {VcsDeltaKind.RENAME, VcsDeltaKind.COPY}:
            if self.previous_path is None:
                raise IndexingValidationError(_ERR_PLAN)
            _path(self.previous_path)
            if self.previous_path == self.relative_path:
                raise IndexingValidationError(_ERR_PLAN)
        elif self.previous_path is not None:
            raise IndexingValidationError(_ERR_PLAN)


@dataclass(frozen=True, slots=True)
class IndexOperation:
    """One immutable content-addressed plan operation."""

    ordinal: int
    kind: IndexOperationKind
    reason: IndexOperationReason
    relative_path: str
    previous_path: str | None
    content_digest: str | None
    cache_key: str | None
    previous_source_file_id: str | None
    previous_file_revision_id: str | None
    previous_semantic_ids: tuple[str, ...]
    generated: bool

    def __post_init__(self) -> None:
        """Require a closed shape for add, modify, rename, delete, and reuse."""
        _validate_operation_coordinates(self)
        _validate_operation_shape(self)

    @property
    def id(self) -> str:
        """Derive stable operation identity including invalidation lineage."""
        return _identity("index-operation.v1", self.canonical_document)

    @property
    def invalidated_semantic_ids(self) -> tuple[str, ...]:
        """Return prior units whose authority ends; a copy preserves its source."""
        if self.reason is IndexOperationReason.COPIED_CONTENT:
            return ()
        return self.previous_semantic_ids

    @property
    def canonical_document(self) -> dict[str, object]:
        """Return the exact canonical plan representation persisted by adapters."""
        return {
            "cache_key": self.cache_key,
            "content_digest": self.content_digest,
            "generated": self.generated,
            "kind": self.kind.value,
            "ordinal": self.ordinal,
            "previous_file_revision_id": self.previous_file_revision_id,
            "previous_path": self.previous_path,
            "previous_semantic_ids": list(self.previous_semantic_ids),
            "previous_source_file_id": self.previous_source_file_id,
            "reason": self.reason.value,
            "relative_path": self.relative_path,
        }


def _validate_operation_coordinates(value: IndexOperation) -> None:
    """Validate values shared by every operation shape."""
    if (
        isinstance(cast("object", value.ordinal), bool)
        or not isinstance(cast("object", value.ordinal), int)
        or value.ordinal < 0
    ):
        raise IndexingValidationError(_ERR_PLAN)
    _enum(value.kind, IndexOperationKind, _ERR_PLAN)
    _enum(value.reason, IndexOperationReason, _ERR_PLAN)
    _path(value.relative_path)
    if value.previous_path is not None:
        _path(value.previous_path)
    for digest_value in (
        value.content_digest,
        value.cache_key,
        value.previous_source_file_id,
        value.previous_file_revision_id,
    ):
        if digest_value is not None:
            _digest(digest_value, _ERR_PLAN)
    _sorted_digests(value.previous_semantic_ids, _ERR_PLAN)
    if not isinstance(cast("object", value.generated), bool):
        raise IndexingValidationError(_ERR_PLAN)


def _validate_operation_shape(value: IndexOperation) -> None:
    """Validate required current and previous coordinates by operation kind."""
    current_required = value.kind is not IndexOperationKind.DELETE
    previous_required = (
        value.kind
        in {
            IndexOperationKind.MODIFY,
            IndexOperationKind.RENAME,
            IndexOperationKind.DELETE,
            IndexOperationKind.REUSE,
        }
        or value.reason is IndexOperationReason.COPIED_CONTENT
    )
    if current_required != (value.content_digest is not None and value.cache_key is not None):
        raise IndexingValidationError(_ERR_PLAN)
    if previous_required != (
        value.previous_source_file_id is not None and value.previous_file_revision_id is not None
    ):
        raise IndexingValidationError(_ERR_PLAN)
    if value.kind is IndexOperationKind.RENAME and value.previous_path is None:
        raise IndexingValidationError(_ERR_PLAN)
    if (
        value.kind is IndexOperationKind.ADD
        and value.previous_path is not None
        and value.reason is not IndexOperationReason.COPIED_CONTENT
    ):
        raise IndexingValidationError(_ERR_PLAN)
    if value.kind not in {IndexOperationKind.ADD, IndexOperationKind.RENAME} and (
        value.previous_path is not None
    ):
        raise IndexingValidationError(_ERR_PLAN)


@dataclass(frozen=True, slots=True)
class IndexPlan:
    """Deterministic complete plan whose cost scales with changed operations at execution."""

    operations: tuple[IndexOperation, ...]

    def __post_init__(self) -> None:
        """Require unique paths, dense ordinals, and bounded plan size."""
        if len(self.operations) > _MAX_FILES:
            raise IndexingValidationError(_ERR_PLAN)
        if tuple(item.ordinal for item in self.operations) != tuple(range(len(self.operations))):
            raise IndexingValidationError(_ERR_PLAN)
        paths = tuple(item.relative_path for item in self.operations)
        if len(paths) != len(set(paths)):
            raise IndexingValidationError(_ERR_PLAN)

    @classmethod
    def create(
        cls,
        previous: Sequence[PriorIndexedUnit],
        current: Sequence[CurrentIndexUnit],
        vcs_deltas: Sequence[VcsDelta],
        *,
        include_generated: bool,
    ) -> IndexPlan:
        """Combine VCS topology hints with authoritative paths, hashes, and cache keys."""
        if not isinstance(cast("object", include_generated), bool):
            raise IndexingValidationError(_ERR_PLAN)
        prior = _unique_by_path(previous)
        observed = _unique_by_path(current)
        deltas = _unique_deltas(vcs_deltas)
        effective = {
            path: item for path, item in observed.items() if include_generated or not item.generated
        }
        generated_excluded = {
            path for path, item in observed.items() if item.generated and not include_generated
        }
        operations, consumed_prior, consumed_current = _lineage_operations(prior, effective, deltas)
        operations.extend(_current_operations(prior, effective, consumed_prior, consumed_current))
        operations.extend(_deleted_operations(prior, consumed_prior, generated_excluded))
        ordered = sorted(
            operations,
            key=lambda item: (
                item.relative_path,
                _KIND_ORDER[item.kind],
                item.previous_path or "",
            ),
        )
        return cls(tuple(item.number(ordinal) for ordinal, item in enumerate(ordered)))

    @property
    def digest(self) -> str:
        """Return the replay identity of the full ordered plan."""
        return _identity(
            "index-plan.v1",
            {"operations": [item.canonical_document for item in self.operations]},
        )

    @property
    def changed_count(self) -> int:
        """Count operations that require parsing or invalidation work."""
        return sum(item.kind is not IndexOperationKind.REUSE for item in self.operations)


@dataclass(frozen=True, slots=True)
class _UnorderedOperation:
    kind: IndexOperationKind
    reason: IndexOperationReason
    relative_path: str
    previous_path: str | None
    content_digest: str | None
    cache_key: str | None
    previous_source_file_id: str | None
    previous_file_revision_id: str | None
    previous_semantic_ids: tuple[str, ...]
    generated: bool

    def number(self, ordinal: int) -> IndexOperation:
        return IndexOperation(
            ordinal,
            self.kind,
            self.reason,
            self.relative_path,
            self.previous_path,
            self.content_digest,
            self.cache_key,
            self.previous_source_file_id,
            self.previous_file_revision_id,
            self.previous_semantic_ids,
            self.generated,
        )


_KIND_ORDER = {
    IndexOperationKind.DELETE: 0,
    IndexOperationKind.RENAME: 1,
    IndexOperationKind.MODIFY: 2,
    IndexOperationKind.ADD: 3,
    IndexOperationKind.REUSE: 4,
}


@dataclass(frozen=True, slots=True)
class IndexRun:
    """Append-only checkpoint state for one authorized incremental indexing run."""

    id: str
    operation_id: str
    brain_id: str
    project_id: str
    repository_id: str
    base_snapshot_id: str | None
    target_snapshot_id: str
    target_commit_id: str | None
    working_digest: str
    implementation_fingerprint: str
    plan_digest: str
    total_operations: int
    changed_operations: int
    cursor: int
    indexed_count: int
    reused_count: int
    deleted_count: int
    failed_count: int
    state: IndexRunState
    detected_at: datetime
    started_at: datetime | None
    updated_at: datetime
    completed_at: datetime | None
    failure_code: str | None = None

    @classmethod
    def queue(  # noqa: PLR0913 -- Run identity binds every exact repository coordinate.
        cls,
        *,
        operation_id: str,
        brain_id: str,
        project_id: str,
        repository_id: str,
        base_snapshot_id: str | None,
        target_snapshot_id: str,
        target_commit_id: str | None,
        working_digest: str,
        implementation_fingerprint: str,
        plan: IndexPlan,
        detected_at: datetime,
    ) -> IndexRun:
        """Create a replay-stable queued run before any semantic mutation."""
        run_id = _identity(
            "index-run.v1",
            {
                "brain_id": brain_id,
                "operation_id": operation_id,
                "project_id": project_id,
                "repository_id": repository_id,
            },
        )
        return cls(
            run_id,
            operation_id,
            brain_id,
            project_id,
            repository_id,
            base_snapshot_id,
            target_snapshot_id,
            target_commit_id,
            working_digest,
            implementation_fingerprint,
            plan.digest,
            len(plan.operations),
            plan.changed_count,
            0,
            0,
            0,
            0,
            0,
            IndexRunState.QUEUED,
            detected_at,
            None,
            detected_at,
            None,
            None,
        )

    def __post_init__(self) -> None:
        """Reject incoherent progress, state, time, and repository identity."""
        _validate_run_identity(self)
        _validate_run_progress(self)
        _validate_run_times_and_state(self)

    def begin(self, at: datetime) -> IndexRun:
        """Claim a queued run exactly once."""
        _utc(at, _ERR_RUN)
        if self.state is IndexRunState.RUNNING:
            return self
        if self.state is not IndexRunState.QUEUED or at < self.updated_at:
            raise IndexingValidationError(_ERR_RUN)
        return replace(self, state=IndexRunState.RUNNING, started_at=at, updated_at=at)

    def request_cancel(self, at: datetime) -> IndexRun:
        """Persist cancellation intent without racing a worker checkpoint."""
        _utc(at, _ERR_RUN)
        if self.state in {
            IndexRunState.CANCELLING,
            IndexRunState.CANCELLED,
            IndexRunState.COMPLETED,
            IndexRunState.FAILED,
        }:
            return self
        if at < self.updated_at:
            raise IndexingValidationError(_ERR_RUN)
        return replace(self, state=IndexRunState.CANCELLING, updated_at=at)

    def checkpoint(self, operation: IndexOperation, *, failed: bool, at: datetime) -> IndexRun:
        """Advance exactly one ordered operation after its atomic persistence boundary."""
        _utc(at, _ERR_RUN)
        if (
            self.state is not IndexRunState.RUNNING
            or operation.ordinal != self.cursor
            or at < self.updated_at
        ):
            raise IndexingValidationError(_ERR_RUN)
        indexed = self.indexed_count
        reused = self.reused_count
        deleted = self.deleted_count
        failures = self.failed_count
        if failed:
            failures += 1
        elif operation.kind is IndexOperationKind.REUSE:
            reused += 1
        elif operation.kind is IndexOperationKind.DELETE:
            deleted += 1
        else:
            indexed += 1
        return replace(
            self,
            cursor=self.cursor + 1,
            indexed_count=indexed,
            reused_count=reused,
            deleted_count=deleted,
            failed_count=failures,
            updated_at=at,
        )

    def finish(self, at: datetime) -> IndexRun:
        """Complete only after every immutable plan operation has checkpointed."""
        _utc(at, _ERR_RUN)
        if (
            self.state is not IndexRunState.RUNNING
            or self.cursor != self.total_operations
            or at < self.updated_at
        ):
            raise IndexingValidationError(_ERR_RUN)
        return replace(
            self,
            state=IndexRunState.COMPLETED,
            updated_at=at,
            completed_at=at,
        )

    def cancel(self, at: datetime) -> IndexRun:
        """Acknowledge cancellation at an operation boundary."""
        _utc(at, _ERR_RUN)
        if self.state is IndexRunState.CANCELLED:
            return self
        if self.state is not IndexRunState.CANCELLING or at < self.updated_at:
            raise IndexingValidationError(_ERR_RUN)
        return replace(
            self,
            state=IndexRunState.CANCELLED,
            updated_at=at,
            completed_at=at,
        )

    def fail(self, failure_code: str, at: datetime) -> IndexRun:
        """Terminate with a bounded content-free failure classification."""
        _token(failure_code, _ERR_RUN)
        _utc(at, _ERR_RUN)
        if self.state is IndexRunState.FAILED and self.failure_code == failure_code:
            return self
        if self.state not in {IndexRunState.QUEUED, IndexRunState.RUNNING} or at < self.updated_at:
            raise IndexingValidationError(_ERR_RUN)
        return replace(
            self,
            state=IndexRunState.FAILED,
            failure_code=failure_code,
            updated_at=at,
            completed_at=at,
        )

    @property
    def freshness_seconds(self) -> float | None:
        """Expose end-to-end detection-to-completion freshness for SLO reporting."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.detected_at).total_seconds()


def _validate_run_identity(value: IndexRun) -> None:
    """Validate run and repository coordinates independently of lifecycle state."""
    _digest(value.id, _ERR_RUN)
    if _OPERATION.fullmatch(value.operation_id) is None:
        raise IndexingValidationError(_ERR_RUN)
    for identity in (value.brain_id, value.project_id, value.repository_id):
        if (
            not identity
            or len(identity) > _MAX_IDENTITY
            or any(char.isspace() for char in identity)
        ):
            raise IndexingValidationError(_ERR_RUN)
    for digest_value in (
        value.base_snapshot_id,
        value.target_snapshot_id,
        value.working_digest,
        value.implementation_fingerprint,
        value.plan_digest,
    ):
        if digest_value is not None:
            _digest(digest_value, _ERR_RUN)
    if value.target_commit_id is not None and (
        not value.target_commit_id
        or len(value.target_commit_id) > _MAX_IDENTITY
        or any(char.isspace() for char in value.target_commit_id)
    ):
        raise IndexingValidationError(_ERR_RUN)


def _validate_run_progress(value: IndexRun) -> None:
    """Validate dense operation progress and mutually exclusive counters."""
    counts = (
        value.total_operations,
        value.changed_operations,
        value.cursor,
        value.indexed_count,
        value.reused_count,
        value.deleted_count,
        value.failed_count,
    )
    if any(
        isinstance(cast("object", count), bool)
        or not isinstance(cast("object", count), int)
        or count < 0
        for count in counts
    ):
        raise IndexingValidationError(_ERR_RUN)
    processed = value.indexed_count + value.reused_count + value.deleted_count + value.failed_count
    if (
        value.changed_operations > value.total_operations
        or value.cursor > value.total_operations
        or processed != value.cursor
    ):
        raise IndexingValidationError(_ERR_RUN)


def _validate_run_times_and_state(value: IndexRun) -> None:
    """Validate monotonic UTC lifecycle and terminal evidence."""
    _enum(value.state, IndexRunState, _ERR_RUN)
    _utc(value.detected_at, _ERR_RUN)
    _utc(value.updated_at, _ERR_RUN)
    if value.started_at is not None:
        _utc(value.started_at, _ERR_RUN)
    if value.completed_at is not None:
        _utc(value.completed_at, _ERR_RUN)
    if value.updated_at < value.detected_at:
        raise IndexingValidationError(_ERR_RUN)
    terminal = value.state in {
        IndexRunState.CANCELLED,
        IndexRunState.COMPLETED,
        IndexRunState.FAILED,
    }
    if terminal != (value.completed_at is not None):
        raise IndexingValidationError(_ERR_RUN)
    if value.state is IndexRunState.COMPLETED and value.cursor != value.total_operations:
        raise IndexingValidationError(_ERR_RUN)
    if (value.state is IndexRunState.FAILED) != (value.failure_code is not None):
        raise IndexingValidationError(_ERR_RUN)
    if value.failure_code is not None:
        _token(value.failure_code, _ERR_RUN)


@dataclass(frozen=True, slots=True)
class IndexProjectionEvent:
    """Bounded projection/invalidation work emitted by one changed file operation."""

    run_id: str
    operation_id: str
    ordinal: int
    snapshot_id: str
    previous_file_revision_ids: tuple[str, ...]
    current_file_revision_ids: tuple[str, ...]
    affected_semantic_ids: tuple[str, ...]
    dependent_fact_ids: tuple[str, ...]
    assertion_evidence_ids: tuple[str, ...]
    reembed_semantic_ids: tuple[str, ...]
    occurred_at: datetime

    def __post_init__(self) -> None:
        """Require sorted bounded content-free impact sets and stable lineage."""
        for value in (self.run_id, self.operation_id, self.snapshot_id):
            _digest(value, _ERR_EVENT)
        if (
            isinstance(cast("object", self.ordinal), bool)
            or not isinstance(cast("object", self.ordinal), int)
            or self.ordinal < 0
        ):
            raise IndexingValidationError(_ERR_EVENT)
        for values in (
            self.previous_file_revision_ids,
            self.current_file_revision_ids,
            self.affected_semantic_ids,
            self.reembed_semantic_ids,
        ):
            _sorted_digests(values, _ERR_EVENT)
            if len(values) > _MAX_SEMANTIC_IDS:
                raise IndexingValidationError(_ERR_EVENT)
        for values in (self.dependent_fact_ids, self.assertion_evidence_ids):
            _sorted_graph_ids(values, _ERR_EVENT)
            if len(values) > _MAX_SEMANTIC_IDS:
                raise IndexingValidationError(_ERR_EVENT)
        _utc(self.occurred_at, _ERR_EVENT)

    @property
    def id(self) -> str:
        """Derive an idempotent event identity from its complete impact manifest."""
        return _identity(
            "index-projection-event.v1",
            {
                "affected_semantic_ids": list(self.affected_semantic_ids),
                "assertion_evidence_ids": list(self.assertion_evidence_ids),
                "current_file_revision_ids": list(self.current_file_revision_ids),
                "dependent_fact_ids": list(self.dependent_fact_ids),
                "occurred_at": _micros(self.occurred_at),
                "operation_id": self.operation_id,
                "ordinal": self.ordinal,
                "previous_file_revision_ids": list(self.previous_file_revision_ids),
                "reembed_semantic_ids": list(self.reembed_semantic_ids),
                "run_id": self.run_id,
                "snapshot_id": self.snapshot_id,
            },
        )


def freshness_p95_seconds(values: Iterable[float]) -> float:
    """Calculate the published nearest-rank p95 without dropping queued observations."""
    ordered = sorted(values)
    if not ordered or any(not math.isfinite(value) or value < 0 for value in ordered):
        raise IndexingValidationError(_ERR_RUN)
    rank = max(1, math.ceil(len(ordered) * 0.95))
    return ordered[rank - 1]


def _lineage_operations(
    prior: dict[str, PriorIndexedUnit],
    current: dict[str, CurrentIndexUnit],
    deltas: tuple[VcsDelta, ...],
) -> tuple[list[_UnorderedOperation], set[str], set[str]]:
    operations: list[_UnorderedOperation] = []
    consumed_prior: set[str] = set()
    consumed_current: set[str] = set()
    for delta in deltas:
        if delta.kind not in {VcsDeltaKind.RENAME, VcsDeltaKind.COPY}:
            continue
        old_path = cast("str", delta.previous_path)
        old = prior.get(old_path)
        new = current.get(delta.relative_path)
        if old is None or new is None or delta.relative_path in consumed_current:
            raise IndexingValidationError(_ERR_PLAN)
        consumed_current.add(delta.relative_path)
        if delta.kind is VcsDeltaKind.RENAME:
            if old_path in consumed_prior:
                raise IndexingValidationError(_ERR_PLAN)
            consumed_prior.add(old_path)
            operations.append(
                _changed(
                    IndexOperationKind.RENAME,
                    IndexOperationReason.PATH_CHANGED,
                    new,
                    old,
                    old_path,
                )
            )
        else:
            operations.append(
                _changed(
                    IndexOperationKind.ADD,
                    IndexOperationReason.COPIED_CONTENT,
                    new,
                    old,
                    old_path,
                )
            )
    return operations, consumed_prior, consumed_current


def _current_operations(
    prior: dict[str, PriorIndexedUnit],
    current: dict[str, CurrentIndexUnit],
    consumed_prior: set[str],
    consumed_current: set[str],
) -> list[_UnorderedOperation]:
    operations: list[_UnorderedOperation] = []
    for path, unit in sorted(current.items()):
        if path in consumed_current:
            continue
        old = prior.get(path)
        if old is None:
            operations.append(
                _changed(
                    IndexOperationKind.ADD,
                    IndexOperationReason.NEW_CONTENT,
                    unit,
                    None,
                    None,
                )
            )
            continue
        consumed_prior.add(path)
        kind = (
            IndexOperationKind.REUSE
            if unit.cache_key == old.cache_key
            else IndexOperationKind.MODIFY
        )
        reason = _same_path_reason(unit, old)
        operations.append(_changed(kind, reason, unit, old, None))
    return operations


def _same_path_reason(
    current: CurrentIndexUnit, previous: PriorIndexedUnit
) -> IndexOperationReason:
    if current.cache_key == previous.cache_key:
        return IndexOperationReason.CACHE_HIT
    if current.content_digest == previous.content_digest:
        return IndexOperationReason.FINGERPRINT_CHANGED
    return IndexOperationReason.CONTENT_CHANGED


def _deleted_operations(
    prior: dict[str, PriorIndexedUnit],
    consumed_prior: set[str],
    generated_excluded: set[str],
) -> list[_UnorderedOperation]:
    operations: list[_UnorderedOperation] = []
    for path, old in sorted(prior.items()):
        if path in consumed_prior:
            continue
        reason = (
            IndexOperationReason.GENERATED_EXCLUDED
            if path in generated_excluded
            else IndexOperationReason.CONTENT_DELETED
        )
        operations.append(
            _UnorderedOperation(
                IndexOperationKind.DELETE,
                reason,
                path,
                None,
                None,
                None,
                old.source_file_id,
                old.file_revision_id,
                old.semantic_ids,
                path in generated_excluded,
            )
        )
    return operations


def _changed(
    kind: IndexOperationKind,
    reason: IndexOperationReason,
    current: CurrentIndexUnit,
    previous: PriorIndexedUnit | None,
    previous_path: str | None,
) -> _UnorderedOperation:
    return _UnorderedOperation(
        kind,
        reason,
        current.relative_path,
        previous_path,
        current.content_digest,
        current.cache_key,
        None if previous is None else previous.source_file_id,
        None if previous is None else previous.file_revision_id,
        () if previous is None else previous.semantic_ids,
        current.generated,
    )


def _unique_by_path[PathItem](values: Sequence[PathItem]) -> dict[str, PathItem]:
    if len(values) > _MAX_FILES:
        raise IndexingValidationError(_ERR_PLAN)
    result: dict[str, PathItem] = {}
    for item in values:
        path = cast("str", getattr(item, "relative_path", None))
        if path in result:
            raise IndexingValidationError(_ERR_PLAN)
        result[path] = item
    return result


def _unique_deltas(values: Sequence[VcsDelta]) -> tuple[VcsDelta, ...]:
    if len(values) > _MAX_FILES:
        raise IndexingValidationError(_ERR_PLAN)
    result: dict[tuple[str, str, str], VcsDelta] = {}
    destinations: set[str] = set()
    for item in values:
        identity = (item.kind.value, item.previous_path or "", item.relative_path)
        if identity in result:
            continue
        if item.kind in {VcsDeltaKind.RENAME, VcsDeltaKind.COPY}:
            if item.relative_path in destinations:
                raise IndexingValidationError(_ERR_PLAN)
            destinations.add(item.relative_path)
        result[identity] = item
    return tuple(result[key] for key in sorted(result))


def _sorted_digests(values: tuple[str, ...], error: str) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(error)
    for value in values:
        _digest(value, error)


def _sorted_graph_ids(values: tuple[str, ...], error: str) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(error)
    for value in values:
        if _DIGEST.fullmatch(value) is not None:
            continue
        try:
            parsed = UUID(value)
        except ValueError as exception:
            raise IndexingValidationError(error) from exception
        if parsed.version != _UUID7_VERSION or str(parsed) != value:
            raise IndexingValidationError(error)


def _path(value: str) -> None:
    if not value or len(value.encode()) > _MAX_PATH_BYTES or "\\" in value or "\x00" in value:
        raise IndexingValidationError(_ERR_PLAN)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_PLAN)


def _digest(value: str, error: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise IndexingValidationError(error)


def _token(value: str, error: str) -> None:
    if _TOKEN.fullmatch(value) is None:
        raise IndexingValidationError(error)


def _enum(value: object, expected: type[StrEnum], error: str) -> None:
    if not isinstance(value, expected):
        raise IndexingValidationError(error)


def _utc(value: datetime, error: str) -> None:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise IndexingValidationError(error)


def _identity(namespace: str, document: dict[str, object]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{namespace}\0{payload}".encode()).hexdigest()


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)
