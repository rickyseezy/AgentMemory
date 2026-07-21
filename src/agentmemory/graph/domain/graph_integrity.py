"""GRA-006 resumable graph migrations and fail-closed integrity repair policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import cast

from agentmemory.graph.domain.errors import GraphValidationError
from agentmemory.graph.domain.models import stable_graph_id

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_OPERATION = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_MAX_BATCH = 4_096
_MAX_OBSERVATIONS = 10_000
_ERR_MIGRATION = "graph migration state is invalid"
_ERR_INTEGRITY = "graph integrity observation is invalid"
_ERR_APPROVAL = "destructive graph repair requires explicit approval"
_ERR_REBUILD = "destructive graph repair requires a verified canonical rebuild path"


class GraphMigrationState(StrEnum):
    """Closed durable migration lifecycle."""

    RUNNING = "running"
    PAUSED = "paused"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"


class GraphProjectionKind(StrEnum):
    """Closed projection surfaces inspected by the integrity worker."""

    ASSERTION = "assertion"
    EDGE = "edge"
    VECTOR = "vector"


class IntegrityFindingKind(StrEnum):
    """Closed corruption taxonomy required by GRA-006."""

    UNSUPPORTED_ASSERTION = "unsupported_assertion"
    ORPHAN_VECTOR = "orphan_vector"
    ORPHAN_EDGE = "orphan_edge"
    INVALID_TEMPORAL_RANGE = "invalid_temporal_range"
    SCOPE_MISMATCH = "scope_mismatch"
    STALE_GENERATION = "stale_generation"


class GraphRepairAction(StrEnum):
    """Only governed projection actions; canonical history is never silently deleted."""

    SHADOW_WRITE = "shadow_write"
    QUARANTINE = "quarantine"
    DESTRUCTIVE_REBUILD = "destructive_rebuild"


@dataclass(frozen=True, slots=True)
class GraphMigrationRun:
    """Durable migration state whose cursor and lineage live outside Neo4j."""

    operation_id: str
    brain_id: str
    migration_id: str
    migration_checksum: str
    source_watermark: int
    batch_size: int
    cursor: int
    scanned_count: int
    changed_count: int
    quarantined_count: int
    state: GraphMigrationState
    started_at: datetime
    updated_at: datetime

    @classmethod
    def start(  # noqa: PLR0913 -- Migration identity binds all durable coordinates.
        cls,
        *,
        operation_id: str,
        brain_id: str,
        migration_id: str,
        migration_checksum: str,
        source_watermark: int,
        batch_size: int,
        started_at: datetime,
    ) -> GraphMigrationRun:
        """Create the first running snapshot at cursor zero."""
        return cls(
            operation_id,
            brain_id,
            migration_id,
            migration_checksum,
            source_watermark,
            batch_size,
            0,
            0,
            0,
            0,
            GraphMigrationState.RUNNING,
            started_at,
            started_at,
        )

    def __post_init__(self) -> None:
        """Reject ambiguous identity, time, progress, state, and checksum values."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            raise GraphValidationError(_ERR_MIGRATION)
        _stable_id(self.brain_id, _ERR_MIGRATION)
        if _TOKEN.fullmatch(self.migration_id) is None:
            raise GraphValidationError(_ERR_MIGRATION)
        _digest(self.migration_checksum, _ERR_MIGRATION)
        if (
            isinstance(cast("object", self.source_watermark), bool)
            or not isinstance(cast("object", self.source_watermark), int)
            or self.source_watermark < 0
            or isinstance(cast("object", self.batch_size), bool)
            or not isinstance(cast("object", self.batch_size), int)
            or not 1 <= self.batch_size <= _MAX_BATCH
            or not 0 <= self.cursor <= self.source_watermark
            or min(self.scanned_count, self.changed_count, self.quarantined_count) < 0
            or self.changed_count + self.quarantined_count > self.scanned_count
        ):
            raise GraphValidationError(_ERR_MIGRATION)
        _enum(self.state, GraphMigrationState, _ERR_MIGRATION)
        _utc(self.started_at, _ERR_MIGRATION)
        _utc(self.updated_at, _ERR_MIGRATION)
        if self.updated_at < self.started_at:
            raise GraphValidationError(_ERR_MIGRATION)
        if self.state in {GraphMigrationState.VALIDATING, GraphMigrationState.COMPLETED} and (
            self.cursor != self.source_watermark
        ):
            raise GraphValidationError(_ERR_MIGRATION)

    def checkpoint(
        self,
        next_cursor: int,
        scanned: int,
        changed: int,
        quarantined: int,
        at: datetime,
    ) -> GraphMigrationRun:
        """Advance one committed batch; exact checkpoint replay is idempotent."""
        if (
            next_cursor == self.cursor
            and scanned == self.scanned_count
            and changed == self.changed_count
            and quarantined == self.quarantined_count
            and at == self.updated_at
        ):
            return self
        if (
            self.state not in {GraphMigrationState.RUNNING, GraphMigrationState.PAUSED}
            or not self.cursor < next_cursor <= self.source_watermark
            or scanned < 1
            or changed < 0
            or quarantined < 0
            or changed + quarantined > scanned
        ):
            raise GraphValidationError(_ERR_MIGRATION)
        return replace(
            self,
            cursor=next_cursor,
            scanned_count=self.scanned_count + scanned,
            changed_count=self.changed_count + changed,
            quarantined_count=self.quarantined_count + quarantined,
            state=GraphMigrationState.RUNNING,
            updated_at=at,
        )

    def begin_validation(self, at: datetime) -> GraphMigrationRun:
        """Enter validation only after the fixed source watermark is exhausted."""
        if self.state is not GraphMigrationState.RUNNING or self.cursor != self.source_watermark:
            raise GraphValidationError(_ERR_MIGRATION)
        return replace(self, state=GraphMigrationState.VALIDATING, updated_at=at)

    def complete(self, at: datetime) -> GraphMigrationRun:
        """Commit a terminal successful migration snapshot."""
        if self.state is not GraphMigrationState.VALIDATING:
            raise GraphValidationError(_ERR_MIGRATION)
        return replace(self, state=GraphMigrationState.COMPLETED, updated_at=at)


@dataclass(frozen=True, slots=True)
class GraphMigrationBatch:
    """One atomically applied, cursor-bounded migration batch result."""

    next_cursor: int
    scanned: int
    changed: int
    quarantined: int

    def __post_init__(self) -> None:
        """Require coherent nonnegative per-batch counters."""
        values = (self.next_cursor, self.scanned, self.changed, self.quarantined)
        if (
            any(
                not isinstance(cast("object", value), int)
                or isinstance(cast("object", value), bool)
                or value < 0
                for value in values
            )
            or self.changed + self.quarantined > self.scanned
        ):
            raise GraphValidationError(_ERR_MIGRATION)


@dataclass(frozen=True, slots=True)
class GraphIntegrityObservation:
    """Content-free projection metadata supplied by a bounded scanner."""

    projection_id: str
    projection_kind: GraphProjectionKind
    brain_id: str
    project_id: str
    repository_id: str
    canonical_id: str | None
    canonical_supported: bool
    temporal_valid: bool
    scope_matches: bool
    generation_id: str
    projection_digest: str

    def __post_init__(self) -> None:
        """Defensively validate untrusted projection metadata."""
        _projection_id(self.projection_id)
        for value in (self.brain_id, self.project_id, self.repository_id):
            _stable_id(value, _ERR_INTEGRITY)
        if self.canonical_id is not None:
            _stable_id(self.canonical_id, _ERR_INTEGRITY)
        _enum(self.projection_kind, GraphProjectionKind, _ERR_INTEGRITY)
        for flag in (self.canonical_supported, self.temporal_valid, self.scope_matches):
            if not isinstance(cast("object", flag), bool):
                raise GraphValidationError(_ERR_INTEGRITY)
        _digest(self.generation_id, _ERR_INTEGRITY)
        _digest(self.projection_digest, _ERR_INTEGRITY)


@dataclass(frozen=True, slots=True)
class GraphIntegrityFinding:
    """Stable content-free evidence for one exact projection defect."""

    id: str
    kind: IntegrityFindingKind
    projection_id: str
    projection_kind: GraphProjectionKind
    brain_id: str
    project_id: str
    repository_id: str
    canonical_id: str | None
    observed_generation_id: str
    expected_generation_id: str
    projection_digest: str
    checked_at: datetime

    def __post_init__(self) -> None:
        """Reject forged persisted finding evidence."""
        _digest(self.id, _ERR_INTEGRITY)
        _enum(self.kind, IntegrityFindingKind, _ERR_INTEGRITY)
        _enum(self.projection_kind, GraphProjectionKind, _ERR_INTEGRITY)
        _projection_id(self.projection_id)
        for value in (self.brain_id, self.project_id, self.repository_id):
            _stable_id(value, _ERR_INTEGRITY)
        if self.canonical_id is not None:
            _stable_id(self.canonical_id, _ERR_INTEGRITY)
        for value in (
            self.observed_generation_id,
            self.expected_generation_id,
            self.projection_digest,
        ):
            _digest(value, _ERR_INTEGRITY)
        _utc(self.checked_at, _ERR_INTEGRITY)


@dataclass(frozen=True, slots=True)
class GraphRepairPlan:
    """Governed immutable repair decision."""

    finding_id: str
    action: GraphRepairAction
    approval_id: str | None

    def __post_init__(self) -> None:
        """Bind every repair to a stable finding and closed action."""
        _digest(self.finding_id, _ERR_INTEGRITY)
        _enum(self.action, GraphRepairAction, _ERR_INTEGRITY)
        if self.approval_id is not None:
            _stable_id(self.approval_id, _ERR_APPROVAL)
        if (self.action is GraphRepairAction.DESTRUCTIVE_REBUILD) != (self.approval_id is not None):
            raise GraphValidationError(_ERR_APPROVAL)


class GraphIntegrityPolicy:
    """Convert bounded projection metadata into deterministic corruption findings."""

    @staticmethod
    def evaluate(
        observations: tuple[GraphIntegrityObservation, ...],
        current_generation_id: str,
        checked_at: datetime,
    ) -> tuple[GraphIntegrityFinding, ...]:
        """Emit every applicable finding in stable identity order."""
        _digest(current_generation_id, _ERR_INTEGRITY)
        _utc(checked_at, _ERR_INTEGRITY)
        if len(observations) > _MAX_OBSERVATIONS or len(
            {item.projection_id for item in observations}
        ) != len(observations):
            raise GraphValidationError(_ERR_INTEGRITY)
        findings: list[GraphIntegrityFinding] = []
        for observation in sorted(observations, key=lambda item: item.projection_id):
            kinds: list[IntegrityFindingKind] = []
            if not observation.canonical_supported:
                kinds.append(IntegrityFindingKind.UNSUPPORTED_ASSERTION)
            if observation.canonical_id is None:
                kinds.append(
                    IntegrityFindingKind.ORPHAN_VECTOR
                    if observation.projection_kind is GraphProjectionKind.VECTOR
                    else IntegrityFindingKind.ORPHAN_EDGE
                )
            if not observation.temporal_valid:
                kinds.append(IntegrityFindingKind.INVALID_TEMPORAL_RANGE)
            if not observation.scope_matches:
                kinds.append(IntegrityFindingKind.SCOPE_MISMATCH)
            if observation.generation_id != current_generation_id:
                kinds.append(IntegrityFindingKind.STALE_GENERATION)
            findings.extend(
                _finding(observation, kind, current_generation_id, checked_at) for kind in kinds
            )
        return tuple(findings)


class GraphRepairPolicy:
    """Select non-destructive repair unless explicit destructive authority is complete."""

    @staticmethod
    def plan(
        finding: GraphIntegrityFinding,
        *,
        destructive: bool = False,
        approval_id: str | None = None,
        canonical_rebuild_verified: bool = False,
    ) -> GraphRepairPlan:
        """Return a closed repair action without mutating the finding or canonical history."""
        if destructive:
            if approval_id is None:
                raise GraphValidationError(_ERR_APPROVAL)
            _stable_id(approval_id, _ERR_APPROVAL)
            if not canonical_rebuild_verified:
                raise GraphValidationError(_ERR_REBUILD)
            return GraphRepairPlan(finding.id, GraphRepairAction.DESTRUCTIVE_REBUILD, approval_id)
        shadow_kinds = {
            IntegrityFindingKind.UNSUPPORTED_ASSERTION,
            IntegrityFindingKind.INVALID_TEMPORAL_RANGE,
            IntegrityFindingKind.STALE_GENERATION,
        }
        action = (
            GraphRepairAction.SHADOW_WRITE
            if finding.kind in shadow_kinds
            else GraphRepairAction.QUARANTINE
        )
        return GraphRepairPlan(finding.id, action, None)


def _finding(
    observation: GraphIntegrityObservation,
    kind: IntegrityFindingKind,
    expected_generation_id: str,
    checked_at: datetime,
) -> GraphIntegrityFinding:
    document = {
        "brain_id": observation.brain_id,
        "checked_at": _time(checked_at),
        "expected_generation_id": expected_generation_id,
        "kind": kind.value,
        "projection_digest": observation.projection_digest,
        "projection_id": observation.projection_id,
    }
    identity = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return GraphIntegrityFinding(
        identity,
        kind,
        observation.projection_id,
        observation.projection_kind,
        observation.brain_id,
        observation.project_id,
        observation.repository_id,
        observation.canonical_id,
        observation.generation_id,
        expected_generation_id,
        observation.projection_digest,
        checked_at,
    )


def _stable_id(value: object, message: str) -> None:
    try:
        stable_graph_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as error:
        raise GraphValidationError(message) from error


def _digest(value: object, message: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise GraphValidationError(message)


def _projection_id(value: object) -> None:
    if isinstance(value, str) and _DIGEST.fullmatch(value) is not None and set(value) != {"0"}:
        return
    _stable_id(value, _ERR_INTEGRITY)


def _enum(value: object, enum_type: type[StrEnum], message: str) -> None:
    if not isinstance(value, enum_type):
        raise GraphValidationError(message)


def _utc(value: object, message: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise GraphValidationError(message)


def _time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
