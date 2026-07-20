"""Resumable historical task-lineage backfill state for MEM-001."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Never, cast
from uuid import UUID

from agentmemory.memory.domain.errors import MemoryValidationError

if TYPE_CHECKING:
    from agentmemory.memory.domain.consolidation import MemoryScope


_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_EVENT_TYPE = re.compile(r"^agentmemory\.[a-z0-9._-]{1,180}\.v[1-9][0-9]*$")
_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted", "local_only"})


class TaskLineageBackfillState(StrEnum):
    """Closed historical lineage migration lifecycle."""

    PENDING = "pending"
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class TaskLineageBackfillProgress:
    """Content-free exact cursor and bounded progress evidence."""

    operation_id: str
    state: TaskLineageBackfillState
    cursor_created_at: int | None
    cursor_event_id: str | None
    watermark_created_at: int | None
    watermark_event_id: str | None
    scanned: int
    indexed: int
    ignored: int
    total: int
    last_error_code: str | None

    def __post_init__(self) -> None:
        """Reject cursor, count, and terminal-state divergence."""
        if self.operation_id != "mem001-task-lineage-v1":
            _invalid("operation_id", "unsupported")
        _require_state(self.state)
        if (self.cursor_created_at is None) != (self.cursor_event_id is None):
            _invalid("cursor", "invalid_shape")
        if (self.watermark_created_at is None) != (self.watermark_event_id is None):
            _invalid("watermark", "invalid_shape")
        _optional_position(self.cursor_created_at, self.cursor_event_id, "cursor")
        _optional_position(self.watermark_created_at, self.watermark_event_id, "watermark")
        _require_counts(self.scanned, self.indexed, self.ignored, self.total)
        _require_progress_positions(self)
        _require_progress_state(self)


@dataclass(frozen=True, slots=True)
class TaskLineageRecord:
    """Exact non-content task metadata derived from one canonical event."""

    event_id: str
    principal_id: str
    scope: MemoryScope
    session_id: str
    task_id: str
    correlation_id: str
    causation_id: str
    event_type: str
    classification: str
    retention_policy_id: str
    occurred_at_microseconds: int
    canonical_event_sha256: str
    source_created_at: int

    def __post_init__(self) -> None:
        """Authenticate the exact non-content lineage shape independently of its adapter."""
        for value, field in (
            (self.event_id, "lineage.event_id"),
            (self.principal_id, "lineage.principal_id"),
            (self.session_id, "lineage.session_id"),
            (self.task_id, "lineage.task_id"),
            (self.correlation_id, "lineage.correlation_id"),
            (self.causation_id, "lineage.causation_id"),
        ):
            _require_uuid7(value, field)
        if _EVENT_TYPE.fullmatch(self.event_type) is None:
            _invalid("lineage.event_type", "invalid")
        if self.classification not in _CLASSIFICATIONS:
            _invalid("lineage.classification", "unsupported")
        if _TOKEN.fullmatch(self.retention_policy_id) is None:
            _invalid("lineage.retention_policy_id", "invalid")
        _require_positive_integer(self.occurred_at_microseconds, "lineage.occurred_at")
        _require_digest(self.canonical_event_sha256, "lineage.canonical_event_sha256")
        _require_positive_integer(self.source_created_at, "lineage.source_created_at")


@dataclass(frozen=True, slots=True)
class TaskLineageBackfillOutcome:
    """One ordered source disposition, optionally carrying task lineage."""

    event_id: str
    source_created_at: int
    record: TaskLineageRecord | None

    def __post_init__(self) -> None:
        """Bind an optional lineage record to the exact ordered source row."""
        _require_uuid7(self.event_id, "outcome.event_id")
        _require_positive_integer(self.source_created_at, "outcome.source_created_at")
        _require_outcome_record(self.record, self.event_id, self.source_created_at)


def _require_state(value: object) -> None:
    if not isinstance(value, TaskLineageBackfillState):
        _invalid("state", "unsupported")


def _require_counts(scanned: object, indexed: object, ignored: object, total: object) -> None:
    values = (scanned, indexed, ignored, total)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        _invalid("counts", "invalid_type")
    resolved = cast("tuple[int, int, int, int]", values)
    if min(resolved) < 0 or resolved[0] != resolved[1] + resolved[2] or resolved[0] > resolved[3]:
        _invalid("counts", "inconsistent")


def _require_progress_positions(progress: TaskLineageBackfillProgress) -> None:
    if (progress.total == 0) != (progress.watermark_created_at is None):
        _invalid("watermark", "inconsistent")
    if (progress.scanned == 0) != (progress.cursor_created_at is None):
        _invalid("cursor", "inconsistent")
    cursor = _position(progress.cursor_created_at, progress.cursor_event_id)
    watermark = _position(progress.watermark_created_at, progress.watermark_event_id)
    if cursor is not None and watermark is not None and cursor > watermark:
        _invalid("cursor", "past_watermark")


def _require_progress_state(progress: TaskLineageBackfillProgress) -> None:
    if progress.state is TaskLineageBackfillState.COMPLETED and progress.scanned != progress.total:
        _invalid("state", "incomplete")
    if progress.last_error_code not in {
        None,
        "dependency_unavailable",
        "integrity_violation",
        "interrupted",
    }:
        _invalid("last_error_code", "unsupported")
    if progress.state is TaskLineageBackfillState.INTERRUPTED:
        if progress.last_error_code is None:
            _invalid("last_error_code", "required")
    elif progress.last_error_code is not None:
        _invalid("last_error_code", "state_mismatch")
    if progress.state is TaskLineageBackfillState.PENDING and (
        progress.total != 0 or progress.cursor_created_at is not None
    ):
        _invalid("state", "pending_progress")


def _require_outcome_record(record: object, event_id: str, source_created_at: int) -> None:
    if record is None:
        return
    if not isinstance(record, TaskLineageRecord):
        _invalid("outcome.record", "source_mismatch")
    if record.event_id != event_id or record.source_created_at != source_created_at:
        _invalid("outcome.record", "source_mismatch")


def _optional_position(created_at: int | None, event_id: str | None, field: str) -> None:
    if created_at is None or event_id is None:
        return
    _require_positive_integer(created_at, f"{field}.created_at")
    _require_uuid7(event_id, f"{field}.event_id")


def _position(created_at: int | None, event_id: str | None) -> tuple[int, str] | None:
    if created_at is None or event_id is None:
        return None
    return (created_at, event_id)


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except AttributeError, TypeError, ValueError:
        _invalid(field, "invalid_uuid7")
    if parsed.version != _UUID_VERSION or str(parsed) != value:
        _invalid(field, "invalid_uuid7")


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        _invalid(field, "invalid_digest")


def _require_positive_integer(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _invalid(field, "invalid")


def _invalid(field: str, code: str) -> Never:
    raise MemoryValidationError.single(field, code)
