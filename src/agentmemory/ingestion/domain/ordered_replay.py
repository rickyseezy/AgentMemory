"""Causal ordering claims and pure deterministic replay reductions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Never

from agentmemory.ingestion.domain.errors import IngestionValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
CANONICAL_EVENT_PROJECTION_FINGERPRINT = hashlib.sha256(
    b"agentmemory-canonical-event-projection-reducer-v1"
).hexdigest()


class OrderClaimDisposition(StrEnum):
    """Closed causal arbitration result for one live projection event."""

    READY = "ready"
    READY_AFTER_GAP = "ready_after_gap"
    BUSY = "busy"
    WAIT = "wait"
    LATE_REPLAY_REQUIRED = "late_replay_required"
    UNORDERED = "unordered"


class ReplayRunState(StrEnum):
    """Closed durable lifecycle for one shadow-only causal replay."""

    QUEUED = "queued"
    BUILDING = "building"
    VALIDATING = "validating"
    READY = "ready"
    PARTIAL = "partial"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class OrderedEventClaim:
    """Exact per-key watermark, gap, and lease evidence for one event."""

    ordering_key: str
    event_sequence: int | None
    prior_sequence: int | None
    prior_state_sha256: str
    disposition: OrderClaimDisposition
    owner: str | None
    lease_until_microseconds: int | None
    gap_from_sequence: int | None
    gap_to_sequence: int | None

    def __post_init__(self) -> None:
        """Reject ambiguous order, gap, and ownership evidence."""
        _require_uuid7(self.ordering_key, "ordering_key")
        if _DIGEST.fullmatch(self.prior_state_sha256) is None:
            _invalid("prior_state_sha256", "invalid_digest")
        if self.event_sequence is not None and self.event_sequence < 1:
            _invalid("event_sequence", "out_of_range")
        if self.prior_sequence is not None and self.prior_sequence < 0:
            _invalid("prior_sequence", "out_of_range")
        leased = self.disposition in {
            OrderClaimDisposition.READY,
            OrderClaimDisposition.READY_AFTER_GAP,
        }
        has_lease = self.owner is not None and self.lease_until_microseconds is not None
        if leased != has_lease:
            _invalid("order_claim", "invalid_lease")
        if self.owner is not None and _OWNER.fullmatch(self.owner) is None:
            _invalid("owner", "invalid")
        if self.lease_until_microseconds is not None and self.lease_until_microseconds < 0:
            _invalid("lease_until_microseconds", "out_of_range")
        self._validate_disposition_shape()

    def _validate_disposition_shape(self) -> None:  # noqa: C901 -- Closed variant validator.
        if self.disposition is OrderClaimDisposition.UNORDERED:
            if (
                self.event_sequence is not None
                or self.prior_sequence is not None
                or self.gap_from_sequence is not None
                or self.gap_to_sequence is not None
            ):
                _invalid("order_claim", "invalid_unordered")
            return
        if self.event_sequence is None or self.prior_sequence is None:
            _invalid("order_claim", "missing_sequence")
        event_sequence = self.event_sequence
        prior_sequence = self.prior_sequence
        if self.disposition is OrderClaimDisposition.READY:
            if (
                event_sequence != prior_sequence + 1
                or self.gap_from_sequence is not None
                or self.gap_to_sequence is not None
            ):
                _invalid("order_claim", "invalid_ready")
            return
        if self.disposition in {
            OrderClaimDisposition.WAIT,
            OrderClaimDisposition.READY_AFTER_GAP,
        }:
            if (
                event_sequence <= prior_sequence + 1
                or self.gap_from_sequence != prior_sequence + 1
                or self.gap_to_sequence != event_sequence - 1
            ):
                _invalid("order_claim", "invalid_gap")
            return
        if self.disposition is OrderClaimDisposition.BUSY:
            if (
                event_sequence <= prior_sequence
                or self.gap_from_sequence is not None
                or self.gap_to_sequence is not None
            ):
                _invalid("order_claim", "invalid_busy")
            return
        if (
            event_sequence > prior_sequence
            or self.gap_from_sequence is not None
            or self.gap_to_sequence is not None
        ):
            _invalid("order_claim", "invalid_late_event")


@dataclass(frozen=True, slots=True)
class RecordedOperationEvidence:
    """Immutable provider result/version snapshot consumed by a pure reducer."""

    operation_id: str
    profile_id: str
    model_revision: str
    purpose: str
    result_sha256: str

    def __post_init__(self) -> None:
        """Require immutable identities without retaining provider content."""
        _require_uuid7(self.operation_id, "operation_id")
        _require_uuid7(self.profile_id, "profile_id")
        if _FINGERPRINT.fullmatch(self.model_revision) is None:
            _invalid("model_revision", "invalid_fingerprint")
        if _SAFE_NAME.fullmatch(self.purpose) is None:
            _invalid("purpose", "invalid")
        if _DIGEST.fullmatch(self.result_sha256) is None:
            _invalid("result_sha256", "invalid_digest")


@dataclass(frozen=True, slots=True)
class OrderedReductionInput:
    """All immutable inputs available to one pure live/replay reduction."""

    event_id: str
    ordering_key: str
    event_sequence: int | None
    event_schema_version: int
    canonical_sha256: str
    projection_sha256: str
    requires_recorded_operation: bool
    recorded_operation: RecordedOperationEvidence | None

    def __post_init__(self) -> None:
        """Require exact canonical and recorded nondeterministic evidence."""
        _require_uuid7(self.event_id, "event_id")
        _require_uuid7(self.ordering_key, "ordering_key")
        if self.event_sequence is not None and self.event_sequence < 1:
            _invalid("event_sequence", "out_of_range")
        if self.event_schema_version < 1:
            _invalid("event_schema_version", "out_of_range")
        for value, field_name in (
            (self.canonical_sha256, "canonical_sha256"),
            (self.projection_sha256, "projection_sha256"),
        ):
            if _DIGEST.fullmatch(value) is None:
                _invalid(field_name, "invalid_digest")
        if self.requires_recorded_operation != (self.recorded_operation is not None):
            _invalid("recorded_operation", "missing_or_unexpected")


@dataclass(frozen=True, slots=True)
class OrderedProjectionState:
    """Final deterministic state for one ordering key in one generation."""

    ordering_key: str
    applied_sequence: int
    state_sha256: str

    def __post_init__(self) -> None:
        """Validate one content-free generation state record."""
        _require_uuid7(self.ordering_key, "ordering_key")
        if self.applied_sequence < 0:
            _invalid("applied_sequence", "out_of_range")
        if _DIGEST.fullmatch(self.state_sha256) is None:
            _invalid("state_sha256", "invalid_digest")


@dataclass(frozen=True, slots=True)
class ReplayRunRequest:
    """Authorized immutable selection and shadow-generation target for replay."""

    operation_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    projection_name: str
    projection_generation: str
    code_fingerprint: str
    from_ingested_at_microseconds: int | None = None
    to_ingested_at_microseconds: int | None = None
    from_event_id: str | None = None
    to_event_id: str | None = None

    def __post_init__(self) -> None:
        """Reject mutable code identities and reversed event/time selections."""
        for value, field_name in (
            (self.operation_id, "operation_id"),
            (self.brain_id, "brain_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
            (self.projection_generation, "projection_generation"),
        ):
            _require_uuid7(value, field_name)
        if _SAFE_NAME.fullmatch(self.projection_name) is None:
            _invalid("projection_name", "invalid")
        if _FINGERPRINT.fullmatch(self.code_fingerprint) is None:
            _invalid("code_fingerprint", "invalid_fingerprint")
        for timestamp_bound, field_name in (
            (self.from_ingested_at_microseconds, "from_ingested_at_microseconds"),
            (self.to_ingested_at_microseconds, "to_ingested_at_microseconds"),
        ):
            if timestamp_bound is not None and timestamp_bound < 0:
                _invalid(field_name, "out_of_range")
        if (
            self.from_ingested_at_microseconds is not None
            and self.to_ingested_at_microseconds is not None
            and self.from_ingested_at_microseconds > self.to_ingested_at_microseconds
        ):
            _invalid("ingested_at_range", "reversed")
        for event_bound, field_name in (
            (self.from_event_id, "from_event_id"),
            (self.to_event_id, "to_event_id"),
        ):
            if event_bound is not None:
                _require_uuid7(event_bound, field_name)
        if (
            self.from_event_id is not None
            and self.to_event_id is not None
            and self.from_event_id > self.to_event_id
        ):
            _invalid("event_id_range", "reversed")

    @property
    def request_sha256(self) -> str:
        """Bind the immutable selection independently of the caller's operation ID."""
        return _canonical_digest(
            {
                "actor_id": self.actor_id,
                "brain_id": self.brain_id,
                "code_fingerprint": self.code_fingerprint,
                "from_event_id": self.from_event_id,
                "from_ingested_at_microseconds": self.from_ingested_at_microseconds,
                "grant_id": self.grant_id,
                "projection_generation": self.projection_generation,
                "projection_name": self.projection_name,
                "schema_version": 1,
                "to_event_id": self.to_event_id,
                "to_ingested_at_microseconds": self.to_ingested_at_microseconds,
            }
        )


@dataclass(frozen=True, slots=True)
class OrderedReplayRun:
    """Content-free durable status and immutable bounds for one replay run."""

    request: ReplayRunRequest
    state: ReplayRunState
    source_watermark_ingested_at_microseconds: int
    source_watermark_event_id: str
    source_count: int
    processed_count: int
    cursor_ingested_at_microseconds: int | None
    cursor_event_id: str | None
    shadow_digest: str | None
    live_digest: str | None
    failure_code: str | None
    lease_owner: str | None
    lease_until_microseconds: int | None
    created_at_microseconds: int
    updated_at_microseconds: int
    completed_at_microseconds: int | None

    def __post_init__(self) -> None:  # noqa: C901, PLR0912 -- Closed lifecycle validator.
        """Reject forged lifecycle, cursor, digest, and lease combinations."""
        _require_uuid7(self.source_watermark_event_id, "source_watermark_event_id")
        if self.source_watermark_ingested_at_microseconds < 0:
            _invalid("source_watermark_ingested_at_microseconds", "out_of_range")
        if self.source_count < 0 or not 0 <= self.processed_count <= self.source_count:
            _invalid("replay_counts", "out_of_range")
        has_cursor = (
            self.cursor_ingested_at_microseconds is not None and self.cursor_event_id is not None
        )
        if (self.cursor_ingested_at_microseconds is None) != (self.cursor_event_id is None):
            _invalid("replay_cursor", "invalid_shape")
        if has_cursor:
            cursor_time = self.cursor_ingested_at_microseconds
            cursor_event = self.cursor_event_id
            if cursor_time is None or cursor_event is None:
                _invalid("replay_cursor", "invalid_shape")
            if cursor_time < 0:
                _invalid("cursor_ingested_at_microseconds", "out_of_range")
            _require_uuid7(cursor_event, "cursor_event_id")
        if (self.processed_count > 0) != has_cursor:
            _invalid("replay_cursor", "count_mismatch")
        for value, field_name in (
            (self.shadow_digest, "shadow_digest"),
            (self.live_digest, "live_digest"),
        ):
            if value is not None and _DIGEST.fullmatch(value) is None:
                _invalid(field_name, "invalid_digest")
        leased = self.state in {ReplayRunState.BUILDING, ReplayRunState.VALIDATING}
        if leased != (self.lease_owner is not None and self.lease_until_microseconds is not None):
            _invalid("replay_lease", "invalid_shape")
        if self.lease_owner is not None and _OWNER.fullmatch(self.lease_owner) is None:
            _invalid("lease_owner", "invalid")
        if self.lease_until_microseconds is not None and self.lease_until_microseconds < 0:
            _invalid("lease_until_microseconds", "out_of_range")
        terminal = self.state in {ReplayRunState.READY, ReplayRunState.SUPERSEDED}
        if terminal != (
            self.shadow_digest is not None
            and self.live_digest is not None
            and self.completed_at_microseconds is not None
        ):
            _invalid("replay_terminal", "invalid_shape")
        if self.state is ReplayRunState.PARTIAL:
            if self.failure_code is None or self.completed_at_microseconds is not None:
                _invalid("replay_partial", "invalid_shape")
        elif self.failure_code is not None:
            _invalid("failure_code", "unexpected")
        if terminal and self.processed_count != self.source_count:
            _invalid("replay_counts", "incomplete_terminal")
        if self.state is ReplayRunState.READY and self.shadow_digest != self.live_digest:
            _invalid("replay_digest", "ready_mismatch")
        if self.state is ReplayRunState.SUPERSEDED and self.shadow_digest == self.live_digest:
            _invalid("replay_digest", "superseded_match")
        if (
            min(
                self.created_at_microseconds,
                self.updated_at_microseconds,
                self.completed_at_microseconds or 0,
            )
            < 0
        ):
            _invalid("replay_timestamp", "out_of_range")


@dataclass(frozen=True, slots=True)
class ReplaySourceRecord:
    """One canonically ordered immutable reduction input selected for replay."""

    source_ordinal: int
    ingested_at_microseconds: int
    reduction: OrderedReductionInput

    def __post_init__(self) -> None:
        """Require a positive ordinal and nonnegative canonical ingestion time."""
        if self.source_ordinal < 1:
            _invalid("source_ordinal", "out_of_range")
        if self.ingested_at_microseconds < 0:
            _invalid("ingested_at_microseconds", "out_of_range")


@dataclass(frozen=True, slots=True)
class ReplaySourcePage:
    """One bounded causal-order page after a durable processed-count cursor."""

    records: tuple[ReplaySourceRecord, ...]
    complete: bool

    def __post_init__(self) -> None:
        """Reject duplicate or nonascending source ordinals."""
        ordinals = tuple(item.source_ordinal for item in self.records)
        if tuple(sorted(ordinals)) != ordinals or len(set(ordinals)) != len(ordinals):
            _invalid("source_page", "invalid_order")


def reduce_projection(
    prior_state_sha256: str,
    reduction: OrderedReductionInput,
    code_fingerprint: str,
) -> str:
    """Reduce one event using only prior state and immutable recorded evidence."""
    if _DIGEST.fullmatch(prior_state_sha256) is None:
        _invalid("prior_state_sha256", "invalid_digest")
    if _FINGERPRINT.fullmatch(code_fingerprint) is None:
        _invalid("code_fingerprint", "invalid_fingerprint")
    recorded = reduction.recorded_operation
    document: dict[str, object] = {
        "canonical_sha256": reduction.canonical_sha256,
        "code_fingerprint": code_fingerprint,
        "event_id": reduction.event_id,
        "event_schema_version": reduction.event_schema_version,
        "event_sequence": reduction.event_sequence,
        "ordering_key": reduction.ordering_key,
        "prior_state_sha256": prior_state_sha256,
        "projection_sha256": reduction.projection_sha256,
        "recorded_operation": (
            None
            if recorded is None
            else {
                "model_revision": recorded.model_revision,
                "operation_id": recorded.operation_id,
                "profile_id": recorded.profile_id,
                "purpose": recorded.purpose,
                "result_sha256": recorded.result_sha256,
            }
        ),
        "schema_version": 1,
    }
    return _canonical_digest(document)


def generation_digest(
    states: tuple[OrderedProjectionState, ...],
    code_fingerprint: str,
) -> str:
    """Digest final per-key states independently of concurrent key arrival."""
    if _FINGERPRINT.fullmatch(code_fingerprint) is None:
        _invalid("code_fingerprint", "invalid_fingerprint")
    ordered = sorted(states, key=lambda item: item.ordering_key)
    if len({item.ordering_key for item in ordered}) != len(ordered):
        _invalid("states", "duplicate_ordering_key")
    return _canonical_digest(
        {
            "code_fingerprint": code_fingerprint,
            "schema_version": 1,
            "states": [
                {
                    "applied_sequence": item.applied_sequence,
                    "ordering_key": item.ordering_key,
                    "state_sha256": item.state_sha256,
                }
                for item in ordered
            ],
        }
    )


def _canonical_digest(document: dict[str, object]) -> str:
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _require_uuid7(value: str, field_name: str) -> None:
    if _UUID7.fullmatch(value) is None:
        _invalid(field_name, "invalid_id")


def _invalid(field_name: str, code: str) -> Never:
    raise IngestionValidationError.single(field_name, code)
