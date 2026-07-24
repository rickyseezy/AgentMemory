"""PRO-008 pure live embedding-generation migration contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Never
from uuid import UUID

from agentmemory.providers.domain.errors import EmbeddingMigrationValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_REF = re.compile(r"^(?:artifact|cas|local-object|sqlite)://[A-Za-z0-9._:/-]{1,480}$")
_UUID_VERSION = 7
_MICROS = 1_000_000
_MAX_RATIO_MICROS = 10 * _MICROS
_MAX_COUNT = 2**63 - 1
_MAX_TIME = 2**63 - 1
_MAX_ROLLBACK_WINDOW = 365 * 24 * 60 * 60 * _MICROS
_ERR_INPUT = "embedding migration input is invalid"
_ERR_PROGRESS = "embedding migration progress is invalid"


class EmbeddingMigrationState(StrEnum):
    """Durable, resumable live generation migration lifecycle."""

    PLANNED = "planned"
    BUILDING = "building"
    BACKFILLING = "backfilling"
    DUAL_WRITE = "dual_write"
    CATCHING_UP = "catching_up"
    VALIDATING = "validating"
    SHADOWING = "shadowing"
    READY = "ready"
    PAUSED = "paused"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"

    def require_transition(self, target: EmbeddingMigrationState) -> None:
        """Reject shortcuts that could expose incomplete or unvalidated vectors."""
        pausable = frozenset(
            {
                EmbeddingMigrationState.PAUSED,
                EmbeddingMigrationState.FAILED,
            }
        )
        transitions: dict[EmbeddingMigrationState, frozenset[EmbeddingMigrationState]] = {
            EmbeddingMigrationState.PLANNED: frozenset(
                {EmbeddingMigrationState.BUILDING} | pausable
            ),
            EmbeddingMigrationState.BUILDING: frozenset(
                {EmbeddingMigrationState.BACKFILLING} | pausable
            ),
            EmbeddingMigrationState.BACKFILLING: frozenset(
                {EmbeddingMigrationState.DUAL_WRITE} | pausable
            ),
            EmbeddingMigrationState.DUAL_WRITE: frozenset(
                {EmbeddingMigrationState.CATCHING_UP} | pausable
            ),
            EmbeddingMigrationState.CATCHING_UP: frozenset(
                {EmbeddingMigrationState.VALIDATING} | pausable
            ),
            EmbeddingMigrationState.VALIDATING: frozenset(
                {EmbeddingMigrationState.SHADOWING} | pausable
            ),
            EmbeddingMigrationState.SHADOWING: frozenset(
                {EmbeddingMigrationState.READY} | pausable
            ),
            EmbeddingMigrationState.READY: pausable,
            EmbeddingMigrationState.PAUSED: frozenset(),
            EmbeddingMigrationState.ACTIVE: frozenset({EmbeddingMigrationState.ROLLED_BACK}),
            EmbeddingMigrationState.ROLLED_BACK: frozenset(),
            EmbeddingMigrationState.FAILED: frozenset(),
        }
        if target not in transitions[self]:
            message = f"embedding migration transition {self.value}->{target.value} is invalid"
            raise EmbeddingMigrationValidationError(message)


@dataclass(frozen=True, slots=True)
class MigrationProgress:
    """Monotonic canonical-content cursors for snapshot and live catch-up."""

    backfill_cursor: int
    catchup_watermark: int
    catchup_cursor: int

    def __post_init__(self) -> None:
        """Require bounded progress without gaps, rewind, or future reads."""
        if (
            not 0 <= self.backfill_cursor <= _MAX_COUNT
            or not self.backfill_cursor <= self.catchup_watermark <= _MAX_COUNT
            or not self.backfill_cursor <= self.catchup_cursor <= self.catchup_watermark
        ):
            raise EmbeddingMigrationValidationError(_ERR_PROGRESS)


@dataclass(frozen=True, slots=True, kw_only=True)
class MigrationContent:
    """Content-addressed canonical input reference; old vectors are never replay input."""

    sequence: int
    source_entity_id: str
    source_content_hash: str
    content_ref: str
    classification: str

    def __post_init__(self) -> None:
        """Require ordered content identity and a local protected payload reference."""
        if (
            not 1 <= self.sequence <= _MAX_COUNT
            or not _uuid7(self.source_entity_id)
            or _DIGEST.fullmatch(self.source_content_hash) is None
            or _CONTENT_REF.fullmatch(self.content_ref) is None
            or self.classification
            not in {"public", "internal", "confidential", "restricted", "local_only"}
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class MigrationContentPage:
    """One fixed-watermark canonical replay page with a durable next cursor."""

    records: tuple[MigrationContent, ...]
    next_cursor: int
    complete: bool

    def __post_init__(self) -> None:
        """Require strict source order and cursor agreement."""
        sequences = tuple(record.sequence for record in self.records)
        if (
            not 0 <= self.next_cursor <= _MAX_COUNT
            or sequences != tuple(sorted(set(sequences)))
            or (sequences and sequences[-1] > self.next_cursor)
            or (sequences and not self.complete and sequences[-1] != self.next_cursor)
            or (not sequences and not self.complete)
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddingMigrationPolicy:
    """Version-independent production cutover and retention thresholds."""

    minimum_coverage_micros: int
    maximum_quality_regression_micros: int
    maximum_latency_ratio_micros: int
    minimum_shadow_samples: int
    maximum_shadow_mismatches: int
    rollback_window_microseconds: int

    @classmethod
    def production(cls) -> EmbeddingMigrationPolicy:
        """Return conservative no-loss production activation gates."""
        return cls(
            minimum_coverage_micros=1_000_000,
            maximum_quality_regression_micros=40_000,
            maximum_latency_ratio_micros=1_250_000,
            minimum_shadow_samples=100,
            maximum_shadow_mismatches=0,
            rollback_window_microseconds=35 * 24 * 60 * 60 * _MICROS,
        )

    def __post_init__(self) -> None:
        """Reject permissive, negative, or unbounded release policy."""
        if (
            not 0 <= self.minimum_coverage_micros <= _MICROS
            or not 0 <= self.maximum_quality_regression_micros <= _MICROS
            or not _MICROS <= self.maximum_latency_ratio_micros <= _MAX_RATIO_MICROS
            or not 1 <= self.minimum_shadow_samples <= _MAX_COUNT
            or not 0 <= self.maximum_shadow_mismatches <= _MAX_COUNT
            or not 1 <= self.rollback_window_microseconds <= _MAX_ROLLBACK_WINDOW
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddingMigrationValidation:
    """Content-free coverage, quality, privacy, latency, and shadow evidence."""

    canonical_count: int
    target_count: int
    covered_count: int
    missing_count: int
    stale_count: int
    duplicate_count: int
    privacy_violation_count: int
    quality_score_micros: int
    baseline_quality_score_micros: int
    p95_latency_microseconds: int
    baseline_p95_latency_microseconds: int
    shadow_sample_count: int
    shadow_mismatch_count: int
    evidence_digest: str

    def __post_init__(self) -> None:
        """Reject negative, inconsistent, unbounded, or content-bearing evidence."""
        counts = (
            self.canonical_count,
            self.target_count,
            self.covered_count,
            self.missing_count,
            self.stale_count,
            self.duplicate_count,
            self.privacy_violation_count,
            self.p95_latency_microseconds,
            self.baseline_p95_latency_microseconds,
            self.shadow_sample_count,
            self.shadow_mismatch_count,
        )
        if (
            any(not 0 <= value <= _MAX_COUNT for value in counts)
            or not 0 <= self.quality_score_micros <= _MICROS
            or not 0 <= self.baseline_quality_score_micros <= _MICROS
            or self.baseline_p95_latency_microseconds < 1
            or self.shadow_mismatch_count > self.shadow_sample_count
            or _DIGEST.fullmatch(self.evidence_digest) is None
        ):
            _invalid()

    @property
    def digest(self) -> str:
        """Bind every cutover metric to one immutable evidence identity."""
        return _digest(
            {
                "baseline_p95_latency_microseconds": self.baseline_p95_latency_microseconds,
                "baseline_quality_score_micros": self.baseline_quality_score_micros,
                "canonical_count": self.canonical_count,
                "covered_count": self.covered_count,
                "duplicate_count": self.duplicate_count,
                "evidence_digest": self.evidence_digest,
                "missing_count": self.missing_count,
                "p95_latency_microseconds": self.p95_latency_microseconds,
                "privacy_violation_count": self.privacy_violation_count,
                "quality_score_micros": self.quality_score_micros,
                "shadow_mismatch_count": self.shadow_mismatch_count,
                "shadow_sample_count": self.shadow_sample_count,
                "stale_count": self.stale_count,
                "target_count": self.target_count,
            }
        )

    def passes(self, policy: EmbeddingMigrationPolicy) -> bool:
        """Require all independent activation gates without score compensation."""
        coverage_micros = (
            _MICROS
            if self.canonical_count == 0 and self.covered_count == 0
            else (
                0
                if self.canonical_count == 0
                else self.covered_count * _MICROS // self.canonical_count
            )
        )
        latency_ratio_micros = (
            self.p95_latency_microseconds * _MICROS // self.baseline_p95_latency_microseconds
        )
        return (
            self.target_count == self.canonical_count
            and self.covered_count == self.canonical_count
            and coverage_micros >= policy.minimum_coverage_micros
            and self.missing_count == 0
            and self.stale_count == 0
            and self.duplicate_count == 0
            and self.privacy_violation_count == 0
            and self.quality_score_micros + policy.maximum_quality_regression_micros
            >= self.baseline_quality_score_micros
            and latency_ratio_micros <= policy.maximum_latency_ratio_micros
            and self.shadow_sample_count >= policy.minimum_shadow_samples
            and self.shadow_mismatch_count <= policy.maximum_shadow_mismatches
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddingGenerationMigration:
    """One durable live migration from an active generation to one shadow."""

    migration_id: str
    brain_id: str
    source_space_id: str
    source_space_fingerprint: str
    source_generation_id: str
    target_space_id: str
    target_space_fingerprint: str
    target_generation_id: str
    source_watermark: int
    progress: MigrationProgress
    state: EmbeddingMigrationState
    validation_digest: str | None
    rollback_until_microseconds: int | None
    source_retired_at_microseconds: int | None
    source_deleted_at_microseconds: int | None
    resume_state: EmbeddingMigrationState | None
    version: int
    created_at_microseconds: int
    updated_at_microseconds: int

    def __post_init__(self) -> None:
        """Protect identity, fixed-watermark, activation, and rollback invariants."""
        identities = (
            self.migration_id,
            self.brain_id,
            self.source_space_id,
            self.source_generation_id,
            self.target_space_id,
            self.target_generation_id,
        )
        effective_state = (
            self.resume_state if self.state is EmbeddingMigrationState.PAUSED else self.state
        )
        backfill_complete = self.progress.backfill_cursor == self.source_watermark
        caught_up = self.progress.catchup_cursor == self.progress.catchup_watermark
        dual_write_or_later = effective_state in {
            EmbeddingMigrationState.DUAL_WRITE,
            EmbeddingMigrationState.CATCHING_UP,
            EmbeddingMigrationState.VALIDATING,
            EmbeddingMigrationState.SHADOWING,
            EmbeddingMigrationState.READY,
            EmbeddingMigrationState.ACTIVE,
            EmbeddingMigrationState.ROLLED_BACK,
        }
        validation_complete = effective_state in {
            EmbeddingMigrationState.READY,
            EmbeddingMigrationState.ACTIVE,
            EmbeddingMigrationState.ROLLED_BACK,
        }
        activated = self.state in {
            EmbeddingMigrationState.ACTIVE,
            EmbeddingMigrationState.ROLLED_BACK,
        }
        if (
            any(not _uuid7(value) for value in identities)
            or self.source_space_id == self.target_space_id
            or self.source_generation_id == self.target_generation_id
            or ((self.state is EmbeddingMigrationState.PAUSED) != (self.resume_state is not None))
            or self.resume_state
            in {
                EmbeddingMigrationState.PAUSED,
                EmbeddingMigrationState.ACTIVE,
                EmbeddingMigrationState.ROLLED_BACK,
                EmbeddingMigrationState.FAILED,
            }
            or _DIGEST.fullmatch(self.source_space_fingerprint) is None
            or _DIGEST.fullmatch(self.target_space_fingerprint) is None
            or not 0 <= self.source_watermark <= _MAX_COUNT
            or self.progress.backfill_cursor > self.source_watermark
            or self.progress.catchup_watermark < self.source_watermark
            or (dual_write_or_later and not backfill_complete)
            or (
                self.state
                in {
                    EmbeddingMigrationState.VALIDATING,
                    EmbeddingMigrationState.SHADOWING,
                    EmbeddingMigrationState.READY,
                    EmbeddingMigrationState.ACTIVE,
                    EmbeddingMigrationState.ROLLED_BACK,
                }
                and not caught_up
            )
            or (validation_complete != (self.validation_digest is not None))
            or (
                self.validation_digest is not None
                and _DIGEST.fullmatch(self.validation_digest) is None
            )
            or (activated != (self.rollback_until_microseconds is not None))
            or (
                self.rollback_until_microseconds is not None
                and self.rollback_until_microseconds <= self.updated_at_microseconds
                and self.source_retired_at_microseconds is None
            )
            or (
                self.source_retired_at_microseconds is not None
                and (
                    self.state is not EmbeddingMigrationState.ACTIVE
                    or self.rollback_until_microseconds is None
                    or self.source_retired_at_microseconds < self.rollback_until_microseconds
                )
            )
            or (
                self.source_deleted_at_microseconds is not None
                and (
                    self.source_retired_at_microseconds is None
                    or self.source_deleted_at_microseconds < self.source_retired_at_microseconds
                )
            )
            or not 1 <= self.version <= 2**63 - 1
            or not 0 <= self.created_at_microseconds <= self.updated_at_microseconds <= _MAX_TIME
        ):
            _invalid()

    def transition(
        self,
        target: EmbeddingMigrationState,
        *,
        at_microseconds: int,
        validation_digest: str | None = None,
        rollback_until_microseconds: int | None = None,
        progress: MigrationProgress | None = None,
    ) -> EmbeddingGenerationMigration:
        """Return the next version while preserving every immutable coordinate."""
        self.state.require_transition(target)
        if at_microseconds < self.updated_at_microseconds:
            _invalid()
        if target is EmbeddingMigrationState.ROLLED_BACK and not self.rollback_eligible(
            at_microseconds
        ):
            _invalid()
        return replace(
            self,
            state=target,
            resume_state=(
                self.state if target is EmbeddingMigrationState.PAUSED else self.resume_state
            ),
            progress=self.progress if progress is None else progress,
            validation_digest=(
                None
                if target is EmbeddingMigrationState.FAILED
                else (self.validation_digest if validation_digest is None else validation_digest)
            ),
            rollback_until_microseconds=(
                self.rollback_until_microseconds
                if rollback_until_microseconds is None
                else rollback_until_microseconds
            ),
            version=self.version + 1,
            updated_at_microseconds=at_microseconds,
        )

    def resume(self, *, at_microseconds: int) -> EmbeddingGenerationMigration:
        """Resume exactly the durable phase captured when the migration paused."""
        if (
            self.state is not EmbeddingMigrationState.PAUSED
            or self.resume_state is None
            or at_microseconds < self.updated_at_microseconds
        ):
            _invalid()
        return replace(
            self,
            state=self.resume_state,
            resume_state=None,
            version=self.version + 1,
            updated_at_microseconds=at_microseconds,
        )

    def activate(
        self,
        *,
        at_microseconds: int,
        rollback_until_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Create the active snapshot only from an explicitly approved ready version."""
        if (
            self.state is not EmbeddingMigrationState.READY
            or self.validation_digest is None
            or at_microseconds < self.updated_at_microseconds
            or rollback_until_microseconds <= at_microseconds
        ):
            _invalid()
        return replace(
            self,
            state=EmbeddingMigrationState.ACTIVE,
            rollback_until_microseconds=rollback_until_microseconds,
            version=self.version + 1,
            updated_at_microseconds=at_microseconds,
        )

    def rollback_eligible(self, now_microseconds: int) -> bool:
        """Allow rollback only while the source read-only retention anchor is live."""
        return (
            self.state is EmbeddingMigrationState.ACTIVE
            and self.rollback_until_microseconds is not None
            and self.updated_at_microseconds <= now_microseconds < self.rollback_until_microseconds
        )

    def deletion_eligible(self, now_microseconds: int) -> bool:
        """Allow governed source deletion only after the rollback window expires."""
        return (
            self.state is EmbeddingMigrationState.ACTIVE
            and self.rollback_until_microseconds is not None
            and now_microseconds >= self.rollback_until_microseconds
        )


def migration_request_digest(  # noqa: PLR0913 -- Digest binds every identity coordinate.
    *,
    brain_id: str,
    source_space_id: str,
    source_generation_id: str,
    target_space_id: str,
    target_generation_id: str,
    source_watermark: int,
) -> str:
    """Bind idempotent planning to both exact spaces/generations and watermark."""
    identities = (
        brain_id,
        source_space_id,
        source_generation_id,
        target_space_id,
        target_generation_id,
    )
    if (
        any(not _uuid7(value) for value in identities)
        or source_space_id == target_space_id
        or source_generation_id == target_generation_id
        or not 0 <= source_watermark <= _MAX_COUNT
    ):
        _invalid()
    return _digest(
        {
            "brain_id": brain_id,
            "source_generation_id": source_generation_id,
            "source_space_id": source_space_id,
            "source_watermark": source_watermark,
            "target_generation_id": target_generation_id,
            "target_space_id": target_space_id,
        }
    )


def _digest(document: dict[str, object]) -> str:
    payload = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _uuid7(value: str) -> bool:
    try:
        parsed = UUID(value)
    except AttributeError, TypeError, ValueError:
        return False
    return parsed.version == _UUID_VERSION and str(parsed) == value


def _invalid() -> Never:
    raise EmbeddingMigrationValidationError(_ERR_INPUT)
