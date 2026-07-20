"""PF-002 deterministic, generation-isolated projection rebuild model."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

_MAX_VERSION_PIN_LENGTH = 256
_MAX_STABLE_ID_LENGTH = 512
_MAX_SOURCE_EVENT_ID_LENGTH = 128
_MAX_TARGET_TYPE_LENGTH = 64
_MAX_REASON_LENGTH = 128
_MAX_OPERATION_ID_LENGTH = 128


class ProjectionType(StrEnum):
    """Closed set of rebuildable, non-authoritative projection families."""

    GRAPH = "graph"
    MEMORY = "memory"
    SEARCH = "search"
    CODE = "code"
    VECTOR = "vector"


class RebuildState(StrEnum):
    """Durable projection rebuild lifecycle."""

    QUEUED = "queued"
    BUILDING = "building"
    PARTIAL = "partial"
    VALIDATING = "validating"
    READY = "ready"
    ACTIVE = "active"
    FAILED = "failed"
    SUPERSEDED = "superseded"

    def require_transition(self, target: RebuildState) -> None:
        """Reject state changes that could expose unvalidated derived state."""
        transitions: dict[RebuildState, frozenset[RebuildState]] = {
            RebuildState.QUEUED: frozenset({RebuildState.BUILDING, RebuildState.FAILED}),
            RebuildState.BUILDING: frozenset(
                {RebuildState.PARTIAL, RebuildState.VALIDATING, RebuildState.FAILED}
            ),
            RebuildState.PARTIAL: frozenset({RebuildState.BUILDING, RebuildState.FAILED}),
            RebuildState.VALIDATING: frozenset({RebuildState.READY, RebuildState.FAILED}),
            RebuildState.READY: frozenset(
                {RebuildState.ACTIVE, RebuildState.SUPERSEDED, RebuildState.FAILED}
            ),
            RebuildState.ACTIVE: frozenset({RebuildState.SUPERSEDED}),
            RebuildState.FAILED: frozenset(),
            RebuildState.SUPERSEDED: frozenset(),
        }
        if target not in transitions[self]:
            msg = f"projection rebuild transition {self.value}->{target.value} is invalid"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class RebuildManifest:
    """Every implementation and provider pin required to reproduce a generation."""

    application_build: str
    relational_schema: str
    graph_schema: str
    parser_version: str
    extractor_version: str
    provider_versions: tuple[str, ...]
    embedding_space: str
    implementation_fingerprint: Sha256Digest

    def __post_init__(self) -> None:
        """Require explicit immutable pins and canonical provider ordering."""
        pins = (
            self.application_build,
            self.relational_schema,
            self.graph_schema,
            self.parser_version,
            self.extractor_version,
            self.embedding_space,
        )
        if any(not pin or len(pin) > _MAX_VERSION_PIN_LENGTH for pin in pins):
            msg = "rebuild manifest contains an invalid version pin"
            raise DomainValidationError(msg)
        if (
            not self.provider_versions
            or self.provider_versions != tuple(sorted(set(self.provider_versions)))
            or any(
                not value or len(value) > _MAX_VERSION_PIN_LENGTH
                for value in self.provider_versions
            )
        ):
            msg = "provider versions must be a non-empty sorted unique tuple"
            raise DomainValidationError(msg)

    def canonical_bytes(self) -> bytes:
        """Return a cross-runtime deterministic manifest representation."""
        return canonical_json(
            {
                "application_build": self.application_build,
                "embedding_space": self.embedding_space,
                "extractor_version": self.extractor_version,
                "graph_schema": self.graph_schema,
                "implementation_fingerprint": self.implementation_fingerprint.value,
                "parser_version": self.parser_version,
                "provider_versions": list(self.provider_versions),
                "relational_schema": self.relational_schema,
                "schema_version": 1,
            }
        ).encode()

    @property
    def digest(self) -> Sha256Digest:
        """Bind the exact manifest into rebuild identity and audit evidence."""
        return Sha256Digest.from_bytes(self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class ProjectionRecord:
    """One deterministic record emitted from canonical source evidence."""

    stable_id: str
    source_event_id: str
    source_sequence: int
    source_digest: Sha256Digest
    content_digest: Sha256Digest
    payload_json: str

    def __post_init__(self) -> None:
        """Reject ambiguous identity, lineage, and non-canonical content."""
        if not self.stable_id or len(self.stable_id) > _MAX_STABLE_ID_LENGTH:
            msg = "stable projection ID is invalid"
            raise DomainValidationError(msg)
        if not self.source_event_id or len(self.source_event_id) > _MAX_SOURCE_EVENT_ID_LENGTH:
            msg = "source event ID is invalid"
            raise DomainValidationError(msg)
        if self.source_sequence < 1:
            msg = "source sequence must be positive"
            raise DomainValidationError(msg)
        try:
            payload = cast("object", json.loads(self.payload_json))
        except (json.JSONDecodeError, UnicodeError) as error:
            msg = "projection payload is invalid JSON"
            raise DomainValidationError(msg) from error
        if canonical_json(payload) != self.payload_json:
            msg = "projection payload is not canonical JSON"
            raise DomainValidationError(msg)
        if Sha256Digest.from_bytes(self.payload_json.encode()) != self.content_digest:
            msg = "projection content digest does not match payload"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Canonical event materialization input plus deletion-check identity."""

    projection: ProjectionRecord
    target_type: str
    target_id_hash: Sha256Digest
    missing_dependency: str | None = None

    def __post_init__(self) -> None:
        """Keep typed dependency details bounded and privacy-safe."""
        if not self.target_type or len(self.target_type) > _MAX_TARGET_TYPE_LENGTH:
            msg = "projection source target type is invalid"
            raise DomainValidationError(msg)
        if self.missing_dependency is not None and (
            not self.missing_dependency or len(self.missing_dependency) > _MAX_REASON_LENGTH
        ):
            msg = "missing dependency code is invalid"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class SourcePage:
    """One immutable, watermark-bounded canonical replay page."""

    records: tuple[SourceRecord, ...]
    next_cursor: int
    complete: bool

    def __post_init__(self) -> None:
        """Require a monotonic nonnegative resumable cursor."""
        if self.next_cursor < 0:
            msg = "rebuild cursor cannot be negative"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class StartProjectionRebuildCommand:
    """Request one projection family at a fixed canonical watermark."""

    operation_id: str
    brain_id: Uuid7Id
    actor_id: Uuid7Id
    grant_id: Uuid7Id
    projection_type: ProjectionType
    manifest: RebuildManifest
    requested_watermark: int | None = None

    def __post_init__(self) -> None:
        """Reject unsafe operation identifiers and watermarks at the boundary."""
        if not self.operation_id or len(self.operation_id) > _MAX_OPERATION_ID_LENGTH:
            msg = "projection rebuild operation ID is invalid"
            raise DomainValidationError(msg)
        if self.requested_watermark is not None and self.requested_watermark < 0:
            msg = "requested watermark cannot be negative"
            raise DomainValidationError(msg)


@dataclass(frozen=True, slots=True)
class ProjectionValidation:
    """Deterministic validation evidence for one complete shadow generation."""

    record_count: int
    generation_digest: Sha256Digest
    lineage_complete: bool
    integrity_valid: bool
    authorization_valid: bool
    tombstones_current: bool
    golden_queries_passed: bool

    @property
    def passed(self) -> bool:
        """Require every independent activation gate."""
        return (
            self.record_count >= 0
            and self.lineage_complete
            and self.integrity_valid
            and self.authorization_valid
            and self.tombstones_current
            and self.golden_queries_passed
        )


@dataclass(frozen=True, slots=True)
class ProjectionRebuild:
    """Durable rebuild operation snapshot returned through application ports."""

    operation_id: str
    brain_id: Uuid7Id
    actor_id: Uuid7Id
    grant_id: Uuid7Id
    projection_type: ProjectionType
    source_watermark: int
    cursor: int
    rebuild_key: Sha256Digest
    generation_id: Sha256Digest
    manifest: RebuildManifest
    state: RebuildState
    active_generation_at_start: Sha256Digest | None
    record_count: int
    skipped_tombstones: int
    generation_digest: Sha256Digest | None
    partial_reason: str | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        """Protect the immutable watermark and monotonic progress invariants."""
        if self.source_watermark < 0 or self.cursor < 0 or self.cursor > self.source_watermark:
            msg = "projection rebuild progress is invalid"
            raise DomainValidationError(msg)
        if self.record_count < 0 or self.skipped_tombstones < 0:
            msg = "projection rebuild counters cannot be negative"
            raise DomainValidationError(msg)


def canonical_json(value: object) -> str:
    """Encode a finite JSON object using the product's deterministic grammar."""
    if not isinstance(value, dict):
        msg = "canonical JSON root must be an object"
        raise DomainValidationError(msg)
    normalized = cast("dict[object, object]", value)
    _require_finite(normalized)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        msg = "value cannot be represented as canonical JSON"
        raise DomainValidationError(msg) from error


def derive_rebuild_key(
    projection_type: ProjectionType,
    brain_id: Uuid7Id,
    source_watermark: int,
    implementation_fingerprint: Sha256Digest,
) -> Sha256Digest:
    """Derive the normative PF-002 idempotency key with length-delimited fields."""
    if source_watermark < 0:
        msg = "source watermark cannot be negative"
        raise DomainValidationError(msg)
    return Sha256Digest.from_bytes(
        _framed(
            (
                projection_type.value,
                brain_id.value,
                str(source_watermark),
                implementation_fingerprint.value,
            )
        )
    )


def derive_generation_id(rebuild_key: Sha256Digest, manifest_digest: Sha256Digest) -> Sha256Digest:
    """Derive a collision-resistant immutable shadow-generation identifier."""
    return Sha256Digest.from_bytes(
        _framed(("pf002-generation-v1", rebuild_key.value, manifest_digest.value))
    )


def projection_digest(records: Iterable[ProjectionRecord]) -> Sha256Digest:
    """Digest a generation independent of replay page or arrival order."""
    ordered = sorted(records, key=lambda record: record.stable_id)
    if len({record.stable_id for record in ordered}) != len(ordered):
        msg = "duplicate stable projection ID"
        raise DomainValidationError(msg)
    return Sha256Digest.from_bytes(
        _framed(
            tuple(
                f"{record.stable_id}:{record.content_digest.value}:{record.source_digest.value}"
                for record in ordered
            )
        )
    )


def _framed(values: tuple[str, ...]) -> bytes:
    return b"".join(f"{len(value.encode())}:".encode() + value.encode() for value in values)


def _require_finite(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        msg = "canonical JSON numbers must be finite"
        raise DomainValidationError(msg)
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        if any(not isinstance(key, str) for key in mapping):
            msg = "canonical JSON object keys must be strings"
            raise DomainValidationError(msg)
        for child in mapping.values():
            _require_finite(child)
    elif isinstance(value, list):
        for child in cast("list[object]", value):
            _require_finite(child)
