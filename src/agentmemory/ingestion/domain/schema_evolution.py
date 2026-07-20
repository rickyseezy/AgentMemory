"""Immutable event-schema lineage, derived views, and migration progress."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Never, cast
from uuid import UUID

from agentmemory.ingestion.domain.errors import IngestionValidationError

if TYPE_CHECKING:
    from collections.abc import Mapping

_UUID_VERSION = 7
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_MAX_EXTENSIONS = 256

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class SchemaEvolutionDisposition(StrEnum):
    """Closed processing result for one immutable source event."""

    CURRENT = "current"
    UPCASTED = "upcasted"
    QUARANTINED = "quarantined"


class SchemaQuarantineReason(StrEnum):
    """Content-free reason an event cannot enter a current derived view."""

    UNSUPPORTED_MAJOR = "unsupported_major"
    FUTURE_VERSION = "future_version"
    MISSING_UPCASTER = "missing_upcaster"
    INVALID_TRANSFORM = "invalid_transform"
    EXTENSION_LOSS = "extension_loss"


class SchemaMigrationState(StrEnum):
    """Durable lifecycle of one resumable schema migration operation."""

    PENDING = "pending"
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True, order=True)
class EventSchemaKey:
    """One advertised family, compatibility major, and sequential revision."""

    family: str
    major: int
    version: int

    def __post_init__(self) -> None:
        """Require a canonical family and positive compatibility coordinates."""
        if _TOKEN.fullmatch(self.family) is None:
            _invalid("schema_family", "invalid")
        if self.major < 1:
            _invalid("schema_major", "out_of_range")
        if self.version < 1:
            _invalid("schema_version", "out_of_range")

    @property
    def token(self) -> str:
        """Return the stable registry and evidence token."""
        return f"{self.family}@{self.major}.{self.version}"


@dataclass(frozen=True, slots=True)
class EventSchemaDocument:
    """Strict canonical source document with unknown additive fields retained."""

    event_id: str
    schema: EventSchemaKey
    fields: Mapping[str, JsonValue]
    canonical_bytes: bytes
    sha256: str

    @classmethod
    def decode(
        cls,
        raw: bytes,
        schema: EventSchemaKey | None = None,
        *,
        maximum_bytes: int = _MAX_DOCUMENT_BYTES,
    ) -> EventSchemaDocument:
        """Decode duplicate-free canonical JSON without discarding any field."""
        if not raw or len(raw) > maximum_bytes:
            _invalid("event_document", "size_invalid")
        try:
            text = raw.decode("utf-8", errors="strict")
            parsed = json.loads(
                text,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except UnicodeDecodeError, json.JSONDecodeError:
            _invalid("event_document", "invalid_json")
        if not isinstance(parsed, dict):
            _invalid("event_document", "object_required")
        document = cast("dict[str, JsonValue]", parsed)
        event_id = document.get("id")
        if not isinstance(event_id, str):
            _invalid("id", "required")
        _require_uuid7(event_id, "id")
        resolved_schema = schema or _embedded_schema(document)
        canonical = _canonical_json(document)
        return cls(
            event_id,
            resolved_schema,
            MappingProxyType(document),
            canonical,
            hashlib.sha256(canonical).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class EventSchemaSource:
    """Authorized decrypted source bytes paired with their immutable stored schema."""

    event_id: str
    schema: EventSchemaKey
    canonical_bytes: bytes
    canonical_sha256: str

    def __post_init__(self) -> None:
        """Authenticate identity, canonical bytes, and persisted digest before upcasting."""
        _require_uuid7(self.event_id, "event_id")
        _require_digest(self.canonical_sha256, "canonical_sha256")
        decoded = EventSchemaDocument.decode(self.canonical_bytes, self.schema)
        if decoded.event_id != self.event_id or decoded.sha256 != self.canonical_sha256:
            _invalid("schema_source", "digest_mismatch")


@dataclass(frozen=True, slots=True, order=True)
class UpcastStepEvidence:
    """One exact adjacent transform applied to a derived view."""

    source: EventSchemaKey
    target: EventSchemaKey
    upcaster_id: str
    input_sha256: str
    output_sha256: str

    def __post_init__(self) -> None:
        """Reject leaps, arbitrary identifiers, and malformed fingerprints."""
        if (
            self.source.family != self.target.family
            or self.source.major != self.target.major
            or self.target.version != self.source.version + 1
        ):
            _invalid("upcast_step", "not_adjacent")
        _require_token(self.upcaster_id, "upcaster_id")
        _require_digest(self.input_sha256, "input_sha256")
        _require_digest(self.output_sha256, "output_sha256")


@dataclass(frozen=True, slots=True)
class EventSchemaOutcome:
    """Current derived bytes or content-free quarantine evidence."""

    event_id: str
    source_schema: EventSchemaKey
    target_schema: EventSchemaKey
    disposition: SchemaEvolutionDisposition
    original_sha256: str
    derived_bytes: bytes | None
    derived_sha256: str | None
    steps: tuple[UpcastStepEvidence, ...]
    quarantine_reason: SchemaQuarantineReason | None

    def __post_init__(self) -> None:  # noqa: C901, PLR0912 -- Complete closed shape.
        """Require outcome bytes, trace, and quarantine facts to agree."""
        _require_uuid7(self.event_id, "event_id")
        _require_digest(self.original_sha256, "original_sha256")
        if self.disposition is SchemaEvolutionDisposition.QUARANTINED:
            if self.derived_bytes is not None or self.derived_sha256 is not None:
                _invalid("derived_view", "quarantine_shape")
            if self.quarantine_reason is None:
                _invalid("quarantine_reason", "required")
        else:
            if self.derived_bytes is None or self.derived_sha256 is None:
                _invalid("derived_view", "required")
            if hashlib.sha256(self.derived_bytes).hexdigest() != self.derived_sha256:
                _invalid("derived_sha256", "mismatch")
            if self.quarantine_reason is not None:
                _invalid("quarantine_reason", "prohibited")
        if self.disposition is SchemaEvolutionDisposition.CURRENT and self.steps:
            _invalid("upcast_steps", "unexpected")
        if self.disposition is SchemaEvolutionDisposition.UPCASTED and not self.steps:
            _invalid("upcast_steps", "required")
        if self.steps:
            if self.steps[0].source != self.source_schema:
                _invalid("upcast_steps", "source_mismatch")
            if self.steps[-1].target != self.target_schema:
                _invalid("upcast_steps", "target_mismatch")
            for previous, current in zip(self.steps, self.steps[1:], strict=False):
                if previous.target != current.source:
                    _invalid("upcast_steps", "broken_chain")

    @property
    def trace_sha256(self) -> str:
        """Fingerprint the complete ordered transformation trace."""
        encoded = _canonical_json(
            [
                {
                    "input_sha256": item.input_sha256,
                    "output_sha256": item.output_sha256,
                    "source": item.source.token,
                    "target": item.target.token,
                    "upcaster_id": item.upcaster_id,
                }
                for item in self.steps
            ]
        )
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class SchemaMigrationProgress:
    """Content-free durable checkpoint for one bounded migration run."""

    operation_id: str
    state: SchemaMigrationState
    target: EventSchemaKey
    cursor: str | None
    scanned: int
    upcasted: int
    current: int
    quarantined: int
    total: int

    def __post_init__(self) -> None:
        """Reject impossible counters, cursor state, or terminal progress."""
        _require_token(self.operation_id, "operation_id")
        counters = (self.scanned, self.upcasted, self.current, self.quarantined, self.total)
        if any(item < 0 for item in counters):
            _invalid("migration_progress", "negative")
        if self.scanned != self.upcasted + self.current + self.quarantined:
            _invalid("migration_progress", "count_mismatch")
        if self.scanned > self.total:
            _invalid("migration_progress", "overflow")
        if self.cursor is not None:
            _require_uuid7(self.cursor, "cursor")
        if self.state is SchemaMigrationState.COMPLETED and self.scanned != self.total:
            _invalid("migration_progress", "incomplete")


def canonical_document(fields: Mapping[str, JsonValue]) -> bytes:
    """Serialize one derived view with deterministic JSON rules."""
    return _canonical_json(dict(fields))


def extension_fields(
    fields: Mapping[str, JsonValue],
    known_fields: frozenset[str],
) -> Mapping[str, JsonValue]:
    """Return an immutable bounded snapshot of fields unknown to one revision."""
    extensions = {key: value for key, value in fields.items() if key not in known_fields}
    if len(extensions) > _MAX_EXTENSIONS:
        _invalid("extensions", "too_many")
    return MappingProxyType(extensions)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except TypeError, ValueError:
        _invalid("event_document", "invalid_value")


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            _invalid("event_document", "duplicate_key")
        result[key] = value
    return result


def _reject_constant(_: str) -> Never:
    _invalid("event_document", "non_finite")


def _embedded_schema(document: Mapping[str, JsonValue]) -> EventSchemaKey:
    family = document.get("schema_family")
    major = document.get("schema_major")
    version = document.get("schema_version")
    if not isinstance(family, str):
        _invalid("schema_family", "required")
    if not isinstance(major, int) or isinstance(major, bool):
        _invalid("schema_major", "required")
    if not isinstance(version, int) or isinstance(version, bool):
        _invalid("schema_version", "required")
    return EventSchemaKey(family, major, version)


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise IngestionValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise IngestionValidationError.single(field, "invalid_uuid7")


def _require_token(value: str, field: str) -> None:
    if _TOKEN.fullmatch(value) is None:
        _invalid(field, "invalid")


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        _invalid(field, "invalid_digest")


def _invalid(field: str, code: str) -> Never:
    raise IngestionValidationError.single(field, code)
