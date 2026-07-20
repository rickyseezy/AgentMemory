"""Strict transcript decoding and sensitive-text redaction adapters."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.generic_adapter import (
    DecodedTranscriptRecord,
    TranscriptEncoding,
    TranscriptFormat,
    TranscriptRole,
)

_MAX_RECORD_BYTES = 32_768
_MAX_ADDITIONAL_PATTERNS = 32
_MAX_PATTERN_LENGTH = 512
_PROHIBITED_FIELDS = frozenset(
    {"chain_of_thought", "hidden_reasoning", "private_reasoning", "reasoning_trace", "scratchpad"}
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|password|secret)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_SECRET = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")
_PREFIXED_SECRET = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"
)


@dataclass(frozen=True, slots=True)
class StrictTranscriptDecoder:
    """Decode only an explicitly selected format and encoding."""

    def decode(
        self,
        source: bytes,
        transcript_format: TranscriptFormat,
        encoding: TranscriptEncoding,
        default_occurred_at: datetime,
    ) -> tuple[DecodedTranscriptRecord, ...]:
        """Return records with offsets measured in the original source bytes."""
        text, prefix_size, codec = _decode_source(source, encoding)
        if transcript_format is TranscriptFormat.PLAIN_TEXT:
            records = _plain_records(text, prefix_size, codec, default_occurred_at)
        elif transcript_format is TranscriptFormat.JSON_LINES:
            records = _json_lines_records(text, prefix_size, codec, default_occurred_at)
        else:
            records = _json_array_records(text, prefix_size, codec, default_occurred_at)
        if not records:
            field = "source"
            raise IngestionValidationError.single(field, "no_records")
        return records


@dataclass(frozen=True, slots=True)
class RegexSensitiveTextRedactor:
    """Deterministically redact well-known credentials and configured private expressions."""

    additional_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Compile bounded patterns at configuration time."""
        if len(self.additional_patterns) > _MAX_ADDITIONAL_PATTERNS:
            msg = "too many additional redaction patterns"
            raise ValueError(msg)
        for pattern in self.additional_patterns:
            if not pattern or len(pattern) > _MAX_PATTERN_LENGTH:
                msg = "invalid additional redaction pattern"
                raise ValueError(msg)
            re.compile(pattern)

    def redact(self, value: str) -> str:
        """Return idempotently redacted text before any event payload exists."""
        redacted = _ASSIGNMENT_SECRET.sub(r"\1\2[REDACTED]", value)
        redacted = _BEARER_SECRET.sub("Bearer [REDACTED]", redacted)
        redacted = _PREFIXED_SECRET.sub("[REDACTED]", redacted)
        for pattern in self.additional_patterns:
            redacted = re.sub(pattern, "[REDACTED]", redacted)
        return redacted


def _decode_source(
    source: bytes,
    encoding: TranscriptEncoding,
) -> tuple[str, int, str]:
    signatures = {
        TranscriptEncoding.UTF8_BOM: (b"\xef\xbb\xbf", "utf-8"),
        TranscriptEncoding.UTF16_LE: (b"\xff\xfe", "utf-16-le"),
        TranscriptEncoding.UTF16_BE: (b"\xfe\xff", "utf-16-be"),
    }
    if encoding is TranscriptEncoding.UTF8:
        if source.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
            field = "encoding"
            raise IngestionValidationError.single(field, "bom_mismatch")
        prefix, codec = b"", "utf-8"
    else:
        prefix, codec = signatures[encoding]
        if not source.startswith(prefix):
            field = "encoding"
            raise IngestionValidationError.single(field, "bom_required")
    try:
        return source[len(prefix) :].decode(codec, errors="strict"), len(prefix), codec
    except UnicodeDecodeError as error:
        field = "encoding"
        raise IngestionValidationError.single(field, "invalid_bytes") from error


def _plain_records(
    text: str,
    prefix_size: int,
    codec: str,
    occurred_at: datetime,
) -> tuple[DecodedTranscriptRecord, ...]:
    records: list[DecodedTranscriptRecord] = []
    character_offset = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        start = prefix_size + len(text[:character_offset].encode(codec))
        end = start + len(line.encode(codec))
        character_offset += len(line)
        if content:
            _require_record_size(content)
            records.append(
                DecodedTranscriptRecord(start, end, content, TranscriptRole.UNKNOWN, occurred_at)
            )
    if character_offset < len(text):  # pragma: no cover - splitlines retains final content.
        raise AssertionError
    return tuple(records)


def _json_lines_records(
    text: str,
    prefix_size: int,
    codec: str,
    occurred_at: datetime,
) -> tuple[DecodedTranscriptRecord, ...]:
    records: list[DecodedTranscriptRecord] = []
    character_offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        start = prefix_size + len(text[:character_offset].encode(codec))
        end = start + len(line.encode(codec))
        character_offset += len(line)
        if stripped:
            records.append(_record_from_json(stripped, start, end, occurred_at))
    return tuple(records)


def _json_array_records(
    text: str,
    prefix_size: int,
    codec: str,
    occurred_at: datetime,
) -> tuple[DecodedTranscriptRecord, ...]:
    decoder = json.JSONDecoder()
    cursor = _skip_space(text, 0)
    if cursor >= len(text) or text[cursor] != "[":
        field = "source"
        raise IngestionValidationError.single(field, "json_array_required")
    cursor += 1
    records: list[DecodedTranscriptRecord] = []
    while True:
        cursor = _skip_space(text, cursor)
        if cursor < len(text) and text[cursor] == "]":
            cursor += 1
            break
        start_character = cursor
        try:
            value, cursor = decoder.raw_decode(text, cursor)
        except json.JSONDecodeError as error:
            field = "source"
            raise IngestionValidationError.single(field, "invalid_json") from error
        start = prefix_size + len(text[:start_character].encode(codec))
        end = prefix_size + len(text[:cursor].encode(codec))
        records.append(_record_from_value(value, start, end, occurred_at))
        cursor = _skip_space(text, cursor)
        if cursor < len(text) and text[cursor] == ",":
            cursor += 1
            continue
        if cursor >= len(text) or text[cursor] != "]":
            field = "source"
            raise IngestionValidationError.single(field, "invalid_json_array")
    if _skip_space(text, cursor) != len(text):
        field = "source"
        raise IngestionValidationError.single(field, "trailing_data")
    return tuple(records)


def _record_from_json(
    value: str,
    start: int,
    end: int,
    occurred_at: datetime,
) -> DecodedTranscriptRecord:
    try:
        decoded = cast("object", json.loads(value))
    except json.JSONDecodeError as error:
        field = "source"
        raise IngestionValidationError.single(field, "invalid_json") from error
    return _record_from_value(decoded, start, end, occurred_at)


def _record_from_value(
    value: object,
    start: int,
    end: int,
    default_occurred_at: datetime,
) -> DecodedTranscriptRecord:
    if not isinstance(value, dict):
        field = "source"
        raise IngestionValidationError.single(field, "unsafe_record")
    document = cast("dict[object, object]", value)
    if _contains_prohibited(document):
        field = "source"
        raise IngestionValidationError.single(field, "unsafe_record")
    content = document.get("content")
    role_value = document.get("role", "unknown")
    time_value = document.get("timestamp")
    if not isinstance(content, str) or not isinstance(role_value, str):
        field = "source"
        raise IngestionValidationError.single(field, "invalid_record")
    try:
        role = TranscriptRole(role_value.casefold())
    except ValueError as error:
        field = "role"
        raise IngestionValidationError.single(field, "unsupported") from error
    occurred_at = _parse_time(time_value) if time_value is not None else default_occurred_at
    _require_record_size(content)
    return DecodedTranscriptRecord(start, end, content, role, occurred_at)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        field = "timestamp"
        raise IngestionValidationError.single(field, "invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        field = "timestamp"
        raise IngestionValidationError.single(field, "invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(None):
        field = "timestamp"
        raise IngestionValidationError.single(field, "not_utc")
    return parsed


def _contains_prohibited(value: object) -> bool:
    if isinstance(value, dict):
        document = cast("dict[object, object]", value)
        return any(
            str(key).casefold() in _PROHIBITED_FIELDS or _contains_prohibited(item)
            for key, item in document.items()
        )
    if isinstance(value, list):
        items = cast("list[object]", value)
        return any(_contains_prohibited(item) for item in items)
    return False


def _require_record_size(content: str) -> None:
    if not content or len(content.encode()) > _MAX_RECORD_BYTES:
        field = "content"
        raise IngestionValidationError.single(field, "invalid_size")


def _skip_space(value: str, cursor: int) -> int:
    while cursor < len(value) and value[cursor].isspace():
        cursor += 1
    return cursor
