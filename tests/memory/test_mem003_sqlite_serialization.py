"""MEM-003 strict SQLite serialization and boundary-validation tests."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentmemory.memory.adapters.outbound import sqlite_deduplication as adapter
from agentmemory.memory.domain.errors import MemoryIntegrityError, MemoryValidationError


def test_strict_json_accepts_only_canonical_unique_objects() -> None:
    assert adapter._strict_object(b'{"answer":42}') == {"answer": 42}
    for raw in (
        b'{"answer":1,"answer":2}',
        b'{"answer":NaN}',
        b"[]",
        b'{ "answer":42}',
    ):
        with pytest.raises(MemoryIntegrityError):
            adapter._strict_object(raw)

    with pytest.raises(MemoryIntegrityError):
        adapter._canonical_json({"invalid"})


def test_limit_digest_and_scalar_decoders_fail_closed() -> None:
    adapter._validate_limit(1)
    for invalid_limit in (True, 0, 257):
        with pytest.raises(MemoryValidationError):
            adapter._validate_limit(invalid_limit)

    assert adapter._digest("a" * 64, "digest") == bytes.fromhex("a" * 64)
    for invalid_digest in ("not-hex", "0" * 64, "a" * 62):
        with pytest.raises(MemoryValidationError):
            adapter._digest(invalid_digest, "digest")

    assert adapter._bytes(b"value") == b"value"
    assert adapter._bytes(bytearray(b"value")) == b"value"
    assert adapter._bytes(memoryview(b"value")) == b"value"
    with pytest.raises(MemoryIntegrityError):
        adapter._bytes("value")

    assert adapter._integer(1) == 1
    for invalid_integer in (True, "1"):
        with pytest.raises(MemoryIntegrityError):
            adapter._integer(invalid_integer)


def test_result_field_and_time_decoders_reject_type_or_timezone_drift() -> None:
    document: adapter.JsonValue = {"text": "value", "items": ["a", "b"]}
    assert isinstance(document, dict)
    assert adapter._string(document, "text") == "value"
    assert adapter._string_list(document, "items") == ("a", "b")

    for invalid_string in ({"text": 1}, {"text": None}):
        with pytest.raises(MemoryIntegrityError):
            adapter._string(invalid_string, "text")
    invalid_lists: tuple[dict[str, adapter.JsonValue], ...] = (
        {"items": "a"},
        {"items": ["a", 1]},
    )
    for invalid_list in invalid_lists:
        with pytest.raises(MemoryIntegrityError):
            adapter._string_list(invalid_list, "items")

    instant = datetime(2026, 7, 21, 10, tzinfo=UTC)
    micros = adapter._micros(instant)
    assert adapter._time(micros) == instant
    with pytest.raises(MemoryValidationError):
        adapter._micros(instant.replace(tzinfo=None))
    with pytest.raises(MemoryIntegrityError):
        adapter._time(10**30)
