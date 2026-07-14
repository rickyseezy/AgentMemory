"""Duplicate-key and non-finite-number rejecting JSON codec."""

from __future__ import annotations

import json
from typing import Any, Never, cast


class StrictJsonError(ValueError):
    """A JSON document is ambiguous or outside the strict profile."""


def loads(data: bytes | str) -> object:
    """Parse JSON while rejecting duplicate names and non-standard numbers."""
    try:
        return json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, StrictJsonError) as error:
        message = "JSON document is invalid"
        raise StrictJsonError(message) from error


def canonical_bytes(value: object) -> bytes:
    """Encode deterministic UTF-8 JSON without insignificant whitespace."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        message = "JSON value cannot be encoded canonically"
        raise StrictJsonError(message) from error


def require_object(value: object) -> dict[str, object]:
    """Narrow a decoded root to a string-keyed object."""
    if not isinstance(value, dict):
        message = "JSON root must be an object"
        raise StrictJsonError(message)
    mapping = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in mapping):
        message = "JSON object contains a non-string key"
        raise StrictJsonError(message)
    return cast("dict[str, object]", mapping)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            message = "JSON object contains a duplicate key"
            raise StrictJsonError(message)
        result[key] = value
    return result


def _reject_constant(value: str) -> Never:
    message = f"JSON constant {value!r} is forbidden"
    raise StrictJsonError(message)
