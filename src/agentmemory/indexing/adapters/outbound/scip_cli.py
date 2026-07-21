"""Pinned SCIP CLI binary conversion and strict document normalization."""

from __future__ import annotations

import json
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from agentmemory.indexing.domain.errors import (
    IndexingUnavailableError,
    IndexingValidationError,
)

_ERR_CLI = "SCIP CLI conversion failed"
_ERR_DOCUMENT = "SCIP CLI document is invalid"
_MAX_BINARY_BYTES = 256 * 1024 * 1024
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MIN_TIMEOUT_SECONDS = 0.1
_MAX_TIMEOUT_SECONDS = 300.0
_POSITION_ENCODINGS = {
    1: "UTF8CodeUnitOffsetFromLineStart",
    2: "UTF16CodeUnitOffsetFromLineStart",
    3: "UTF32CodeUnitOffsetFromLineStart",
}
_KINDS = {
    7: "Class",
    8: "Constant",
    9: "Constructor",
    11: "Enum",
    15: "Field",
    17: "Function",
    21: "Interface",
    26: "Method",
    29: "Module",
    30: "Namespace",
    35: "Package",
    37: "Parameter",
    41: "Property",
    49: "Struct",
    53: "Trait",
    54: "Type",
    55: "TypeAlias",
    61: "Variable",
}
_INDEX_FIELDS = frozenset({"metadata", "documents", "external_symbols"})
_DOCUMENT_FIELDS = frozenset(
    {"language", "relative_path", "occurrences", "symbols", "text", "position_encoding"}
)
_OCCURRENCE_FIELDS = frozenset(
    {
        "range",
        "symbol",
        "symbol_roles",
        "override_documentation",
        "syntax_kind",
        "diagnostics",
    }
)
_SYMBOL_FIELDS = frozenset(
    {
        "symbol",
        "documentation",
        "relationships",
        "kind",
        "display_name",
        "signature_documentation",
        "enclosing_symbol",
    }
)
_RELATIONSHIP_FIELDS = frozenset(
    {"symbol", "is_reference", "is_implementation", "is_type_definition", "is_definition"}
)


@dataclass(frozen=True, slots=True)
class ScipCliPolicy:
    """Exact local binary identity and execution bounds."""

    binary: Path = Path("/usr/local/bin/scip")
    version: str = "0.9.0"
    timeout_seconds: float = 30.0
    max_binary_bytes: int = _MAX_BINARY_BYTES
    max_json_bytes: int = _MAX_JSON_BYTES

    def __post_init__(self) -> None:
        """Reject path search, version ambiguity, and ineffective limits."""
        if (
            not self.binary.is_absolute()
            or self.version != "0.9.0"
            or not _MIN_TIMEOUT_SECONDS <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS
            or not 1 <= self.max_binary_bytes <= _MAX_BINARY_BYTES
            or not 1 <= self.max_json_bytes <= _MAX_JSON_BYTES
        ):
            raise IndexingValidationError(_ERR_CLI)


class ScipCliDocumentConverter:
    """Convert one bounded protobuf index using fixed argv and normalize one document."""

    def __init__(self, policy: ScipCliPolicy | None = None) -> None:
        """Bind a release-pinned image binary without consulting PATH."""
        self._policy = policy or ScipCliPolicy()

    def convert(self, payload: bytes, relative_path: str) -> bytes:
        """Return canonical strict JSON accepted by the SCIP evidence mapper."""
        if not payload or len(payload) > self._policy.max_binary_bytes:
            raise IndexingValidationError(_ERR_DOCUMENT)
        with tempfile.TemporaryDirectory(prefix="agentmemory-scip-") as directory:
            root = Path(directory)
            index_path = root / "index.scip"
            output_path = root / "index.json"
            index_path.write_bytes(payload)
            index_path.chmod(0o600)
            with output_path.open("wb") as output:
                try:
                    # The executable path and every argument are fixed by the release policy.
                    result = subprocess.run(  # noqa: S603  # nosec B603
                        [str(self._policy.binary), "print", "--json", str(index_path)],
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=self._policy.timeout_seconds,
                        cwd=root,
                        env={"NO_COLOR": "1", "PATH": "/usr/local/bin:/usr/bin:/bin"},
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise IndexingUnavailableError(_ERR_CLI) from error
            if result.returncode != 0:
                raise IndexingValidationError(_ERR_DOCUMENT)
            try:
                if output_path.stat().st_size > self._policy.max_json_bytes:
                    raise IndexingValidationError(_ERR_DOCUMENT)
                output_payload = output_path.read_bytes()
            except OSError as error:
                raise IndexingUnavailableError(_ERR_CLI) from error
        return normalize_scip_cli_json(output_payload, relative_path)


def normalize_scip_cli_json(payload: bytes, relative_path: str) -> bytes:
    """Select and strictly reduce one SCIP 0.9 Go-JSON document."""
    if not payload or len(payload) > _MAX_JSON_BYTES:
        raise IndexingValidationError(_ERR_DOCUMENT)
    try:
        value = json.loads(payload, object_pairs_hook=_unique_object)
        index = _object(value, _INDEX_FIELDS)
        documents = _list(index.get("documents"))
        selected = _document_for_path(documents, relative_path)
        _value_error_if(condition=selected is None)
        selected = cast("dict[str, object]", selected)
        encoding = _POSITION_ENCODINGS.get(_integer(selected.get("position_encoding")))
        _value_error_if(condition=encoding is None)
        encoding = cast("str", encoding)
        normalized = {
            "relative_path": _string(selected.get("relative_path")),
            "language": _string(selected.get("language")),
            "position_encoding": encoding,
            "occurrences": [_occurrence(item) for item in _list(selected.get("occurrences"))],
            "symbols": [_symbol(item) for item in _list(selected.get("symbols"))],
        }
        return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise IndexingValidationError(_ERR_DOCUMENT) from error


def _occurrence(value: object) -> dict[str, object]:
    item = _object(value, _OCCURRENCE_FIELDS)
    compact_range = _list(item.get("range"))
    return {
        "range": [_integer(coordinate) for coordinate in compact_range],
        "symbol": _string(item.get("symbol")),
        "symbol_roles": _integer(item.get("symbol_roles", 0)),
    }


def _document_for_path(documents: list[object], relative_path: str) -> dict[str, object] | None:
    for value in documents:
        document = _object(value, _DOCUMENT_FIELDS)
        if document.get("relative_path") == relative_path:
            return document
    return None


def _symbol(value: object) -> dict[str, object]:
    item = _object(value, _SYMBOL_FIELDS)
    kind = _KINDS.get(_integer(item.get("kind", 0)), "UnspecifiedKind")
    display_name = item.get("display_name")
    return {
        "symbol": _string(item.get("symbol")),
        "display_name": None if display_name in {None, ""} else _string(display_name),
        "kind": kind,
        "relationships": [
            _relationship(relationship) for relationship in _list(item.get("relationships", []))
        ],
    }


def _relationship(value: object) -> dict[str, object]:
    item = _object(value, _RELATIONSHIP_FIELDS)
    return {
        "symbol": _string(item.get("symbol")),
        "is_reference": _boolean(item.get("is_reference", False)),
        "is_implementation": _boolean(item.get("is_implementation", False)),
        "is_type_definition": _boolean(item.get("is_type_definition", False)),
        "is_definition": _boolean(item.get("is_definition", False)),
    }


def _object(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(_ERR_DOCUMENT)
    result = cast("dict[object, object]", value)
    if any(not isinstance(key, str) or key not in fields for key in result):
        raise ValueError(_ERR_DOCUMENT)
    return cast("dict[str, object]", result)


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(_ERR_DOCUMENT)
    return cast("list[object]", value)


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(_ERR_DOCUMENT)
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(_ERR_DOCUMENT)
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError(_ERR_DOCUMENT)
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_ERR_DOCUMENT)
        result[key] = value
    return result


def _value_error_if(*, condition: bool) -> None:
    if condition:
        raise ValueError(_ERR_DOCUMENT)
