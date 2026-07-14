"""Fail-closed validation for the immutable default-model source lock."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn, cast

type JSONValue = None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]
type JSONObject = dict[str, JSONValue]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ROLES: Final = ("embedding", "reranking", "extraction")
_KINDS: Final = {
    "embedding": "direct-gguf",
    "reranking": "llama-cpp-conversion",
    "extraction": "direct-gguf",
}
_EXPECTED_OUTPUTS: Final = {
    "embedding": "models/embedding/model.gguf",
    "reranking": "models/reranking/model.gguf",
    "extraction": "models/extraction/model.gguf",
}


class ModelLockError(ValueError):
    """The model source lock is malformed, ambiguous, or mutable."""


def _invalid(message: str) -> NoReturn:
    raise ModelLockError(message)


def _object(value: JSONValue, name: str) -> JSONObject:
    if not isinstance(value, dict):
        _invalid(f"{name} must be an object")
    return value


def _string(value: JSONValue, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _invalid(f"{name} must be a non-empty normalized string")
    return value


def _closed(document: JSONObject, expected: set[str], name: str) -> None:
    if set(document) != expected:
        _invalid(f"{name} fields are not the closed v1 contract")


def _relative_file(value: JSONValue, name: str) -> str:
    path = _string(value, name)
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts or "." in parsed.parts or "\\" in path:
        _invalid(f"{name} must be a canonical relative POSIX path")
    return path


def _validate_file(value: JSONValue, seen: set[str], prefix: str) -> None:
    document = _object(value, prefix)
    _closed(document, {"path", "sha256", "size"}, prefix)
    path = _relative_file(document["path"], f"{prefix}.path")
    if path in seen:
        _invalid(f"{prefix}.path is duplicated")
    seen.add(path)
    digest = _string(document["sha256"], f"{prefix}.sha256")
    if _SHA256.fullmatch(digest) is None:
        _invalid(f"{prefix}.sha256 is not SHA-256")
    size = document["size"]
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 16 * 1024**3:
        _invalid(f"{prefix}.size is outside the release bound")


def _validate_assembly(value: JSONValue, role: str) -> None:
    document = _object(value, f"{role}.assembly")
    kind = _KINDS[role]
    output = _EXPECTED_OUTPUTS[role]
    if kind == "direct-gguf":
        _closed(
            document,
            {"kind", "input", "output", "output_sha256", "output_size"},
            f"{role}.assembly",
        )
        input_path = _relative_file(document["input"], f"{role}.assembly.input")
        if not input_path.endswith(".gguf"):
            _invalid(f"{role}.assembly.input must be GGUF")
    else:
        _closed(
            document,
            {"kind", "arguments", "output", "output_sha256", "output_size"},
            f"{role}.assembly",
        )
        arguments = document["arguments"]
        expected = [
            "convert_hf_to_gguf.py",
            "--outtype",
            "q8_0",
            "--outfile",
            output,
            "source/reranking",
        ]
        if arguments != expected:
            _invalid("reranking conversion arguments are not the reviewed command")
    if document["kind"] != kind or document["output"] != output:
        _invalid(f"{role}.assembly does not match the closed runtime layout")
    output_digest = _string(document["output_sha256"], f"{role}.assembly.output_sha256")
    output_size = document["output_size"]
    if (
        _SHA256.fullmatch(output_digest) is None
        or not isinstance(output_size, int)
        or isinstance(output_size, bool)
    ):
        _invalid(f"{role}.assembly output binding is invalid")
    if not 1 <= output_size <= 16 * 1024**3:
        _invalid(f"{role}.assembly output size is outside the release bound")


def _validate_llama_cpp(value: JSONValue) -> None:
    llama_cpp = _object(value, "llama_cpp")
    _closed(
        llama_cpp,
        {"repository", "revision", "release", "server_container", "converter_container"},
        "llama_cpp",
    )
    if llama_cpp["repository"] != "https://github.com/ggml-org/llama.cpp.git":
        _invalid("llama.cpp source authority is invalid")
    revision = _string(llama_cpp["revision"], "llama_cpp.revision")
    server = _string(llama_cpp["server_container"], "llama_cpp.server_container")
    converter = _string(llama_cpp["converter_container"], "llama_cpp.converter_container")
    if (
        _REVISION.fullmatch(revision) is None
        or "@sha256:" not in server
        or "@sha256:" not in converter
    ):
        _invalid("llama.cpp revision or container is mutable")


def _validate_model(value: JSONValue, index: int) -> str:
    model = _object(value, f"models[{index}]")
    _closed(model, {"role", "model_id", "license", "source", "assembly"}, f"models[{index}]")
    role = _string(model["role"], f"models[{index}].role")
    if role not in _ROLES:
        _invalid("model role is unsupported")
    _string(model["model_id"], f"{role}.model_id")
    if model["license"] != "Apache-2.0":
        _invalid(f"{role}.license is not approved")
    source = _object(model["source"], f"{role}.source")
    _closed(source, {"repository", "revision", "files"}, f"{role}.source")
    repository = _string(source["repository"], f"{role}.source.repository")
    source_revision = _string(source["revision"], f"{role}.source.revision")
    if not repository.startswith("Qwen/") or _REVISION.fullmatch(source_revision) is None:
        _invalid(f"{role}.source is not an immutable official Qwen revision")
    files = source["files"]
    if not isinstance(files, list) or not files:
        _invalid(f"{role}.source.files must not be empty")
    seen: set[str] = set()
    for file_index, file_value in enumerate(files):
        _validate_file(file_value, seen, f"{role}.source.files[{file_index}]")
    _validate_assembly(model["assembly"], role)
    return role


def validate_model_source_lock(raw: bytes) -> JSONObject:
    """Decode and validate one exact model-source lock document."""
    try:
        decoded = cast("JSONValue", json.loads(raw, object_pairs_hook=_reject_duplicate_pairs))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        message = "model source lock is not valid JSON"
        raise ModelLockError(message) from error
    document = _object(decoded, "lock")
    _closed(document, {"schema_version", "llama_cpp", "models"}, "lock")
    if document["schema_version"] != 1:
        _invalid("model source lock schema is unsupported")
    _validate_llama_cpp(document["llama_cpp"])
    models = document["models"]
    if not isinstance(models, list) or len(models) != len(_ROLES):
        _invalid("model source lock must contain exactly three roles")
    observed = [_validate_model(value, index) for index, value in enumerate(models)]
    if observed != list(_ROLES):
        _invalid("model roles are missing, duplicated, or out of canonical order")
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, JSONValue]]) -> JSONObject:
    result: JSONObject = {}
    for key, value in pairs:
        if key in result:
            _invalid("model source lock contains a duplicate JSON key")
        result[key] = value
    return result


def _fail(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> None:
    """Validate the repository model lock from a CLI or release job."""
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    arguments = parser.parse_args()
    try:
        validate_model_source_lock(arguments.lock.read_bytes())
    except (OSError, ModelLockError) as error:
        _fail(str(error))


if __name__ == "__main__":
    main()
