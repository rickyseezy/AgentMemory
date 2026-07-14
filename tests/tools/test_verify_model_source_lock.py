from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import cast

import pytest
from tools.verify_model_source_lock import (
    JSONObject,
    ModelLockError,
    validate_model_source_lock,
)

_ROOT = Path(__file__).parents[2]
_LOCK = _ROOT / "deploy/model-source-lock.v1.json"


def test_pf001_default_model_sources_are_exact_official_immutable_artifacts() -> None:
    document = validate_model_source_lock(_LOCK.read_bytes())
    models = cast("list[JSONObject]", document["models"])

    assert [model["role"] for model in models] == [
        "embedding",
        "reranking",
        "extraction",
    ]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("schema", "schema"),
        ("missing-role", "three roles"),
        ("mutable-revision", "immutable"),
        ("bad-digest", "SHA-256"),
        ("zero-size", "release bound"),
        ("output-escape", "runtime layout"),
        ("command", "reviewed command"),
        ("license", "approved"),
    ],
)
def test_pf001_model_source_lock_rejects_drift(
    mutation: str,
    message: str,
) -> None:
    document = copy.deepcopy(validate_model_source_lock(_LOCK.read_bytes()))
    candidate = copy.deepcopy(document)
    _mutate(candidate, mutation)

    with pytest.raises(ModelLockError, match=message):
        validate_model_source_lock(json.dumps(candidate).encode())


def _mutate(document: JSONObject, mutation: str) -> None:
    models = cast("list[JSONObject]", document["models"])
    if mutation == "schema":
        document["schema_version"] = 2
    elif mutation == "missing-role":
        models.pop()
    elif mutation == "license":
        models[2]["license"] = "unknown"
    else:
        model_index = 1 if mutation == "command" else 0
        model = models[model_index]
        source = cast("JSONObject", model["source"])
        files = cast("list[JSONObject]", source["files"])
        assembly = cast("JSONObject", model["assembly"])
        if mutation == "mutable-revision":
            source["revision"] = "main"
        elif mutation == "bad-digest":
            files[0]["sha256"] = "0"
        elif mutation == "zero-size":
            files[0]["size"] = 0
        elif mutation == "output-escape":
            assembly["output"] = "../escape"
        elif mutation == "command":
            assembly["arguments"] = ["sh", "-c"]
        else:
            raise AssertionError(mutation)


def test_pf001_model_source_lock_rejects_duplicate_and_non_json_documents() -> None:
    with pytest.raises(ModelLockError, match="duplicate"):
        validate_model_source_lock(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(ModelLockError, match="valid JSON"):
        validate_model_source_lock(b"not-json")
