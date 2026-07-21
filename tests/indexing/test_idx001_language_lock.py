"""IDX-001 release language lock and query-pack drift tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from agentmemory.indexing.adapters.outbound.language_catalog import LANGUAGE_SPECS
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import (
    _tags,  # pyright: ignore[reportPrivateUsage]
)


def test_language_lock_matches_catalog_grammars_and_effective_queries() -> None:
    path = Path(__file__).parents[2] / "deploy" / "indexing-language-lock.v1.json"
    document = cast("dict[str, object]", json.loads(path.read_text()))
    assert document["schema_version"] == 1
    assert document["tree_sitter_version"] == "0.26.0"
    assert document["language_pack_version"] == "1.13.2"
    locked = {
        str(item["name"]): item for item in cast("list[dict[str, object]]", document["languages"])
    }
    assert set(locked) == {item.name for item in LANGUAGE_SPECS}
    for specification in LANGUAGE_SPECS:
        release = locked[specification.name]
        assert release["repository"] == specification.grammar_repository
        assert release["revision"] == specification.grammar_revision
        tags = _tags(specification.name)
        assert tags is not None
        assert release["query_sha256"] == hashlib.sha256(tags.encode()).hexdigest()
    assert cast("list[str]", locked["typescript"]["runtime_names"]) == [
        "typescript",
        "tsx",
    ]


def test_language_lock_covers_every_supported_release_platform() -> None:
    path = Path(__file__).parents[2] / "deploy" / "indexing-language-lock.v1.json"
    document = cast("dict[str, object]", json.loads(path.read_text()))
    bundles = cast("dict[str, str]", document["platform_bundles"])
    assert set(bundles) == {
        "linux-aarch64",
        "linux-x86_64",
        "macos-arm64",
        "macos-x86_64",
        "windows-aarch64",
        "windows-x86_64",
    }
    assert all(len(value) == 64 for value in bundles.values())
