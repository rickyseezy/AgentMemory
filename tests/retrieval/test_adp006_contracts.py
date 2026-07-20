"""ADP-006 checked-in continuity payload and conformance contract tests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from agentmemory.retrieval.domain.continuity import ContinuityKind

_ROOT = Path(__file__).parents[2]
_CONTRACT = _ROOT / "contracts" / "agent-events" / "continuity-items.v1.schema.json"
_CORPUS = _ROOT / "conformance" / "agent-hosts" / "cross-host-continuity.v1.json"


def _document(path: Path) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))


def test_payload_contract_is_versioned_closed_and_matches_domain_kinds() -> None:
    schema = _document(_CONTRACT)
    continuity = schema["properties"]["continuity"]
    item = schema["$defs"]["item"]
    assert schema["$id"] == "urn:agentmemory:schema:continuity-items:v1"
    assert continuity["additionalProperties"] is False
    assert item["additionalProperties"] is False
    assert set(item["properties"]["kind"]["enum"]) == {kind.value for kind in ContinuityKind}
    assert continuity["properties"]["items"]["maxItems"] == 32
    assert item["properties"]["content"]["maxLength"] == 8_192


def test_cross_host_corpus_conforms_to_checked_in_payload_fragment() -> None:
    schema = _document(_CONTRACT)
    corpus = _document(_CORPUS)
    item_schema = schema["$defs"]["item"]["properties"]
    identifier = re.compile(item_schema["semantic_id"]["pattern"])
    allowed_kinds = set(item_schema["kind"]["enum"])
    assert (
        1
        <= len(corpus["items"])
        <= schema["properties"]["continuity"]["properties"]["items"]["maxItems"]
    )
    for item in corpus["items"]:
        assert set(item) == {"semantic_id", "kind", "content", "event_family"}
        assert identifier.fullmatch(item["semantic_id"]) is not None
        assert item["kind"] in allowed_kinds
        assert 1 <= len(item["content"]) <= item_schema["content"]["maxLength"]
