"""IDX-001 pinned SCIP CLI JSON normalization and supply-chain tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentmemory.indexing.adapters.outbound.scip_cli import (
    ScipCliPolicy,
    normalize_scip_cli_json,
)
from agentmemory.indexing.adapters.outbound.scip_import import ScipJsonDecoder
from agentmemory.indexing.domain.errors import IndexingValidationError


def test_real_scip_go_json_shape_normalizes_to_strict_document() -> None:
    symbol = "scip-python python example 1.0 main/hello()."
    payload = json.dumps(
        {
            "metadata": {"version": 0},
            "documents": [
                {
                    "relative_path": "main.py",
                    "language": "python",
                    "position_encoding": 3,
                    "occurrences": [
                        {
                            "range": [0, 4, 9],
                            "symbol": symbol,
                            "symbol_roles": 1,
                            "syntax_kind": 17,
                        }
                    ],
                    "symbols": [
                        {
                            "symbol": symbol,
                            "display_name": "hello",
                            "kind": 17,
                            "documentation": ["docs"],
                            "relationships": [
                                {
                                    "symbol": "scip-python python base 1.0 Base#hello().",
                                    "is_implementation": True,
                                    "is_reference": True,
                                }
                            ],
                        }
                    ],
                }
            ],
            "external_symbols": [],
        }
    ).encode()
    normalized = normalize_scip_cli_json(payload, "main.py")
    document = ScipJsonDecoder.decode(normalized)
    assert document.position_encoding.value == "UTF32CodeUnitOffsetFromLineStart"
    assert document.symbols[0].kind == "Function"
    assert document.symbols[0].relationships[0].is_implementation


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"[]",
        b'{"documents":[],"documents":[]}',
        b'{"documents":[],"unknown":true}',
        b'{"documents":{}}',
        b'{"documents":["not-a-document"]}',
        b'{"documents":[{"relative_path":"other.py","language":"python",'
        b'"position_encoding":3,"occurrences":[],"symbols":[]}]}',
        b'{"documents":[{"relative_path":"main.py","position_encoding":3,'
        b'"occurrences":[],"symbols":[]}]}',
        b'{"documents":[{"relative_path":"main.py","language":"python",'
        b'"position_encoding":3,"occurrences":[{"range":[0,true,1],'
        b'"symbol":"local x"}],"symbols":[]}]}',
        b'{"documents":[{"relative_path":"main.py","language":"python",'
        b'"position_encoding":3,"occurrences":[],"symbols":[{"symbol":"local x",'
        b'"relationships":[{"symbol":"local y","is_reference":1}]}]}]}',
        b'{"documents":[{"relative_path":"main.py","language":"python",'
        b'"position_encoding":0,"occurrences":[],"symbols":[]}]}',
    ],
)
def test_scip_cli_normalization_rejects_duplicate_unknown_and_ambiguous_input(
    payload: bytes,
) -> None:
    with pytest.raises(IndexingValidationError):
        normalize_scip_cli_json(payload, "main.py")


def test_scip_cli_policy_refuses_path_search_and_unpinned_versions() -> None:
    with pytest.raises(IndexingValidationError):
        ScipCliPolicy(binary=Path("scip"))
    with pytest.raises(IndexingValidationError):
        ScipCliPolicy(version="latest")


def test_core_image_pins_both_scip_linux_architectures_by_release_digest() -> None:
    dockerfile = (Path(__file__).parents[2] / "deploy" / "docker" / "core.Dockerfile").read_text()
    assert "scip-linux-amd64.tar.gz" in dockerfile
    assert "fc2e7273e110be9f35924da1066000183791e8bfdb0391355de6eaaa070fec75" in dockerfile
    assert "scip-linux-arm64.tar.gz" in dockerfile
    assert "e97aaf597ab6a6b6fbb1bbc43993e6efb596284aaea9c3fa5b20d75186367c5e" in dockerfile
