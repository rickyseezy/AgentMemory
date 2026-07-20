"""ING-006 checked compatibility-manifest verifier tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools.verify_event_schema_compatibility import (
    CompatibilityManifestError,
    validate_compatibility_manifest,
)


def manifest(**changes: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "contracts": [
            {
                "family": "agent_event",
                "major": 1,
                "current_version": 3,
                "producer_versions": [1, 2, 3],
                "consumer_versions": [3],
                "upcast_edges": [[1, 2], [2, 3]],
            }
        ],
    }
    document.update(changes)
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def test_every_advertised_producer_reaches_the_current_consumer_by_adjacent_steps() -> None:
    contracts = validate_compatibility_manifest(manifest())
    assert contracts[0].producer_versions == (1, 2, 3)
    assert contracts[0].upcast_edges == ((1, 2), (2, 3))


@pytest.mark.parametrize(
    "contracts",
    [
        [
            {
                "family": "agent_event",
                "major": 1,
                "current_version": 3,
                "producer_versions": [1, 3],
                "consumer_versions": [3],
                "upcast_edges": [[2, 3]],
            }
        ],
        [
            {
                "family": "agent_event",
                "major": 1,
                "current_version": 3,
                "producer_versions": [1],
                "consumer_versions": [2],
                "upcast_edges": [[1, 3]],
            }
        ],
    ],
)
def test_missing_consumer_chain_and_leap_are_rejected(contracts: object) -> None:
    with pytest.raises(CompatibilityManifestError):
        validate_compatibility_manifest(manifest(contracts=contracts))


def test_checked_in_manifest_is_valid_and_canonical() -> None:
    root = Path(__file__).parents[2]
    contracts = validate_compatibility_manifest(
        (root / "deploy" / "event-schema-compatibility.v1.json").read_bytes()
    )
    assert [(item.family, item.major) for item in contracts] == [("agent_event", 1)]
