"""Verify every advertised event producer reaches every current consumer safely."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Never, cast

_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MAX_BYTES = 256 * 1024
_EDGE_SIZE = 2
_ERR_INVALID_JSON = "compatibility manifest is not valid JSON"


class CompatibilityManifestError(ValueError):
    """Reject incomplete, ambiguous, or unsafe compatibility advertisements."""


@dataclass(frozen=True, slots=True, order=True)
class AdvertisedContract:
    """One family/major compatibility line verified by release CI."""

    family: str
    major: int
    current_version: int
    producer_versions: tuple[int, ...]
    consumer_versions: tuple[int, ...]
    upcast_edges: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        """Require canonical versions and adjacent complete producer chains."""
        if _TOKEN.fullmatch(self.family) is None:
            _invalid("contract family is invalid")
        if self.major < 1 or self.current_version < 1:
            _invalid("contract version is invalid")
        _canonical_versions(self.producer_versions, "producer versions")
        _canonical_versions(self.consumer_versions, "consumer versions")
        if self.current_version not in self.consumer_versions:
            _invalid("current version has no advertised consumer")
        if tuple(sorted(set(self.upcast_edges))) != self.upcast_edges:
            _invalid("upcast edges are not canonical")
        for source, target in self.upcast_edges:
            if source < 1 or target != source + 1:
                _invalid("upcast edge is not adjacent")
        edges = dict(self.upcast_edges)
        for producer in self.producer_versions:
            current = producer
            visited: set[int] = set()
            while current != self.current_version:
                if current > self.current_version or current in visited or current not in edges:
                    _invalid("advertised producer has no complete upcast chain")
                visited.add(current)
                current = edges[current]


def validate_compatibility_manifest(raw: bytes) -> tuple[AdvertisedContract, ...]:
    """Decode a bounded strict manifest and prove all advertised compatibility paths."""
    if not raw or len(raw) > _MAX_BYTES:
        _invalid("compatibility manifest size is invalid")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompatibilityManifestError(_ERR_INVALID_JSON) from error
    if not isinstance(document, dict):
        _invalid("compatibility manifest root must be an object")
    root = cast("dict[object, object]", document)
    if set(root) != {"schema_version", "contracts"} or root.get("schema_version") != 1:
        _invalid("compatibility manifest root is unsupported")
    raw_contracts = root.get("contracts")
    if not isinstance(raw_contracts, list) or not raw_contracts:
        _invalid("compatibility contracts are required")
    contracts = tuple(_contract(item) for item in cast("list[object]", raw_contracts))
    identities = tuple((item.family, item.major) for item in contracts)
    if tuple(sorted(set(identities))) != identities:
        _invalid("compatibility contracts are not canonical")
    return contracts


def main(argv: list[str] | None = None) -> int:
    """Validate one checked-in compatibility contract for CI and release tooling."""
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args(argv)
    path = cast("Path", arguments.manifest)
    try:
        validate_compatibility_manifest(path.read_bytes())
    except (OSError, CompatibilityManifestError) as error:
        sys.stderr.write(f"event schema compatibility error: {error}\n")
        return 1
    return 0


def _contract(value: object) -> AdvertisedContract:
    if not isinstance(value, dict):
        _invalid("compatibility contract must be an object")
    item = cast("dict[object, object]", value)
    expected = {
        "family",
        "major",
        "current_version",
        "producer_versions",
        "consumer_versions",
        "upcast_edges",
    }
    if set(item) != expected:
        _invalid("compatibility contract fields are not closed")
    family = item.get("family")
    major = item.get("major")
    current = item.get("current_version")
    if not isinstance(family, str):
        _invalid("compatibility family is required")
    if not _integer(major) or not _integer(current):
        _invalid("compatibility versions must be integers")
    producers = _versions(item.get("producer_versions"), "producer versions")
    consumers = _versions(item.get("consumer_versions"), "consumer versions")
    raw_edges = item.get("upcast_edges")
    if not isinstance(raw_edges, list):
        _invalid("upcast edges must be an array")
    edges: list[tuple[int, int]] = []
    for raw_edge_value in cast("list[object]", raw_edges):
        if not isinstance(raw_edge_value, list):
            _invalid("upcast edge is invalid")
        raw_edge = cast("list[object]", raw_edge_value)
        if len(raw_edge) != _EDGE_SIZE:
            _invalid("upcast edge is invalid")
        if not _integer(raw_edge[0]) or not _integer(raw_edge[1]):
            _invalid("upcast edge is invalid")
        edges.append((cast("int", raw_edge[0]), cast("int", raw_edge[1])))
    return AdvertisedContract(
        family,
        cast("int", major),
        cast("int", current),
        producers,
        consumers,
        tuple(edges),
    )


def _versions(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        _invalid(f"{label} must be an integer array")
    raw = cast("list[object]", value)
    if not all(_integer(item) for item in raw):
        _invalid(f"{label} must be an integer array")
    return tuple(cast("list[int]", raw))


def _canonical_versions(values: tuple[int, ...], label: str) -> None:
    if not values or values[0] < 1 or tuple(sorted(set(values))) != values:
        _invalid(f"{label} are not canonical")


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _invalid("compatibility manifest contains a duplicate key")
        result[key] = value
    return result


def _invalid(message: str) -> Never:
    raise CompatibilityManifestError(message)


if __name__ == "__main__":
    raise SystemExit(main())
