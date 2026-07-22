"""Dependency-free public types implemented by external AgentMemory adapters."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, Self, cast

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_PROTOCOL = re.compile(r"^[1-9][0-9]{0,4}\.(?:0|[1-9][0-9]{0,4})$")


class AdapterKind(StrEnum):
    """Public runtime kind."""

    AGENT = "agent"
    PROVIDER = "provider"


class AdapterCapability(StrEnum):
    """Public protocol-v1 capability names."""

    AGENT_EVENT_CAPTURE = "agent.event.capture"
    AGENT_SESSION_RESUME = "agent.session.resume"
    AGENT_EXPLICIT_CHECKPOINT = "agent.checkpoint.explicit"
    PROVIDER_EMBED = "provider.embed"
    PROVIDER_RERANK = "provider.rerank"
    PROVIDER_EXTRACT = "provider.extract"


class AdapterPermission(StrEnum):
    """Public least-authority permission names."""

    CANONICAL_EVENT_WRITE = "canonical_event.write"
    WORKSPACE_METADATA_READ = "workspace.metadata.read"
    TRANSCRIPT_READ = "transcript.read"
    PROVIDER_EXECUTE = "provider.execute"
    PROVIDER_GATEWAY = "provider.gateway"


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """Replay-resistant live conformance request from AgentMemory Core."""

    schema_version: int
    challenge: str
    manifest_digest: str
    package_digest: str
    protocol: str
    kind: AdapterKind
    capabilities: tuple[AdapterCapability, ...]

    @classmethod
    def from_json(cls, value: bytes) -> Self:
        """Decode one strict object with no duplicate or unknown fields."""
        document = _strict_object(value)
        expected = {
            "capabilities",
            "challenge",
            "kind",
            "manifest_digest",
            "package_digest",
            "protocol",
            "schema_version",
        }
        if set(document) != expected:
            message = "probe request fields are invalid"
            raise ValueError(message)
        request = cls(
            schema_version=_integer(document, "schema_version"),
            challenge=_string(document, "challenge"),
            manifest_digest=_string(document, "manifest_digest"),
            package_digest=_string(document, "package_digest"),
            protocol=_string(document, "protocol"),
            kind=AdapterKind(_string(document, "kind")),
            capabilities=tuple(
                AdapterCapability(item) for item in _string_array(document, "capabilities")
            ),
        )
        request.validate()
        return request

    def validate(self) -> None:
        """Validate exact v1 identities and a canonical non-empty capability set."""
        canonical = tuple(sorted(set(self.capabilities), key=str))
        if (
            self.schema_version != 1
            or _CHALLENGE.fullmatch(self.challenge) is None
            or _DIGEST.fullmatch(self.manifest_digest) is None
            or _DIGEST.fullmatch(self.package_digest) is None
            or _PROTOCOL.fullmatch(self.protocol) is None
            or not self.capabilities
            or self.capabilities != canonical
        ):
            message = "probe request is invalid"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    """Exact successful live conformance response."""

    request: ProbeRequest

    def to_json(self) -> bytes:
        """Echo every security identity and declared capability canonically."""
        return canonical_json(
            {
                "capabilities": [item.value for item in self.request.capabilities],
                "challenge": self.request.challenge,
                "manifest_digest": self.request.manifest_digest,
                "package_digest": self.request.package_digest,
                "protocol": self.request.protocol,
                "schema_version": 1,
                "status": "passed",
            }
        )


class AgentAdapter(Protocol):
    """Liskov-compatible public agent adapter boundary."""

    async def capture(self, canonical_event: bytes) -> bytes:
        """Return a content-free durable acknowledgement for one canonical event."""
        ...


class ProviderAdapter(Protocol):
    """Liskov-compatible public provider adapter boundary."""

    async def invoke(self, operation: str, request: bytes) -> bytes:
        """Execute one declared provider operation and return its bounded response."""
        ...


def canonical_json(document: object) -> bytes:
    """Encode contract JSON deterministically without NaN or non-ASCII ambiguity."""
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _strict_object(value: bytes) -> dict[str, object]:
    decoded = json.loads(value, object_pairs_hook=_unique_object)
    if not isinstance(decoded, dict):
        message = "probe request must be an object"
        raise TypeError(message)
    return cast("dict[str, object]", decoded)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "probe request contains a duplicate field"
            raise ValueError(message)
        result[key] = value
    return result


def _string(document: dict[str, object], field: str) -> str:
    value = document[field]
    if not isinstance(value, str):
        message = f"{field} must be a string"
        raise TypeError(message)
    return value


def _integer(document: dict[str, object], field: str) -> int:
    value = document[field]
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{field} must be an integer"
        raise TypeError(message)
    return value


def _string_array(document: dict[str, object], field: str) -> tuple[str, ...]:
    value = document[field]
    if not isinstance(value, list):
        message = f"{field} must be an array"
        raise TypeError(message)
    result: list[str] = []
    for item in cast("list[object]", value):
        if not isinstance(item, str):
            message = f"{field} items must be strings"
            raise TypeError(message)
        result.append(item)
    return tuple(result)
