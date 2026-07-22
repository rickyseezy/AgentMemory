"""PF-003 strict replay-resistant live adapter capability probe."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from agentmemory.extensions.domain.errors import AdapterProbeError, AdapterValidationError
from agentmemory.extensions.domain.models import AdapterCapability, AdapterProbeEvidence

if TYPE_CHECKING:
    from agentmemory.extensions.domain.models import AdapterManifest, ProtocolVersion
    from agentmemory.extensions.domain.ports import (
        AdapterChallengeGenerator,
        AdapterClock,
        AdapterProbeTransport,
    )

_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_MIN_TIMEOUT_MS = 100
_MAX_TIMEOUT_MS = 30_000
_MIN_RESPONSE_BYTES = 128
_MAX_RESPONSE_BYTES = 1024 * 1024
_RESPONSE_FIELDS = frozenset(
    {
        "capabilities",
        "challenge",
        "manifest_digest",
        "package_digest",
        "protocol",
        "schema_version",
        "status",
    }
)
_ERR_POLICY = "adapter probe resource policy is invalid"
_ERR_CHALLENGE = "adapter probe challenge is invalid"
_ERR_TRANSPORT = "adapter probe transport failed"
_ERR_RESPONSE = "adapter probe response is invalid"


@dataclass(frozen=True, slots=True)
class StrictAdapterCapabilityProbe:
    """Challenge one isolated runtime and verify every returned identity claim."""

    transport: AdapterProbeTransport
    challenges: AdapterChallengeGenerator
    clock: AdapterClock
    timeout_milliseconds: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        """Bound runtime and response work before any adapter invocation."""
        if (
            not _MIN_TIMEOUT_MS <= self.timeout_milliseconds <= _MAX_TIMEOUT_MS
            or not _MIN_RESPONSE_BYTES <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise AdapterValidationError(_ERR_POLICY)

    async def probe(
        self,
        manifest: AdapterManifest,
        negotiated_protocol: ProtocolVersion,
    ) -> AdapterProbeEvidence:
        """Return evidence only for an exact challenge/package/protocol/capability match."""
        challenge = self.challenges.new()
        if _CHALLENGE.fullmatch(challenge) is None:
            raise AdapterProbeError(_ERR_CHALLENGE)
        request = _canonical_bytes(
            {
                "capabilities": [item.value for item in manifest.capabilities],
                "challenge": challenge,
                "kind": manifest.kind.value,
                "manifest_digest": manifest.manifest_digest,
                "package_digest": manifest.package_digest,
                "protocol": str(negotiated_protocol),
                "schema_version": 1,
            }
        )
        try:
            response = await self.transport.exchange(
                manifest,
                request,
                self.timeout_milliseconds,
                self.max_response_bytes,
            )
        except Exception as error:
            raise AdapterProbeError(_ERR_TRANSPORT) from error
        if len(response.body) > self.max_response_bytes:
            raise AdapterProbeError(_ERR_RESPONSE)
        document = _strict_object(response.body)
        expected = {
            "capabilities": [item.value for item in manifest.capabilities],
            "challenge": challenge,
            "manifest_digest": manifest.manifest_digest,
            "package_digest": manifest.package_digest,
            "protocol": str(negotiated_protocol),
            "schema_version": 1,
            "status": "passed",
        }
        if document != expected or response.runtime_digest != manifest.package_digest:
            raise AdapterProbeError(_ERR_RESPONSE)
        return AdapterProbeEvidence.create(
            manifest=manifest,
            negotiated_protocol=negotiated_protocol,
            observed_capabilities=tuple(
                AdapterCapability(value) for value in cast("list[str]", document["capabilities"])
            ),
            runtime_digest=response.runtime_digest,
            probed_at=self.clock.now(),
        )


def _strict_object(value: bytes) -> dict[str, object]:
    if not value:
        raise AdapterProbeError(_ERR_RESPONSE)
    try:
        decoded = json.loads(value, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, AdapterProbeError) as error:
        raise AdapterProbeError(_ERR_RESPONSE) from error
    if not isinstance(decoded, dict):
        raise AdapterProbeError(_ERR_RESPONSE)
    mapping = cast("dict[str, object]", decoded)
    if frozenset(mapping) != _RESPONSE_FIELDS:
        raise AdapterProbeError(_ERR_RESPONSE)
    return mapping


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterProbeError(_ERR_RESPONSE)
        result[key] = value
    return result


def _canonical_bytes(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
