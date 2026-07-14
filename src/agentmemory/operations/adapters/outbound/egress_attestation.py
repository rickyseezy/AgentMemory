"""Authenticate the launcher's default-offline runtime network inspection."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, cast

from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_document,
    read_protected_file,
    zero_secret,
)
from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.value_objects import Sha256Digest

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.domain.readiness import ReadinessBinding
    from agentmemory.shared.clock import Clock

_FIELDS: Final = {
    "schema_version",
    "operation_id",
    "plan_digest",
    "release_id",
    "generation_id",
    "internal_network_id",
    "core_network_ids",
    "external_network_ids",
    "gateway_enabled",
    "inspected_at",
    "hmac_sha256",
}
_MAX_ATTESTATION_BYTES: Final = 16_384


class AuthenticatedEgressAttestationCheck:
    """Verify exact inventory evidence without granting Core Docker access."""

    def __init__(
        self,
        attestation_file: Path,
        attestation_hmac_key_file: Path,
        clock: Clock,
    ) -> None:
        """Store protected file references only."""
        self._attestation_file = attestation_file
        self._attestation_hmac_key_file = attestation_hmac_key_file
        self._clock = clock

    async def verify_default_denied(self, binding: ReadinessBinding) -> str:
        """Require an authentic, fresh, internal-network-only runtime observation."""
        network_id = await asyncio.to_thread(self._verify_sync, binding, self._clock.now())
        return f"internal_network:{network_id}:external_count:0:gateway:false"

    def _verify_sync(self, binding: ReadinessBinding, now: datetime) -> str:
        payload = read_protected_document(self._attestation_file, _MAX_ATTESTATION_BYTES)
        try:
            decoded: object = json.loads(payload)
        except (json.JSONDecodeError, UnicodeError) as error:
            msg = "egress attestation is invalid"
            raise DomainValidationError(msg) from error
        if not isinstance(decoded, dict):
            msg = "egress attestation schema is invalid"
            raise DomainValidationError(msg)
        raw = cast("dict[str, object]", decoded)
        if set(raw) != _FIELDS or raw.get("schema_version") != 1:
            msg = "egress attestation schema is invalid"
            raise DomainValidationError(msg)
        signature = raw.pop("hmac_sha256", None)
        canonical = json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()
        key = read_protected_file(self._attestation_hmac_key_file, frozenset({32}))
        try:
            expected = hmac.digest(key, canonical, hashlib.sha256).hex()
        finally:
            zero_secret(key)
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            msg = "egress attestation authentication failed"
            raise DomainValidationError(msg)
        if (
            raw.get("operation_id") != binding.operation_id.value
            or raw.get("plan_digest") != binding.plan_digest.value
            or raw.get("release_id") != binding.release_id.value
            or raw.get("generation_id") != binding.generation_id.value
        ):
            msg = "egress attestation binding is invalid"
            raise DomainValidationError(msg)
        network_id = raw.get("internal_network_id")
        core_networks = raw.get("core_network_ids")
        if (
            not isinstance(network_id, str)
            or Sha256Digest(network_id).value != network_id
            or core_networks != [network_id]
            or raw.get("external_network_ids") != []
            or raw.get("gateway_enabled") is not False
        ):
            msg = "default egress network policy was not denied"
            raise DomainValidationError(msg)
        inspected_at = _parse_time(raw.get("inspected_at"))
        now = now.astimezone(UTC)
        if inspected_at > now + timedelta(seconds=5) or now - inspected_at > timedelta(minutes=5):
            msg = "egress attestation is stale"
            raise DomainValidationError(msg)
        return network_id


def _parse_time(raw: object) -> datetime:
    if not isinstance(raw, str) or not raw.endswith("Z"):
        msg = "egress attestation time is invalid"
        raise DomainValidationError(msg)
    try:
        result = datetime.fromisoformat(f"{raw[:-1]}+00:00")
    except ValueError as error:
        msg = "egress attestation time is invalid"
        raise DomainValidationError(msg) from error
    return result.astimezone(UTC)
