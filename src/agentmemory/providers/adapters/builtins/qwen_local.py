"""Certified Qwen local profile adapter over release-verified sidecars."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import ProviderAdapterError, ProviderErrorCode
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    ProviderLimits,
    ProviderManifest,
    ProviderOperation,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.profile_ports import LocalProviderProbe
    from agentmemory.providers.domain.profiles import ProviderProbeResult, ProviderProfile

QWEN_LOCAL_MANIFEST = ProviderManifest(
    adapter_id="qwen-local",
    implementation_version="1.0.0",
    implementation_digest=hashlib.sha256(
        b"agentmemory:qwen-local:1.0.0:provider-protocol-1.0"
    ).hexdigest(),
    protocol_version="1.0",
    execution_class=ProviderExecutionClass.LOCAL,
    operations=(ProviderOperation.EMBEDDING, ProviderOperation.RERANKING),
    purposes=tuple(sorted(CanonicalPurpose, key=str)),
    limits=ProviderLimits(32, 2 * 1024 * 1024, 32_768, 1_000_000, 120_000),
    revision_evidence=True,
    cancellation=True,
    vendor="qwen",
)


class QwenLocalProviderAdapter:
    """Apply remote-equivalent conformance to the default local model runtime."""

    def __init__(self, probe: LocalProviderProbe) -> None:
        """Bind the release-verified local sidecar probe."""
        self._probe = probe

    @property
    def manifest(self) -> ProviderManifest:
        """Return the immutable Qwen local manifest."""
        return QWEN_LOCAL_MANIFEST

    async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
        """Require the local sidecar to echo the complete requested capability."""
        self.manifest.validate_configuration(profile.configuration)
        result = await self._probe.probe(profile)
        configuration = profile.configuration
        if (
            result.adapter_id != self.manifest.adapter_id
            or result.model_id != configuration.model_id
            or result.operation is not configuration.operation
            or result.purposes != configuration.purposes
            or result.max_items < configuration.limits.max_items
            or not result.cancellation_verified
        ):
            raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE)
        return result
