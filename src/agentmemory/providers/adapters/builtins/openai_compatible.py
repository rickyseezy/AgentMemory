"""Strict OpenAI-compatible embedding adapter with no permissive response coercion."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.providers.adapters.builtins.base import CertifiedRemoteAdapter, certified_manifest
from agentmemory.providers.adapters.builtins.openai import OpenAIProtocol
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderLimits,
    ProviderOperation,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.profile_ports import ProviderGatewayTransport

OPENAI_COMPATIBLE_MANIFEST = certified_manifest(
    adapter_id="openai-compatible",
    vendor="openai-compatible",
    operations=(ProviderOperation.EMBEDDING,),
    purposes=tuple(sorted(CanonicalPurpose, key=str)),
    limits=ProviderLimits(100, 8 * 1024 * 1024, 32_768, 1_000_000, 120_000),
)


class OpenAICompatibleProviderAdapter(CertifiedRemoteAdapter):
    """Use the exact OpenAI embedding wire contract against an approved endpoint policy."""

    def __init__(self, transport: ProviderGatewayTransport) -> None:
        """Bind the strict compatible protocol to one approved gateway route."""
        super().__init__(
            OPENAI_COMPATIBLE_MANIFEST,
            transport,
            OpenAIProtocol(),
        )
