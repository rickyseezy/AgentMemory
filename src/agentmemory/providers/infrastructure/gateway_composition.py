"""Production composition root for the independently isolated egress gateway."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from agentmemory.providers.adapters.credential_vault import (
    EncryptedProviderCredentialVault,
)
from agentmemory.providers.adapters.gateway_audit import AppendOnlyProviderEgressTelemetry
from agentmemory.providers.adapters.gateway_http_api import create_provider_gateway_app
from agentmemory.providers.adapters.gateway_network import (
    NetworkAddressPolicy,
    PinnedHttpsProviderTransport,
    StdlibPinnedHttpsExchange,
    SystemDnsResolver,
)
from agentmemory.providers.adapters.gateway_usage import InMemoryGatewayUsageAuthority
from agentmemory.providers.adapters.permit_codec import ProtectedFileProviderPermitCodec
from agentmemory.providers.application.gateway import ProviderGatewayOperationHandler

if TYPE_CHECKING:
    from fastapi import FastAPI

    from agentmemory.providers.infrastructure.gateway_configuration import (
        ProviderGatewaySettings,
    )


def create_gateway_app(settings: ProviderGatewaySettings) -> FastAPI:
    """Compose the only production path able to acquire an Internet socket."""
    now_microseconds = _now_microseconds
    handler = ProviderGatewayOperationHandler(
        permits=ProtectedFileProviderPermitCodec(settings.permit_hmac_key_file),
        usage=InMemoryGatewayUsageAuthority(),
        credentials=EncryptedProviderCredentialVault(
            settings.credential_vault_file,
            settings.credential_vault_key_file,
            settings.credential_vault_hmac_key_file,
        ),
        transport=PinnedHttpsProviderTransport(
            SystemDnsResolver(),
            StdlibPinnedHttpsExchange(),
            NetworkAddressPolicy.public_only(),
            now_microseconds=now_microseconds,
        ),
        telemetry=AppendOnlyProviderEgressTelemetry(settings.audit_file),
        now_microseconds=now_microseconds,
    )
    return create_provider_gateway_app(handler, settings.client_capability_file)


def _now_microseconds() -> int:
    return time.time_ns() // 1000
