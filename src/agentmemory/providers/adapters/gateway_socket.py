"""Core-side signed operation adapter for the isolated provider gateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.domain.containment import ExecuteProviderEgress
from agentmemory.providers.domain.errors import ProviderContainmentDeniedError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.providers.domain.containment import ProviderEgressPermit
    from agentmemory.providers.domain.containment_ports import (
        ProviderGatewayEnvelopeClient,
        ProviderPermitCodec,
        ProviderWireOperationCodec,
    )
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationOutcome,
        ProviderOperationRequest,
    )
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation

_ERR_DENIED = "provider egress is denied"


@dataclass(frozen=True, slots=True)
class SignedInternalProviderSocketGateway:
    """Prepare deterministically and invoke only the signed internal gateway."""

    permits: ProviderPermitCodec
    wire: ProviderWireOperationCodec
    client: ProviderGatewayEnvelopeClient

    async def execute(
        self,
        permit: ProviderEgressPermit,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        """Bind prepared bytes to the permit before crossing the process boundary."""
        prepared = self.wire.prepare(
            endpoint,
            operation,
            payloads,
            downstream_idempotency_key,
        )
        try:
            if prepared.digest != permit.wire_request_digest:
                raise ProviderContainmentDeniedError(_ERR_DENIED)
            response = await self.client.execute(
                ExecuteProviderEgress(
                    permit_token=self.permits.encode(permit),
                    path=prepared.path,
                    body=prepared.body,
                )
            )
            return self.wire.parse(endpoint, operation, response)
        finally:
            prepared.destroy()
