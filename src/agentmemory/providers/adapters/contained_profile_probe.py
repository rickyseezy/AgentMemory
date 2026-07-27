"""Permit-bound remote profile probes through the isolated PRO-009 gateway."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.adapters.strict_json import canonical_bytes
from agentmemory.providers.domain.containment import ExecuteProviderEgress
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
    ProviderErrorCode,
    ProviderProfileDependencyError,
)
from agentmemory.providers.domain.profile_ports import ProviderGatewayResponse

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.providers.domain.containment_ports import (
        ProviderGatewayEnvelopeClient,
        ProviderPermitCodec,
    )
    from agentmemory.providers.domain.profile_ports import (
        ProviderGatewayRequest,
        ProviderProfileProbeEgressAuthority,
    )

_MAX_BODY_BYTES = 8 * 1024 * 1024
_MIN_TIMEOUT_MILLISECONDS = 100
_MAX_TIMEOUT_MILLISECONDS = 300_000
_ERR_INPUT = "provider gateway probe request is invalid"
_ERR_DENIED = "provider gateway probe request is denied"
_ERR_UNAVAILABLE = "provider gateway is unavailable"


@dataclass(frozen=True, slots=True)
class ContainedProviderProfileProbeTransport:
    """Authorize a fixed public-canary probe immediately before gateway dispatch."""

    authority: ProviderProfileProbeEgressAuthority
    permits: ProviderPermitCodec
    gateway: ProviderGatewayEnvelopeClient
    now_microseconds: Callable[[], int]

    async def execute(self, request: ProviderGatewayRequest) -> ProviderGatewayResponse:
        """Send no policy or credential reference across the process boundary."""
        _validate(request)
        try:
            permit = await self.authority.authorize_probe(
                request,
                self.now_microseconds(),
            )
            if (
                permit.wire_request_digest != hashlib.sha256(request.body).hexdigest()
                or permit.operation_id != request.operation_id
                or permit.profile_id != request.profile_id
                or permit.profile_version != request.profile_version
                or permit.operation_type != request.operation_type
                or permit.purpose != request.purpose
                or (
                    request.operation_id.startswith("profile-probe:")
                    and permit.profile_attestation_id != request.configuration_digest
                )
            ):
                _deny()
            response = await self.gateway.execute(
                ExecuteProviderEgress(
                    permit_token=self.permits.encode(permit),
                    path=request.path,
                    body=bytearray(request.body),
                )
            )
        except ProviderContainmentDeniedError as error:
            raise ProviderAdapterError(ProviderErrorCode.PRIVACY_DENIAL) from error
        except ProviderContainmentValidationError as error:
            raise ProviderAdapterError(ProviderErrorCode.INVALID_CONFIGURATION) from error
        except ProviderContainmentDependencyError as error:
            raise ProviderProfileDependencyError(_ERR_UNAVAILABLE) from error
        revision_fingerprint = hashlib.sha256(
            canonical_bytes(
                {
                    "adapter_id": request.adapter_id,
                    "configuration_digest": request.configuration_digest,
                    "destination_fingerprint": permit.destination.fingerprint,
                    "model_id": request.model_id,
                    "operation_type": request.operation_type,
                    "profile_id": request.profile_id,
                    "profile_version": request.profile_version,
                }
            )
        ).hexdigest()
        return ProviderGatewayResponse(
            status_code=response.status_code,
            body=response.body,
            model_revision=request.model_id,
            revision_fingerprint=revision_fingerprint,
            endpoint_fingerprint=permit.destination.fingerprint,
            cancellation_verified=True,
            retry_after_microseconds=response.retry_after_microseconds,
        )


def _validate(request: ProviderGatewayRequest) -> None:
    if (
        request.method != "POST"
        or not request.path.startswith("/")
        or any(value in request.path for value in ("..", "\\", "\x00", "?", "#", "//"))
        or not request.body
        or len(request.body) > _MAX_BODY_BYTES
        or not _MIN_TIMEOUT_MILLISECONDS
        <= request.timeout_milliseconds
        <= _MAX_TIMEOUT_MILLISECONDS
        or not 1 <= request.max_response_bytes <= _MAX_BODY_BYTES
    ):
        raise ProviderAdapterError(ProviderErrorCode.INVALID_CONFIGURATION)


def _deny() -> None:
    raise ProviderContainmentDeniedError(_ERR_DENIED)
