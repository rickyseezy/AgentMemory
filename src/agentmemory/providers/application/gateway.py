"""PRO-009 independent provider gateway execution use case."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.domain.containment import (
    ContentTaint,
    ProviderEgressDecisionFact,
    ProviderEgressHttpResponse,
    ProviderEgressRequest,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from agentmemory.providers.domain.containment import (
        ExecuteProviderEgress,
        ProviderEgressPermit,
        ProviderGatewayCredential,
    )
    from agentmemory.providers.domain.containment_ports import (
        ProviderCredentialBroker,
        ProviderEgressOperationContextResolver,
        ProviderEgressTelemetryRecorder,
        ProviderGatewayUsageAuthority,
        ProviderPermitDecoder,
        ProviderPinnedTransport,
        ProviderWireOperationCodec,
    )
    from agentmemory.providers.domain.idempotency import ProviderOperationRequest
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation

_ERR_DENIED = "provider egress is denied"
_ERR_UNAVAILABLE = "provider gateway is unavailable"
_MAX_RETRY_AFTER_SECONDS = 7 * 24 * 60 * 60
_PRIVACY_CLASSIFICATIONS = {
    "public": Classification.PUBLIC,
    "internal": Classification.INTERNAL,
    "confidential": Classification.CONFIDENTIAL,
    "restricted": Classification.RESTRICTED,
    "local_only": Classification.LOCAL_ONLY,
}


@dataclass(frozen=True, slots=True)
class ResolvedProviderEgressRequestFactory:
    """Build the exact authorization request from current context and wire bytes."""

    contexts: ProviderEgressOperationContextResolver
    wire: ProviderWireOperationCodec

    async def create(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
    ) -> ProviderEgressRequest:
        """Resolve and bind every current coordinate without acquiring a socket."""
        context = await self.contexts.resolve(endpoint, operation)
        prepared = self.wire.prepare(
            endpoint,
            operation,
            payloads,
            operation.downstream_idempotency_key,
        )
        try:
            return ProviderEgressRequest(
                operation_id=operation.operation_id,
                brain_id=operation.brain_id,
                project_id=operation.project_id,
                profile_id=endpoint.profile_id,
                profile_version=endpoint.profile_version,
                profile_attestation_id=endpoint.capability_attestation_id,
                model_revision=endpoint.output_contract.model_revision,
                purpose=endpoint.output_contract.purpose.value,
                operation_type=endpoint.output_contract.operation.value,
                destination=context.destination,
                taint=ContentTaint(
                    classification=_PRIVACY_CLASSIFICATIONS[operation.privacy_class.value],
                    private_block=operation.private_block or context.private_block,
                    secret_bearing=operation.secret_bearing or context.secret_bearing,
                ),
                retention_days=context.retention_days,
                training_allowed=context.training_allowed,
                policy_version=context.policy_version,
                security_epoch=context.security_epoch,
                quota_requests_per_minute=context.quota_requests_per_minute,
                quota_tokens_per_minute=context.quota_tokens_per_minute,
                budget_monthly_micros=context.budget_monthly_micros,
                request_bytes=len(prepared.body),
                maximum_response_bytes=context.maximum_response_bytes,
                timeout_milliseconds=context.timeout_milliseconds,
                content_digests=operation.content_sha256,
                wire_request_digest=prepared.digest,
                token_count=operation.token_count,
                estimated_cost_micros=operation.estimated_cost_micros,
            )
        finally:
            prepared.destroy()


@dataclass(frozen=True, slots=True)
class ProviderGatewayOperationHandler:
    """Independently authenticate, account, broker, connect, and audit one egress."""

    permits: ProviderPermitDecoder
    usage: ProviderGatewayUsageAuthority
    credentials: ProviderCredentialBroker
    transport: ProviderPinnedTransport
    telemetry: ProviderEgressTelemetryRecorder
    now_microseconds: Callable[[], int]

    async def execute(
        self,
        command: ExecuteProviderEgress,
    ) -> ProviderEgressHttpResponse:
        """Execute one exact signed operation and destroy body/credential buffers."""
        permit: ProviderEgressPermit | None = None
        credential: ProviderGatewayCredential | None = None
        response: ProviderEgressHttpResponse | None = None
        outcome_code = "dependency_failure"
        request_bytes = len(command.body)
        try:
            permit = self.permits.decode(command.permit_token)
            _verify_wire_digest(command.body, permit.wire_request_digest)
            await self.usage.authorize(permit, self.now_microseconds())
            credential = await self.credentials.resolve(permit)
            response = await self.transport.execute(
                permit,
                method="POST",
                path=command.path,
                headers={
                    "Accept": "application/json",
                    credential.header_name: credential.text(),
                    "Content-Type": "application/json",
                },
                body=bytes(command.body),
                maximum_response_bytes=permit.maximum_response_bytes,
                timeout_milliseconds=permit.timeout_milliseconds,
            )
            response = _normalize_retry_after(response, self.now_microseconds())
            outcome_code = "succeeded"
        except asyncio.CancelledError:
            outcome_code = "cancelled"
            raise
        except ProviderContainmentDeniedError:
            outcome_code = "denied"
            raise
        except ProviderContainmentValidationError:
            outcome_code = "invalid"
            raise
        except ProviderContainmentDependencyError:
            raise
        except Exception as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
        finally:
            if credential is not None:
                credential.destroy()
            command.body[:] = b"\x00" * len(command.body)
            if permit is not None:
                await self.telemetry.record_egress(
                    ProviderEgressDecisionFact(
                        permit_digest=permit.digest,
                        operation_id=permit.operation_id,
                        destination_fingerprint=permit.destination.fingerprint,
                        outcome_code=outcome_code,
                        request_bytes=request_bytes,
                        response_bytes=0 if response is None else len(response.body),
                        status_code=None if response is None else response.status_code,
                        occurred_at_microseconds=self.now_microseconds(),
                    )
                )
        if response is None:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE)
        return response


def _verify_wire_digest(body: bytearray, expected: str) -> None:
    if hashlib.sha256(bytes(body)).hexdigest() != expected:
        raise ProviderContainmentDeniedError(_ERR_DENIED)


def _normalize_retry_after(
    response: ProviderEgressHttpResponse,
    now_microseconds: int,
) -> ProviderEgressHttpResponse:
    """Expose one bounded absolute retry hint and discard all vendor headers."""
    values = tuple(value for name, value in response.headers if name.lower() == "retry-after")
    retry_at = _parse_retry_after(values[0], now_microseconds) if len(values) == 1 else None
    return ProviderEgressHttpResponse(
        response.status_code,
        (),
        response.body,
        retry_at,
    )


def _parse_retry_after(value: str, now_microseconds: int) -> int | None:
    stripped = value.strip()
    if stripped.isdecimal():
        seconds = int(stripped)
        if seconds <= _MAX_RETRY_AFTER_SECONDS:
            return now_microseconds + seconds * 1_000_000
        return None
    try:
        parsed = parsedate_to_datetime(stripped)
    except TypeError, ValueError, OverflowError:
        return None
    if parsed.tzinfo is None:
        return None
    retry_at = round(parsed.astimezone(UTC).timestamp() * 1_000_000)
    if now_microseconds <= retry_at <= (now_microseconds + _MAX_RETRY_AFTER_SECONDS * 1_000_000):
        return retry_at
    return None
