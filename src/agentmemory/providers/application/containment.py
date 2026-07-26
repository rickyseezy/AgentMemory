"""PRO-009 contained provider gateway and custom-adapter orchestration."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.domain.containment import ProviderRuntimeFact
from agentmemory.providers.domain.errors import ProviderContainmentDependencyError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.containment import (
        AdapterOperationResult,
        AdapterOperationSandbox,
        ProviderEgressPolicy,
    )
    from agentmemory.providers.domain.containment_ports import (
        AdapterRuntimeSupervisor,
        AuthorizedProviderSocketGateway,
        ProviderContainmentRepository,
        ProviderEgressAuthority,
        ProviderEgressRequestFactory,
        ProviderRuntimeTelemetryRecorder,
    )
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationOutcome,
        ProviderOperationRequest,
    )
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation

_ERR_RUNTIME = "provider adapter runtime failed"
_ZERO_DIGEST = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishProviderEgressPolicyCommand:
    """Owner/admin request to publish one exact immutable Brain policy."""

    scope: AuthorizedScope
    operation_id: str
    request_digest: str
    policy: ProviderEgressPolicy
    published_at_microseconds: int


@dataclass(frozen=True, slots=True, kw_only=True)
class GetProviderEgressPolicyQuery:
    """Authorized request for the active exact Brain policy."""

    scope: AuthorizedScope
    requested_at_microseconds: int


@dataclass(frozen=True, slots=True)
class PublishProviderEgressPolicyHandler:
    """Publish through the canonical containment repository port."""

    repository: ProviderContainmentRepository

    async def execute(
        self,
        command: PublishProviderEgressPolicyCommand,
    ) -> ProviderEgressPolicy:
        """Return the newly published policy or its exact idempotent replay."""
        return await self.repository.publish(
            command.scope,
            command.operation_id,
            command.request_digest,
            command.policy,
            command.published_at_microseconds,
        )


@dataclass(frozen=True, slots=True)
class GetProviderEgressPolicyHandler:
    """Read the active policy through current authorization."""

    repository: ProviderContainmentRepository

    async def execute(
        self,
        query: GetProviderEgressPolicyQuery,
    ) -> ProviderEgressPolicy | None:
        """Return the active policy or ``None`` after authorization."""
        return await self.repository.get(
            query.scope,
            query.requested_at_microseconds,
        )


@dataclass(frozen=True, slots=True)
class ContainedProviderEndpointGateway:
    """Authorize exact egress immediately before delegating socket acquisition."""

    requests: ProviderEgressRequestFactory
    authority: ProviderEgressAuthority
    socket_gateway: AuthorizedProviderSocketGateway
    now_microseconds: Callable[[], int]

    async def execute(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        """Fail before a socket and destroy payload buffers on authorization failure."""
        request = await self.requests.create(endpoint, operation, payloads)
        try:
            permit = await self.authority.authorize(request, self.now_microseconds())
        except Exception:
            _zero(payloads)
            raise
        return await self.socket_gateway.execute(
            permit,
            endpoint,
            operation,
            payloads,
            downstream_idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class ContainedAdapterOperationHandler:
    """Run one operation sandbox, guarantee input destruction, and record safe evidence."""

    supervisor: AdapterRuntimeSupervisor
    telemetry: ProviderRuntimeTelemetryRecorder
    now_microseconds: Callable[[], int]

    async def execute(
        self,
        sandbox: AdapterOperationSandbox,
        inputs: Sequence[bytearray],
    ) -> AdapterOperationResult:
        """Return content-addressed output or one bounded runtime dependency error."""
        outcome_code = "adapter_crash"
        cleanup_digest = _ZERO_DIGEST
        runtime_milliseconds = 0
        try:
            result = await self.supervisor.execute(sandbox, inputs)
            outcome_code = "succeeded"
            cleanup_digest = result.cleanup_digest
            runtime_milliseconds = result.runtime_milliseconds
        except asyncio.CancelledError:
            outcome_code = "cancelled"
            raise
        except Exception as error:
            raise ProviderContainmentDependencyError(_ERR_RUNTIME) from error
        finally:
            _zero(inputs)
            await self.telemetry.record(
                ProviderRuntimeFact(
                    operation_id=sandbox.operation_id,
                    adapter_image_digest=sandbox.image.rsplit("@sha256:", 1)[1],
                    outcome_code=outcome_code,
                    runtime_milliseconds=runtime_milliseconds,
                    cleanup_digest=cleanup_digest,
                    occurred_at_microseconds=self.now_microseconds(),
                )
            )
        return result


def _zero(values: Sequence[bytearray]) -> None:
    for value in values:
        value[:] = b"\x00" * len(value)
