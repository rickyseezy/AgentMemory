"""PRO-007 idempotent provider execution with safe fallback and durable retry."""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderPermanentFailureError,
    ProviderResilienceValidationError,
    ProviderRetryScheduledError,
)
from agentmemory.providers.domain.idempotency import (
    ProviderClaimDisposition,
    ProviderExecutionResult,
    ProviderPurpose,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose, ProviderOperation
from agentmemory.providers.domain.resilience import (
    ProviderDispatchFact,
    ProviderErrorPolicy,
    ProviderRetryAction,
    ProviderRetryContext,
    retry_jitter_seed,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.idempotency import (
        ProviderOperationClaim,
        ProviderOperationRequest,
    )
    from agentmemory.providers.domain.ports import ProviderOperationCache
    from agentmemory.providers.domain.resilience import (
        EquivalentEndpointSet,
        ProviderCircuitPermit,
        ProviderCircuitPolicy,
        ProviderEndpointAttestation,
        ProviderRetryPolicy,
    )
    from agentmemory.providers.domain.resilience_ports import (
        ProviderCircuitRepository,
        ProviderDispatchEvidenceRecorder,
        ProviderEndpointGateway,
    )
    from agentmemory.shared.clock import Clock

_OWNER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_LEASE_MICROSECONDS = 60_000_000
_MAX_POLL_SECONDS = 1.0
_ERR_INPUT = "provider resilient execution request is invalid"
_PURPOSES = {
    ProviderPurpose.EMBED_DOCUMENT: frozenset(
        {
            CanonicalPurpose.RETRIEVAL_DOCUMENT,
            CanonicalPurpose.CODE_DOCUMENT,
            CanonicalPurpose.SEMANTIC_SIMILARITY,
            CanonicalPurpose.CLASSIFICATION,
            CanonicalPurpose.CLUSTERING,
        }
    ),
    ProviderPurpose.EMBED_QUERY: frozenset(
        {
            CanonicalPurpose.RETRIEVAL_QUERY,
            CanonicalPurpose.CODE_QUERY,
        }
    ),
    ProviderPurpose.RERANK: frozenset(CanonicalPurpose),
}


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecuteResilientProviderOperation:
    """One immutable provider operation and its proven-equivalent endpoints."""

    operation: ProviderOperationRequest
    endpoints: EquivalentEndpointSet
    deadline_at_microseconds: int
    payloads: tuple[bytearray, ...] = field(repr=False)

    def __post_init__(self) -> None:
        """Bind primary profile, model revision, operation type, and deadline."""
        contract = self.endpoints.primary.output_contract
        expected_operation = {
            ProviderPurpose.EMBED_DOCUMENT: ProviderOperation.EMBEDDING,
            ProviderPurpose.EMBED_QUERY: ProviderOperation.EMBEDDING,
            ProviderPurpose.RERANK: ProviderOperation.RERANKING,
        }.get(self.operation.purpose)
        if (
            expected_operation is None
            or expected_operation is not contract.operation
            or self.operation.profile_id != self.endpoints.primary.profile_id
            or self.operation.model_revision != contract.model_revision
            or contract.purpose not in _PURPOSES.get(self.operation.purpose, frozenset())
            or self.operation.preprocessing_digest != contract.preprocessing_digest
            or self.deadline_at_microseconds < 1
            or len(self.payloads) != len(self.operation.content_sha256)
            or tuple(hashlib.sha256(bytes(payload)).hexdigest() for payload in self.payloads)
            != self.operation.content_sha256
        ):
            raise ProviderResilienceValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class _EndpointContext:
    command: ExecuteResilientProviderOperation
    claim: ProviderOperationClaim
    endpoint: ProviderEndpointAttestation
    ordinal: int


@dataclass(frozen=True, slots=True, kw_only=True)
class _EndpointAttempt:
    result: ProviderExecutionResult | None = None
    failure: ProviderAdapterError | None = None
    circuit_open_until_microseconds: int | None = None

    def __post_init__(self) -> None:
        if (
            sum(
                value is not None
                for value in (
                    self.result,
                    self.failure,
                    self.circuit_open_until_microseconds,
                )
            )
            != 1
        ):
            raise ProviderResilienceValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class ResilientProviderOperationHandler:
    """Serialize billable work, apply circuits/fallback, and durably retry."""

    cache: ProviderOperationCache
    gateway: ProviderEndpointGateway
    circuits: ProviderCircuitRepository
    evidence: ProviderDispatchEvidenceRecorder
    retry_policy: ProviderRetryPolicy
    circuit_policy: ProviderCircuitPolicy
    clock: Clock
    owner: str
    poll_seconds: float = 0.01

    def __post_init__(self) -> None:
        """Require one bounded worker identity and contention wait."""
        ProviderErrorPolicy.verify_complete()
        if _OWNER.fullmatch(self.owner) is None or not 0 <= self.poll_seconds <= _MAX_POLL_SECONDS:
            raise ProviderResilienceValidationError(_ERR_INPUT)

    async def execute(
        self,
        command: ExecuteResilientProviderOperation,
    ) -> ProviderExecutionResult:
        """Return a charged/cached result, safe retry time, or permanent code."""
        while True:
            now = _microseconds(self.clock)
            if now >= command.deadline_at_microseconds:
                raise ProviderPermanentFailureError(ProviderErrorCode.TIMEOUT)
            claim = await self.cache.claim(
                command.operation,
                self.owner,
                now,
                min(now + _LEASE_MICROSECONDS, command.deadline_at_microseconds),
            )
            if claim.disposition is ProviderClaimDisposition.CACHED:
                if claim.cached_outcome is None:
                    raise ProviderResilienceValidationError(_ERR_INPUT)
                return ProviderExecutionResult(claim.cached_outcome, cached=True)
            if claim.disposition is ProviderClaimDisposition.FAILED:
                if claim.failure_code is None:
                    raise ProviderResilienceValidationError(_ERR_INPUT)
                return _raise_permanent(ProviderErrorCode(claim.failure_code))
            if claim.disposition is ProviderClaimDisposition.WAIT:
                await asyncio.sleep(self.poll_seconds)
                continue
            return await self._execute_claim(command, claim)

    async def _execute_claim(
        self,
        command: ExecuteResilientProviderOperation,
        claim: ProviderOperationClaim,
    ) -> ProviderExecutionResult:
        primary_error: ProviderAdapterError | None = None
        primary_open_until: int | None = None
        for ordinal, endpoint in enumerate(command.endpoints.endpoints):
            attempted = await self._try_endpoint(
                _EndpointContext(command, claim, endpoint, ordinal)
            )
            if attempted.result is not None:
                return attempted.result
            if attempted.circuit_open_until_microseconds is not None:
                if ordinal == 0:
                    primary_open_until = attempted.circuit_open_until_microseconds
                continue
            failure = attempted.failure
            if failure is None:
                raise ProviderResilienceValidationError(_ERR_INPUT)
            traits = ProviderErrorPolicy.traits(failure.code)
            if ordinal == 0:
                primary_error = failure
                if not traits.fallback_safe:
                    return await self._fail_permanently(
                        claim,
                        failure.code,
                        _microseconds(self.clock),
                    )
            elif not traits.fallback_safe:
                continue

        failure = primary_error or ProviderAdapterError(
            ProviderErrorCode.TRANSIENT_UPSTREAM,
            retry_after_microseconds=primary_open_until,
        )
        return await self._retry_or_fail(command, claim, failure)

    async def _try_endpoint(self, context: _EndpointContext) -> _EndpointAttempt:
        now = _microseconds(self.clock)
        permit = await self.circuits.acquire(
            context.endpoint,
            self.circuit_policy,
            now,
        )
        if not permit.allowed:
            await self._record(context, "circuit_open", now)
            return _EndpointAttempt(
                circuit_open_until_microseconds=permit.snapshot.open_until_microseconds
            )
        await self._record(context, "started", now)
        try:
            outcome = await self.gateway.execute(
                context.endpoint,
                context.command.operation,
                context.command.payloads,
                context.command.operation.downstream_idempotency_key,
            )
        except asyncio.CancelledError:
            await self._cancel_attempt(context, permit)
            raise
        except ProviderAdapterError as error:
            failure = error
        except Exception:  # noqa: BLE001 -- adapters cannot leak arbitrary exceptions.
            failure = ProviderAdapterError(ProviderErrorCode.ADAPTER_CRASH)
        else:
            completed_at = _microseconds(self.clock)
            await self.cache.complete(context.claim, outcome, completed_at)
            await self.circuits.success(permit, self.circuit_policy, completed_at)
            await self._record(context, "succeeded", completed_at)
            return _EndpointAttempt(
                result=ProviderExecutionResult(outcome, cached=False),
            )
        failed_at = _microseconds(self.clock)
        await self.circuits.failure(
            permit,
            failure.code,
            self.circuit_policy,
            failed_at,
        )
        await self._record(context, failure.code.value, failed_at)
        return _EndpointAttempt(failure=failure)

    async def _cancel_attempt(
        self,
        context: _EndpointContext,
        permit: ProviderCircuitPermit,
    ) -> None:
        cancelled_at = _microseconds(self.clock)
        await self.circuits.abandon(permit, self.circuit_policy, cancelled_at)
        await self.cache.release_retry(
            context.claim,
            ProviderErrorCode.CANCELLATION.value,
            cancelled_at,
        )
        await self._record(
            context,
            ProviderErrorCode.CANCELLATION.value,
            cancelled_at,
        )

    async def _retry_or_fail(
        self,
        command: ExecuteResilientProviderOperation,
        claim: ProviderOperationClaim,
        failure: ProviderAdapterError,
    ) -> ProviderExecutionResult:
        now = _microseconds(self.clock)
        retry_after = failure.retry_after_microseconds
        if retry_after is not None:
            retry_after = max(now, retry_after)
        decision = self.retry_policy.decide(
            failure.code,
            ProviderRetryContext(
                attempt=claim.attempt,
                now_microseconds=now,
                deadline_at_microseconds=command.deadline_at_microseconds,
                jitter_seed=retry_jitter_seed(
                    command.operation.downstream_idempotency_key,
                    command.endpoints.primary.endpoint_fingerprint,
                    claim.attempt,
                ),
                retry_after_microseconds=retry_after,
            ),
        )
        if decision.action is ProviderRetryAction.RETRY:
            if decision.retry_at_microseconds is None:
                raise ProviderResilienceValidationError(_ERR_INPUT)
            await self.cache.release_retry(
                claim,
                failure.code.value,
                decision.retry_at_microseconds,
            )
            raise ProviderRetryScheduledError(
                failure.code,
                decision.retry_at_microseconds,
            )
        return await self._fail_permanently(claim, failure.code, now)

    async def _fail_permanently(
        self,
        claim: ProviderOperationClaim,
        code: ProviderErrorCode,
        failed_at_microseconds: int,
    ) -> ProviderExecutionResult:
        await self.cache.fail(
            claim,
            code.value,
            failed_at_microseconds,
        )
        raise ProviderPermanentFailureError(code)

    async def _record(
        self,
        context: _EndpointContext,
        outcome_code: str,
        occurred_at_microseconds: int,
    ) -> None:
        await self.evidence.record(
            ProviderDispatchFact(
                operation_key_sha256=context.command.operation.cache_key_sha256,
                endpoint=context.endpoint,
                attempt=context.claim.attempt,
                fallback_ordinal=context.ordinal,
                outcome_code=outcome_code,
                occurred_at_microseconds=occurred_at_microseconds,
            )
        )


def _microseconds(clock: Clock) -> int:
    return round(clock.now().timestamp() * 1_000_000)


def _raise_permanent(code: ProviderErrorCode) -> ProviderExecutionResult:
    raise ProviderPermanentFailureError(code)
