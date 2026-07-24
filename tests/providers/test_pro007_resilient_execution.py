"""PRO-007 fallback, retry, circuit, and duplicate-charge orchestration tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, cast

import pytest

from agentmemory.providers.application.resilient_execution import (
    ExecuteResilientProviderOperation,
    ResilientProviderOperationHandler,
)
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderPermanentFailureError,
    ProviderResilienceValidationError,
    ProviderRetryScheduledError,
)
from agentmemory.providers.domain.idempotency import (
    ProviderClaimDisposition,
    ProviderOperationClaim,
    ProviderOperationOutcome,
    ProviderOperationRequest,
    ProviderPurpose,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose
from agentmemory.providers.domain.resilience import (
    EquivalentEndpointSet,
    ProviderCircuitPermit,
    ProviderCircuitPolicy,
    ProviderCircuitSnapshot,
    ProviderCircuitState,
    ProviderDispatchFact,
    ProviderEndpointAttestation,
    ProviderRetryPolicy,
)
from tests.core.support import NOW, FixedClock
from tests.providers.test_ing002_provider_idempotency_domain_application import (
    outcome,
    request,
)
from tests.providers.test_pro007_resilience_domain import (
    FALLBACK_ENDPOINT,
    FALLBACK_PROFILE_ID,
    PRIMARY_ENDPOINT,
    endpoint,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentmemory.shared.clock import Clock

NOW_MICROSECONDS = round(NOW.timestamp() * 1_000_000)


@dataclass(slots=True)
class _Cache:
    cached_outcome: ProviderOperationOutcome | None = None
    failure_code: str | None = None
    wait_once: bool = False
    attempt: int = 1
    claims: list[tuple[str, int, int]] = field(default_factory=list[tuple[str, int, int]])
    completed: list[tuple[ProviderOperationClaim, ProviderOperationOutcome, int]] = field(
        default_factory=list[tuple[ProviderOperationClaim, ProviderOperationOutcome, int]]
    )
    released: list[tuple[ProviderOperationClaim, str, int]] = field(
        default_factory=list[tuple[ProviderOperationClaim, str, int]]
    )
    failed: list[tuple[ProviderOperationClaim, str, int]] = field(
        default_factory=list[tuple[ProviderOperationClaim, str, int]]
    )

    async def claim(
        self,
        operation: ProviderOperationRequest,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderOperationClaim:
        self.claims.append((owner, now_microseconds, lease_until_microseconds))
        if self.wait_once:
            self.wait_once = False
            return ProviderOperationClaim(
                operation,
                ProviderClaimDisposition.WAIT,
                None,
                None,
                self.attempt,
                None,
            )
        if self.cached_outcome is not None:
            return ProviderOperationClaim(
                operation,
                ProviderClaimDisposition.CACHED,
                None,
                None,
                self.attempt,
                self.cached_outcome,
            )
        if self.failure_code is not None:
            return ProviderOperationClaim(
                operation,
                ProviderClaimDisposition.FAILED,
                None,
                None,
                self.attempt,
                None,
                self.failure_code,
            )
        return ProviderOperationClaim(
            operation,
            ProviderClaimDisposition.CLAIMED,
            owner,
            lease_until_microseconds,
            self.attempt,
            None,
        )

    async def complete(
        self,
        claim: ProviderOperationClaim,
        result: ProviderOperationOutcome,
        completed_at_microseconds: int,
    ) -> None:
        self.completed.append((claim, result, completed_at_microseconds))
        self.cached_outcome = result

    async def release_retry(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        self.released.append((claim, reason_code, retry_at_microseconds))
        self.attempt += 1

    async def fail(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        failed_at_microseconds: int,
    ) -> None:
        self.failed.append((claim, reason_code, failed_at_microseconds))
        self.failure_code = reason_code


@dataclass(slots=True)
class _Gateway:
    responses: dict[str, list[ProviderOperationOutcome | BaseException]]
    calls: list[tuple[str, ProviderOperationRequest, str]] = field(
        default_factory=list[tuple[str, ProviderOperationRequest, str]]
    )

    async def execute(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
        payloads: Sequence[bytearray],
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        del payloads
        self.calls.append((endpoint.endpoint_fingerprint, operation, downstream_idempotency_key))
        response = self.responses[endpoint.endpoint_fingerprint].pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


@dataclass(slots=True)
class _Circuits:
    snapshots: dict[str, ProviderCircuitSnapshot] = field(default_factory=dict[str, Any])
    acquisitions: list[str] = field(default_factory=list[str])
    successes: list[str] = field(default_factory=list[str])
    failures: list[tuple[str, ProviderErrorCode]] = field(
        default_factory=list[tuple[str, ProviderErrorCode]]
    )
    abandons: list[str] = field(default_factory=list[str])

    async def acquire(
        self,
        endpoint: ProviderEndpointAttestation,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> ProviderCircuitPermit:
        fingerprint = endpoint.endpoint_fingerprint
        self.acquisitions.append(fingerprint)
        snapshot = self.snapshots.setdefault(
            fingerprint,
            ProviderCircuitSnapshot.initial(fingerprint),
        )
        permit = policy.acquire(snapshot, now_microseconds)
        self.snapshots[fingerprint] = permit.snapshot
        return permit

    async def success(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        fingerprint = permit.snapshot.endpoint_fingerprint
        self.successes.append(fingerprint)
        self.snapshots[fingerprint] = policy.after_success(permit.snapshot, now_microseconds)

    async def failure(
        self,
        permit: ProviderCircuitPermit,
        code: ProviderErrorCode,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        fingerprint = permit.snapshot.endpoint_fingerprint
        self.failures.append((fingerprint, code))
        self.snapshots[fingerprint] = policy.after_failure(
            permit.snapshot,
            code,
            now_microseconds,
        )

    async def abandon(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        fingerprint = permit.snapshot.endpoint_fingerprint
        self.abandons.append(fingerprint)
        self.snapshots[fingerprint] = policy.after_abandon(
            permit.snapshot,
            now_microseconds,
        )


@dataclass(slots=True)
class _Evidence:
    facts: list[tuple[str, str, int, int, str, int]] = field(
        default_factory=list[tuple[str, str, int, int, str, int]]
    )

    async def record(self, fact: ProviderDispatchFact) -> None:
        self.facts.append(
            (
                fact.operation_key_sha256,
                fact.endpoint.endpoint_fingerprint,
                fact.attempt,
                fact.fallback_ordinal,
                fact.outcome_code,
                fact.occurred_at_microseconds,
            )
        )


def command(**changes: object) -> ExecuteResilientProviderOperation:
    value = ExecuteResilientProviderOperation(
        operation=request(),
        endpoints=execution_endpoints(),
        deadline_at_microseconds=NOW_MICROSECONDS + 100_000_000,
        payloads=(bytearray(b"provider-content"),),
    )
    return replace(value, **cast("Any", changes))


def execution_endpoints() -> EquivalentEndpointSet:
    """Bind the ING-002 operation profile to one equivalent fallback."""
    return EquivalentEndpointSet(
        endpoint(profile_id=request().profile_id),
        (
            endpoint(
                profile_id=FALLBACK_PROFILE_ID,
                endpoint_fingerprint=FALLBACK_ENDPOINT,
            ),
        ),
    )


def handler(
    cache: _Cache,
    gateway: _Gateway,
    circuits: _Circuits | None = None,
    evidence: _Evidence | None = None,
    clock: Clock | None = None,
) -> ResilientProviderOperationHandler:
    return ResilientProviderOperationHandler(
        cache=cache,
        gateway=gateway,
        circuits=circuits or _Circuits(),
        evidence=evidence or _Evidence(),
        retry_policy=ProviderRetryPolicy.production(),
        circuit_policy=ProviderCircuitPolicy.production(),
        clock=clock or FixedClock(NOW),
        owner="provider-resilience-worker",
        poll_seconds=0,
    )


@pytest.mark.parametrize(
    "changed",
    [
        {
            "operation": request(
                profile_id="018f0000-0000-7000-8000-000000000799",
            )
        },
        {"operation": request(model_revision="b" * 40)},
        {"operation": request(purpose=ProviderPurpose.EMBED_QUERY)},
        {"operation": request(preprocessing_revision="different-preprocessing-v1")},
        {"deadline_at_microseconds": 0},
        {"payloads": (bytearray(b"different-content"),)},
    ],
)
def test_command_rejects_semantic_contract_or_deadline_substitution(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
        command(**changed)


def test_command_accepts_only_compatible_canonical_embedding_purposes() -> None:
    for purpose in (
        CanonicalPurpose.RETRIEVAL_DOCUMENT,
        CanonicalPurpose.CODE_DOCUMENT,
        CanonicalPurpose.SEMANTIC_SIMILARITY,
        CanonicalPurpose.CLASSIFICATION,
        CanonicalPurpose.CLUSTERING,
    ):
        contract = replace(endpoint().output_contract, purpose=purpose)
        assert (
            command(
                endpoints=EquivalentEndpointSet(
                    endpoint(
                        profile_id=request().profile_id,
                        contract=contract,
                    ),
                    (),
                )
            ).endpoints.primary.output_contract.purpose
            is purpose
        )


@pytest.mark.parametrize(
    ("owner", "poll_seconds"),
    [("", 0.01), ("x" * 129, 0.01), ("worker", -0.01), ("worker", 1.01)],
)
def test_handler_rejects_invalid_owner_or_poll(
    owner: str,
    poll_seconds: float,
) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
        ResilientProviderOperationHandler(
            cache=_Cache(),
            gateway=_Gateway({}),
            circuits=_Circuits(),
            evidence=_Evidence(),
            retry_policy=ProviderRetryPolicy.production(),
            circuit_policy=ProviderCircuitPolicy.production(),
            clock=FixedClock(NOW),
            owner=owner,
            poll_seconds=poll_seconds,
        )


@pytest.mark.asyncio
async def test_primary_success_commits_before_replay_and_never_charges_twice() -> None:
    cache = _Cache()
    gateway = _Gateway({PRIMARY_ENDPOINT: [outcome()]})
    evidence = _Evidence()
    execution = handler(cache, gateway, evidence=evidence)

    first = await execution.execute(command())
    replayed = await execution.execute(command())

    assert first.cached is False
    assert replayed.cached is True
    assert len(gateway.calls) == 1
    assert gateway.calls[0][2] == request().downstream_idempotency_key
    assert len(cache.completed) == 1
    assert [fact[4] for fact in evidence.facts] == ["started", "succeeded"]


@pytest.mark.asyncio
async def test_transient_primary_uses_only_proven_equivalent_fallback_with_same_key() -> None:
    cache = _Cache()
    gateway = _Gateway(
        {
            PRIMARY_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.TRANSIENT_UPSTREAM)],
            FALLBACK_ENDPOINT: [outcome()],
        }
    )
    circuits = _Circuits()
    evidence = _Evidence()

    result = await handler(cache, gateway, circuits, evidence).execute(command())

    assert result.outcome == outcome()
    assert [call[0] for call in gateway.calls] == [PRIMARY_ENDPOINT, FALLBACK_ENDPOINT]
    assert {call[2] for call in gateway.calls} == {request().downstream_idempotency_key}
    assert circuits.failures == [(PRIMARY_ENDPOINT, ProviderErrorCode.TRANSIENT_UPSTREAM)]
    assert circuits.successes == [FALLBACK_ENDPOINT]
    assert [fact[3] for fact in evidence.facts] == [0, 0, 1, 1]


@pytest.mark.asyncio
async def test_nonretryable_primary_fails_immediately_without_unsafe_fallback() -> None:
    cache = _Cache()
    gateway = _Gateway(
        {
            PRIMARY_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.AUTHENTICATION)],
            FALLBACK_ENDPOINT: [outcome()],
        }
    )
    with pytest.raises(ProviderPermanentFailureError) as captured:
        await handler(cache, gateway).execute(command())

    assert captured.value.code is ProviderErrorCode.AUTHENTICATION
    assert [call[0] for call in gateway.calls] == [PRIMARY_ENDPOINT]
    assert cache.failed[0][1] == ProviderErrorCode.AUTHENTICATION.value


@pytest.mark.asyncio
async def test_retryable_failure_schedules_bounded_retry_and_honors_retry_after() -> None:
    cache = _Cache()
    retry_after = NOW_MICROSECONDS + 5_000_000
    gateway = _Gateway(
        {
            PRIMARY_ENDPOINT: [
                ProviderAdapterError(
                    ProviderErrorCode.RATE_LIMIT,
                    retry_after_microseconds=retry_after,
                )
            ],
            FALLBACK_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.TRANSIENT_UPSTREAM)],
        }
    )

    with pytest.raises(ProviderRetryScheduledError) as captured:
        await handler(cache, gateway).execute(command())

    assert captured.value.code is ProviderErrorCode.RATE_LIMIT
    assert captured.value.retry_at_microseconds >= retry_after
    assert cache.released[0][1:] == (
        ProviderErrorCode.RATE_LIMIT.value,
        captured.value.retry_at_microseconds,
    )
    assert cache.failed == []


@pytest.mark.asyncio
async def test_attempt_exhaustion_persists_and_replays_permanent_failure() -> None:
    cache = _Cache(attempt=ProviderRetryPolicy.production().max_attempts)
    gateway = _Gateway(
        {
            PRIMARY_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.TIMEOUT)],
            FALLBACK_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.TIMEOUT)],
        }
    )
    execution = handler(cache, gateway)

    with pytest.raises(ProviderPermanentFailureError) as first:
        await execution.execute(command())
    calls_after_first = len(gateway.calls)
    with pytest.raises(ProviderPermanentFailureError) as replayed:
        await execution.execute(command())

    assert first.value.code is ProviderErrorCode.TIMEOUT
    assert replayed.value.code is ProviderErrorCode.TIMEOUT
    assert len(gateway.calls) == calls_after_first
    assert cache.failure_code == ProviderErrorCode.TIMEOUT.value


@pytest.mark.asyncio
async def test_open_primary_circuit_uses_fallback_and_all_open_endpoints_queue() -> None:
    primary_open_until = NOW_MICROSECONDS + 2_000_000
    circuits = _Circuits(
        snapshots={
            PRIMARY_ENDPOINT: ProviderCircuitSnapshot(
                endpoint_fingerprint=PRIMARY_ENDPOINT,
                state=ProviderCircuitState.OPEN,
                consecutive_failures=5,
                window_started_at_microseconds=NOW_MICROSECONDS,
                open_until_microseconds=primary_open_until,
                probe_in_flight=False,
                version=5,
            )
        }
    )
    fallback_gateway = _Gateway({FALLBACK_ENDPOINT: [outcome()]})
    result = await handler(_Cache(), fallback_gateway, circuits).execute(command())
    assert result.outcome == outcome()
    assert [call[0] for call in fallback_gateway.calls] == [FALLBACK_ENDPOINT]

    fallback_open_until = NOW_MICROSECONDS + 3_000_000
    all_open = _Circuits(
        snapshots={
            PRIMARY_ENDPOINT: circuits.snapshots[PRIMARY_ENDPOINT],
            FALLBACK_ENDPOINT: ProviderCircuitSnapshot(
                endpoint_fingerprint=FALLBACK_ENDPOINT,
                state=ProviderCircuitState.OPEN,
                consecutive_failures=5,
                window_started_at_microseconds=NOW_MICROSECONDS,
                open_until_microseconds=fallback_open_until,
                probe_in_flight=False,
                version=5,
            ),
        }
    )
    cache = _Cache()
    with pytest.raises(ProviderRetryScheduledError) as captured:
        await handler(cache, _Gateway({}), all_open).execute(command())
    assert captured.value.retry_at_microseconds >= primary_open_until


@pytest.mark.asyncio
async def test_fallback_configuration_failure_does_not_override_retryable_primary() -> None:
    cache = _Cache()
    gateway = _Gateway(
        {
            PRIMARY_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.TIMEOUT)],
            FALLBACK_ENDPOINT: [ProviderAdapterError(ProviderErrorCode.INVALID_CONFIGURATION)],
        }
    )
    with pytest.raises(ProviderRetryScheduledError) as captured:
        await handler(cache, gateway).execute(command())
    assert captured.value.code is ProviderErrorCode.TIMEOUT
    assert cache.failed == []


@pytest.mark.asyncio
async def test_arbitrary_adapter_crash_is_typed_and_can_fallback() -> None:
    gateway = _Gateway(
        {
            PRIMARY_ENDPOINT: [RuntimeError("must not cross boundary")],
            FALLBACK_ENDPOINT: [outcome()],
        }
    )
    circuits = _Circuits()
    result = await handler(_Cache(), gateway, circuits).execute(command())
    assert result.outcome == outcome()
    assert circuits.failures == [(PRIMARY_ENDPOINT, ProviderErrorCode.ADAPTER_CRASH)]


@pytest.mark.asyncio
async def test_cancellation_abandons_circuit_and_releases_same_stable_operation() -> None:
    cache = _Cache()
    gateway = _Gateway({PRIMARY_ENDPOINT: [asyncio.CancelledError()]})
    circuits = _Circuits()
    with pytest.raises(asyncio.CancelledError):
        await handler(cache, gateway, circuits).execute(command())
    assert circuits.abandons == [PRIMARY_ENDPOINT]
    assert cache.released[0][1] == ProviderErrorCode.CANCELLATION.value


@pytest.mark.asyncio
async def test_busy_operation_waits_then_replays_without_endpoint_access() -> None:
    cache = _Cache(cached_outcome=outcome(), wait_once=True)
    gateway = _Gateway({})
    result = await handler(cache, gateway).execute(command())
    assert result.cached is True
    assert len(cache.claims) == 2
    assert gateway.calls == []


@pytest.mark.asyncio
async def test_expired_caller_deadline_fails_before_claim_or_endpoint_access() -> None:
    cache = _Cache()
    gateway = _Gateway({})
    with pytest.raises(ProviderPermanentFailureError) as captured:
        await handler(cache, gateway).execute(command(deadline_at_microseconds=NOW_MICROSECONDS))
    assert captured.value.code is ProviderErrorCode.TIMEOUT
    assert cache.claims == []
    assert gateway.calls == []
