"""ING-002 provider-operation idempotency domain and application tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Any, cast

import pytest

from agentmemory.providers.application.idempotent_execution import (
    ExecuteProviderOperationHandler,
)
from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderOperationDependencyError,
    ProviderPermanentFailureError,
)
from agentmemory.providers.domain.idempotency import (
    ProviderClaimDisposition,
    ProviderOperationClaim,
    ProviderOperationOutcome,
    ProviderOperationRequest,
    ProviderPrivacyClass,
    ProviderPurpose,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock, digest

PROFILE_ID = "018f0000-0000-7000-8000-000000000601"
OPERATION_ID = "018f0000-0000-7000-8000-000000000602"
MODEL_REVISION = "a" * 40
CONTENT_DIGEST = digest("provider-content").value
RESULT_DIGEST = digest("provider-result").value


def request(**changes: object) -> ProviderOperationRequest:
    value = ProviderOperationRequest(
        operation_id=OPERATION_ID,
        idempotency_key="embed:session-1:document-1",
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        model_revision=MODEL_REVISION,
        purpose=ProviderPurpose.EMBED_DOCUMENT,
        content_sha256=(CONTENT_DIGEST,),
        preprocessing_revision="source-text-v1",
        privacy_class=ProviderPrivacyClass.INTERNAL,
    )
    return replace(value, **cast("Any", changes))


def outcome() -> ProviderOperationOutcome:
    return ProviderOperationOutcome(
        result_sha256=RESULT_DIGEST,
        result_ref=f"cas://sha256/{RESULT_DIGEST}",
        usage_units=17,
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("operation_id", "bad"),
        ("idempotency_key", "bad key"),
        ("brain_id", "bad"),
        ("profile_id", "bad"),
        ("model_revision", "bad revision"),
        ("content_sha256", ("bad",)),
        ("content_sha256", ()),
        ("preprocessing_revision", "bad revision"),
    ],
)
def test_provider_operation_rejects_ambiguous_cache_dimensions(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="provider"):
        request(**{field_name: value})


def test_cache_key_binds_every_required_semantic_dimension() -> None:
    baseline = request()
    variants = (
        replace(baseline, content_sha256=(digest("other-content").value,)),
        replace(baseline, profile_id="018f0000-0000-7000-8000-000000000603"),
        replace(baseline, model_revision="b" * 40),
        replace(baseline, purpose=ProviderPurpose.EMBED_QUERY),
        replace(baseline, preprocessing_revision="query-text-v2"),
        replace(baseline, privacy_class=ProviderPrivacyClass.CONFIDENTIAL),
        replace(baseline, brain_id="018f0000-0000-7000-8000-000000000604"),
    )
    assert len({baseline.cache_key_sha256, *(item.cache_key_sha256 for item in variants)}) == 8
    assert baseline.request_sha256 == replace(baseline, operation_id=OPERATION_ID).request_sha256
    assert baseline.request_sha256 != replace(baseline, operation_id=PROFILE_ID).request_sha256


def test_provider_operation_accepts_named_model_revision_and_hashes_preprocessing() -> None:
    operation = request(model_revision="text-embedding-3-large@2026-07-01")
    assert operation.model_revision == "text-embedding-3-large@2026-07-01"
    assert operation.preprocessing_digest == digest("source-text-v1").value


@pytest.mark.parametrize(
    ("result_sha256", "result_ref", "usage_units"),
    [
        ("bad", f"cas://sha256/{RESULT_DIGEST}", 1),
        (RESULT_DIGEST, "cas://sha256/wrong", 1),
        (RESULT_DIGEST, f"cas://sha256/{RESULT_DIGEST}", -1),
    ],
)
def test_provider_outcome_rejects_non_content_addressed_or_negative_evidence(
    result_sha256: str,
    result_ref: str,
    usage_units: int,
) -> None:
    with pytest.raises(ValueError, match="outcome"):
        ProviderOperationOutcome(result_sha256, result_ref, usage_units)


@pytest.mark.parametrize(
    "changes",
    [
        {"attempt": 0},
        {"owner": None},
        {
            "disposition": ProviderClaimDisposition.WAIT,
            "owner": None,
            "lease_until_microseconds": None,
            "cached_outcome": outcome(),
        },
    ],
)
def test_provider_claim_rejects_ambiguous_lease_cache_and_attempt(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="provider operation"):
        replace(claimed(ProviderClaimDisposition.CLAIMED), **cast("Any", changes))


@pytest.mark.parametrize(
    ("owner", "poll_seconds"),
    [("", 0.01), ("x" * 129, 0.01), ("worker", -0.01), ("worker", 1.01)],
)
def test_provider_handler_rejects_invalid_worker_or_poll_interval(
    owner: str,
    poll_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="provider operation"):
        ExecuteProviderOperationHandler(
            _Cache([]),
            _BillingBackend(),
            FixedClock(NOW),
            owner,
            poll_seconds=poll_seconds,
        )


@dataclass
class _Cache:
    claim_results: list[ProviderOperationClaim]
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
        del operation, owner, now_microseconds, lease_until_microseconds
        return self.claim_results.pop(0)

    async def complete(
        self,
        claim: ProviderOperationClaim,
        result: ProviderOperationOutcome,
        completed_at_microseconds: int,
    ) -> None:
        self.completed.append((claim, result, completed_at_microseconds))

    async def release_retry(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        self.released.append((claim, reason_code, retry_at_microseconds))

    async def fail(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        failed_at_microseconds: int,
    ) -> None:
        self.failed.append((claim, reason_code, failed_at_microseconds))


@dataclass
class _BillingBackend:
    result: ProviderOperationOutcome = field(default_factory=outcome)
    error: Exception | None = None
    invocations: list[tuple[ProviderOperationRequest, str]] = field(
        default_factory=list[tuple[ProviderOperationRequest, str]]
    )

    async def execute(
        self,
        operation: ProviderOperationRequest,
        downstream_idempotency_key: str,
    ) -> ProviderOperationOutcome:
        self.invocations.append((operation, downstream_idempotency_key))
        if self.error is not None:
            raise self.error
        return self.result


def claimed(disposition: ProviderClaimDisposition) -> ProviderOperationClaim:
    cached = outcome() if disposition is ProviderClaimDisposition.CACHED else None
    failure_code = (
        ProviderErrorCode.AUTHENTICATION.value
        if disposition is ProviderClaimDisposition.FAILED
        else None
    )
    return ProviderOperationClaim(
        operation=request(),
        disposition=disposition,
        owner="provider-worker-1" if disposition is ProviderClaimDisposition.CLAIMED else None,
        lease_until_microseconds=(42 if disposition is ProviderClaimDisposition.CLAIMED else None),
        attempt=1,
        cached_outcome=cached,
        failure_code=failure_code,
    )


@pytest.mark.asyncio
async def test_claimed_provider_operation_executes_and_commits_once() -> None:
    cache = _Cache([claimed(ProviderClaimDisposition.CLAIMED)])
    backend = _BillingBackend()
    result = await ExecuteProviderOperationHandler(
        cache,
        backend,
        FixedClock(NOW),
        "provider-worker-1",
        poll_seconds=0,
    ).execute(request())
    assert result.outcome == outcome()
    assert result.cached is False
    assert len(cache.completed) == 1
    assert backend.invocations[0][1].startswith("am-provider-v1:")


@pytest.mark.asyncio
async def test_completed_provider_operation_replays_without_billing() -> None:
    cache = _Cache([claimed(ProviderClaimDisposition.CACHED)])
    backend = _BillingBackend()
    result = await ExecuteProviderOperationHandler(
        cache,
        backend,
        FixedClock(NOW),
        "provider-worker-1",
        poll_seconds=0,
    ).execute(request())
    assert result.outcome == outcome()
    assert result.cached is True
    assert backend.invocations == []
    assert cache.completed == []


@pytest.mark.asyncio
async def test_failed_provider_operation_replays_without_billing() -> None:
    cache = _Cache([claimed(ProviderClaimDisposition.FAILED)])
    backend = _BillingBackend()
    with pytest.raises(ProviderPermanentFailureError) as captured:
        await ExecuteProviderOperationHandler(
            cache,
            backend,
            FixedClock(NOW),
            "provider-worker-1",
            poll_seconds=0,
        ).execute(request())
    assert captured.value.code is ProviderErrorCode.AUTHENTICATION
    assert backend.invocations == []


@pytest.mark.asyncio
async def test_busy_provider_operation_waits_then_replays() -> None:
    cache = _Cache(
        [
            claimed(ProviderClaimDisposition.WAIT),
            claimed(ProviderClaimDisposition.CACHED),
        ]
    )
    result = await ExecuteProviderOperationHandler(
        cache,
        _BillingBackend(),
        FixedClock(NOW),
        "provider-worker-1",
        poll_seconds=0,
    ).execute(request())
    assert result.cached is True


@pytest.mark.asyncio
async def test_dependency_failure_releases_provider_claim_for_same_key_retry() -> None:
    cache = _Cache([claimed(ProviderClaimDisposition.CLAIMED)])
    backend = _BillingBackend(error=ProviderOperationDependencyError("provider unavailable"))
    with pytest.raises(ProviderOperationDependencyError):
        await ExecuteProviderOperationHandler(
            cache,
            backend,
            FixedClock(NOW),
            "provider-worker-1",
            poll_seconds=0,
        ).execute(request())
    assert cache.released[0][1] == "provider_dependency_unavailable"


@pytest.mark.asyncio
async def test_wait_loop_is_cancellation_aware() -> None:
    cache = _Cache([claimed(ProviderClaimDisposition.WAIT)] * 10)
    handler = ExecuteProviderOperationHandler(
        cache,
        _BillingBackend(),
        FixedClock(NOW),
        "provider-worker-1",
        poll_seconds=0.01,
    )
    task = asyncio.create_task(handler.execute(request()))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
