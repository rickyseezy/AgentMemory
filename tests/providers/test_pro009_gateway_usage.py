"""PRO-009 independent gateway rate, token, budget, and replay tests."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters.gateway_usage import (
    InMemoryGatewayUsageAuthority,
    _month,
)
from agentmemory.providers.domain.errors import ProviderContainmentDeniedError
from tests.core.support import digest
from tests.providers.test_pro009_containment_application import permit

if TYPE_CHECKING:
    from agentmemory.providers.domain.containment import ProviderEgressPermit

_MINUTE = 60_000_000


def distinct(
    index: int,
    *,
    quota_requests_per_minute: int | None = None,
    quota_tokens_per_minute: int | None = None,
    token_count: int | None = None,
) -> ProviderEgressPermit:
    value = replace(
        permit(),
        operation_id=f"provider-operation-{index}",
        request_digest=digest(f"request-{index}").value,
        issued_at_microseconds=1_000,
        expires_at_microseconds=10 * _MINUTE,
    )
    return replace(
        value,
        quota_requests_per_minute=(
            value.quota_requests_per_minute
            if quota_requests_per_minute is None
            else quota_requests_per_minute
        ),
        quota_tokens_per_minute=(
            value.quota_tokens_per_minute
            if quota_tokens_per_minute is None
            else quota_tokens_per_minute
        ),
        token_count=value.token_count if token_count is None else token_count,
    )


@pytest.mark.asyncio
async def test_gateway_usage_enforces_replay_request_and_token_limits_atomically() -> None:
    authority = InMemoryGatewayUsageAuthority(maximum_profiles=10, maximum_permit_records=10)
    now = 2_000
    first = distinct(
        1,
        quota_requests_per_minute=2,
        quota_tokens_per_minute=3,
        token_count=2,
    )
    second = distinct(
        2,
        quota_requests_per_minute=2,
        quota_tokens_per_minute=3,
        token_count=2,
    )

    await authority.authorize(first, now)
    for denied in (first, second):
        with pytest.raises(ProviderContainmentDeniedError, match="usage"):
            await authority.authorize(denied, now)


@pytest.mark.asyncio
async def test_minute_reset_preserves_monthly_budget_and_month_reset_releases_it() -> None:
    authority = InMemoryGatewayUsageAuthority(maximum_profiles=10, maximum_permit_records=10)
    january = round(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1_000_000)
    first = replace(
        distinct(1),
        issued_at_microseconds=january - 1,
        expires_at_microseconds=january + 40 * 24 * 60 * _MINUTE,
        budget_monthly_micros=10,
        estimated_cost_micros=6,
    )
    second = replace(
        distinct(2),
        issued_at_microseconds=january - 1,
        expires_at_microseconds=january + 40 * 24 * 60 * _MINUTE,
        budget_monthly_micros=10,
        estimated_cost_micros=6,
    )

    await authority.authorize(first, january)
    with pytest.raises(ProviderContainmentDeniedError, match="usage"):
        await authority.authorize(second, january + _MINUTE)
    await authority.authorize(second, january + 32 * 24 * 60 * _MINUTE)


@pytest.mark.asyncio
async def test_concurrent_admission_cannot_exceed_one_request_capacity() -> None:
    authority = InMemoryGatewayUsageAuthority(maximum_profiles=10, maximum_permit_records=10)
    values = tuple(distinct(index, quota_requests_per_minute=1) for index in range(1, 9))
    results = await asyncio.gather(
        *(authority.authorize(value, 2_000) for value in values),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, ProviderContainmentDeniedError) for result in results) == 7


@pytest.mark.asyncio
async def test_invalid_time_or_exhausted_bounded_state_fails_closed() -> None:
    authority = InMemoryGatewayUsageAuthority(maximum_profiles=1, maximum_permit_records=1)
    with pytest.raises(ProviderContainmentDeniedError, match="usage"):
        await authority.authorize(permit(), 999)
    await authority.authorize(distinct(1), 2_000)
    with pytest.raises(ProviderContainmentDeniedError, match="usage"):
        await authority.authorize(
            replace(
                distinct(2),
                profile_id="018f0000-0000-7000-8000-000000000999",
            ),
            2_000,
        )


@pytest.mark.parametrize(
    ("maximum_profiles", "maximum_permit_records"),
    [(0, 1), (1, 0)],
)
def test_usage_authority_rejects_unbounded_capacity(
    maximum_profiles: int,
    maximum_permit_records: int,
) -> None:
    with pytest.raises(ValueError, match="usage"):
        InMemoryGatewayUsageAuthority(
            maximum_profiles=maximum_profiles,
            maximum_permit_records=maximum_permit_records,
        )


@pytest.mark.asyncio
async def test_expired_permit_record_is_removed_before_new_admission() -> None:
    authority = InMemoryGatewayUsageAuthority(maximum_profiles=10, maximum_permit_records=1)
    first = replace(distinct(1), expires_at_microseconds=3_000)
    second = replace(
        distinct(2),
        issued_at_microseconds=3_001,
        expires_at_microseconds=5_000,
    )

    await authority.authorize(first, 2_000)
    await authority.authorize(second, 4_000)


def test_negative_calendar_timestamp_is_denied() -> None:
    with pytest.raises(ProviderContainmentDeniedError, match="usage"):
        _month(-1)
