"""Bounded independent PRO-009 gateway admission accounting."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import ProviderContainmentDeniedError

if TYPE_CHECKING:
    from agentmemory.providers.domain.containment import ProviderEgressPermit

_MICROSECONDS_PER_MINUTE = 60_000_000
_MAX_PROFILES = 100_000
_MAX_PERMIT_RECORDS = 1_000_000
_ERR_USAGE = "provider gateway usage is denied"


@dataclass(slots=True)
class _Usage:
    minute: int
    requests: int
    tokens: int
    month: tuple[int, int]
    cost_micros: int


class InMemoryGatewayUsageAuthority:
    """Atomically enforce a second rate/budget/replay boundary in the gateway."""

    def __init__(
        self,
        *,
        maximum_profiles: int = _MAX_PROFILES,
        maximum_permit_records: int = _MAX_PERMIT_RECORDS,
    ) -> None:
        """Create finite state; capacity exhaustion denies instead of evicting authority."""
        if (
            not 1 <= maximum_profiles <= _MAX_PROFILES
            or not 1 <= maximum_permit_records <= _MAX_PERMIT_RECORDS
        ):
            raise ValueError(_ERR_USAGE)
        self._maximum_profiles = maximum_profiles
        self._maximum_permit_records = maximum_permit_records
        self._profiles: dict[str, _Usage] = {}
        self._permits: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def authorize(
        self,
        permit: ProviderEgressPermit,
        now_microseconds: int,
    ) -> None:
        """Reserve one live permit against exact minute and UTC-month ceilings."""
        async with self._lock:
            self._authorize(permit, now_microseconds)

    def _authorize(
        self,
        permit: ProviderEgressPermit,
        now_microseconds: int,
    ) -> None:
        if not permit.issued_at_microseconds <= now_microseconds < permit.expires_at_microseconds:
            raise ProviderContainmentDeniedError(_ERR_USAGE)
        expired = [
            digest for digest, expires_at in self._permits.items() if expires_at <= now_microseconds
        ]
        for digest in expired:
            del self._permits[digest]
        permit_digest = permit.digest
        if permit_digest in self._permits:
            raise ProviderContainmentDeniedError(_ERR_USAGE)
        usage = self._profiles.get(permit.profile_id)
        minute = now_microseconds // _MICROSECONDS_PER_MINUTE
        month = _month(now_microseconds)
        if usage is None:
            if len(self._profiles) >= self._maximum_profiles:
                raise ProviderContainmentDeniedError(_ERR_USAGE)
            usage = _Usage(minute, 0, 0, month, 0)
        if usage.minute != minute:
            usage.minute = minute
            usage.requests = 0
            usage.tokens = 0
        if usage.month != month:
            usage.month = month
            usage.cost_micros = 0
        if (
            usage.requests + 1 > permit.quota_requests_per_minute
            or usage.tokens + permit.token_count > permit.quota_tokens_per_minute
            or usage.cost_micros + permit.estimated_cost_micros > permit.budget_monthly_micros
            or len(self._permits) >= self._maximum_permit_records
        ):
            raise ProviderContainmentDeniedError(_ERR_USAGE)
        usage.requests += 1
        usage.tokens += permit.token_count
        usage.cost_micros += permit.estimated_cost_micros
        self._profiles[permit.profile_id] = usage
        self._permits[permit_digest] = permit.expires_at_microseconds


def _month(microseconds: int) -> tuple[int, int]:
    if microseconds < 0:
        raise ProviderContainmentDeniedError(_ERR_USAGE)
    try:
        value = datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC)
    except (OSError, OverflowError, ValueError) as error:
        raise ProviderContainmentDeniedError(_ERR_USAGE) from error
    return value.year, value.month
