"""Translate PRO-007 provider outcomes at the PF-004 anti-corruption boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderPermanentFailureError,
    ProviderResilienceConflictError,
    ProviderResilienceDependencyError,
    ProviderRetryScheduledError,
)
from agentmemory.resilience.domain.errors import RecallDependencyError, RecallIntegrityError

if TYPE_CHECKING:
    from agentmemory.resilience.domain.models import (
        ChannelName,
        DependencyName,
        RecallChannelSuccess,
        RecallQuery,
    )
    from agentmemory.resilience.domain.ports import RecallChannelSource

_ERR_PROVIDER_DEPENDENCY = "provider recall channel is unavailable"
_ERR_PROVIDER_INTEGRITY = "provider recall evidence diverged"


@dataclass(frozen=True, slots=True)
class ProviderRecallSource:
    """Keep provider failure local to its optional recall channel."""

    delegate: RecallChannelSource

    @property
    def channel(self) -> ChannelName:
        """Preserve the delegate's declared channel identity."""
        return self.delegate.channel

    @property
    def dependency(self) -> DependencyName:
        """Preserve the dependency circuit identity."""
        return self.delegate.dependency

    async def recall(self, request: RecallQuery) -> RecallChannelSuccess:
        """Translate only typed provider availability and integrity failures."""
        try:
            return await self.delegate.recall(request)
        except ProviderResilienceConflictError as error:
            raise RecallIntegrityError(_ERR_PROVIDER_INTEGRITY) from error
        except (
            ProviderAdapterError,
            ProviderPermanentFailureError,
            ProviderResilienceDependencyError,
            ProviderRetryScheduledError,
        ) as error:
            raise RecallDependencyError(_ERR_PROVIDER_DEPENDENCY) from error
