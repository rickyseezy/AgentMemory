"""PF-004 narrow repository and recall-channel ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.resilience.domain.models import (
        ChannelName,
        CircuitPermit,
        CircuitPolicy,
        DependencyName,
        RecallChannelSuccess,
        RecallQuery,
    )


class DependencyHealthRepository(Protocol):
    """Atomically persist installation-local circuit snapshots."""

    async def acquire(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> CircuitPermit:
        """Reserve an allowed dependency call or the sole half-open probe."""
        ...

    async def record_success(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> None:
        """Close the dependency circuit after a successful call."""
        ...

    async def record_failure(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> None:
        """Record one typed dependency or deadline failure."""
        ...

    async def record_abandon(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> None:
        """Release a cancelled half-open probe without billing a failure."""
        ...


class RecallAuthorization(Protocol):
    """Authorize the complete scope before any channel work."""

    async def authorize(self, request: RecallQuery) -> None:
        """Fail closed unless the full query scope is currently authorized."""
        ...


class RecallClock(Protocol):
    """Supply UTC time independently from caller-controlled query fields."""

    def now(self) -> datetime:
        """Return the current UTC wall-clock time."""
        ...


class RecallChannelSource(Protocol):
    """One independent bounded recall channel."""

    @property
    def channel(self) -> ChannelName:
        """Return the one channel implemented by this source."""
        ...

    @property
    def dependency(self) -> DependencyName:
        """Return the dependency guarded by this source call."""
        ...

    async def recall(self, request: RecallQuery) -> RecallChannelSuccess:
        """Return a bounded typed success or raise a typed failure."""
        ...
