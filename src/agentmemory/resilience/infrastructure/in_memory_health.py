"""Concurrency-safe installation-local dependency health repository."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from agentmemory.resilience.domain.models import CircuitSnapshot

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.resilience.domain.models import CircuitPermit, CircuitPolicy, DependencyName


class InMemoryDependencyHealthRepository:
    """Serialize every circuit transition without leaking dependency exceptions."""

    def __init__(self) -> None:
        """Create an empty process-local circuit registry."""
        self._snapshots: dict[DependencyName, CircuitSnapshot] = {}
        self._lock = asyncio.Lock()

    async def acquire(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> CircuitPermit:
        """Atomically acquire an ordinary call or half-open probe."""
        async with self._lock:
            current = self._snapshots.get(dependency, CircuitSnapshot.initial(dependency))
            permit = policy.permit(current, now)
            self._snapshots[dependency] = permit.snapshot
            return permit

    async def record_success(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> None:
        """Atomically close and reset one dependency circuit."""
        async with self._lock:
            current = self._snapshots.get(dependency, CircuitSnapshot.initial(dependency))
            self._snapshots[dependency] = policy.after_success(current, now)

    async def record_failure(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> None:
        """Atomically apply one dependency failure transition."""
        async with self._lock:
            current = self._snapshots.get(dependency, CircuitSnapshot.initial(dependency))
            self._snapshots[dependency] = policy.after_failure(current, now)

    async def record_abandon(
        self, dependency: DependencyName, policy: CircuitPolicy, now: datetime
    ) -> None:
        """Atomically release a cancelled probe without adding a failure."""
        async with self._lock:
            current = self._snapshots.get(dependency, CircuitSnapshot.initial(dependency))
            self._snapshots[dependency] = policy.after_abandon(current, now)

    async def snapshot(self, dependency: DependencyName) -> CircuitSnapshot:
        """Return the current immutable snapshot for diagnostics and tests."""
        async with self._lock:
            return self._snapshots.get(dependency, CircuitSnapshot.initial(dependency))
