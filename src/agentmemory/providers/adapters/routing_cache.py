"""Bounded in-process PRO-005 route-decision cache."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import ProviderRoutingValidationError

if TYPE_CHECKING:
    from agentmemory.providers.domain.routing import RouteDecision

_MAXIMUM_CAPACITY = 1_000_000


class BoundedProviderRouteCache:
    """Concurrency-safe LRU whose keys already contain every invalidation version."""

    def __init__(self, *, maximum_entries: int = 4096) -> None:
        """Require an explicit production bound."""
        if not 1 <= maximum_entries <= _MAXIMUM_CAPACITY:
            msg = "provider route cache capacity is invalid"
            raise ProviderRoutingValidationError(msg)
        self._maximum_entries = maximum_entries
        self._entries: OrderedDict[str, RouteDecision] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> RouteDecision | None:
        """Return and promote one exact entry."""
        async with self._lock:
            decision = self._entries.get(key)
            if decision is not None:
                self._entries.move_to_end(key)
            return decision

    async def put(self, key: str, decision: RouteDecision) -> None:
        """Insert one exact decision and evict the least recently used entry."""
        async with self._lock:
            self._entries[key] = decision
            self._entries.move_to_end(key)
            while len(self._entries) > self._maximum_entries:
                self._entries.popitem(last=False)
