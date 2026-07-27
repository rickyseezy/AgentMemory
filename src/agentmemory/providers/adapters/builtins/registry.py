"""Closed production registry for PRO-001 certified built-in adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileConflictError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from agentmemory.providers.adapters.drift_probe import ProviderDriftVectorAdapter
    from agentmemory.providers.domain.profile_ports import ProviderAdapterPort

_ERR_AMBIGUOUS = "provider adapter registry is ambiguous"
_ERR_EMPTY = "provider adapter registry is empty"


class CertifiedProviderAdapterRegistry:
    """Resolve exactly one immutable implementation per certified adapter ID."""

    def __init__(self, adapters: Iterable[ProviderAdapterPort]) -> None:
        """Index a non-empty set while rejecting duplicate adapter identities."""
        by_id: dict[str, ProviderAdapterPort] = {}
        for adapter in adapters:
            adapter_id = adapter.manifest.adapter_id
            if adapter_id in by_id:
                raise ProviderProfileConflictError(_ERR_AMBIGUOUS)
            by_id[adapter_id] = adapter
        if not by_id:
            raise ProviderProfileConflictError(_ERR_EMPTY)
        self._adapters = by_id

    def get(self, adapter_id: str) -> ProviderAdapterPort:
        """Return one exact certified adapter without fallback or alias matching."""
        try:
            return self._adapters[adapter_id]
        except KeyError as error:
            raise ProviderAdapterError(ProviderErrorCode.UNSUPPORTED_CAPABILITY) from error

    def get_drift(self, adapter_id: str) -> ProviderDriftVectorAdapter:
        """Return the exact certified adapter through its drift-only capability."""
        return cast("ProviderDriftVectorAdapter", self.get(adapter_id))
