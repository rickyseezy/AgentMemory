"""Kind-safe composition registry for public agent and provider adapter ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from agentmemory.extensions.domain.errors import AdapterConflictError, AdapterValidationError
from agentmemory.extensions.domain.models import AdapterKind

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.ports import AgentAdapterPort
    from agentmemory.providers.domain.profile_ports import ProviderAdapterPort

_ERR_DUPLICATE = "duplicate runtime registration"
_ERR_CONFORMANCE = "runtime conformance failed"
_ERR_MISSING = "runtime is not registered"
_ERR_KIND = "runtime kind does not match requested port"


@dataclass(frozen=True, slots=True)
class _RuntimeBinding:
    kind: AdapterKind
    implementation: object


class ExternalAdapterRuntimeRegistry:
    """Resolve approved implementations solely by adapter ID and declared kind."""

    def __init__(self) -> None:
        """Create one initially empty installation-scoped registry."""
        self._bindings: dict[str, _RuntimeBinding] = {}

    def register(self, adapter_id: str, kind: AdapterKind, implementation: object) -> None:
        """Register one structurally conforming implementation exactly once."""
        if adapter_id in self._bindings:
            raise AdapterConflictError(_ERR_DUPLICATE)
        if kind is AdapterKind.AGENT:
            valid = callable(getattr(implementation, "execute", None))
        else:
            valid = hasattr(implementation, "manifest") and callable(
                getattr(implementation, "probe", None)
            )
        if not valid:
            raise AdapterValidationError(_ERR_CONFORMANCE)
        self._bindings[adapter_id] = _RuntimeBinding(kind, implementation)

    def agent(self, adapter_id: str) -> AgentAdapterPort:
        """Return one agent implementation without vendor branching."""
        binding = self._resolve(adapter_id, AdapterKind.AGENT)
        return cast("AgentAdapterPort", binding.implementation)

    def provider(self, adapter_id: str) -> ProviderAdapterPort:
        """Return one provider implementation without vendor branching."""
        binding = self._resolve(adapter_id, AdapterKind.PROVIDER)
        return cast("ProviderAdapterPort", binding.implementation)

    def _resolve(self, adapter_id: str, expected: AdapterKind) -> _RuntimeBinding:
        try:
            binding = self._bindings[adapter_id]
        except KeyError as error:
            raise AdapterValidationError(_ERR_MISSING) from error
        if binding.kind is not expected:
            raise AdapterValidationError(_ERR_KIND)
        return binding
