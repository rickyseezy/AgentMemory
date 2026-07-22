"""PF-003 Liskov substitution and kind-safe runtime registry tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.extensions.adapters.runtime_registry import ExternalAdapterRuntimeRegistry
from agentmemory.extensions.domain.errors import AdapterConflictError, AdapterValidationError
from agentmemory.extensions.domain.models import AdapterKind

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.agent_event import AgentEvent


@dataclass
class AgentAdapter:
    identity: str = "first"
    calls: int = 0

    async def execute(self, event: object) -> object:
        self.calls += 1
        return event


@dataclass
class ProviderAdapter:
    manifest: object

    async def probe(self, profile: object) -> object:
        return profile


def test_pf003_registry_resolves_by_kind_without_vendor_switches() -> None:
    agent = AgentAdapter()
    provider = ProviderAdapter(manifest=object())
    registry = ExternalAdapterRuntimeRegistry()

    registry.register("community-agent", AdapterKind.AGENT, agent)
    registry.register("community-provider", AdapterKind.PROVIDER, provider)

    assert cast("object", registry.agent("community-agent")) is agent
    assert cast("object", registry.provider("community-provider")) is provider


def test_pf003_registry_rejects_wrong_kind_duplicate_and_missing_runtime() -> None:
    registry = ExternalAdapterRuntimeRegistry()
    registry.register("community-agent", AdapterKind.AGENT, AgentAdapter())

    with pytest.raises(AdapterValidationError, match="kind"):
        registry.provider("community-agent")
    with pytest.raises(AdapterConflictError, match="duplicate"):
        registry.register("community-agent", AdapterKind.AGENT, AgentAdapter())
    with pytest.raises(AdapterValidationError, match="conformance"):
        registry.register("broken", AdapterKind.AGENT, object())
    with pytest.raises(AdapterValidationError, match="not registered"):
        registry.agent("missing")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identity",
    ["first", "second"],
)
async def test_pf003_agent_implementations_are_liskov_substitutable(
    identity: str,
) -> None:
    implementation = AgentAdapter(identity=identity)
    registry = ExternalAdapterRuntimeRegistry()
    registry.register("external", AdapterKind.AGENT, implementation)

    event = cast("AgentEvent", object())
    await registry.agent("external").execute(event)
    assert implementation.calls == 1
