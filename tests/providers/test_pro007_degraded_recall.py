"""PRO-007 recall continues without an unavailable semantic provider channel."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderPermanentFailureError,
    ProviderResilienceConflictError,
    ProviderRetryScheduledError,
)
from agentmemory.resilience.application.recall import RecallQueryHandler
from agentmemory.resilience.domain.errors import RecallIntegrityError
from agentmemory.resilience.domain.models import (
    ChannelName,
    DependencyName,
    RecallChannelSuccess,
    RecallQuery,
)
from agentmemory.resilience.infrastructure.in_memory_health import (
    InMemoryDependencyHealthRepository,
)
from agentmemory.resilience.infrastructure.provider_recall import ProviderRecallSource
from tests.resilience.test_pf004_recall import (
    Authorization,
    Clock,
    Source,
    execution_policy,
    query,
)


@dataclass(slots=True)
class _FailingProviderSource:
    error: Exception
    channel: ChannelName = ChannelName.VECTOR
    dependency: DependencyName = DependencyName.EMBEDDING

    async def recall(self, request: RecallQuery) -> RecallChannelSuccess:
        del request
        raise self.error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        ProviderRetryScheduledError(ProviderErrorCode.TIMEOUT, 1),
        ProviderPermanentFailureError(ProviderErrorCode.QUOTA),
    ],
)
async def test_recall_returns_exact_lexical_and_graph_with_missing_vector_disclosed(
    error: Exception,
) -> None:
    vector = ProviderRecallSource(_FailingProviderSource(error))
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(
            Source(ChannelName.EXACT, DependencyName.CANONICAL_LEDGER),
            Source(ChannelName.LEXICAL, DependencyName.NONCANONICAL_WORKER),
            vector,
            Source(ChannelName.GRAPH, DependencyName.NEO4J),
        ),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy(
            {
                ChannelName.EXACT: 0.1,
                ChannelName.LEXICAL: 0.1,
                ChannelName.VECTOR: 0.1,
                ChannelName.GRAPH: 0.1,
            }
        ),
        clock=Clock(),
    )

    response = await handler.execute(query("pro007-degraded-recall"))

    assert tuple(item.candidate_id for item in response.candidates) == (
        "exact-1",
        "graph-1",
        "lexical-1",
    )
    assert response.degraded_channels == (ChannelName.VECTOR,)
    assert response.outcomes[ChannelName.VECTOR].code == "AM_DEPENDENCY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_divergent_fallback_evidence_fails_recall_instead_of_degrading() -> None:
    vector = ProviderRecallSource(
        _FailingProviderSource(ProviderResilienceConflictError("provider evidence diverged"))
    )
    handler = RecallQueryHandler.create(
        authorization=Authorization(),
        sources=(vector,),
        health=InMemoryDependencyHealthRepository(),
        execution_policy=execution_policy({ChannelName.VECTOR: 0.1}),
        clock=Clock(),
    )

    with pytest.raises(RecallIntegrityError, match="provider recall evidence diverged"):
        await handler.execute(query("pro007-integrity"))
