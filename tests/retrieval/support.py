"""Deterministic ADP-006 application doubles and authorized scope fixture."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.retrieval.application.start_session_briefing import (
    DeterministicBriefingRetrievalPipeline,
    StartSessionBriefingHandler,
)
from agentmemory.retrieval.domain.continuity import (
    BriefingBudget,
    ProcedureEnvironment,
    StartSessionBriefingQuery,
)

if TYPE_CHECKING:
    from agentmemory.retrieval.domain.continuity import (
        CodeRevision,
        ContextInjectedEvent,
        ContinuityItem,
        ProcedureCandidate,
    )

CONTEXT_EVENT_ID = "018f0000-0000-7000-8000-000000000199"
BRIEFING_OPERATION_ID = "018f0000-0000-7000-8000-000000000198"
BRIEFING_REQUESTED_AT = datetime(2026, 7, 21, 12, tzinfo=UTC)


def scope() -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId("018f0000-0000-7000-8000-000000000004"),
        principal_id=StableId("018f0000-0000-7000-8000-000000000002"),
        role=RetrievalRole.OWNER,
        mode=RetrievalScopeMode.CURRENT,
        members=(
            ScopeMember(
                StableId("018f0000-0000-7000-8000-000000000010"),
                (StableId("018f0000-0000-7000-8000-000000000020"),),
                (),
            ),
        ),
        classification_ceiling=Classification.LOCAL_ONLY,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action="memory.recall",
        purpose="interactive_recall",
    )


@dataclass
class FakeContinuityRepository:
    items: tuple[ContinuityItem, ...]
    scopes: list[AuthorizedScope] | None = None

    async def list_items(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ContinuityItem, ...]:
        if self.scopes is not None:
            self.scopes.append(authorized_scope)
        return self.items[:candidate_limit]


@dataclass
class FakeProcedureRepository:
    procedures: tuple[ProcedureCandidate, ...]

    async def list_candidates(
        self, authorized_scope: AuthorizedScope, candidate_limit: int
    ) -> tuple[ProcedureCandidate, ...]:
        del authorized_scope
        return self.procedures[:candidate_limit]


@dataclass
class FakeCodeRevisionQuery:
    revisions: tuple[CodeRevision, ...] = ()

    async def current_revisions(
        self, authorized_scope: AuthorizedScope
    ) -> tuple[CodeRevision, ...]:
        del authorized_scope
        return self.revisions


@dataclass
class FakeContextInjectionRepository:
    events: list[ContextInjectedEvent] | None = None

    async def record(
        self,
        authorized_scope: AuthorizedScope,
        event: ContextInjectedEvent,
    ) -> str:
        del authorized_scope
        if self.events is not None:
            self.events.append(event)
        return event.event_id


def briefing_handler(
    items: FakeContinuityRepository,
    procedures: FakeProcedureRepository,
) -> StartSessionBriefingHandler:
    """Compose the full MEM-006 handler around ADP-006 focused doubles."""
    return StartSessionBriefingHandler(
        items,
        FakeContinuityRepository(()),
        FakeCodeRevisionQuery(),
        DeterministicBriefingRetrievalPipeline.production(),
        procedures,
        FakeContextInjectionRepository(),
        lambda: UUID(CONTEXT_EVENT_ID),
    )


def briefing_query(
    authorized_scope: AuthorizedScope,
    budget: BriefingBudget,
    environment: ProcedureEnvironment,
) -> StartSessionBriefingQuery:
    """Build one complete deterministic MEM-006 query for focused tests."""
    return StartSessionBriefingQuery(
        authorized_scope,
        budget,
        environment,
        BRIEFING_OPERATION_ID,
        BRIEFING_REQUESTED_AT,
    )
