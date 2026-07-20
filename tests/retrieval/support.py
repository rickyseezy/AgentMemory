"""Deterministic ADP-006 application doubles and authorized scope fixture."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from agentmemory.retrieval.domain.continuity import ContinuityItem, ProcedureCandidate


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
