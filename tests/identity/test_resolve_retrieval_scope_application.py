"""ID-004 retrieval-scope authorization and graph-expansion tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeHandler,
    ResolveRetrievalScopeQuery,
)
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizationSnapshot,
    Classification,
    ProjectBinding,
    RelatedProject,
    RetrievalGrant,
    RetrievalRole,
    RetrievalScopeMode,
)
from agentmemory.identity.domain.value_objects import StableId

BRAIN = StableId("018f0000-0000-7000-8000-000000000001")
OTHER_BRAIN = StableId("018f0000-0000-7000-8000-000000000099")
ACTOR = StableId("018f0000-0000-7000-8000-000000000002")
GRANT = StableId("018f0000-0000-7000-8000-000000000003")
P1 = StableId("018f0000-0000-7000-8000-000000000010")
P2 = StableId("018f0000-0000-7000-8000-000000000011")
P3 = StableId("018f0000-0000-7000-8000-000000000012")
R1 = StableId("018f0000-0000-7000-8000-000000000020")
R2 = StableId("018f0000-0000-7000-8000-000000000021")
C1 = StableId("018f0000-0000-7000-8000-000000000030")


def _bindings() -> tuple[ProjectBinding, ...]:
    return (
        ProjectBinding(BRAIN, P1, (R1,), (C1,)),
        ProjectBinding(BRAIN, P2, (R2,), ()),
        ProjectBinding(BRAIN, P3, (R2,), ()),
    )


def _graph_calls() -> list[tuple[int, int, tuple[StableId, ...]]]:
    return []


@dataclass(slots=True)
class _Authorization:
    role: RetrievalRole = RetrievalRole.OWNER
    project_id: StableId | None = None
    repository_id: StableId | None = None
    version: int = 1
    extra_grants: tuple[RetrievalGrant, ...] = ()
    calls: int = 0

    async def snapshot(
        self, brain_id: StableId, actor_id: StableId, grant_id: StableId, at: int
    ) -> AuthorizationSnapshot:
        del at
        self.calls += 1
        if brain_id != BRAIN or actor_id != ACTOR or grant_id != GRANT:
            raise IdentityAuthorizationError
        return AuthorizationSnapshot(
            brain_id,
            actor_id,
            (
                RetrievalGrant(
                    GRANT,
                    self.role,
                    self.project_id,
                    self.repository_id,
                    self.version,
                ),
                *self.extra_grants,
            ),
            _bindings(),
            Classification.LOCAL_ONLY,
            4,
            9,
        )


@dataclass(slots=True)
class _Graph:
    results: tuple[RelatedProject, ...] = ()
    calls: list[tuple[int, int, tuple[StableId, ...]]] = field(default_factory=_graph_calls)

    async def expand(
        self,
        brain_id: StableId,
        seed_project_id: StableId,
        allowed_project_ids: tuple[StableId, ...],
        max_depth: int,
        max_cost: int,
    ) -> tuple[RelatedProject, ...]:
        assert brain_id == BRAIN
        assert seed_project_id == P1
        self.calls.append((max_depth, max_cost, allowed_project_ids))
        return self.results


def _query(
    mode: RetrievalScopeMode,
    *,
    brain: StableId = BRAIN,
    selected: tuple[StableId, ...] = (),
) -> ResolveRetrievalScopeQuery:
    return ResolveRetrievalScopeQuery(
        operation_id="scope-1",
        brain_id=brain,
        actor_id=ACTOR,
        grant_id=GRANT,
        mode=mode,
        current_project_id=P1,
        current_repository_id=R1,
        current_checkout_id=C1,
        selected_project_ids=selected,
        at=100,
        max_related_depth=3,
        max_related_cost=10,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("role", list(RetrievalRole))
@pytest.mark.parametrize("mode", list(RetrievalScopeMode))
async def test_full_role_scope_matrix(role: RetrievalRole, mode: RetrievalScopeMode) -> None:
    authorization = _Authorization(role=role)
    graph = _Graph((RelatedProject(P2, 1, 1, "repository_topology"),))
    selected = (P2,) if mode in {RetrievalScopeMode.SELECTED, RetrievalScopeMode.GLOBAL} else ()
    handler = ResolveRetrievalScopeHandler(authorization, graph)
    allowed = role in {
        RetrievalRole.OWNER,
        RetrievalRole.ADMIN,
        RetrievalRole.EDITOR,
        RetrievalRole.READER,
    } and not (
        mode is RetrievalScopeMode.GLOBAL and role not in {RetrievalRole.OWNER, RetrievalRole.ADMIN}
    )
    if not allowed:
        with pytest.raises(IdentityAuthorizationError):
            await handler.execute(_query(mode, selected=selected))
        return
    result = await handler.execute(_query(mode, selected=selected))
    assert result.scope.brain_id == BRAIN
    assert result.scope.mode is mode


@pytest.mark.asyncio
async def test_current_is_exact_and_selected_is_explicit() -> None:
    handler = ResolveRetrievalScopeHandler(_Authorization(), _Graph())
    current = await handler.execute(_query(RetrievalScopeMode.CURRENT))
    assert current.scope.project_ids == (P1,)
    assert current.scope.repository_ids == (R1,)
    assert current.scope.checkout_ids == (C1,)
    with pytest.raises(IdentityValidationError):
        await handler.execute(_query(RetrievalScopeMode.SELECTED))


@pytest.mark.asyncio
async def test_related_intersects_authorization_and_preserves_bounds_and_boost() -> None:
    graph = _Graph(
        (
            RelatedProject(P2, 1, 2, "repository_topology"),
            RelatedProject(P3, 4, 12, "repository_topology"),
        )
    )
    result = await ResolveRetrievalScopeHandler(_Authorization(), graph).execute(
        _query(RetrievalScopeMode.RELATED)
    )
    assert result.scope.project_ids == (P1, P2)
    assert result.scope.members[0].project_id == P1
    assert result.scope.members[0].rank_boost_micros == 1_000_000
    assert graph.calls == [(3, 10, (P1, P2, P3))]


@pytest.mark.asyncio
async def test_cross_brain_and_ambiguous_current_binding_are_rejected() -> None:
    handler = ResolveRetrievalScopeHandler(_Authorization(), _Graph())
    with pytest.raises(IdentityAuthorizationError):
        await handler.execute(_query(RetrievalScopeMode.CURRENT, brain=OTHER_BRAIN))
    ambiguous = ResolveRetrievalScopeQuery(
        "scope-2", BRAIN, ACTOR, GRANT, RetrievalScopeMode.CURRENT, P1, None, None, (), 100
    )
    with pytest.raises(IdentityConflictError):
        await handler.execute(ambiguous)


@pytest.mark.asyncio
async def test_narrow_grant_cannot_select_another_project_and_revocation_changes_key() -> None:
    first = await ResolveRetrievalScopeHandler(
        _Authorization(project_id=P1, version=1), _Graph()
    ).execute(_query(RetrievalScopeMode.CURRENT))
    second = await ResolveRetrievalScopeHandler(
        _Authorization(project_id=P1, version=2), _Graph()
    ).execute(_query(RetrievalScopeMode.CURRENT))
    assert first.scope.cache_key != second.scope.cache_key
    with pytest.raises(IdentityAuthorizationError):
        await ResolveRetrievalScopeHandler(_Authorization(project_id=P1), _Graph()).execute(
            _query(RetrievalScopeMode.SELECTED, selected=(P2,))
        )


@pytest.mark.asyncio
async def test_broad_reader_grant_cannot_launder_narrow_admin_global_permission() -> None:
    broad_reader = RetrievalGrant(
        StableId("018f0000-0000-7000-8000-000000000004"),
        RetrievalRole.READER,
        None,
        None,
        1,
    )
    authorization = _Authorization(
        role=RetrievalRole.ADMIN,
        project_id=P1,
        extra_grants=(broad_reader,),
    )
    with pytest.raises(IdentityAuthorizationError):
        await ResolveRetrievalScopeHandler(authorization, _Graph()).execute(
            _query(RetrievalScopeMode.GLOBAL, selected=(P2,))
        )


@pytest.mark.asyncio
async def test_session_global_derives_all_authorized_projects_without_caller_ids() -> None:
    authorization = _Authorization()
    handler = ResolveRetrievalScopeHandler(authorization, _Graph())

    result = await handler.execute_session_scoped(_query(RetrievalScopeMode.GLOBAL))

    assert result.scope.mode is RetrievalScopeMode.GLOBAL
    assert result.scope.project_ids == (P1, P2, P3)
    assert authorization.calls == 1


@pytest.mark.asyncio
async def test_session_scope_rejects_selected_or_caller_supplied_projects() -> None:
    handler = ResolveRetrievalScopeHandler(_Authorization(), _Graph())
    with pytest.raises(IdentityValidationError):
        await handler.execute_session_scoped(_query(RetrievalScopeMode.SELECTED, selected=(P1,)))
    with pytest.raises(IdentityValidationError):
        await handler.execute_session_scoped(_query(RetrievalScopeMode.CURRENT, selected=(P2,)))


@pytest.mark.asyncio
async def test_session_global_requires_owner_or_admin() -> None:
    handler = ResolveRetrievalScopeHandler(
        _Authorization(role=RetrievalRole.READER),
        _Graph(),
    )
    with pytest.raises(IdentityAuthorizationError):
        await handler.execute_session_scoped(_query(RetrievalScopeMode.GLOBAL))
