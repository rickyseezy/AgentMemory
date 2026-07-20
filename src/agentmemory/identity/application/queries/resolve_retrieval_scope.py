"""ID-004 authorization-first retrieval-scope resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizationSnapshot,
    AuthorizedScope,
    ProjectBinding,
    RelatedProject,
    RetrievalRole,
    RetrievalScopeMode,
    RetrievalScopeResolution,
    ScopeExplanation,
    ScopeMember,
    TemporalScope,
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.value_objects import StableId

_OPERATION = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_RELATED_DEPTH = 3
_MAX_RELATED_COST = 100
_MAX_SELECTED_PROJECTS = 500
_CURRENT_BOOST_MICROS = 1_000_000
_RECALL_ROLES = frozenset(
    {RetrievalRole.OWNER, RetrievalRole.ADMIN, RetrievalRole.EDITOR, RetrievalRole.READER}
)
_GLOBAL_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})


class RetrievalScopeAuthorizationRepository(Protocol):
    """Load an authorization snapshot before any graph or search access."""

    async def snapshot(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
        at: int,
    ) -> AuthorizationSnapshot:
        """Return current grants, canonical bindings, and security epochs."""
        ...


class RelatedProjectGraphPort(Protocol):
    """Expand only an already-authorized evidence graph within fixed bounds."""

    async def expand(
        self,
        brain_id: StableId,
        seed_project_id: StableId,
        allowed_project_ids: tuple[StableId, ...],
        max_depth: int,
        max_cost: int,
    ) -> tuple[RelatedProject, ...]:
        """Return only evidence-backed related Projects inside allowed IDs."""
        ...


@dataclass(frozen=True, slots=True)
class ResolveRetrievalScopeQuery:
    """Explicit retrieval scope request; absence never means global."""

    operation_id: str
    brain_id: StableId
    actor_id: StableId
    grant_id: StableId
    mode: RetrievalScopeMode
    current_project_id: StableId | None
    current_repository_id: StableId | None
    current_checkout_id: StableId | None
    selected_project_ids: tuple[StableId, ...]
    at: int
    max_related_depth: int = 3
    max_related_cost: int = 10
    temporal_from: int | None = None
    temporal_to: int | None = None

    def __post_init__(self) -> None:
        """Bound every request before repository access."""
        if _OPERATION.fullmatch(self.operation_id) is None or self.at < 1:
            msg = "retrieval scope request is invalid"
            raise IdentityValidationError(msg)
        if (
            not 1 <= self.max_related_depth <= _MAX_RELATED_DEPTH
            or not 1 <= self.max_related_cost <= _MAX_RELATED_COST
        ):
            msg = "related scope bounds are invalid"
            raise IdentityValidationError(msg)
        if len(self.selected_project_ids) > _MAX_SELECTED_PROJECTS or len(
            set(self.selected_project_ids)
        ) != len(self.selected_project_ids):
            msg = "selected Project IDs are invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class ResolveRetrievalScopeHandler:
    """Resolve grants and exact IDs before permitting graph traversal or retrieval."""

    authorization: RetrievalScopeAuthorizationRepository
    graph: RelatedProjectGraphPort

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        """Authorize, select, and seal one explicit retrieval scope."""
        snapshot = await self.authorization.snapshot(
            query.brain_id, query.actor_id, query.grant_id, query.at
        )
        if snapshot.brain_id != query.brain_id or snapshot.principal_id != query.actor_id:
            raise IdentityAuthorizationError
        role = self._effective_role(snapshot)
        if role not in _RECALL_ROLES:
            raise IdentityAuthorizationError
        if query.mode is RetrievalScopeMode.GLOBAL and role not in _GLOBAL_ROLES:
            raise IdentityAuthorizationError
        binding_roles = _GLOBAL_ROLES if query.mode is RetrievalScopeMode.GLOBAL else _RECALL_ROLES
        bindings = self._authorized_bindings(snapshot, binding_roles)
        if query.mode is RetrievalScopeMode.CURRENT:
            members, reasons = self._current(query, bindings)
        elif query.mode is RetrievalScopeMode.RELATED:
            members, reasons = await self._related(query, bindings)
        else:
            members, reasons = self._selected(query, bindings)
        scope = AuthorizedScope.create(
            brain_id=query.brain_id,
            principal_id=query.actor_id,
            role=role,
            mode=query.mode,
            members=members,
            classification_ceiling=snapshot.classification_ceiling,
            temporal_scope=TemporalScope(query.temporal_from, query.temporal_to),
            grant_version=snapshot.grant_version,
            policy_version=snapshot.policy_version,
            security_epoch=snapshot.security_epoch,
            action="memory.recall",
            purpose="interactive_recall",
        )
        return RetrievalScopeResolution(scope, ScopeExplanation(query.mode, reasons))

    @staticmethod
    def _effective_role(snapshot: AuthorizationSnapshot) -> RetrievalRole:
        order = {
            RetrievalRole.OWNER: 0,
            RetrievalRole.ADMIN: 1,
            RetrievalRole.EDITOR: 2,
            RetrievalRole.READER: 3,
            RetrievalRole.AUDITOR: 4,
            RetrievalRole.ADAPTER: 5,
            RetrievalRole.WORKER: 6,
        }
        return min((grant.role for grant in snapshot.grants), key=order.__getitem__)

    @staticmethod
    def _authorized_bindings(
        snapshot: AuthorizationSnapshot,
        allowed_roles: frozenset[RetrievalRole],
    ) -> tuple[ProjectBinding, ...]:
        allowed: list[ProjectBinding] = []
        for binding in snapshot.bindings:
            repositories: set[StableId] = set()
            for grant in snapshot.grants:
                if grant.role not in allowed_roles:
                    continue
                if grant.project_id is not None and grant.project_id != binding.project_id:
                    continue
                repositories.update(
                    binding.repository_ids
                    if grant.repository_id is None
                    else (grant.repository_id,)
                )
            scoped = tuple(
                sorted(
                    repositories.intersection(binding.repository_ids), key=lambda item: item.value
                )
            )
            if scoped:
                allowed.append(
                    ProjectBinding(
                        binding.brain_id,
                        binding.project_id,
                        scoped,
                        binding.checkout_ids,
                    )
                )
        return tuple(sorted(allowed, key=lambda item: item.project_id.value))

    @staticmethod
    def _current(
        query: ResolveRetrievalScopeQuery,
        bindings: tuple[ProjectBinding, ...],
    ) -> tuple[tuple[ScopeMember, ...], tuple[str, ...]]:
        if query.current_project_id is None or query.current_repository_id is None:
            msg = "current retrieval scope is ambiguous"
            raise IdentityConflictError(msg)
        binding = next(
            (item for item in bindings if item.project_id == query.current_project_id), None
        )
        if binding is None or query.current_repository_id not in binding.repository_ids:
            raise IdentityAuthorizationError
        checkouts: tuple[StableId, ...] = ()
        if query.current_checkout_id is not None:
            if query.current_checkout_id not in binding.checkout_ids:
                raise IdentityAuthorizationError
            checkouts = (query.current_checkout_id,)
        member = ScopeMember(
            binding.project_id, (query.current_repository_id,), checkouts, _CURRENT_BOOST_MICROS
        )
        return (member,), (f"current:{binding.project_id.value}",)

    async def _related(
        self,
        query: ResolveRetrievalScopeQuery,
        bindings: tuple[ProjectBinding, ...],
    ) -> tuple[tuple[ScopeMember, ...], tuple[str, ...]]:
        current, reasons = self._current(query, bindings)
        allowed_ids = tuple(item.project_id for item in bindings)
        related = await self.graph.expand(
            query.brain_id,
            current[0].project_id,
            allowed_ids,
            query.max_related_depth,
            query.max_related_cost,
        )
        by_project = {item.project_id: item for item in bindings}
        accepted: dict[StableId, RelatedProject] = {}
        for candidate in related:
            if (
                candidate.project_id in by_project
                and candidate.project_id != current[0].project_id
                and candidate.depth <= query.max_related_depth
                and candidate.cost <= query.max_related_cost
            ):
                previous = accepted.get(candidate.project_id)
                if previous is None or (candidate.cost, candidate.depth) < (
                    previous.cost,
                    previous.depth,
                ):
                    accepted[candidate.project_id] = candidate
        ordered = sorted(
            accepted.values(), key=lambda item: (item.cost, item.depth, item.project_id.value)
        )
        members = list(current)
        explanation = list(reasons)
        for relation in ordered:
            binding = by_project[relation.project_id]
            members.append(ScopeMember(binding.project_id, binding.repository_ids, (), 0))
            explanation.append(f"related:{binding.project_id.value}:{relation.evidence}")
        return tuple(members), tuple(explanation)

    @staticmethod
    def _selected(
        query: ResolveRetrievalScopeQuery,
        bindings: tuple[ProjectBinding, ...],
    ) -> tuple[tuple[ScopeMember, ...], tuple[str, ...]]:
        if not query.selected_project_ids:
            msg = "selected and global scopes require explicit Projects"
            raise IdentityValidationError(msg)
        by_project = {item.project_id: item for item in bindings}
        if any(project_id not in by_project for project_id in query.selected_project_ids):
            raise IdentityAuthorizationError
        ordered = sorted(query.selected_project_ids, key=lambda item: item.value)
        members = tuple(
            ScopeMember(
                by_project[project_id].project_id, by_project[project_id].repository_ids, ()
            )
            for project_id in ordered
        )
        reasons = tuple(f"{query.mode.value}:{project_id.value}" for project_id in ordered)
        return members, reasons
