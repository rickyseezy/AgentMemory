"""ID-004 Brain-scoped SQLite authorization and evidence-graph adapters."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityDependencyError,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizationSnapshot,
    Classification,
    ProjectBinding,
    RelatedProject,
    RetrievalGrant,
    RetrievalRole,
)
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncEngine

_MAX_GRAPH_PROJECTS = 500

_ACTIVE_GRANTS = """
SELECT g.id, g.role, g.project_id, g.repository_id, g.version,
       b.version AS policy_version, i.security_epoch
FROM scope_grants AS requested
JOIN principals AS p ON p.id = requested.principal_id
JOIN brains AS b ON b.id = requested.brain_id
JOIN installation_state AS i ON i.singleton_key = 'local'
JOIN scope_grants AS g
  ON g.principal_id = requested.principal_id AND g.brain_id = requested.brain_id
WHERE requested.id = :grant_id
  AND requested.principal_id = :actor_id
  AND requested.brain_id = :brain_id
  AND requested.valid_from <= :at
  AND (requested.valid_to IS NULL OR requested.valid_to > :at)
  AND g.valid_from <= :at AND (g.valid_to IS NULL OR g.valid_to > :at)
  AND p.status = 'active' AND b.status = 'active'
ORDER BY g.id
"""

_ACTIVE_BINDINGS = """
SELECT p.id AS project_id, pr.repository_id, c.id AS checkout_id
FROM projects AS p
JOIN project_repositories AS pr ON pr.project_id = p.id
JOIN repositories AS r ON r.id = pr.repository_id AND r.brain_id = p.brain_id
LEFT JOIN checkouts AS c
  ON c.repository_id = r.id AND c.brain_id = p.brain_id AND c.status = 'active'
WHERE p.brain_id = :brain_id AND p.status = 'active' AND r.status = 'active'
  AND EXISTS (
    SELECT 1 FROM scope_grants AS authorized
    WHERE authorized.principal_id = :actor_id
      AND authorized.brain_id = p.brain_id
      AND authorized.role IN ('owner','admin','editor','reader')
      AND authorized.valid_from <= :at
      AND (authorized.valid_to IS NULL OR authorized.valid_to > :at)
      AND (authorized.project_id IS NULL OR authorized.project_id = p.id)
      AND (authorized.repository_id IS NULL OR authorized.repository_id = pr.repository_id)
  )
ORDER BY p.id, pr.repository_id, c.id
"""


@dataclass(frozen=True, slots=True)
class SqliteRetrievalScopeAuthorizationRepository:
    """Load one current grant snapshot before any retrieval-related operation."""

    engine: AsyncEngine

    async def snapshot(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
        at: int,
    ) -> AuthorizationSnapshot:
        """Return active grants and canonical bindings from one read transaction."""
        try:
            async with self.engine.connect() as connection:
                grants = (
                    (
                        await connection.execute(
                            text(_ACTIVE_GRANTS),
                            {
                                "grant_id": grant_id.value,
                                "actor_id": actor_id.value,
                                "brain_id": brain_id.value,
                                "at": at,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
                _require_grants(grants)
                rows = (
                    (
                        await connection.execute(
                            text(_ACTIVE_BINDINGS),
                            {
                                "brain_id": brain_id.value,
                                "actor_id": actor_id.value,
                                "at": at,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
        except IdentityAuthorizationError:
            raise
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        grant_values = tuple(
            RetrievalGrant(
                StableId(str(row["id"])),
                RetrievalRole(str(row["role"])),
                _stable_id(row["project_id"]),
                _stable_id(row["repository_id"]),
                int(str(row["version"])),
            )
            for row in grants
        )
        return AuthorizationSnapshot(
            brain_id,
            actor_id,
            grant_values,
            _bindings(brain_id, rows),
            Classification.LOCAL_ONLY,
            int(str(grants[0]["policy_version"])),
            int(str(grants[0]["security_epoch"])),
        )


@dataclass(frozen=True, slots=True)
class SqliteRelatedProjectGraph:
    """Traverse the active repository-topology graph with preauthorized IDs only."""

    engine: AsyncEngine

    async def expand(
        self,
        brain_id: StableId,
        seed_project_id: StableId,
        allowed_project_ids: tuple[StableId, ...],
        max_depth: int,
        max_cost: int,
    ) -> tuple[RelatedProject, ...]:
        """Return shortest authorized Project paths, bounded and cycle-safe."""
        if seed_project_id not in allowed_project_ids:
            raise IdentityAuthorizationError
        allowed_json = json.dumps([item.value for item in allowed_project_ids])
        try:
            async with self.engine.connect() as connection:
                mappings = (
                    (
                        await connection.execute(
                            text(
                                "SELECT p.id AS project_id, pr.repository_id "
                                "FROM projects p JOIN project_repositories pr "
                                "ON pr.project_id=p.id "
                                "JOIN repositories r ON r.id=pr.repository_id "
                                "WHERE p.brain_id=:brain AND r.brain_id=:brain "
                                "AND p.status='active' AND r.status='active' "
                                "AND p.id IN (SELECT value FROM json_each(:allowed))"
                            ),
                            {"brain": brain_id.value, "allowed": allowed_json},
                        )
                    )
                    .mappings()
                    .all()
                )
                links = (
                    (
                        await connection.execute(
                            text(
                                "WITH allowed_repositories AS ("
                                "SELECT pr.repository_id FROM projects p "
                                "JOIN project_repositories pr ON pr.project_id=p.id "
                                "JOIN repositories r ON r.id=pr.repository_id "
                                "WHERE p.brain_id=:brain AND r.brain_id=:brain "
                                "AND p.status='active' AND r.status='active' "
                                "AND p.id IN (SELECT value FROM json_each(:allowed))) "
                                "SELECT subject_id,target_id FROM repository_topology_links "
                                "WHERE brain_id=:brain AND status='active' "
                                "AND subject_type='repository' AND target_type='repository' "
                                "AND subject_id IN (SELECT repository_id "
                                "FROM allowed_repositories) "
                                "AND target_id IN (SELECT repository_id "
                                "FROM allowed_repositories)"
                            ),
                            {"brain": brain_id.value, "allowed": allowed_json},
                        )
                    )
                    .mappings()
                    .all()
                )
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        adjacency = _project_adjacency(mappings, links)
        found: dict[str, tuple[int, int]] = {}
        queue: deque[tuple[str, int, int]] = deque([(seed_project_id.value, 0, 0)])
        visited = {seed_project_id.value}
        while queue and len(visited) <= _MAX_GRAPH_PROJECTS:
            project, depth, cost = queue.popleft()
            if depth >= max_depth or cost >= max_cost:
                continue
            for neighbor in sorted(adjacency.get(project, ())):
                next_depth, next_cost = depth + 1, cost + 1
                if next_cost > max_cost or neighbor in visited:
                    continue
                visited.add(neighbor)
                found[neighbor] = (next_depth, next_cost)
                queue.append((neighbor, next_depth, next_cost))
        return tuple(
            RelatedProject(StableId(project), depth, cost, "repository_topology")
            for project, (depth, cost) in sorted(
                found.items(), key=lambda item: (item[1][1], item[1][0], item[0])
            )
        )


def _stable_id(value: object) -> StableId | None:
    return None if value is None else StableId(str(value))


def _require_grants(grants: Sequence[RowMapping]) -> None:
    if not grants:
        raise IdentityAuthorizationError


def _bindings(brain_id: StableId, rows: Sequence[RowMapping]) -> tuple[ProjectBinding, ...]:
    repositories: dict[str, set[str]] = defaultdict(set)
    checkouts: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        project = str(row["project_id"])
        repositories[project].add(str(row["repository_id"]))
        if row["checkout_id"] is not None:
            checkouts[project].add(str(row["checkout_id"]))
    return tuple(
        ProjectBinding(
            brain_id,
            StableId(project),
            tuple(StableId(value) for value in sorted(repositories[project])),
            tuple(StableId(value) for value in sorted(checkouts[project])),
        )
        for project in sorted(repositories)
    )


def _project_adjacency(
    mappings: Sequence[RowMapping], links: Sequence[RowMapping]
) -> dict[str, set[str]]:
    repositories_by_project: dict[str, set[str]] = defaultdict(set)
    projects_by_repository: dict[str, set[str]] = defaultdict(set)
    for item in mappings:
        project = str(item["project_id"])
        repository = str(item["repository_id"])
        repositories_by_project[project].add(repository)
        projects_by_repository[repository].add(project)
    repository_neighbors: dict[str, set[str]] = defaultdict(set)
    for item in links:
        subject = str(item["subject_id"])
        target = str(item["target_id"])
        repository_neighbors[subject].add(target)
        repository_neighbors[target].add(subject)
    adjacency: dict[str, set[str]] = defaultdict(set)
    for project, project_repositories in repositories_by_project.items():
        candidate_repositories = set(project_repositories)
        for repository in project_repositories:
            candidate_repositories.update(repository_neighbors[repository])
        for repository in candidate_repositories:
            for neighbor in projects_by_repository[repository]:
                if neighbor != project:
                    adjacency[project].add(neighbor)
    return adjacency
