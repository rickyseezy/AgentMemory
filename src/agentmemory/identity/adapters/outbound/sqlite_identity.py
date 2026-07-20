"""Brain-scoped SQLite identity query repositories for ID-001."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
)
from agentmemory.identity.domain.value_objects import IdentityCandidate, StableId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from agentmemory.identity.domain.value_objects import (
        DeviceIdentity,
        Fingerprint,
        ProjectManifest,
        VcsIdentity,
    )

_PROJECT_FOR_MANIFEST = """
SELECT p.id AS project_id, pr.repository_id AS repository_id
FROM projects AS p
JOIN project_repositories AS pr ON pr.project_id = p.id
WHERE p.brain_id = :brain_id
  AND p.id = :project_id
  AND p.status = 'active'
  AND (:repository_id IS NULL OR pr.repository_id = :repository_id)
  AND (:repository_fingerprint IS NULL OR EXISTS (
    SELECT 1 FROM repository_fingerprints AS rf
    WHERE rf.brain_id = p.brain_id
      AND rf.repository_id = pr.repository_id
      AND rf.fingerprint = :repository_fingerprint
      AND rf.active = 1
  ))
ORDER BY pr.repository_id
"""

_KNOWN_PROJECT = """
SELECT 1 FROM projects
WHERE brain_id = :brain_id AND id = :project_id AND status = 'active'
"""

_PROJECTS_FOR_REPOSITORIES = """
SELECT p.id AS project_id, pr.repository_id AS repository_id
FROM projects AS p
JOIN project_repositories AS pr ON pr.project_id = p.id
WHERE p.brain_id = :brain_id
  AND p.status = 'active'
  AND pr.repository_id IN (SELECT value FROM json_each(:repository_ids_json))
ORDER BY p.id, pr.repository_id
"""

_CHECKOUT_OBSERVATION = """
SELECT p.id AS project_id, c.repository_id AS repository_id, c.id AS checkout_id
FROM checkouts AS c
JOIN project_repositories AS pr ON pr.repository_id = c.repository_id
JOIN projects AS p ON p.id = pr.project_id AND p.brain_id = c.brain_id
WHERE c.brain_id = :brain_id
  AND c.device_id = :device_id
  AND c.status = 'active'
  AND p.status = 'active'
  AND (c.canonical_path_hash = :path_fingerprint
       OR (:checkout_fingerprint IS NOT NULL
           AND c.checkout_fingerprint = :checkout_fingerprint)
       OR (:file_fingerprint IS NOT NULL
           AND c.file_fingerprint = :file_fingerprint
           AND c.volume_fingerprint = :volume_fingerprint))
ORDER BY p.id, c.repository_id, c.id
"""

_CHECKOUT_HEURISTIC = """
SELECT p.id AS project_id, c.repository_id AS repository_id, c.id AS checkout_id
FROM checkouts AS c
JOIN project_repositories AS pr ON pr.repository_id = c.repository_id
JOIN projects AS p ON p.id = pr.project_id AND p.brain_id = c.brain_id
WHERE c.brain_id = :brain_id
  AND c.device_id = :device_id
  AND c.status = 'active'
  AND p.status = 'active'
  AND EXISTS (
    SELECT 1 FROM checkout_aliases AS a
    WHERE a.checkout_id = c.id
      AND a.brain_id = c.brain_id
      AND a.path_fingerprint = :path_fingerprint
      AND a.approved = 1
  )
ORDER BY p.id, c.repository_id, c.id
"""


@dataclass(frozen=True, slots=True)
class SqliteIdentityAuthorizationPolicy:
    """Authorize identity resolution through the current canonical owner grant."""

    engine: AsyncEngine

    async def authorize_resolution(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        """Deny unless the exact active principal/grant remains valid for the Brain."""
        statement = text(
            "SELECT 1 FROM scope_grants AS g "
            "JOIN principals AS p ON p.id = g.principal_id "
            "JOIN brains AS b ON b.id = g.brain_id "
            "WHERE g.id = :grant_id AND g.principal_id = :actor_id "
            "AND g.brain_id = :brain_id AND g.role = 'owner' "
            "AND p.status = 'active' AND b.status = 'active' "
            "AND g.valid_from <= CAST(strftime('%s','now') AS INTEGER) * 1000000 "
            "AND (g.valid_to IS NULL OR g.valid_to > "
            "CAST(strftime('%s','now') AS INTEGER) * 1000000)"
        )
        try:
            async with self.engine.connect() as connection:
                row = (
                    await connection.execute(
                        statement,
                        {
                            "grant_id": grant_id.value,
                            "actor_id": actor_id.value,
                            "brain_id": brain_id.value,
                        },
                    )
                ).first()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        if row is None:
            raise IdentityAuthorizationError


@dataclass(frozen=True, slots=True)
class SqliteProjectRepository:
    """Read active Project mappings without exposing persistence rows."""

    engine: AsyncEngine

    async def resolve_manifest(
        self,
        brain_id: StableId,
        manifest: ProjectManifest,
        repository_fingerprint: Fingerprint | None,
    ) -> tuple[IdentityCandidate, ...]:
        """Resolve an exact manifest UUID and optional declared Repository UUID."""
        parameters: dict[str, object] = {
            "brain_id": brain_id.value,
            "project_id": manifest.project_id.value,
            "repository_id": (
                None if manifest.repository_id is None else manifest.repository_id.value
            ),
            "repository_fingerprint": (
                None
                if repository_fingerprint is None
                else bytes.fromhex(repository_fingerprint.value)
            ),
        }
        candidates = await self._candidates(_PROJECT_FOR_MANIFEST, parameters)
        if candidates:
            return candidates
        try:
            async with self.engine.connect() as connection:
                known = (await connection.execute(text(_KNOWN_PROJECT), parameters)).first()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        if known is not None:
            raise IdentityConflictError
        return ()

    async def find_by_repository(
        self,
        brain_id: StableId,
        repository_ids: tuple[StableId, ...],
    ) -> tuple[IdentityCandidate, ...]:
        """Resolve Projects for an exact bounded Repository-ID set."""
        if not repository_ids:
            return ()
        return await self._candidates(
            _PROJECTS_FOR_REPOSITORIES,
            {
                "brain_id": brain_id.value,
                "repository_ids_json": json.dumps(
                    [repository_id.value for repository_id in repository_ids]
                ),
            },
        )

    async def _candidates(
        self,
        query: str,
        parameters: dict[str, object],
    ) -> tuple[IdentityCandidate, ...]:
        try:
            async with self.engine.connect() as connection:
                rows = (await connection.execute(text(query), parameters)).mappings().all()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        return tuple(
            IdentityCandidate(
                StableId(str(row["project_id"])),
                StableId(str(row["repository_id"])),
                None,
            )
            for row in rows
        )


@dataclass(frozen=True, slots=True)
class SqliteRepositoryIdentityRepository:
    """Resolve active versioned Repository fingerprint aliases."""

    engine: AsyncEngine

    async def find_by_fingerprint(
        self,
        brain_id: StableId,
        fingerprint: Fingerprint,
    ) -> tuple[StableId, ...]:
        """Return deterministic Repository IDs inside the exact Brain."""
        try:
            async with self.engine.connect() as connection:
                rows = (
                    await connection.execute(
                        text(
                            "SELECT repository_id FROM repository_fingerprints "
                            "WHERE brain_id = :brain_id AND fingerprint = :fingerprint "
                            "AND active = 1 ORDER BY repository_id"
                        ),
                        {
                            "brain_id": brain_id.value,
                            "fingerprint": bytes.fromhex(fingerprint.value),
                        },
                    )
                ).all()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        return tuple(StableId(str(row[0])) for row in rows)


@dataclass(frozen=True, slots=True)
class SqliteCheckoutRepository:
    """Resolve exact Checkout observations and explicitly approved continuity aliases."""

    engine: AsyncEngine

    async def find_by_observation(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        checkout_fingerprint: Fingerprint | None,
    ) -> tuple[IdentityCandidate, ...]:
        """Match the keyed canonical path or exact VCS checkout fingerprint."""
        return await self._candidates(
            _CHECKOUT_OBSERVATION,
            {
                "brain_id": brain_id.value,
                "device_id": device.device_id.value,
                "path_fingerprint": bytes.fromhex(device.path_fingerprint.value),
                "checkout_fingerprint": (
                    None
                    if checkout_fingerprint is None
                    else bytes.fromhex(checkout_fingerprint.value)
                ),
                "file_fingerprint": (
                    None
                    if device.file_fingerprint is None
                    else bytes.fromhex(device.file_fingerprint.value)
                ),
                "volume_fingerprint": bytes.fromhex(device.volume_fingerprint.value),
            },
        )

    async def find_approved_heuristic(
        self,
        brain_id: StableId,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
    ) -> tuple[IdentityCandidate, ...]:
        """Use only an owner-approved path alias; names/content never participate."""
        del vcs
        return await self._candidates(
            _CHECKOUT_HEURISTIC,
            {
                "brain_id": brain_id.value,
                "device_id": device.device_id.value,
                "path_fingerprint": bytes.fromhex(device.path_fingerprint.value),
            },
        )

    async def _candidates(
        self,
        query: str,
        parameters: dict[str, object],
    ) -> tuple[IdentityCandidate, ...]:
        try:
            async with self.engine.connect() as connection:
                rows = (await connection.execute(text(query), parameters)).mappings().all()
        except SQLAlchemyError as error:
            raise IdentityDependencyError from error
        return tuple(
            IdentityCandidate(
                StableId(str(row["project_id"])),
                StableId(str(row["repository_id"])),
                StableId(str(row["checkout_id"])),
            )
            for row in rows
        )
