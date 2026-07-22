"""PF-005 canonical workspace scope resolution from governed identity evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSessionRegistration,
    McpWorkspaceScope,
)
from agentmemory.operations.domain.value_objects import Uuid7Id

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock


@dataclass(frozen=True, slots=True)
class SqliteMcpWorkspaceScopeResolver:
    """Select one existing Project/Repository/Checkout without creating path identity."""

    store: SqliteCoreStore

    async def resolve(self, registration: McpSessionRegistration) -> McpWorkspaceScope | None:
        """Apply checkout evidence before repository evidence and reject ambiguity."""
        parameters = {
            "brain": registration.brain_id.value,
            "workspace": bytes.fromhex(registration.workspace_fingerprint.value),
            "repository": _optional_digest(registration.git_repository_id),
            "worktree": _optional_digest(registration.git_worktree_id),
        }
        try:
            async with self.store.engine.connect() as connection:
                checkout_rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT DISTINCT p.id AS project_id,c.repository_id,c.id AS "
                                "checkout_id FROM checkouts c JOIN repositories r "
                                "ON r.id=c.repository_id AND r.brain_id=c.brain_id "
                                "JOIN project_repositories pr ON pr.repository_id=c.repository_id "
                                "JOIN projects p ON p.id=pr.project_id AND p.brain_id=c.brain_id "
                                "WHERE c.brain_id=:brain AND c.status='active' "
                                "AND r.status='active' AND p.status='active' AND "
                                "(c.canonical_path_hash=:workspace OR EXISTS (SELECT 1 FROM "
                                "checkout_aliases a WHERE a.checkout_id=c.id AND "
                                "a.brain_id=c.brain_id AND a.path_fingerprint=:workspace "
                                "AND a.approved=1) OR (:repository IS NOT NULL AND EXISTS "
                                "(SELECT 1 FROM repository_fingerprints rf WHERE "
                                "rf.brain_id=c.brain_id AND rf.repository_id=c.repository_id "
                                "AND rf.fingerprint=:repository AND rf.active=1) AND "
                                "(:worktree IS NULL OR c.worktree_id=:worktree))) "
                                "ORDER BY p.id,c.repository_id,c.id"
                            ),
                            parameters,
                        )
                    )
                    .mappings()
                    .all()
                )
                if checkout_rows:
                    return _single_scope(checkout_rows)
                if registration.git_coverage is McpGitCoverage.NONE:
                    return None
                repository_rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT DISTINCT p.id AS project_id,r.id AS repository_id,NULL "
                                "AS checkout_id FROM repository_fingerprints rf "
                                "JOIN repositories r ON r.id=rf.repository_id "
                                "JOIN project_repositories pr ON pr.repository_id=r.id "
                                "JOIN projects p ON p.id=pr.project_id AND p.brain_id=r.brain_id "
                                "WHERE rf.brain_id=:brain AND rf.fingerprint=:repository "
                                "AND rf.active=1 AND r.status='active' AND p.status='active' "
                                "ORDER BY p.id,r.id"
                            ),
                            parameters,
                        )
                    )
                    .mappings()
                    .all()
                )
                return None if not repository_rows else _single_scope(repository_rows)
        except OperationError:
            raise
        except (SQLAlchemyError, TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace identity resolution is unavailable",
                retryable=True,
            ) from error


@dataclass(frozen=True, slots=True)
class SqliteMcpWorkspaceScopeProvisioner:
    """Provision a privacy-safe identity only after an exact owner authorization check."""

    store: SqliteCoreStore
    clock: Clock

    async def ensure(
        self,
        registration: McpSessionRegistration,
        resolved: McpWorkspaceScope | None,
    ) -> McpWorkspaceScope:
        """Create a missing Project/Repository/Checkout in one serialized transaction."""
        try:
            async with self.store.write_lock, self.store.engine.begin() as connection:
                now = _microseconds(self.clock.now())
                await _authorize_provisioning(connection, registration, now)
                current = await _current_scope(connection, registration)
                if current is not None and current.checkout_id is not None:
                    return current
                scope = current or resolved
                if scope is not None:
                    await _require_scope(connection, registration, scope)
                    project_id = scope.project_id.value
                    repository_id = scope.repository_id.value
                else:
                    project_id, repository_id = await _create_project_repository(
                        connection,
                        registration,
                        now,
                    )
                device_id = await _ensure_device(connection, registration, now)
                checkout_id = str(uuid7())
                workspace = bytes.fromhex(registration.workspace_fingerprint.value)
                worktree = _optional_digest(registration.git_worktree_id)
                await connection.execute(
                    text(
                        "INSERT INTO checkouts "
                        "(id,brain_id,repository_id,device_id,canonical_path_hash,"
                        "checkout_fingerprint,worktree_id,branch,head_commit,last_seen_at,status,"
                        "created_at,updated_at,version) VALUES "
                        "(:id,:brain,:repository,:device,:path,:checkout,:worktree,NULL,NULL,"
                        ":now,'active',:now,:now,1)"
                    ),
                    {
                        "id": checkout_id,
                        "brain": registration.brain_id.value,
                        "repository": repository_id,
                        "device": device_id,
                        "path": workspace,
                        "checkout": worktree or workspace,
                        "worktree": worktree,
                        "now": now,
                    },
                )
                result = McpWorkspaceScope(
                    Uuid7Id(project_id),
                    Uuid7Id(repository_id),
                    Uuid7Id(checkout_id),
                )
                await _append_provisioning_audit(connection, registration, result, now)
                return result
        except OperationError:
            raise
        except SQLAlchemyError as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "workspace identity provisioning is unavailable",
                retryable=True,
            ) from error
        except (TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "workspace identity provisioning failed integrity checks",
            ) from error


async def _authorize_provisioning(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
    now: int,
) -> None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT i.installation_id,i.security_epoch FROM installation_state i "
                    "JOIN brains b ON b.id=:brain AND b.status='active' "
                    "JOIN principals p ON p.id=:actor AND p.status='active' "
                    "JOIN scope_grants g ON g.id=:grant AND g.brain_id=:brain "
                    "AND g.principal_id=:actor AND g.role='owner' AND g.valid_from<=:now "
                    "AND (g.valid_to IS NULL OR g.valid_to>:now) "
                    "WHERE i.singleton_key='local' AND i.owner_principal_id=:actor"
                ),
                {
                    "brain": registration.brain_id.value,
                    "actor": registration.actor_id.value,
                    "grant": registration.grant_id.value,
                    "now": now,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or str(row["installation_id"]) != registration.installation_id.value
        or int(str(row["security_epoch"])) != registration.security_epoch
    ):
        raise OperationError(ErrorCode.FORBIDDEN, "workspace provisioning is not authorized")


async def _current_scope(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
) -> McpWorkspaceScope | None:
    parameters = {
        "brain": registration.brain_id.value,
        "workspace": bytes.fromhex(registration.workspace_fingerprint.value),
        "repository": _optional_digest(registration.git_repository_id),
        "worktree": _optional_digest(registration.git_worktree_id),
    }
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT DISTINCT p.id AS project_id,c.repository_id,c.id AS checkout_id "
                    "FROM checkouts c JOIN repositories r ON r.id=c.repository_id "
                    "AND r.brain_id=c.brain_id JOIN project_repositories pr "
                    "ON pr.repository_id=c.repository_id JOIN projects p "
                    "ON p.id=pr.project_id AND p.brain_id=c.brain_id "
                    "WHERE c.brain_id=:brain AND c.status='active' AND r.status='active' "
                    "AND p.status='active' AND (c.canonical_path_hash=:workspace OR "
                    "(:repository IS NOT NULL AND :worktree IS NOT NULL AND "
                    "c.worktree_id=:worktree AND EXISTS (SELECT 1 FROM "
                    "repository_fingerprints rf WHERE rf.brain_id=:brain AND "
                    "rf.repository_id=c.repository_id AND rf.fingerprint=:repository "
                    "AND rf.active=1))) ORDER BY p.id,c.repository_id,c.id"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    if rows:
        return _single_scope(rows)
    if registration.git_repository_id is None:
        return None
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT DISTINCT p.id AS project_id,r.id AS repository_id,NULL AS "
                    "checkout_id FROM repository_fingerprints rf JOIN repositories r "
                    "ON r.id=rf.repository_id JOIN project_repositories pr "
                    "ON pr.repository_id=r.id JOIN projects p ON p.id=pr.project_id "
                    "AND p.brain_id=r.brain_id WHERE rf.brain_id=:brain "
                    "AND rf.fingerprint=:repository AND rf.active=1 AND r.status='active' "
                    "AND p.status='active' ORDER BY p.id,r.id"
                ),
                parameters,
            )
        )
        .mappings()
        .all()
    )
    return None if not rows else _single_scope(rows)


async def _require_scope(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
    scope: McpWorkspaceScope,
) -> None:
    exists = (
        await connection.execute(
            text(
                "SELECT 1 FROM projects p JOIN project_repositories pr ON pr.project_id=p.id "
                "JOIN repositories r ON r.id=pr.repository_id AND r.brain_id=p.brain_id "
                "WHERE p.id=:project AND r.id=:repository AND p.brain_id=:brain "
                "AND p.status='active' AND r.status='active'"
            ),
            {
                "project": scope.project_id.value,
                "repository": scope.repository_id.value,
                "brain": registration.brain_id.value,
            },
        )
    ).scalar_one_or_none()
    if exists is None:
        raise OperationError(ErrorCode.CONFLICT, "workspace scope changed during provisioning")


async def _create_project_repository(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
    now: int,
) -> tuple[str, str]:
    project_id = str(uuid7())
    repository_id = str(uuid7())
    workspace = registration.workspace_fingerprint.value
    repository_fingerprint = registration.git_repository_id
    root = repository_fingerprint or workspace
    manifest_key = hashlib.sha256(
        _canonical_json(
            {
                "brain_id": registration.brain_id.value,
                "purpose": "mcp-auto-project-v1",
                "workspace_fingerprint": workspace,
            }
        )
    ).digest()
    await connection.execute(
        text(
            "INSERT INTO projects "
            "(id,brain_id,name,manifest_key,status,version,created_at,updated_at,schema_version) "
            "VALUES (:id,:brain,:name,:manifest,'active',1,:now,:now,1)"
        ),
        {
            "id": project_id,
            "brain": registration.brain_id.value,
            "name": f"Workspace {workspace[:12]}",
            "manifest": manifest_key,
            "now": now,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO repositories "
            "(id,brain_id,vcs_type,root_fingerprint,primary_remote_fingerprint,status,"
            "created_at,updated_at,schema_version) VALUES "
            "(:id,:brain,:vcs,:root,NULL,'active',:now,:now,1)"
        ),
        {
            "id": repository_id,
            "brain": registration.brain_id.value,
            "vcs": "git" if repository_fingerprint is not None else "none",
            "root": bytes.fromhex(root),
            "now": now,
        },
    )
    if repository_fingerprint is not None:
        await connection.execute(
            text(
                "INSERT INTO repository_fingerprints "
                "(brain_id,repository_id,algorithm,fingerprint,evidence_json,active,created_at,"
                "updated_at,schema_version) VALUES "
                "(:brain,:repository,'McpGitRepositoryFingerprintV1',:fingerprint,:evidence,"
                "1,:now,:now,1)"
            ),
            {
                "brain": registration.brain_id.value,
                "repository": repository_id,
                "fingerprint": bytes.fromhex(repository_fingerprint),
                "evidence": _canonical_json(
                    {
                        "coverage": registration.git_coverage.value,
                        "source": "pf005-session",
                    }
                ).decode(),
                "now": now,
            },
        )
    await connection.execute(
        text(
            "INSERT INTO project_repositories "
            "(project_id,repository_id,relation_type,created_at,updated_at,schema_version) "
            "VALUES (:project,:repository,'primary',:now,:now,1)"
        ),
        {"project": project_id, "repository": repository_id, "now": now},
    )
    return project_id, repository_id


async def _ensure_device(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
    now: int,
) -> str:
    fingerprint = hashlib.sha256(registration.device_identity.encode()).digest()
    existing = (
        (
            await connection.execute(
                text("SELECT id,status FROM devices WHERE device_fingerprint=:fingerprint"),
                {"fingerprint": fingerprint},
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing is not None:
        if str(existing["status"]) != "verified":
            raise OperationError(ErrorCode.FORBIDDEN, "workspace device identity changed")
        return str(existing["id"])
    device_id = str(uuid7())
    await connection.execute(
        text(
            "INSERT INTO devices "
            "(id,device_fingerprint,status,created_at,updated_at,schema_version) "
            "VALUES (:id,:fingerprint,'verified',:now,:now,1)"
        ),
        {"id": device_id, "fingerprint": fingerprint, "now": now},
    )
    return device_id


async def _append_provisioning_audit(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
    scope: McpWorkspaceScope,
    now: int,
) -> None:
    idempotency_key = (
        f"mcp-workspace:{registration.brain_id.value}:{registration.workspace_fingerprint.value}"
    )
    existing = (
        await connection.execute(
            text("SELECT after_hash FROM audit_events WHERE idempotency_key=:key"),
            {"key": idempotency_key},
        )
    ).scalar_one_or_none()
    fact = _canonical_json(
        {
            "brain_id": registration.brain_id.value,
            "checkout_id": None if scope.checkout_id is None else scope.checkout_id.value,
            "project_id": scope.project_id.value,
            "repository_id": scope.repository_id.value,
            "workspace_fingerprint": registration.workspace_fingerprint.value,
        }
    )
    after = hashlib.sha256(fact).digest()
    if existing is not None:
        if bytes(existing) != after:
            raise OperationError(ErrorCode.CONFLICT, "workspace provisioning audit conflicted")
        return
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = bytes(32) if previous is None else bytes(previous)
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,'mcp.workspace.provisioned',:target,:key,:before,:after,"
            ":previous,:event,:now,1)"
        ),
        {
            "brain": registration.brain_id.value,
            "actor": registration.actor_id.value,
            "target": f"workspace:{scope.project_id.value}:{scope.repository_id.value}",
            "key": idempotency_key,
            "before": bytes(32),
            "after": after,
            "previous": previous_hash,
            "event": hashlib.sha256(previous_hash + fact).digest(),
            "now": now,
        },
    )


def _canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _microseconds(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ValueError
    return int(value.timestamp()) * 1_000_000 + value.microsecond


def _single_scope(rows: Sequence[RowMapping]) -> McpWorkspaceScope:
    scopes = {
        (
            str(row["project_id"]),
            str(row["repository_id"]),
            None if row["checkout_id"] is None else str(row["checkout_id"]),
        )
        for row in rows
    }
    if len(scopes) != 1:
        raise OperationError(ErrorCode.CONFLICT, "workspace identity is ambiguous")
    project_id, repository_id, checkout_id = scopes.pop()
    return McpWorkspaceScope(
        Uuid7Id(project_id),
        Uuid7Id(repository_id),
        None if checkout_id is None else Uuid7Id(checkout_id),
    )


def _optional_digest(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)
