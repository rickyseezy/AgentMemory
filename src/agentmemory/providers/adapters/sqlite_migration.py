"""SQLite PRO-008 migration, active-pointer, and dual-write authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import TYPE_CHECKING, Never, Self
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.providers.domain.embedding_spaces import IndexGenerationState
from agentmemory.providers.domain.errors import (
    EmbeddingMigrationAuthorizationError,
    EmbeddingMigrationConflictError,
    EmbeddingMigrationDependencyError,
    EmbeddingMigrationValidationError,
)
from agentmemory.providers.domain.migration import (
    EmbeddingGenerationMigration,
    EmbeddingMigrationState,
    MigrationProgress,
)
from agentmemory.providers.domain.migration_ports import (
    EmbeddingMigrationActivationRequest,
    EmbeddingMigrationPlan,
    GenerationWriteTarget,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ACTIONS = frozenset(
    {
        "provider.embedding_migration.plan",
        "provider.embedding_migration.read",
        "provider.embedding_migration.run",
        "provider.embedding_migration.pause",
        "provider.embedding_migration.resume",
        "provider.embedding_migration.activate",
        "provider.embedding_migration.rollback",
        "provider.embedding_migration.delete",
    }
)
_ROLES = frozenset({"owner", "admin"})
_TERMINAL = frozenset(
    {
        EmbeddingMigrationState.ACTIVE.value,
        EmbeddingMigrationState.ROLLED_BACK.value,
        EmbeddingMigrationState.FAILED.value,
    }
)
_ERR_AUTHORIZATION = "embedding migration storage action is not authorized"
_ERR_CONFLICT = "embedding migration conflicts with canonical state"
_ERR_STORAGE = "embedding migration storage is unavailable"
_ERR_INTEGRITY = "embedding migration storage failed integrity verification"
_ACTIVATE_ROUTE = (
    "UPDATE embedding_generation_write_routes SET "
    "primary_space_id=:space,primary_space_fingerprint=:fingerprint,"
    "primary_generation_id=:generation,secondary_space_id=NULL,"
    "secondary_space_fingerprint=NULL,secondary_generation_id=NULL,"
    "migration_id=NULL,version=version+1,updated_at=:at "
    "WHERE brain_id=:brain AND source_space_id=:source_space "
    "AND migration_id=:migration"
)
_ROLLBACK_ROUTE = (
    "UPDATE embedding_generation_write_routes SET "
    "primary_space_id=:space,primary_space_fingerprint=:fingerprint,"
    "primary_generation_id=:generation,secondary_space_id=NULL,"
    "secondary_space_fingerprint=NULL,secondary_generation_id=NULL,"
    "migration_id=NULL,version=version+1,updated_at=:at "
    "WHERE brain_id=:brain AND source_space_id=:source_space "
    "AND migration_id IS NULL AND primary_generation_id=:expected"
)


class SqliteEmbeddingMigrationRepository:
    """Persist resumable migration state and atomically switch read/write authority."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the sole canonical relational store."""
        self._store = store

    async def create(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        plan: EmbeddingMigrationPlan,
    ) -> EmbeddingGenerationMigration:
        """Create or exactly replay a plan after current binding verification."""
        try:
            async with _WriteTransaction(self._store) as transaction:
                await _authorize(
                    transaction.connection,
                    scope,
                    plan.migration.created_at_microseconds,
                )
                operation = (
                    (
                        await transaction.connection.execute(
                            text(
                                "SELECT * FROM embedding_migration_operations "
                                "WHERE operation_id=:operation"
                            ),
                            {"operation": operation_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if operation is not None:
                    if (
                        str(operation["brain_id"]) != scope.brain_id.value
                        or _blob(operation["request_digest"]).hex() != request_digest
                    ):
                        _conflict()
                    existing = await _get_migration(
                        transaction.connection,
                        str(operation["migration_id"]),
                    )
                    if existing is None:
                        _conflict()
                    await transaction.commit()
                    return existing
                purpose = await _validate_plan(transaction.connection, scope, plan)
                await _ensure_no_live_migration(transaction.connection, scope, purpose)
                await _ensure_initial_pointer(transaction.connection, plan, purpose)
                await _ensure_initial_route(transaction.connection, plan)
                await _insert_migration(transaction.connection, plan.migration)
                await transaction.connection.execute(
                    text(
                        "INSERT INTO embedding_migration_operations "
                        "(operation_id,brain_id,migration_id,request_digest,principal_id,"
                        "scope_fingerprint,created_at,schema_version) VALUES "
                        "(:operation,:brain,:migration,:request,:principal,:scope,:created,1)"
                    ),
                    {
                        "brain": plan.migration.brain_id,
                        "created": plan.migration.created_at_microseconds,
                        "migration": plan.migration.migration_id,
                        "operation": operation_id,
                        "principal": scope.principal_id.value,
                        "request": bytes.fromhex(request_digest),
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                    },
                )
                await _append_evidence(transaction.connection, None, plan.migration)
                await _append_change_event(
                    transaction.connection,
                    plan.migration,
                    "planned",
                )
                await transaction.commit()
                return plan.migration
        except (
            EmbeddingMigrationAuthorizationError,
            EmbeddingMigrationConflictError,
            EmbeddingMigrationValidationError,
        ):
            raise
        except IntegrityError as error:
            raise EmbeddingMigrationConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error

    async def get(
        self,
        scope: AuthorizedScope,
        migration_id: str,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration | None:
        """Return one authorized Brain-scoped snapshot without existence leakage."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, at_microseconds)
                scoped = (
                    await connection.execute(
                        text(
                            "SELECT 1 FROM embedding_generation_migrations "
                            "WHERE id=:migration AND brain_id=:brain"
                        ),
                        {"brain": scope.brain_id.value, "migration": migration_id},
                    )
                ).scalar_one_or_none()
                return None if scoped is None else await _get_migration(connection, migration_id)
        except (
            EmbeddingMigrationAuthorizationError,
            EmbeddingMigrationConflictError,
            EmbeddingMigrationValidationError,
        ):
            raise
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error

    async def advance(
        self,
        current: EmbeddingGenerationMigration,
        target: EmbeddingMigrationState,
        at_microseconds: int,
        *,
        progress: MigrationProgress | None = None,
        validation_digest: str | None = None,
    ) -> EmbeddingGenerationMigration:
        """Compare-and-swap one ordinary phase and mirror physical generation state."""
        updated = current.transition(
            target,
            at_microseconds=at_microseconds,
            progress=progress,
            validation_digest=validation_digest,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            await _mirror_target_state(
                transaction.connection,
                current,
                target,
                at_microseconds,
            )
            if target is EmbeddingMigrationState.FAILED and current.state in {
                EmbeddingMigrationState.CATCHING_UP,
                EmbeddingMigrationState.VALIDATING,
                EmbeddingMigrationState.SHADOWING,
                EmbeddingMigrationState.READY,
            }:
                await _disable_dual_route(
                    transaction.connection,
                    current,
                    at_microseconds,
                )
            await _persist_migration(transaction.connection, current, updated)
            if target is EmbeddingMigrationState.FAILED:
                await _append_change_event(
                    transaction.connection,
                    updated,
                    "failed",
                )
            await transaction.commit()
        return updated

    async def checkpoint(
        self,
        current: EmbeddingGenerationMigration,
        progress: MigrationProgress,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Persist one monotonic replay cursor with versioned evidence."""
        updated = replace(
            current,
            progress=progress,
            version=current.version + 1,
            updated_at_microseconds=at_microseconds,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            await _persist_migration(transaction.connection, current, updated)
            await transaction.commit()
        return updated

    async def resume(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Compare-and-swap the exact paused phase without changing progress."""
        updated = current.resume(at_microseconds=at_microseconds)
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            await _persist_migration(transaction.connection, current, updated)
            await _append_change_event(transaction.connection, updated, "resumed")
            await transaction.commit()
        return updated

    async def begin_dual_write(
        self,
        current: EmbeddingGenerationMigration,
        catchup_watermark: int,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Publish dual-write routing and catch-up watermark in one transaction."""
        progress = MigrationProgress(
            current.source_watermark,
            catchup_watermark,
            current.source_watermark,
        )
        updated = current.transition(
            EmbeddingMigrationState.CATCHING_UP,
            at_microseconds=at_microseconds,
            progress=progress,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            route = await transaction.connection.execute(
                text(
                    "UPDATE embedding_generation_write_routes SET "
                    "secondary_space_id=:target_space,"
                    "secondary_space_fingerprint=:target_fingerprint,"
                    "secondary_generation_id=:target_generation,migration_id=:migration,"
                    "version=version+1,updated_at=:at "
                    "WHERE brain_id=:brain AND source_space_id=:source_space "
                    "AND primary_generation_id=:source_generation "
                    "AND secondary_generation_id IS NULL"
                ),
                {
                    "at": at_microseconds,
                    "brain": current.brain_id,
                    "migration": current.migration_id,
                    "source_generation": current.source_generation_id,
                    "source_space": current.source_space_id,
                    "target_fingerprint": bytes.fromhex(current.target_space_fingerprint),
                    "target_generation": current.target_generation_id,
                    "target_space": current.target_space_id,
                },
            )
            if route.rowcount != 1:
                _conflict()
            await _persist_migration(transaction.connection, current, updated)
            await _append_change_event(
                transaction.connection,
                updated,
                "dual_write_enabled",
            )
            await transaction.commit()
        return updated

    async def activate(
        self,
        current: EmbeddingGenerationMigration,
        request: EmbeddingMigrationActivationRequest,
    ) -> EmbeddingGenerationMigration:
        """Atomically cut reads/writes to target and retain source read-only."""
        if current.state is EmbeddingMigrationState.ACTIVE:
            return await self._replay_activation(current, request)
        if current.version != request.expected_version:
            _conflict()
        updated = current.activate(
            at_microseconds=request.at_microseconds,
            rollback_until_microseconds=request.rollback_until_microseconds,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _authorize(
                transaction.connection,
                request.scope,
                request.at_microseconds,
            )
            await _require_current(transaction.connection, current)
            await _verify_approval(
                transaction.connection,
                request.scope,
                current,
                request.approval_id,
                request.at_microseconds,
            )
            purpose = await _purpose(transaction.connection, current.source_space_id)
            await _set_generation_state(
                transaction.connection,
                current.target_generation_id,
                IndexGenerationState.SHADOW_READY,
                IndexGenerationState.ACTIVE,
                request.at_microseconds,
            )
            await _set_generation_state(
                transaction.connection,
                current.source_generation_id,
                IndexGenerationState.ACTIVE,
                IndexGenerationState.ROLLBACK_READY,
                request.at_microseconds,
            )
            pointer = await transaction.connection.execute(
                text(
                    "UPDATE active_embedding_generations SET space_id=:space,"
                    "generation_id=:generation,version=version+1,updated_at=:at "
                    "WHERE brain_id=:brain AND purpose=:purpose "
                    "AND generation_id=:source"
                ),
                {
                    "at": request.at_microseconds,
                    "brain": current.brain_id,
                    "generation": current.target_generation_id,
                    "purpose": purpose,
                    "source": current.source_generation_id,
                    "space": current.target_space_id,
                },
            )
            if pointer.rowcount != 1:
                _conflict()
            await _set_single_route(
                transaction.connection,
                current,
                target=True,
                at_microseconds=request.at_microseconds,
            )
            await _insert_activation(
                transaction.connection,
                current,
                request,
            )
            await _persist_migration(transaction.connection, current, updated)
            await _append_change_event(
                transaction.connection,
                updated,
                "activated",
            )
            await transaction.commit()
        return updated

    async def _replay_activation(
        self,
        current: EmbeddingGenerationMigration,
        request: EmbeddingMigrationActivationRequest,
    ) -> EmbeddingGenerationMigration:
        """Replay only the exact immutable activation receipt."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(
                    connection,
                    request.scope,
                    request.at_microseconds,
                )
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM embedding_migration_activations "
                                "WHERE migration_id=:migration"
                            ),
                            {"migration": current.migration_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    row is None
                    or str(row["operation_id"]) != request.operation_id
                    or str(row["approval_id"]) != request.approval_id
                    or int(row["expected_version"]) != request.expected_version
                    or str(row["principal_id"]) != request.scope.principal_id.value
                    or _blob(row["scope_fingerprint"]).hex() != request.scope.scope_fingerprint
                ):
                    _conflict()
                return current
        except (
            EmbeddingMigrationAuthorizationError,
            EmbeddingMigrationConflictError,
            EmbeddingMigrationValidationError,
        ):
            raise
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error

    async def rollback(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Atomically restore source reads/writes and retain target read-only."""
        updated = current.transition(
            EmbeddingMigrationState.ROLLED_BACK,
            at_microseconds=at_microseconds,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            purpose = await _purpose(transaction.connection, current.source_space_id)
            await _set_generation_state(
                transaction.connection,
                current.source_generation_id,
                IndexGenerationState.ROLLBACK_READY,
                IndexGenerationState.ACTIVE,
                at_microseconds,
            )
            await _set_generation_state(
                transaction.connection,
                current.target_generation_id,
                IndexGenerationState.ACTIVE,
                IndexGenerationState.ROLLBACK_READY,
                at_microseconds,
            )
            pointer = await transaction.connection.execute(
                text(
                    "UPDATE active_embedding_generations SET space_id=:space,"
                    "generation_id=:generation,version=version+1,updated_at=:at "
                    "WHERE brain_id=:brain AND purpose=:purpose "
                    "AND generation_id=:target"
                ),
                {
                    "at": at_microseconds,
                    "brain": current.brain_id,
                    "generation": current.source_generation_id,
                    "purpose": purpose,
                    "space": current.source_space_id,
                    "target": current.target_generation_id,
                },
            )
            if pointer.rowcount != 1:
                _conflict()
            await _set_single_route(
                transaction.connection,
                current,
                target=False,
                at_microseconds=at_microseconds,
            )
            await _persist_migration(transaction.connection, current, updated)
            await _append_change_event(
                transaction.connection,
                updated,
                "rolled_back",
            )
            await transaction.commit()
        return updated

    async def retire_source(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Retire the expired source canonically before physical deletion."""
        if not current.deletion_eligible(at_microseconds):
            _conflict()
        if current.source_retired_at_microseconds is not None:
            return current
        updated = replace(
            current,
            source_retired_at_microseconds=at_microseconds,
            version=current.version + 1,
            updated_at_microseconds=at_microseconds,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            await _set_generation_state(
                transaction.connection,
                current.source_generation_id,
                IndexGenerationState.ROLLBACK_READY,
                IndexGenerationState.RETIRED,
                at_microseconds,
            )
            await _persist_migration(transaction.connection, current, updated)
            await _append_change_event(
                transaction.connection,
                updated,
                "source_retired",
            )
            await transaction.commit()
        return updated

    async def complete_source_deletion(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Persist physical cleanup completion as idempotent evidence."""
        if current.source_deleted_at_microseconds is not None:
            return current
        if current.source_retired_at_microseconds is None:
            _conflict()
        updated = replace(
            current,
            source_deleted_at_microseconds=at_microseconds,
            version=current.version + 1,
            updated_at_microseconds=at_microseconds,
        )
        async with _WriteTransaction(self._store) as transaction:
            await _require_current(transaction.connection, current)
            await _persist_migration(transaction.connection, current, updated)
            await _append_change_event(
                transaction.connection,
                updated,
                "source_deleted",
            )
            await transaction.commit()
        return updated

    async def write_targets(
        self,
        brain_id: str,
        source_space_id: str,
    ) -> tuple[GenerationWriteTarget, ...]:
        """Resolve the atomically published primary and optional secondary."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM embedding_generation_write_routes "
                                "WHERE brain_id=:brain AND "
                                "(source_space_id=:space OR primary_space_id=:space) "
                                "ORDER BY CASE WHEN source_space_id=:space THEN 0 ELSE 1 END "
                                "LIMIT 1"
                            ),
                            {"brain": brain_id, "space": source_space_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return ()
                primary = GenerationWriteTarget(
                    str(row["primary_space_id"]),
                    _blob(row["primary_space_fingerprint"]).hex(),
                    str(row["primary_generation_id"]),
                )
                if row["secondary_generation_id"] is None:
                    return (primary,)
                return (
                    primary,
                    GenerationWriteTarget(
                        str(row["secondary_space_id"]),
                        _blob(row["secondary_space_fingerprint"]).hex(),
                        str(row["secondary_generation_id"]),
                    ),
                )
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error

    async def active_target(
        self,
        brain_id: str,
        purpose: str,
    ) -> GenerationWriteTarget | None:
        """Resolve the one atomically active read target for a semantic purpose."""
        try:
            async with self._store.engine.connect() as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT pointer.space_id,pointer.generation_id,"
                                "space.immutable_fingerprint "
                                "FROM active_embedding_generations pointer "
                                "JOIN embedding_spaces space ON space.id=pointer.space_id "
                                "WHERE pointer.brain_id=:brain AND pointer.purpose=:purpose "
                                "AND space.brain_id=pointer.brain_id"
                            ),
                            {"brain": brain_id, "purpose": purpose},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return None
                return GenerationWriteTarget(
                    str(row["space_id"]),
                    str(row["immutable_fingerprint"]),
                    str(row["generation_id"]),
                )
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingMigrationConflictError(_ERR_INTEGRITY) from error


async def _verify_approval(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    migration: EmbeddingGenerationMigration,
    approval_id: str,
    at_microseconds: int,
) -> None:
    approved = (
        await connection.execute(
            text(
                "SELECT 1 FROM scope_grants grant_row "
                "JOIN principals principal ON principal.id=grant_row.principal_id "
                "JOIN brains brain ON brain.id=grant_row.brain_id "
                "WHERE grant_row.id=:approval AND grant_row.principal_id=:principal "
                "AND grant_row.brain_id=:brain AND grant_row.role IN ('owner','admin') "
                "AND grant_row.project_id IS NULL AND grant_row.repository_id IS NULL "
                "AND principal.status='active' AND brain.status='active' "
                "AND grant_row.valid_from<=:at "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:at)"
            ),
            {
                "approval": approval_id,
                "at": at_microseconds,
                "brain": migration.brain_id,
                "principal": scope.principal_id.value,
            },
        )
    ).scalar_one_or_none()
    if approved is None:
        raise EmbeddingMigrationAuthorizationError(_ERR_AUTHORIZATION)


async def _insert_activation(
    connection: AsyncConnection,
    migration: EmbeddingGenerationMigration,
    request: EmbeddingMigrationActivationRequest,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO embedding_migration_activations "
            "(migration_id,operation_id,brain_id,principal_id,approval_id,"
            "scope_fingerprint,expected_version,rollback_until,activated_at,schema_version) "
            "VALUES (:migration,:operation,:brain,:principal,:approval,:scope,:version,"
            ":rollback,:at,1)"
        ),
        {
            "approval": request.approval_id,
            "at": request.at_microseconds,
            "brain": migration.brain_id,
            "migration": migration.migration_id,
            "operation": request.operation_id,
            "principal": request.scope.principal_id.value,
            "rollback": request.rollback_until_microseconds,
            "scope": bytes.fromhex(request.scope.scope_fingerprint),
            "version": migration.version,
        },
    )


async def _validate_plan(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    plan: EmbeddingMigrationPlan,
) -> str:
    migration = plan.migration
    if migration.brain_id != scope.brain_id.value:
        _conflict()
    source = await _binding(connection, migration.source_generation_id)
    target = await _binding(connection, migration.target_generation_id)
    if (
        source is None
        or target is None
        or str(source["brain_id"]) != migration.brain_id
        or str(target["brain_id"]) != migration.brain_id
        or str(source["space_id"]) != migration.source_space_id
        or str(target["space_id"]) != migration.target_space_id
        or str(source["space_fingerprint"]) != migration.source_space_fingerprint
        or str(target["space_fingerprint"]) != migration.target_space_fingerprint
        or str(source["state"]) != IndexGenerationState.ACTIVE.value
        or str(target["state"])
        not in {
            IndexGenerationState.CREATING.value,
            IndexGenerationState.POPULATING.value,
        }
        or str(source["purpose"]) != str(target["purpose"])
        or plan.source_space.space_id != migration.source_space_id
        or plan.target_space.space_id != migration.target_space_id
        or plan.source_generation.generation_id != migration.source_generation_id
        or plan.target_generation.generation_id != migration.target_generation_id
    ):
        _conflict()
    return str(source["purpose"])


async def _binding(
    connection: AsyncConnection,
    generation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT g.brain_id,g.space_id,g.space_fingerprint,g.state,s.purpose "
                    "FROM embedding_index_generations g "
                    "JOIN embedding_spaces s ON s.id=g.space_id "
                    "WHERE g.id=:generation"
                ),
                {"generation": generation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _ensure_no_live_migration(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    purpose: str,
) -> None:
    existing = (
        await connection.execute(
            text(
                "SELECT 1 FROM embedding_generation_migrations m "
                "JOIN embedding_spaces s ON s.id=m.source_space_id "
                "WHERE m.brain_id=:brain AND s.purpose=:purpose "
                "AND m.state NOT IN ('active','rolled_back','failed') LIMIT 1"
            ),
            {"brain": scope.brain_id.value, "purpose": purpose},
        )
    ).scalar_one_or_none()
    if existing is not None:
        _conflict()


async def _ensure_initial_pointer(
    connection: AsyncConnection,
    plan: EmbeddingMigrationPlan,
    purpose: str,
) -> None:
    migration = plan.migration
    row = (
        (
            await connection.execute(
                text(
                    "SELECT space_id,generation_id FROM active_embedding_generations "
                    "WHERE brain_id=:brain AND purpose=:purpose"
                ),
                {"brain": migration.brain_id, "purpose": purpose},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        await connection.execute(
            text(
                "INSERT INTO active_embedding_generations "
                "(brain_id,purpose,space_id,generation_id,version,updated_at,schema_version) "
                "VALUES (:brain,:purpose,:space,:generation,1,:at,1)"
            ),
            {
                "at": migration.created_at_microseconds,
                "brain": migration.brain_id,
                "generation": migration.source_generation_id,
                "purpose": purpose,
                "space": migration.source_space_id,
            },
        )
    elif (
        str(row["space_id"]) != migration.source_space_id
        or str(row["generation_id"]) != migration.source_generation_id
    ):
        _conflict()


async def _ensure_initial_route(
    connection: AsyncConnection,
    plan: EmbeddingMigrationPlan,
) -> None:
    migration = plan.migration
    row = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM embedding_generation_write_routes "
                    "WHERE brain_id=:brain AND source_space_id=:space"
                ),
                {"brain": migration.brain_id, "space": migration.source_space_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        await connection.execute(
            text(
                "INSERT INTO embedding_generation_write_routes "
                "(brain_id,source_space_id,primary_space_id,primary_space_fingerprint,"
                "primary_generation_id,secondary_space_id,secondary_space_fingerprint,"
                "secondary_generation_id,migration_id,version,updated_at,schema_version) "
                "VALUES (:brain,:source_space,:primary_space,:fingerprint,:generation,"
                "NULL,NULL,NULL,NULL,1,:at,1)"
            ),
            {
                "at": migration.created_at_microseconds,
                "brain": migration.brain_id,
                "fingerprint": bytes.fromhex(migration.source_space_fingerprint),
                "generation": migration.source_generation_id,
                "primary_space": migration.source_space_id,
                "source_space": migration.source_space_id,
            },
        )
    elif (
        str(row["primary_space_id"]) != migration.source_space_id
        or str(row["primary_generation_id"]) != migration.source_generation_id
        or row["secondary_generation_id"] is not None
    ):
        _conflict()


async def _insert_migration(
    connection: AsyncConnection,
    migration: EmbeddingGenerationMigration,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO embedding_generation_migrations "
            "(id,brain_id,source_space_id,source_generation_id,source_space_fingerprint,"
            "target_space_id,target_generation_id,target_space_fingerprint,"
            "source_watermark,backfill_cursor,catchup_watermark,catchup_cursor,state,"
            "resume_state,validation_digest,rollback_until,source_retired_at,source_deleted_at,"
            "version,created_at,updated_at,schema_version) VALUES "
            "(:id,:brain,:source_space,:source_generation,:source_fingerprint,"
            ":target_space,:target_generation,:target_fingerprint,:watermark,:backfill,"
            ":catchup_watermark,:catchup_cursor,:state,:resume_state,:validation,:rollback,:retired,"
            ":deleted,:version,:created,:updated,1)"
        ),
        _migration_parameters(migration),
    )


async def _get_migration(
    connection: AsyncConnection,
    migration_id: str,
) -> EmbeddingGenerationMigration | None:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM embedding_generation_migrations WHERE id=:migration"),
                {"migration": migration_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _migration(row)


async def _require_current(
    connection: AsyncConnection,
    current: EmbeddingGenerationMigration,
) -> None:
    persisted = await _get_migration(connection, current.migration_id)
    if persisted != current:
        _conflict()


async def _persist_migration(
    connection: AsyncConnection,
    before: EmbeddingGenerationMigration,
    after: EmbeddingGenerationMigration,
) -> None:
    parameters = _migration_parameters(after)
    parameters["expected_version"] = before.version
    updated = await connection.execute(
        text(
            "UPDATE embedding_generation_migrations SET "
            "backfill_cursor=:backfill,catchup_watermark=:catchup_watermark,"
            "catchup_cursor=:catchup_cursor,state=:state,resume_state=:resume_state,"
            "validation_digest=:validation,"
            "rollback_until=:rollback,source_retired_at=:retired,"
            "source_deleted_at=:deleted,version=:version,updated_at=:updated "
            "WHERE id=:id AND version=:expected_version"
        ),
        parameters,
    )
    if updated.rowcount != 1:
        _conflict()
    await _append_evidence(connection, before, after)


async def _append_evidence(
    connection: AsyncConnection,
    before: EmbeddingGenerationMigration | None,
    after: EmbeddingGenerationMigration,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO embedding_migration_evidence "
            "(migration_id,from_state,to_state,version,snapshot_digest,"
            "occurred_at,schema_version) VALUES "
            "(:migration,:before,:after,:version,:digest,:at,1)"
        ),
        {
            "after": after.state.value,
            "at": after.updated_at_microseconds,
            "before": None if before is None else before.state.value,
            "digest": _snapshot_digest(after),
            "migration": after.migration_id,
            "version": after.version,
        },
    )


async def _append_change_event(
    connection: AsyncConnection,
    migration: EmbeddingGenerationMigration,
    phase: str,
) -> None:
    source_event_id = str(uuid7())
    integration_event_id = str(uuid7())
    topic = "provider.embedding_generation.changed.v1"
    payload = json.dumps(
        {
            "correlation_id": migration.migration_id,
            "data": {
                "brain_id": migration.brain_id,
                "migration_id": migration.migration_id,
                "phase": phase,
                "source_generation_id": migration.source_generation_id,
                "state": migration.state.value,
                "target_generation_id": migration.target_generation_id,
                "version": migration.version,
            },
            "datacontenttype": "application/json",
            "dataschema": "urn:agentmemory:schema:provider:embedding-generation-changed:v1",
            "id": integration_event_id,
            "source": f"urn:agentmemory:brain:{migration.brain_id}:providers",
            "specversion": "1.0",
            "subject": f"embedding-migration/{migration.migration_id}",
            "type": topic,
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    payload_digest = hashlib.sha256(payload.encode()).digest()
    await connection.execute(
        text(
            "INSERT INTO agent_events "
            "(event_id,brain_id,type,payload_hash,classification,occurred_at,"
            "ingested_at,payload_ref,schema_version) VALUES "
            "(:event,:brain,'EmbeddingGenerationRouteChanged',:digest,'internal',"
            ":at,:at,NULL,1)"
        ),
        {
            "at": migration.updated_at_microseconds,
            "brain": migration.brain_id,
            "digest": payload_digest,
            "event": source_event_id,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,"
            "attempts,lease_owner,lease_until,completed_at,payload_sha256,"
            "last_error_code,created_at,schema_version) VALUES "
            "(:id,:source,:topic,:key,:payload,'ready',100,:at,0,NULL,NULL,NULL,"
            ":digest,NULL,:at,1)"
        ),
        {
            "at": migration.updated_at_microseconds,
            "digest": payload_digest,
            "id": integration_event_id,
            "key": migration.brain_id,
            "payload": payload,
            "source": source_event_id,
            "topic": topic,
        },
    )


async def _mirror_target_state(
    connection: AsyncConnection,
    current: EmbeddingGenerationMigration,
    target: EmbeddingMigrationState,
    at_microseconds: int,
) -> None:
    transition: tuple[IndexGenerationState, IndexGenerationState] | None = None
    if target is EmbeddingMigrationState.VALIDATING:
        transition = (
            IndexGenerationState.POPULATING,
            IndexGenerationState.VALIDATING,
        )
    elif target is EmbeddingMigrationState.SHADOWING:
        transition = (
            IndexGenerationState.VALIDATING,
            IndexGenerationState.SHADOW_READY,
        )
    elif target is EmbeddingMigrationState.FAILED:
        expected = {
            EmbeddingMigrationState.PLANNED: IndexGenerationState.POPULATING,
            EmbeddingMigrationState.BUILDING: IndexGenerationState.POPULATING,
            EmbeddingMigrationState.BACKFILLING: IndexGenerationState.POPULATING,
            EmbeddingMigrationState.DUAL_WRITE: IndexGenerationState.POPULATING,
            EmbeddingMigrationState.CATCHING_UP: IndexGenerationState.POPULATING,
            EmbeddingMigrationState.VALIDATING: IndexGenerationState.VALIDATING,
            EmbeddingMigrationState.SHADOWING: IndexGenerationState.SHADOW_READY,
            EmbeddingMigrationState.READY: IndexGenerationState.SHADOW_READY,
        }.get(current.state)
        if expected is not None:
            transition = (expected, IndexGenerationState.FAILED)
    if transition is not None:
        await _set_generation_state(
            connection,
            current.target_generation_id,
            transition[0],
            transition[1],
            at_microseconds,
        )


async def _set_generation_state(
    connection: AsyncConnection,
    generation_id: str,
    expected: IndexGenerationState,
    target: IndexGenerationState,
    at_microseconds: int,
) -> None:
    updated = await connection.execute(
        text(
            "UPDATE embedding_index_generations SET state=:target,"
            "updated_at=:at,version=version+1 WHERE id=:generation AND state=:expected"
        ),
        {
            "at": at_microseconds,
            "expected": expected.value,
            "generation": generation_id,
            "target": target.value,
        },
    )
    if updated.rowcount != 1:
        _conflict()


async def _set_single_route(
    connection: AsyncConnection,
    current: EmbeddingGenerationMigration,
    *,
    target: bool,
    at_microseconds: int,
) -> None:
    space_id = current.target_space_id if target else current.source_space_id
    fingerprint = current.target_space_fingerprint if target else current.source_space_fingerprint
    generation_id = current.target_generation_id if target else current.source_generation_id
    updated = await connection.execute(
        text(_ACTIVATE_ROUTE if target else _ROLLBACK_ROUTE),
        {
            "at": at_microseconds,
            "brain": current.brain_id,
            "fingerprint": bytes.fromhex(fingerprint),
            "generation": generation_id,
            "migration": current.migration_id,
            "expected": current.target_generation_id,
            "source_space": current.source_space_id,
            "space": space_id,
        },
    )
    if updated.rowcount != 1:
        _conflict()


async def _disable_dual_route(
    connection: AsyncConnection,
    current: EmbeddingGenerationMigration,
    at_microseconds: int,
) -> None:
    updated = await connection.execute(
        text(
            "UPDATE embedding_generation_write_routes SET "
            "secondary_space_id=NULL,secondary_space_fingerprint=NULL,"
            "secondary_generation_id=NULL,migration_id=NULL,"
            "version=version+1,updated_at=:at "
            "WHERE brain_id=:brain AND source_space_id=:source_space "
            "AND primary_generation_id=:source_generation "
            "AND migration_id=:migration"
        ),
        {
            "at": at_microseconds,
            "brain": current.brain_id,
            "migration": current.migration_id,
            "source_generation": current.source_generation_id,
            "source_space": current.source_space_id,
        },
    )
    if updated.rowcount != 1:
        _conflict()


async def _purpose(connection: AsyncConnection, space_id: str) -> str:
    value = (
        await connection.execute(
            text("SELECT purpose FROM embedding_spaces WHERE id=:space"),
            {"space": space_id},
        )
    ).scalar_one_or_none()
    if not isinstance(value, str):
        _conflict()
    return str(value)


async def _authorize(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    at_microseconds: int,
) -> None:
    if scope.action not in _ACTIONS or scope.role.value not in _ROLES or at_microseconds < 0:
        raise EmbeddingMigrationAuthorizationError(_ERR_AUTHORIZATION)
    authorized = (
        await connection.execute(
            text(
                "SELECT 1 FROM brains b JOIN principals p ON p.id=:principal "
                "JOIN scope_grants g ON g.principal_id=p.id AND g.brain_id=b.id "
                "WHERE b.id=:brain AND b.status='active' AND p.status='active' "
                "AND g.role IN ('owner','admin') AND g.project_id IS NULL "
                "AND g.repository_id IS NULL AND g.valid_from<=:at "
                "AND (g.valid_to IS NULL OR g.valid_to>:at) LIMIT 1"
            ),
            {
                "at": at_microseconds,
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
            },
        )
    ).scalar_one_or_none()
    if authorized is None:
        raise EmbeddingMigrationAuthorizationError(_ERR_AUTHORIZATION)


def _migration(row: RowMapping) -> EmbeddingGenerationMigration:
    return EmbeddingGenerationMigration(
        migration_id=str(row["id"]),
        brain_id=str(row["brain_id"]),
        source_space_id=str(row["source_space_id"]),
        source_space_fingerprint=_blob(row["source_space_fingerprint"]).hex(),
        source_generation_id=str(row["source_generation_id"]),
        target_space_id=str(row["target_space_id"]),
        target_space_fingerprint=_blob(row["target_space_fingerprint"]).hex(),
        target_generation_id=str(row["target_generation_id"]),
        source_watermark=int(row["source_watermark"]),
        progress=MigrationProgress(
            int(row["backfill_cursor"]),
            int(row["catchup_watermark"]),
            int(row["catchup_cursor"]),
        ),
        state=EmbeddingMigrationState(str(row["state"])),
        resume_state=(
            None
            if row["resume_state"] is None
            else EmbeddingMigrationState(str(row["resume_state"]))
        ),
        validation_digest=_optional_digest(row["validation_digest"]),
        rollback_until_microseconds=_optional_int(row["rollback_until"]),
        source_retired_at_microseconds=_optional_int(row["source_retired_at"]),
        source_deleted_at_microseconds=_optional_int(row["source_deleted_at"]),
        version=int(row["version"]),
        created_at_microseconds=int(row["created_at"]),
        updated_at_microseconds=int(row["updated_at"]),
    )


def _migration_parameters(
    migration: EmbeddingGenerationMigration,
) -> dict[str, object]:
    return {
        "backfill": migration.progress.backfill_cursor,
        "brain": migration.brain_id,
        "catchup_cursor": migration.progress.catchup_cursor,
        "catchup_watermark": migration.progress.catchup_watermark,
        "created": migration.created_at_microseconds,
        "deleted": migration.source_deleted_at_microseconds,
        "id": migration.migration_id,
        "retired": migration.source_retired_at_microseconds,
        "rollback": migration.rollback_until_microseconds,
        "resume_state": (None if migration.resume_state is None else migration.resume_state.value),
        "source_fingerprint": bytes.fromhex(migration.source_space_fingerprint),
        "source_generation": migration.source_generation_id,
        "source_space": migration.source_space_id,
        "state": migration.state.value,
        "target_fingerprint": bytes.fromhex(migration.target_space_fingerprint),
        "target_generation": migration.target_generation_id,
        "target_space": migration.target_space_id,
        "updated": migration.updated_at_microseconds,
        "validation": (
            None
            if migration.validation_digest is None
            else bytes.fromhex(migration.validation_digest)
        ),
        "version": migration.version,
        "watermark": migration.source_watermark,
    }


def _snapshot_digest(migration: EmbeddingGenerationMigration) -> bytes:
    document = {
        key: (value.value if isinstance(value, EmbeddingMigrationState) else value)
        for key, value in {
            "backfill_cursor": migration.progress.backfill_cursor,
            "catchup_cursor": migration.progress.catchup_cursor,
            "catchup_watermark": migration.progress.catchup_watermark,
            "migration_id": migration.migration_id,
            "rollback_until_microseconds": migration.rollback_until_microseconds,
            "resume_state": migration.resume_state,
            "source_deleted_at_microseconds": migration.source_deleted_at_microseconds,
            "source_retired_at_microseconds": migration.source_retired_at_microseconds,
            "state": migration.state,
            "updated_at_microseconds": migration.updated_at_microseconds,
            "validation_digest": migration.validation_digest,
            "version": migration.version,
        }.items()
    }
    return hashlib.sha256(
        json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    ).digest()


def _optional_digest(value: object) -> str | None:
    return None if value is None else _blob(value).hex()


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise TypeError
    return value


def _blob(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError
    return value


def _conflict() -> Never:
    raise EmbeddingMigrationConflictError(_ERR_CONFLICT)


class _WriteTransaction:
    """Short serialized transaction with typed storage errors."""

    def __init__(self, store: SqliteCoreStore) -> None:
        self._store = store
        self.connection: AsyncConnection
        self._committed = False

    async def __aenter__(self) -> Self:
        await self._store.write_lock.acquire()
        try:
            self.connection = await self._store.engine.connect()
            await self.connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException as error:
            if hasattr(self, "connection"):
                await self.connection.close()
            self._store.write_lock.release()
            if isinstance(error, SQLAlchemyError):
                raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, traceback
        storage_error = exc if isinstance(exc, SQLAlchemyError) else None
        try:
            if not self._committed:
                try:
                    await self.connection.rollback()
                except SQLAlchemyError as error:
                    storage_error = error
        finally:
            try:
                await self.connection.close()
            finally:
                self._store.write_lock.release()
        if storage_error is not None:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from storage_error
        return None

    async def commit(self) -> None:
        try:
            await self.connection.commit()
        except SQLAlchemyError as error:
            raise EmbeddingMigrationDependencyError(_ERR_STORAGE) from error
        self._committed = True
