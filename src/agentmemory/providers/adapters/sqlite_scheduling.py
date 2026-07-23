"""PRO-006 SQLite fair queues, rate state, leases, and immutable results."""

# ruff: noqa: C901, PLR0913, TRY301

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.adapters.strict_json import StrictJsonError, canonical_bytes, loads
from agentmemory.providers.domain.errors import (
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingConflictError,
    ProviderSchedulingDependencyError,
    ProviderSchedulingValidationError,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose
from agentmemory.providers.domain.routing import ProviderWorkload
from agentmemory.providers.domain.scheduling import (
    BatchPlanner,
    ProviderBatch,
    ProviderBatchKey,
    ProviderBatchLease,
    ProviderBatchOutcome,
    ProviderDeadlineClass,
    ProviderItemResultStatus,
    ProviderRatePolicy,
    ProviderRateState,
    ProviderSchedulingLimits,
    ProviderWorkItem,
    ProviderWorkState,
    WeightedFairProviderScheduler,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.scheduling import ProviderItemResult

_ERR_AUTHORIZATION = "provider scheduling storage action is not authorized"
_ERR_CONFLICT = "provider scheduling conflicts with immutable history"
_ERR_INTEGRITY = "provider scheduling storage failed integrity verification"
_ERR_STORAGE = "provider scheduling storage is unavailable"
_READ_ACTION = "provider.schedule.read"
_WRITE_ACTIONS = frozenset({"provider.schedule.enqueue", "provider.schedule.cancel"})
_WRITE_ROLES = frozenset({"owner", "admin", "editor", "adapter", "worker"})
_READ_ROLES = _WRITE_ROLES | frozenset({"reader", "auditor"})
_MAX_COST_MICROS = 10**15
_LOCAL_REQUEST_RATE = 1_000_000
_LOCAL_TOKEN_RATE = 1_000_000_000
_MAX_CANDIDATES = 1_000
_DEFAULT_CONCURRENCY = 1
_RETRY_DELAY_MICROSECONDS = 1_000_000

_WORK_SELECT = """
SELECT item_id,operation_id,brain_id,principal_id,grant_version,
       authorization_policy_version,security_epoch,scope_fingerprint,project_id,repository_id,
       profile_id,profile_version,space_id,space_fingerprint,classification,purpose,
       retention_policy_digest,preprocessing_digest,deadline_class,workload,batch_key_digest,
       ordinal,payload_ref,content_digest,token_count,byte_count,estimated_cost_micros,state,
       attempts,next_attempt_at,lease_owner,lease_until,cancel_requested,last_error_code,
       enqueued_at,deadline_at,updated_at,completed_at
FROM provider_work_items
"""


class SqliteProviderSchedulingRepository:
    """Serialize idempotent enqueue, fair dispatch, rate state, and child results."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical single-writer SQLite store."""
        self._store = store
        self._fairness = WeightedFairProviderScheduler()

    async def enqueue(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        work: ProviderWorkItem,
    ) -> ProviderWorkItem:
        """Queue or exactly replay one content-free provider item."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, work.enqueued_at_microseconds)
                operation = (
                    (
                        await connection.execute(
                            text(
                                "SELECT brain_id,request_digest,operation_kind,item_id "
                                "FROM provider_scheduling_operations WHERE operation_id=:operation"
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
                        or _blob(operation["request_digest"]) != bytes.fromhex(request_digest)
                        or str(operation["operation_kind"]) != "enqueue"
                    ):
                        raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                    replay = await _load_work(connection, str(operation["item_id"]))
                    if replay is None or replay.document != work.document:
                        raise ProviderSchedulingConflictError(_ERR_INTEGRITY)
                    return replay
                _require_scope_coordinates(scope, work.batch_key)
                await _validate_authority(connection, work)
                await connection.execute(
                    text(
                        "INSERT INTO provider_scheduling_operations "
                        "(operation_id,brain_id,request_digest,operation_kind,item_id,completed_at,"
                        "schema_version) VALUES "
                        "(:operation,:brain,:request,'enqueue',:item,:at,1)"
                    ),
                    {
                        "at": work.enqueued_at_microseconds,
                        "brain": work.batch_key.brain_id,
                        "item": work.item_id,
                        "operation": operation_id,
                        "request": bytes.fromhex(request_digest),
                    },
                )
                await _insert_work(connection, scope, work)
                await connection.execute(
                    text(
                        "INSERT INTO provider_scheduler_state "
                        "(profile_id,dispatch_cursor,updated_at,schema_version) "
                        "VALUES (:profile,0,:at,1) ON CONFLICT(profile_id) DO NOTHING"
                    ),
                    {
                        "at": work.enqueued_at_microseconds,
                        "profile": work.batch_key.profile_id,
                    },
                )
                await _append_audit(
                    connection,
                    scope,
                    "provider.schedule.enqueued",
                    operation_id,
                    work.item_id,
                    work.content_digest,
                    work.enqueued_at_microseconds,
                )
                return work
        except (
            ProviderSchedulingAuthorizationError,
            ProviderSchedulingConflictError,
            ProviderSchedulingValidationError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderSchedulingConflictError(_ERR_CONFLICT) from error
        except (SQLAlchemyError, ValueError) as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error

    async def get(
        self,
        scope: AuthorizedScope,
        item_id: str,
    ) -> ProviderWorkItem | None:
        """Load one item without revealing cross-Brain existence."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, _now_microseconds())
                row = (
                    (
                        await connection.execute(
                            text(_WORK_SELECT + " WHERE item_id=:item AND brain_id=:brain"),
                            {"brain": scope.brain_id.value, "item": item_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                return None if row is None else _work(row)
        except ProviderSchedulingAuthorizationError, ProviderSchedulingConflictError:
            raise
        except SQLAlchemyError as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error
        except (KeyError, TypeError, ValueError) as error:
            raise ProviderSchedulingConflictError(_ERR_INTEGRITY) from error

    async def cancel(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        item_id: str,
        cancelled_at_microseconds: int,
    ) -> ProviderWorkItem:
        """Cancel queued work or mark one active lease for final-auth denial."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, cancelled_at_microseconds)
                operation = (
                    (
                        await connection.execute(
                            text(
                                "SELECT brain_id,operation_kind,item_id "
                                "FROM provider_scheduling_operations WHERE operation_id=:operation"
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
                        or str(operation["operation_kind"]) != "cancel"
                        or str(operation["item_id"]) != item_id
                    ):
                        raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                    replay = await _load_work(connection, item_id)
                    if replay is None:
                        raise ProviderSchedulingConflictError(_ERR_INTEGRITY)
                    return replay
                row = await _load_work_row(connection, item_id, scope.brain_id.value)
                if row is None:
                    raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)
                state = ProviderWorkState(str(row["state"]))
                if state in {
                    ProviderWorkState.COMPLETED,
                    ProviderWorkState.FAILED,
                }:
                    raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                await connection.execute(
                    text(
                        "INSERT INTO provider_scheduling_operations "
                        "(operation_id,brain_id,request_digest,operation_kind,item_id,completed_at,"
                        "schema_version) VALUES "
                        "(:operation,:brain,:request,'cancel',:item,:at,1)"
                    ),
                    {
                        "at": cancelled_at_microseconds,
                        "brain": scope.brain_id.value,
                        "item": item_id,
                        "operation": operation_id,
                        "request": hashlib.sha256(
                            f"{scope.brain_id.value}\x00{item_id}".encode()
                        ).digest(),
                    },
                )
                if state is ProviderWorkState.LEASED:
                    await connection.execute(
                        text(
                            "UPDATE provider_work_items SET cancel_requested=1,updated_at=:at "
                            "WHERE item_id=:item AND state='leased'"
                        ),
                        {"at": cancelled_at_microseconds, "item": item_id},
                    )
                elif state is not ProviderWorkState.CANCELLED:
                    changed = await connection.execute(
                        text(
                            "UPDATE provider_work_items SET state='cancelled',cancel_requested=1,"
                            "completed_at=:at,updated_at=:at,last_error_code='cancelled' "
                            "WHERE item_id=:item AND state IN ('queued','retry_scheduled')"
                        ),
                        {"at": cancelled_at_microseconds, "item": item_id},
                    )
                    if changed.rowcount != 1:
                        raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                result = await _load_work(connection, item_id)
                if result is None:
                    raise ProviderSchedulingConflictError(_ERR_INTEGRITY)
                await _append_audit(
                    connection,
                    scope,
                    "provider.schedule.cancelled",
                    operation_id,
                    item_id,
                    result.content_digest,
                    cancelled_at_microseconds,
                )
                return result
        except (
            ProviderSchedulingAuthorizationError,
            ProviderSchedulingConflictError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderSchedulingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error

    async def claim_next(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderBatchLease | None:
        """Select one profile/workload fairly and atomically reserve rate/cost/concurrency."""
        if lease_until_microseconds <= now_microseconds:
            raise ProviderSchedulingValidationError(_ERR_INTEGRITY)
        try:
            async with _write_transaction(self._store) as connection:
                profile_id = (
                    await connection.execute(
                        text(
                            "SELECT profile_id FROM provider_work_items "
                            "WHERE state IN ('queued','retry_scheduled') "
                            "AND cancel_requested=0 AND next_attempt_at<=:now "
                            "AND deadline_at>:now "
                            "GROUP BY profile_id ORDER BY MIN(next_attempt_at),"
                            "MIN(enqueued_at),profile_id LIMIT 1"
                        ),
                        {"now": now_microseconds},
                    )
                ).scalar_one_or_none()
                if profile_id is None:
                    return None
                profile = str(profile_id)
                available_values = (
                    await connection.execute(
                        text(
                            "SELECT DISTINCT workload FROM provider_work_items "
                            "WHERE profile_id=:profile "
                            "AND state IN ('queued','retry_scheduled') "
                            "AND cancel_requested=0 AND next_attempt_at<=:now "
                            "AND deadline_at>:now"
                        ),
                        {"now": now_microseconds, "profile": profile},
                    )
                ).scalars()
                available = frozenset(ProviderWorkload(str(value)) for value in available_values)
                cursor = int(
                    (
                        await connection.execute(
                            text(
                                "SELECT dispatch_cursor FROM provider_scheduler_state "
                                "WHERE profile_id=:profile"
                            ),
                            {"profile": profile},
                        )
                    ).scalar_one()
                )
                workload, next_cursor = self._fairness.select(available, cursor)
                if workload is None:
                    return None
                first = (
                    (
                        await connection.execute(
                            text(
                                _WORK_SELECT + " WHERE profile_id=:profile AND workload=:workload "
                                "AND state IN ('queued','retry_scheduled') "
                                "AND cancel_requested=0 AND next_attempt_at<=:now "
                                "AND deadline_at>:now "
                                "ORDER BY next_attempt_at,enqueued_at,ordinal,item_id LIMIT 1"
                            ),
                            {
                                "now": now_microseconds,
                                "profile": profile,
                                "workload": workload.value,
                            },
                        )
                    )
                    .mappings()
                    .one()
                )
                rows = (
                    (
                        await connection.execute(
                            text(
                                _WORK_SELECT + " WHERE profile_id=:profile AND workload=:workload "
                                "AND batch_key_digest=:partition "
                                "AND state IN ('queued','retry_scheduled') "
                                "AND cancel_requested=0 AND next_attempt_at<=:now "
                                "AND deadline_at>:now "
                                "ORDER BY next_attempt_at,enqueued_at,ordinal,item_id "
                                "LIMIT :limit"
                            ),
                            {
                                "limit": _MAX_CANDIDATES,
                                "now": now_microseconds,
                                "partition": _blob(first["batch_key_digest"]),
                                "profile": profile,
                                "workload": workload.value,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
                candidates = tuple(_work(row) for row in rows)
                limits, rate_policy = await _profile_policies(
                    connection,
                    profile,
                    candidates[0].batch_key.profile_version,
                )
                planned = BatchPlanner.plan(candidates, limits)[0]
                rate_state = await _rate_state(
                    connection,
                    profile,
                    candidates[0].batch_key.profile_version,
                    rate_policy,
                    now_microseconds,
                )
                admission = rate_state.admit(
                    rate_policy,
                    now_microseconds=now_microseconds,
                    token_count=planned.token_count,
                    estimated_cost_micros=planned.estimated_cost_micros,
                )
                await _save_rate_state(
                    connection,
                    profile,
                    candidates[0].batch_key.profile_version,
                    admission.state,
                )
                if not admission.allowed:
                    if admission.retry_at_microseconds is not None:
                        await connection.execute(
                            text(
                                "UPDATE provider_work_items SET next_attempt_at=:retry,"
                                "last_error_code=:reason,updated_at=:now "
                                "WHERE profile_id=:profile AND batch_key_digest=:partition "
                                "AND state IN ('queued','retry_scheduled')"
                            ),
                            {
                                "now": now_microseconds,
                                "partition": bytes.fromhex(planned.key.digest),
                                "profile": profile,
                                "reason": admission.reason,
                                "retry": admission.retry_at_microseconds,
                            },
                        )
                    return None
                batch = replace(planned, operation_id=str(uuid7()))
                for work in batch.items:
                    changed = await connection.execute(
                        text(
                            "UPDATE provider_work_items SET state='leased',attempts=attempts+1,"
                            "lease_owner=:owner,lease_until=:until,updated_at=:now,"
                            "last_error_code=NULL WHERE item_id=:item "
                            "AND state IN ('queued','retry_scheduled') "
                            "AND cancel_requested=0 AND next_attempt_at<=:now"
                        ),
                        {
                            "item": work.item_id,
                            "now": now_microseconds,
                            "owner": owner,
                            "until": lease_until_microseconds,
                        },
                    )
                    if changed.rowcount != 1:
                        raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                attempts = tuple(work.attempts + 1 for work in batch.items)
                attempt = max(attempts)
                await _insert_batch(
                    connection,
                    batch,
                    owner,
                    lease_until_microseconds,
                    attempt,
                    now_microseconds,
                )
                await connection.execute(
                    text(
                        "UPDATE provider_scheduler_state SET dispatch_cursor=:cursor,"
                        "updated_at=:now WHERE profile_id=:profile"
                    ),
                    {
                        "cursor": next_cursor,
                        "now": now_microseconds,
                        "profile": profile,
                    },
                )
                leased = replace(
                    batch,
                    items=tuple(
                        value.with_state(
                            ProviderWorkState.LEASED,
                            attempts=value.attempts + 1,
                        )
                        for value in batch.items
                    ),
                )
                return ProviderBatchLease(
                    leased,
                    owner,
                    lease_until_microseconds,
                    attempt,
                )
        except (
            ProviderSchedulingConflictError,
            ProviderSchedulingValidationError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderSchedulingConflictError(_ERR_CONFLICT) from error
        except (SQLAlchemyError, StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error

    async def complete(
        self,
        lease: ProviderBatchLease,
        outcome: ProviderBatchOutcome,
        completed_at_microseconds: int,
    ) -> None:
        """Commit ordered child outcomes and retry only retryable identities."""
        outcome.validate_for(lease.batch)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_lease(connection, lease)
                for result in outcome.results:
                    await connection.execute(
                        text(
                            "INSERT INTO provider_item_results "
                            "(batch_operation_id,item_id,attempt,status,result_digest,result_ref,"
                            "error_code,retry_at,completed_at,schema_version) VALUES "
                            "(:batch,:item,:attempt,:status,:digest,:ref,:error,:retry,:at,1)"
                        ),
                        {
                            "at": completed_at_microseconds,
                            "attempt": lease.attempt,
                            "batch": lease.batch.operation_id,
                            "digest": (
                                None
                                if result.result_digest is None
                                else bytes.fromhex(result.result_digest)
                            ),
                            "error": result.error_code,
                            "item": result.item_id,
                            "ref": result.result_ref,
                            "retry": result.retry_at_microseconds,
                            "status": result.status.value,
                        },
                    )
                    await _apply_result(connection, lease, result, completed_at_microseconds)
                await _close_batch(
                    connection,
                    lease,
                    "completed",
                    None,
                    outcome.retry_at_microseconds,
                    completed_at_microseconds,
                )
                await _release_rate(
                    connection,
                    lease.batch.key.profile_id,
                    lease.batch.key.profile_version,
                    outcome.retry_at_microseconds,
                )
        except ProviderSchedulingConflictError, ProviderSchedulingValidationError:
            raise
        except IntegrityError as error:
            raise ProviderSchedulingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error

    async def release(
        self,
        lease: ProviderBatchLease,
        reason: str,
        retry_at_microseconds: int | None,
        released_at_microseconds: int,
    ) -> None:
        """Release or permanently fail every exact child in one leased batch."""
        try:
            async with _write_transaction(self._store) as connection:
                await _require_lease(connection, lease)
                retryable = retry_at_microseconds is not None
                if retryable:
                    changed = await connection.execute(
                        text(
                            "UPDATE provider_work_items SET state='retry_scheduled',"
                            "next_attempt_at=:retry,lease_owner=NULL,lease_until=NULL,"
                            "updated_at=:at,last_error_code=:reason "
                            "WHERE item_id IN (SELECT item_id FROM provider_batch_items "
                            "WHERE batch_operation_id=:batch) AND state='leased' "
                            "AND lease_owner=:owner AND lease_until=:until"
                        ),
                        {
                            "at": released_at_microseconds,
                            "batch": lease.batch.operation_id,
                            "owner": lease.owner,
                            "reason": reason,
                            "retry": retry_at_microseconds,
                            "until": lease.lease_until_microseconds,
                        },
                    )
                    batch_state = "released"
                else:
                    changed = await connection.execute(
                        text(
                            "UPDATE provider_work_items SET state='failed',"
                            "lease_owner=NULL,lease_until=NULL,completed_at=:at,updated_at=:at,"
                            "last_error_code=:reason WHERE item_id IN "
                            "(SELECT item_id FROM provider_batch_items "
                            "WHERE batch_operation_id=:batch) AND state='leased' "
                            "AND lease_owner=:owner AND lease_until=:until"
                        ),
                        {
                            "at": released_at_microseconds,
                            "batch": lease.batch.operation_id,
                            "owner": lease.owner,
                            "reason": reason,
                            "until": lease.lease_until_microseconds,
                        },
                    )
                    batch_state = "failed"
                if changed.rowcount != len(lease.batch.items):
                    raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                await _close_batch(
                    connection,
                    lease,
                    batch_state,
                    reason,
                    retry_at_microseconds,
                    released_at_microseconds,
                )
                await _release_rate(
                    connection,
                    lease.batch.key.profile_id,
                    lease.batch.key.profile_version,
                    retry_at_microseconds,
                )
        except ProviderSchedulingConflictError:
            raise
        except IntegrityError as error:
            raise ProviderSchedulingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error

    async def recover_expired(self, now_microseconds: int) -> int:
        """Recover every expired batch exactly once and release its concurrency slot."""
        recovered = 0
        try:
            async with _write_transaction(self._store) as connection:
                rows = (
                    (
                        await connection.execute(
                            text(
                                "SELECT batch_operation_id,profile_id,profile_version "
                                "FROM provider_batches WHERE state='leased' AND lease_until<=:now "
                                "ORDER BY lease_until,batch_operation_id"
                            ),
                            {"now": now_microseconds},
                        )
                    )
                    .mappings()
                    .all()
                )
                for row in rows:
                    batch_id = str(row["batch_operation_id"])
                    await connection.execute(
                        text(
                            "UPDATE provider_work_items SET "
                            "state=CASE WHEN cancel_requested=1 THEN 'cancelled' "
                            "ELSE 'retry_scheduled' END,"
                            "next_attempt_at=:now,lease_owner=NULL,lease_until=NULL,"
                            "completed_at=CASE WHEN cancel_requested=1 THEN :now ELSE NULL END,"
                            "updated_at=:now,last_error_code='lease_expired' "
                            "WHERE item_id IN (SELECT item_id FROM provider_batch_items "
                            "WHERE batch_operation_id=:batch) AND state='leased'"
                        ),
                        {"batch": batch_id, "now": now_microseconds},
                    )
                    changed = await connection.execute(
                        text(
                            "UPDATE provider_batches SET state='released',"
                            "reason_code='lease_expired',completed_at=:now "
                            "WHERE batch_operation_id=:batch AND state='leased'"
                        ),
                        {"batch": batch_id, "now": now_microseconds},
                    )
                    if changed.rowcount != 1:
                        raise ProviderSchedulingConflictError(_ERR_CONFLICT)
                    await _release_rate(
                        connection,
                        str(row["profile_id"]),
                        int(row["profile_version"]),
                        None,
                    )
                    recovered += 1
                return recovered
        except ProviderSchedulingConflictError:
            raise
        except SQLAlchemyError as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error


class SqliteProviderDispatchAuthorization:
    """Recheck grant, profile, space, immutable item, and cancellation at dispatch."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind current canonical SQLite authority."""
        self._store = store

    async def authorize(self, work: ProviderWorkItem, now_microseconds: int) -> None:
        """Deny stale/revoked/tampered work before payload materialization."""
        try:
            async with self._store.engine.connect() as connection:
                found = (
                    await connection.execute(
                        text(
                            "SELECT 1 FROM provider_work_items AS work "
                            "JOIN brains AS brain ON brain.id=work.brain_id "
                            "AND brain.status='active' "
                            "JOIN principals AS principal ON principal.id=work.principal_id "
                            "AND principal.status='active' "
                            "JOIN scope_grants AS grant ON grant.principal_id=work.principal_id "
                            "AND grant.brain_id=work.brain_id "
                            "JOIN provider_profiles AS profile ON profile.id=work.profile_id "
                            "AND profile.brain_id=work.brain_id AND profile.status='active' "
                            "AND profile.version=work.profile_version "
                            "JOIN embedding_spaces AS space ON space.id=work.space_id "
                            "AND space.brain_id=work.brain_id "
                            "AND space.profile_id=work.profile_id "
                            "WHERE work.item_id=:item AND work.brain_id=:brain "
                            "AND work.profile_id=:profile AND work.profile_version=:version "
                            "AND work.space_id=:space AND work.space_fingerprint=:fingerprint "
                            "AND work.batch_key_digest=:partition "
                            "AND work.payload_ref=:payload AND work.content_digest=:content "
                            "AND work.cancel_requested=0 "
                            "AND work.state IN ('queued','retry_scheduled','leased') "
                            "AND work.deadline_at>:now AND grant.valid_from<=:now "
                            "AND (grant.valid_to IS NULL OR grant.valid_to>:now) LIMIT 1"
                        ),
                        {
                            "brain": work.batch_key.brain_id,
                            "content": bytes.fromhex(work.content_digest),
                            "fingerprint": bytes.fromhex(work.batch_key.space_fingerprint),
                            "item": work.item_id,
                            "now": now_microseconds,
                            "partition": bytes.fromhex(work.batch_key.digest),
                            "payload": work.payload_ref,
                            "profile": work.batch_key.profile_id,
                            "space": work.batch_key.space_id,
                            "version": work.batch_key.profile_version,
                        },
                    )
                ).scalar_one_or_none()
        except SQLAlchemyError as error:
            raise ProviderSchedulingDependencyError(_ERR_STORAGE) from error
        if found is None:
            raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)


async def _insert_work(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    work: ProviderWorkItem,
) -> None:
    key = work.batch_key
    await connection.execute(
        text(
            "INSERT INTO provider_work_items "
            "(item_id,operation_id,brain_id,principal_id,grant_version,"
            "authorization_policy_version,security_epoch,scope_fingerprint,project_id,"
            "repository_id,profile_id,profile_version,space_id,space_fingerprint,"
            "classification,purpose,retention_policy_digest,preprocessing_digest,"
            "deadline_class,workload,batch_key_digest,ordinal,payload_ref,content_digest,"
            "token_count,byte_count,estimated_cost_micros,state,attempts,next_attempt_at,"
            "lease_owner,lease_until,cancel_requested,last_error_code,enqueued_at,deadline_at,"
            "updated_at,completed_at,schema_version) VALUES "
            "(:item,:operation,:brain,:principal,:grant,:policy,:security,:scope,:project,"
            ":repository,:profile,:profile_version,:space,:space_fingerprint,:classification,"
            ":purpose,:retention,:preprocessing,:deadline,:workload,:partition,:ordinal,"
            ":payload,:content,:tokens,:bytes,:cost,'queued',0,:at,NULL,NULL,0,NULL,:at,"
            ":deadline_at,:at,NULL,1)"
        ),
        {
            "at": work.enqueued_at_microseconds,
            "brain": key.brain_id,
            "bytes": work.byte_count,
            "classification": key.classification.value,
            "content": bytes.fromhex(work.content_digest),
            "cost": work.estimated_cost_micros,
            "deadline": key.deadline_class.value,
            "deadline_at": work.deadline_at_microseconds,
            "grant": scope.grant_version,
            "item": work.item_id,
            "operation": work.operation_id,
            "ordinal": work.ordinal,
            "partition": bytes.fromhex(key.digest),
            "payload": work.payload_ref,
            "policy": scope.policy_version,
            "preprocessing": bytes.fromhex(key.preprocessing_digest),
            "principal": scope.principal_id.value,
            "profile": key.profile_id,
            "profile_version": key.profile_version,
            "project": key.project_id,
            "purpose": key.purpose.value,
            "repository": key.repository_id,
            "retention": bytes.fromhex(key.retention_policy_digest),
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "security": scope.security_epoch,
            "space": key.space_id,
            "space_fingerprint": bytes.fromhex(key.space_fingerprint),
            "tokens": work.token_count,
            "workload": key.workload.value,
        },
    )


async def _validate_authority(
    connection: AsyncConnection,
    work: ProviderWorkItem,
) -> None:
    key = work.batch_key
    row = (
        (
            await connection.execute(
                text(
                    "SELECT revision.document_json,profile.status,profile.version,"
                    "space.immutable_fingerprint,space.purpose "
                    "FROM provider_profiles AS profile "
                    "JOIN provider_profile_revisions AS revision "
                    "ON revision.profile_id=profile.id AND revision.version=:version "
                    "JOIN embedding_spaces AS space ON space.id=:space "
                    "AND space.brain_id=profile.brain_id AND space.profile_id=profile.id "
                    "WHERE profile.id=:profile AND profile.brain_id=:brain "
                    "AND profile.status='active' AND profile.version=:version"
                ),
                {
                    "brain": key.brain_id,
                    "profile": key.profile_id,
                    "space": key.space_id,
                    "version": key.profile_version,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or str(row["immutable_fingerprint"]) != key.space_fingerprint
        or str(row["purpose"]) != key.purpose.value
    ):
        raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)
    limits, _ = _policies_from_document(_blob(row["document_json"]))
    if (
        work.token_count > limits.max_item_tokens
        or work.token_count > limits.max_request_tokens
        or work.byte_count > limits.max_input_bytes
        or work.estimated_cost_micros > limits.max_batch_cost_micros
    ):
        raise ProviderSchedulingValidationError(_ERR_INTEGRITY)


async def _profile_policies(
    connection: AsyncConnection,
    profile_id: str,
    profile_version: int,
) -> tuple[ProviderSchedulingLimits, ProviderRatePolicy]:
    raw = (
        await connection.execute(
            text(
                "SELECT document_json FROM provider_profile_revisions "
                "WHERE profile_id=:profile AND version=:version AND status='active'"
            ),
            {"profile": profile_id, "version": profile_version},
        )
    ).scalar_one_or_none()
    if raw is None:
        raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)
    return _policies_from_document(_blob(raw))


def _policies_from_document(
    raw: bytes,
) -> tuple[ProviderSchedulingLimits, ProviderRatePolicy]:
    document = _mapping(loads(raw))
    configuration = _mapping(document["configuration"])
    configured_limits = _mapping(configuration["limits"])
    quota_raw = configuration.get("quota")
    budget_raw = configuration.get("budget")
    remote = configuration.get("execution_class") == "remote"
    quota = _mapping(quota_raw) if remote else {}
    budget = _mapping(budget_raw) if remote else {}
    monthly_budget = _integer(budget.get("monthly_micros", _MAX_COST_MICROS))
    limits = ProviderSchedulingLimits(
        max_items=_integer(configured_limits["max_items"]),
        max_item_tokens=_integer(configured_limits["max_item_tokens"]),
        max_request_tokens=_integer(configured_limits["max_request_tokens"]),
        max_input_bytes=_integer(configured_limits["max_input_bytes"]),
        max_batch_cost_micros=monthly_budget,
    )
    requests = _integer(quota.get("requests_per_minute", _LOCAL_REQUEST_RATE))
    tokens = _integer(quota.get("tokens_per_minute", _LOCAL_TOKEN_RATE))
    rate = ProviderRatePolicy(
        request_capacity=requests,
        requests_per_minute=requests,
        token_capacity=tokens,
        tokens_per_minute=tokens,
        max_concurrency=_DEFAULT_CONCURRENCY,
        monthly_cost_budget_micros=monthly_budget,
    )
    return limits, rate


async def _rate_state(
    connection: AsyncConnection,
    profile_id: str,
    profile_version: int,
    policy: ProviderRatePolicy,
    now_microseconds: int,
) -> ProviderRateState:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_rate_states WHERE profile_id=:profile"),
                {"profile": profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        state = ProviderRateState.full(
            policy,
            period_start_microseconds=now_microseconds,
        )
        await connection.execute(
            text(
                "INSERT INTO provider_rate_states "
                "(profile_id,profile_version,request_balance_micros,token_balance_micros,"
                "last_refill_at,blocked_until,in_flight,period_start,cost_spent_micros,"
                "version,schema_version) VALUES "
                "(:profile,:profile_version,:requests,:tokens,:at,NULL,0,:at,0,1,1)"
            ),
            {
                "at": now_microseconds,
                "profile": profile_id,
                "profile_version": profile_version,
                "requests": state.request_balance_micros,
                "tokens": state.token_balance_micros,
            },
        )
        return state
    if int(row["profile_version"]) != profile_version:
        raise ProviderSchedulingConflictError(_ERR_INTEGRITY)
    return ProviderRateState(
        request_balance_micros=int(row["request_balance_micros"]),
        token_balance_micros=int(row["token_balance_micros"]),
        last_refill_microseconds=int(row["last_refill_at"]),
        blocked_until_microseconds=(
            None if row["blocked_until"] is None else int(row["blocked_until"])
        ),
        in_flight=int(row["in_flight"]),
        period_start_microseconds=int(row["period_start"]),
        cost_spent_micros=int(row["cost_spent_micros"]),
    )


async def _save_rate_state(
    connection: AsyncConnection,
    profile_id: str,
    profile_version: int,
    state: ProviderRateState,
) -> None:
    changed = await connection.execute(
        text(
            "UPDATE provider_rate_states SET request_balance_micros=:requests,"
            "token_balance_micros=:tokens,last_refill_at=:refill,blocked_until=:blocked,"
            "in_flight=:in_flight,period_start=:period,cost_spent_micros=:cost,"
            "version=version+1 WHERE profile_id=:profile AND profile_version=:profile_version"
        ),
        {
            "blocked": state.blocked_until_microseconds,
            "cost": state.cost_spent_micros,
            "in_flight": state.in_flight,
            "period": state.period_start_microseconds,
            "profile": profile_id,
            "profile_version": profile_version,
            "refill": state.last_refill_microseconds,
            "requests": state.request_balance_micros,
            "tokens": state.token_balance_micros,
        },
    )
    if changed.rowcount != 1:
        raise ProviderSchedulingConflictError(_ERR_CONFLICT)


async def _release_rate(
    connection: AsyncConnection,
    profile_id: str,
    profile_version: int,
    blocked_until: int | None,
) -> None:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_rate_states WHERE profile_id=:profile"),
                {"profile": profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None or int(row["profile_version"]) != profile_version:
        raise ProviderSchedulingConflictError(_ERR_INTEGRITY)
    state = ProviderRateState(
        int(row["request_balance_micros"]),
        int(row["token_balance_micros"]),
        int(row["last_refill_at"]),
        None if row["blocked_until"] is None else int(row["blocked_until"]),
        int(row["in_flight"]),
        int(row["period_start"]),
        int(row["cost_spent_micros"]),
    ).release()
    if blocked_until is not None:
        state = replace(
            state,
            blocked_until_microseconds=max(
                blocked_until,
                state.blocked_until_microseconds or 0,
            ),
        )
    await _save_rate_state(connection, profile_id, profile_version, state)


async def _insert_batch(
    connection: AsyncConnection,
    batch: ProviderBatch,
    owner: str,
    lease_until: int,
    attempt: int,
    created_at: int,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_batches "
            "(batch_operation_id,brain_id,profile_id,profile_version,batch_key_digest,"
            "workload,owner,lease_until,attempt,item_count,token_count,byte_count,"
            "estimated_cost_micros,state,reason_code,provider_retry_at,created_at,"
            "completed_at,schema_version) VALUES "
            "(:batch,:brain,:profile,:profile_version,:partition,:workload,:owner,:until,"
            ":attempt,:items,:tokens,:bytes,:cost,'leased',NULL,NULL,:at,NULL,1)"
        ),
        {
            "at": created_at,
            "attempt": attempt,
            "batch": batch.operation_id,
            "brain": batch.key.brain_id,
            "bytes": batch.byte_count,
            "cost": batch.estimated_cost_micros,
            "items": len(batch.items),
            "owner": owner,
            "partition": bytes.fromhex(batch.key.digest),
            "profile": batch.key.profile_id,
            "profile_version": batch.key.profile_version,
            "tokens": batch.token_count,
            "until": lease_until,
            "workload": batch.key.workload.value,
        },
    )
    for ordinal, work in enumerate(batch.items):
        await connection.execute(
            text(
                "INSERT INTO provider_batch_items "
                "(batch_operation_id,item_id,batch_ordinal,schema_version) "
                "VALUES (:batch,:item,:ordinal,1)"
            ),
            {"batch": batch.operation_id, "item": work.item_id, "ordinal": ordinal},
        )


async def _require_lease(
    connection: AsyncConnection,
    lease: ProviderBatchLease,
) -> None:
    found = (
        await connection.execute(
            text(
                "SELECT 1 FROM provider_batches WHERE batch_operation_id=:batch "
                "AND state='leased' AND owner=:owner AND lease_until=:until "
                "AND attempt=:attempt"
            ),
            {
                "attempt": lease.attempt,
                "batch": lease.batch.operation_id,
                "owner": lease.owner,
                "until": lease.lease_until_microseconds,
            },
        )
    ).scalar_one_or_none()
    if found is None:
        raise ProviderSchedulingConflictError(_ERR_CONFLICT)


async def _apply_result(
    connection: AsyncConnection,
    lease: ProviderBatchLease,
    result: object,
    completed_at: int,
) -> None:
    typed = cast("ProviderItemResult", result)
    values: dict[str, object] = {
        "at": completed_at,
        "item": typed.item_id,
        "owner": lease.owner,
        "until": lease.lease_until_microseconds,
    }
    if typed.status is ProviderItemResultStatus.SUCCEEDED:
        statement = (
            "UPDATE provider_work_items SET state='completed',lease_owner=NULL,"
            "lease_until=NULL,completed_at=:at,updated_at=:at,last_error_code=NULL "
            "WHERE item_id=:item AND state='leased' AND lease_owner=:owner "
            "AND lease_until=:until"
        )
    elif typed.status is ProviderItemResultStatus.RETRYABLE_FAILURE:
        values["retry"] = max(
            completed_at + 1,
            typed.retry_at_microseconds or completed_at + _RETRY_DELAY_MICROSECONDS,
        )
        values["error"] = typed.error_code
        statement = (
            "UPDATE provider_work_items SET state='retry_scheduled',lease_owner=NULL,"
            "lease_until=NULL,next_attempt_at=:retry,updated_at=:at,last_error_code=:error "
            "WHERE item_id=:item AND state='leased' AND lease_owner=:owner "
            "AND lease_until=:until"
        )
    else:
        terminal = (
            ProviderWorkState.CANCELLED.value
            if typed.status is ProviderItemResultStatus.CANCELLED
            else ProviderWorkState.FAILED.value
        )
        values["state"] = terminal
        values["error"] = typed.error_code
        statement = (
            "UPDATE provider_work_items SET state=:state,lease_owner=NULL,lease_until=NULL,"
            "completed_at=:at,updated_at=:at,last_error_code=:error "
            "WHERE item_id=:item AND state='leased' AND lease_owner=:owner "
            "AND lease_until=:until"
        )
    changed = await connection.execute(text(statement), values)
    if changed.rowcount != 1:
        raise ProviderSchedulingConflictError(_ERR_CONFLICT)


async def _close_batch(
    connection: AsyncConnection,
    lease: ProviderBatchLease,
    state: str,
    reason: str | None,
    retry_at: int | None,
    completed_at: int,
) -> None:
    changed = await connection.execute(
        text(
            "UPDATE provider_batches SET state=:state,reason_code=:reason,"
            "provider_retry_at=:retry,completed_at=:at "
            "WHERE batch_operation_id=:batch AND state='leased' "
            "AND owner=:owner AND lease_until=:until AND attempt=:attempt"
        ),
        {
            "at": completed_at,
            "attempt": lease.attempt,
            "batch": lease.batch.operation_id,
            "owner": lease.owner,
            "reason": reason,
            "retry": retry_at,
            "state": state,
            "until": lease.lease_until_microseconds,
        },
    )
    if changed.rowcount != 1:
        raise ProviderSchedulingConflictError(_ERR_CONFLICT)


async def _load_work(
    connection: AsyncConnection,
    item_id: str,
) -> ProviderWorkItem | None:
    row = await _load_work_row(connection, item_id, None)
    return None if row is None else _work(row)


async def _load_work_row(
    connection: AsyncConnection,
    item_id: str,
    brain_id: str | None,
) -> RowMapping | None:
    clause = " WHERE item_id=:item"
    parameters = {"item": item_id}
    if brain_id is not None:
        clause += " AND brain_id=:brain"
        parameters["brain"] = brain_id
    return (
        (await connection.execute(text(_WORK_SELECT + clause), parameters)).mappings().one_or_none()
    )


def _work(row: RowMapping) -> ProviderWorkItem:
    key = ProviderBatchKey(
        brain_id=str(row["brain_id"]),
        project_id=None if row["project_id"] is None else str(row["project_id"]),
        repository_id=(None if row["repository_id"] is None else str(row["repository_id"])),
        classification=Classification(str(row["classification"])),
        profile_id=str(row["profile_id"]),
        profile_version=int(row["profile_version"]),
        space_id=str(row["space_id"]),
        space_fingerprint=_blob(row["space_fingerprint"]).hex(),
        purpose=CanonicalPurpose(str(row["purpose"])),
        retention_policy_digest=_blob(row["retention_policy_digest"]).hex(),
        preprocessing_digest=_blob(row["preprocessing_digest"]).hex(),
        deadline_class=ProviderDeadlineClass(str(row["deadline_class"])),
        workload=ProviderWorkload(str(row["workload"])),
    )
    if _blob(row["batch_key_digest"]).hex() != key.digest:
        raise ProviderSchedulingConflictError(_ERR_INTEGRITY)
    return ProviderWorkItem(
        item_id=str(row["item_id"]),
        operation_id=str(row["operation_id"]),
        batch_key=key,
        ordinal=int(row["ordinal"]),
        payload_ref=str(row["payload_ref"]),
        content_digest=_blob(row["content_digest"]).hex(),
        token_count=int(row["token_count"]),
        byte_count=int(row["byte_count"]),
        estimated_cost_micros=int(row["estimated_cost_micros"]),
        enqueued_at_microseconds=int(row["enqueued_at"]),
        deadline_at_microseconds=int(row["deadline_at"]),
        state=ProviderWorkState(str(row["state"])),
        attempts=int(row["attempts"]),
    )


async def _authorize(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    at_microseconds: int,
) -> None:
    if scope.action not in _WRITE_ACTIONS | {_READ_ACTION} or scope.role.value not in (
        _READ_ROLES if scope.action == _READ_ACTION else _WRITE_ROLES
    ):
        raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)
    found = (
        await connection.execute(
            text(
                "SELECT 1 FROM brains AS brain JOIN principals AS principal "
                "ON principal.id=:principal JOIN scope_grants AS grant "
                "ON grant.principal_id=principal.id AND grant.brain_id=brain.id "
                "WHERE brain.id=:brain AND brain.status='active' "
                "AND principal.status='active' AND grant.role=:role "
                "AND grant.valid_from<=:at "
                "AND (grant.valid_to IS NULL OR grant.valid_to>:at) LIMIT 1"
            ),
            {
                "at": at_microseconds,
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
                "role": scope.role.value,
            },
        )
    ).scalar_one_or_none()
    if found is None:
        raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)


def _require_scope_coordinates(scope: AuthorizedScope, key: ProviderBatchKey) -> None:
    if (
        key.brain_id != scope.brain_id.value
        or (
            key.project_id is not None
            and key.project_id not in {value.value for value in scope.project_ids}
        )
        or (
            key.repository_id is not None
            and key.repository_id not in {value.value for value in scope.repository_ids}
        )
    ):
        raise ProviderSchedulingAuthorizationError(_ERR_AUTHORIZATION)


async def _append_audit(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    action: str,
    operation_id: str,
    item_id: str,
    content_digest: str,
    occurred_at: int,
) -> None:
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = bytes(32) if previous is None else _blob(previous)
    fact = canonical_bytes(
        {
            "action": action,
            "brain_id": scope.brain_id.value,
            "item_id": item_id,
            "operation_id": operation_id,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:at,1)"
        ),
        {
            "action": action,
            "actor": scope.principal_id.value,
            "after": bytes.fromhex(content_digest),
            "at": occurred_at,
            "before": bytes(32),
            "brain": scope.brain_id.value,
            "event": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"{action}:{operation_id}",
            "previous": previous_hash,
            "target": f"provider-work:{item_id}",
        },
    )


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError
    mapping = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in mapping):
        raise TypeError
    return cast("dict[str, object]", mapping)


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise TypeError


def _now_microseconds() -> int:
    return round(datetime.now(tz=UTC).timestamp() * 1_000_000)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    async with store.write_lock, store.engine.connect() as connection:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            await connection.rollback()
            raise
        else:
            await connection.commit()
