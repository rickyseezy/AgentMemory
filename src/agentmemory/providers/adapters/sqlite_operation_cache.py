"""SQLite provider-operation reservation, semantic cache, and conflict audit adapter."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Self
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.providers.domain.errors import (
    ProviderOperationConflictError,
    ProviderOperationDependencyError,
    ProviderOperationIntegrityError,
)
from agentmemory.providers.domain.idempotency import (
    ProviderClaimDisposition,
    ProviderOperationClaim,
    ProviderOperationOutcome,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.idempotency import ProviderOperationRequest

_ERR_STORAGE = "Provider operation cache is unavailable"
_ERR_CONFLICT = "Provider idempotency key was reused with different input"
_ERR_INTEGRITY = "Provider operation cache evidence diverged"


class SqliteProviderOperationCache:
    """Arbitrate provider work under the Core single-writer SQLite policy."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the shared canonical store without opening a connection."""
        self._store = store

    async def claim(
        self,
        operation: ProviderOperationRequest,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderOperationClaim:
        """Claim, wait for, replay, or conflict one persistent operation identity."""
        conflict = False
        async with _WriteTransaction(self._store) as transaction:
            exact = await _exact_row(transaction.connection, operation)
            if exact is not None and _bytes(exact["request_sha256"]).hex() != (
                operation.request_sha256
            ):
                await _append_conflict(transaction.connection, operation, exact, now_microseconds)
                conflict = True
                claim = _wait_claim(operation, int(str(exact["attempts"])))
            elif exact is not None:
                claim = await _claim_existing(
                    transaction.connection,
                    operation,
                    exact,
                    (owner, now_microseconds, lease_until_microseconds),
                )
            else:
                semantic = await _semantic_row(transaction.connection, operation)
                if semantic is not None:
                    claim = await _claim_existing(
                        transaction.connection,
                        operation,
                        semantic,
                        (owner, now_microseconds, lease_until_microseconds),
                    )
                else:
                    await transaction.connection.execute(
                        text(
                            "INSERT INTO provider_operation_results "
                            "(profile_id,idempotency_key,operation_id,brain_id,cache_key_sha256,"
                            "request_sha256,state,attempts,lease_owner,lease_until,retry_at,"
                            "created_at,updated_at,schema_version) VALUES "
                            "(:profile,:key,:operation,:brain,:cache,:request,'processing',1,"
                            ":owner,:lease_until,:now,:now,:now,1)"
                        ),
                        {
                            "brain": operation.brain_id,
                            "cache": bytes.fromhex(operation.cache_key_sha256),
                            "key": operation.idempotency_key,
                            "lease_until": lease_until_microseconds,
                            "now": now_microseconds,
                            "operation": operation.operation_id,
                            "owner": owner,
                            "profile": operation.profile_id,
                            "request": bytes.fromhex(operation.request_sha256),
                        },
                    )
                    claim = ProviderOperationClaim(
                        operation,
                        ProviderClaimDisposition.CLAIMED,
                        owner,
                        lease_until_microseconds,
                        1,
                        None,
                    )
            await transaction.commit()
        if conflict:
            raise ProviderOperationConflictError(_ERR_CONFLICT)
        return claim

    async def complete(
        self,
        claim: ProviderOperationClaim,
        result: ProviderOperationOutcome,
        completed_at_microseconds: int,
    ) -> None:
        """Commit one content-addressed result against the exact live reservation."""
        if claim.disposition is not ProviderClaimDisposition.CLAIMED or claim.owner is None:
            raise ProviderOperationIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            updated = await transaction.connection.execute(
                text(
                    "UPDATE provider_operation_results SET state='completed',lease_owner=NULL,"
                    "lease_until=NULL,result_sha256=:result_hash,result_ref=:result_ref,"
                    "usage_units=:usage,last_error_code=NULL,completed_at=:now,updated_at=:now "
                    "WHERE cache_key_sha256=:cache AND state='processing' "
                    "AND lease_owner=:owner"
                ),
                {
                    "cache": bytes.fromhex(claim.operation.cache_key_sha256),
                    "now": completed_at_microseconds,
                    "owner": claim.owner,
                    "result_hash": bytes.fromhex(result.result_sha256),
                    "result_ref": result.result_ref,
                    "usage": result.usage_units,
                },
            )
            if updated.rowcount != 1:
                raise ProviderOperationIntegrityError(_ERR_INTEGRITY)
            await transaction.commit()

    async def release_retry(
        self,
        claim: ProviderOperationClaim,
        reason_code: str,
        retry_at_microseconds: int,
    ) -> None:
        """Make the exact reservation reclaimable at the requested durable due time."""
        if claim.disposition is not ProviderClaimDisposition.CLAIMED or claim.owner is None:
            raise ProviderOperationIntegrityError(_ERR_INTEGRITY)
        async with _WriteTransaction(self._store) as transaction:
            updated = await transaction.connection.execute(
                text(
                    "UPDATE provider_operation_results SET lease_until=:retry,retry_at=:retry,"
                    "last_error_code=:reason,updated_at=:retry WHERE cache_key_sha256=:cache "
                    "AND state='processing' AND lease_owner=:owner"
                ),
                {
                    "cache": bytes.fromhex(claim.operation.cache_key_sha256),
                    "owner": claim.owner,
                    "reason": reason_code,
                    "retry": retry_at_microseconds,
                },
            )
            if updated.rowcount != 1:
                raise ProviderOperationIntegrityError(_ERR_INTEGRITY)
            await transaction.commit()


async def _exact_row(
    connection: AsyncConnection,
    operation: ProviderOperationRequest,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM provider_operation_results "
                    "WHERE profile_id=:profile AND idempotency_key=:key"
                ),
                {"key": operation.idempotency_key, "profile": operation.profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _semantic_row(
    connection: AsyncConnection,
    operation: ProviderOperationRequest,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM provider_operation_results WHERE cache_key_sha256=:cache"),
                {"cache": bytes.fromhex(operation.cache_key_sha256)},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _claim_existing(
    connection: AsyncConnection,
    operation: ProviderOperationRequest,
    row: RowMapping,
    lease: tuple[str, int, int],
) -> ProviderOperationClaim:
    owner, now, lease_until = lease
    attempt = int(str(row["attempts"]))
    if str(row["state"]) == "completed":
        return ProviderOperationClaim(
            operation,
            ProviderClaimDisposition.CACHED,
            None,
            None,
            attempt,
            _outcome(row),
        )
    current_lease = int(str(row["lease_until"]))
    retry_at = int(str(row["retry_at"]))
    if current_lease > now or retry_at > now:
        return _wait_claim(operation, attempt)
    updated = await connection.execute(
        text(
            "UPDATE provider_operation_results SET lease_owner=:owner,lease_until=:lease,"
            "attempts=attempts+1,last_error_code=NULL,updated_at=:now "
            "WHERE cache_key_sha256=:cache AND state='processing' AND lease_until<=:now "
            "AND retry_at<=:now"
        ),
        {
            "cache": bytes.fromhex(operation.cache_key_sha256),
            "lease": lease_until,
            "now": now,
            "owner": owner,
        },
    )
    if updated.rowcount != 1:
        return _wait_claim(operation, attempt)
    return ProviderOperationClaim(
        operation,
        ProviderClaimDisposition.CLAIMED,
        owner,
        lease_until,
        attempt + 1,
        None,
    )


def _wait_claim(operation: ProviderOperationRequest, attempt: int) -> ProviderOperationClaim:
    return ProviderOperationClaim(
        operation,
        ProviderClaimDisposition.WAIT,
        None,
        None,
        attempt,
        None,
    )


def _outcome(row: RowMapping) -> ProviderOperationOutcome:
    result_hash = _bytes(row["result_sha256"]).hex()
    result_ref = row["result_ref"]
    usage_units = row["usage_units"]
    if not isinstance(result_ref, str) or not isinstance(usage_units, int):
        raise ProviderOperationIntegrityError(_ERR_INTEGRITY)
    try:
        return ProviderOperationOutcome(result_hash, result_ref, usage_units)
    except ValueError as error:
        raise ProviderOperationIntegrityError(_ERR_INTEGRITY) from error


async def _append_conflict(
    connection: AsyncConnection,
    operation: ProviderOperationRequest,
    existing: RowMapping,
    detected_at: int,
) -> None:
    identity_hash = hashlib.sha256(
        f"{operation.profile_id}\x00{operation.idempotency_key}".encode()
    ).hexdigest()
    actual = bytes.fromhex(operation.request_sha256)
    inserted = await connection.execute(
        text(
            "INSERT INTO idempotency_conflicts "
            "(id,brain_id,namespace,identity_key,expected_sha256,actual_sha256,"
            "source_message_id,detected_at,schema_version) VALUES "
            "(:id,:brain,'provider_operation',:identity,:expected,:actual,NULL,:now,1) "
            "ON CONFLICT(namespace,identity_key,actual_sha256) DO NOTHING"
        ),
        {
            "actual": actual,
            "brain": operation.brain_id,
            "expected": _bytes(existing["request_sha256"]),
            "id": str(uuid7()),
            "identity": identity_hash,
            "now": detected_at,
        },
    )
    if inserted.rowcount != 1:
        return
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = previous if isinstance(previous, bytes) else bytes(32)
    fact = json.dumps(
        {
            "action": "provider.idempotency_conflict",
            "brain_id": operation.brain_id,
            "identity_hash": identity_hash,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,'system:provider-idempotency','provider.idempotency_conflict',:target,"
            ":key,:before,:after,:previous,:event_hash,:now,1)"
        ),
        {
            "after": actual,
            "before": _bytes(existing["request_sha256"]),
            "brain": operation.brain_id,
            "event_hash": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"provider-conflict:{identity_hash}:{operation.request_sha256}",
            "now": detected_at,
            "previous": previous_hash,
            "target": f"provider-operation:{identity_hash}",
        },
    )


class _WriteTransaction:
    """Short serialized provider-cache transaction with typed storage failures."""

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
                raise ProviderOperationDependencyError(_ERR_STORAGE) from error
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
            raise ProviderOperationDependencyError(_ERR_STORAGE) from storage_error
        return None

    async def commit(self) -> None:
        try:
            await self.connection.commit()
        except SQLAlchemyError as error:
            raise ProviderOperationDependencyError(_ERR_STORAGE) from error
        self._committed = True


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise ProviderOperationIntegrityError(_ERR_INTEGRITY)
    return value
