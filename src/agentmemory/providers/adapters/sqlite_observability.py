"""SQLite PRO-010 pricing, budget, telemetry, drift, and status authority."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Never, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.providers.domain.errors import (
    ProviderDriftSuspendedError,
    ProviderErrorCode,
    ProviderObservabilityConflictError,
    ProviderObservabilityDependencyError,
    ProviderObservabilityValidationError,
)
from agentmemory.providers.domain.observability import (
    BudgetAdmission,
    BudgetDecision,
    BudgetExhaustionBehavior,
    DriftCanary,
    DriftEvaluation,
    DriftEvaluator,
    DriftObservation,
    DriftVerdict,
    GenerationPinState,
    PricingSnapshot,
    ProviderBudgetPolicy,
    ProviderBudgetReservationRequest,
    ProviderBudgetStatus,
    ProviderDriftProbeLease,
    ProviderGenerationStatus,
    ProviderHealth,
    ProviderHealthStatus,
    ProviderOperationFact,
    ProviderQueueStatus,
    ProviderStatusSnapshot,
)
from agentmemory.providers.domain.profiles import ProviderOperation

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_STORAGE = "Provider observability storage is unavailable"
_ERR_CONFLICT = "Provider observability authority conflicts with current state"
_ERR_INPUT = "provider observability request is invalid"
_ERR_SUSPENDED = "provider generation writes are suspended by drift evidence"
_MAX_STATUS_FACTS = 10_000


class SqliteProviderObservabilityRepository:
    """Persist canonical observability authority and assemble safe operator status."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the shared single-writer canonical store."""
        self._store = store

    async def publish_pricing(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        snapshot: PricingSnapshot,
    ) -> PricingSnapshot:
        """Publish one monotonic non-overlapping catalog and current pointer."""
        try:
            async with _write_transaction(self._store) as connection:
                await _require_profile(
                    connection,
                    snapshot.brain_id,
                    snapshot.profile_id,
                    snapshot.profile_version,
                )
                if await _replay_operation(
                    connection,
                    operation_id,
                    "pricing",
                    snapshot.brain_id,
                    snapshot.snapshot_id,
                    request_digest,
                ):
                    existing = await _get_pricing(connection, snapshot.snapshot_id)
                    if existing != snapshot:
                        _conflict()
                    return snapshot
                active = await _active_pricing(connection, snapshot.profile_id)
                if active is not None and (
                    int(active["catalog_version"]) + 1 != snapshot.version
                    or int(active["effective_until"]) > snapshot.effective_from_microseconds
                ):
                    _conflict()
                existing = await _get_pricing(connection, snapshot.snapshot_id)
                if existing is not None and existing != snapshot:
                    _conflict()
                if existing is None:
                    await _insert_pricing(connection, snapshot)
                await _advance_pricing_pointer(connection, snapshot, active)
                await _insert_operation(
                    connection,
                    scope,
                    operation_id,
                    "pricing",
                    snapshot.snapshot_id,
                    request_digest,
                    snapshot.created_at_microseconds,
                )
            return snapshot  # noqa: TRY300 -- Commit is owned by the transaction context.
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def publish_budget(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        policy: ProviderBudgetPolicy,
    ) -> ProviderBudgetPolicy:
        """Publish one monotonic finite budget backed by an exact catalog currency."""
        try:
            async with _write_transaction(self._store) as connection:
                await _require_profile(
                    connection,
                    policy.brain_id,
                    policy.profile_id,
                    policy.profile_version,
                )
                if await _replay_operation(
                    connection,
                    operation_id,
                    "budget",
                    policy.brain_id,
                    policy.policy_id,
                    request_digest,
                ):
                    existing = await _get_budget(connection, policy.policy_id)
                    if existing != policy:
                        _conflict()
                    return policy
                pricing_row = await _active_pricing(connection, policy.profile_id)
                if (
                    pricing_row is None
                    or int(pricing_row["profile_version"]) != policy.profile_version
                    or _string(pricing_row["currency"]) != policy.currency
                    or int(pricing_row["effective_from"]) > policy.period_start_microseconds
                    or int(pricing_row["effective_until"]) < policy.period_end_microseconds
                ):
                    _conflict()
                active = await _active_budget(connection, policy.profile_id)
                if active is not None and (
                    int(active["policy_version"]) + 1 != policy.version
                    or int(active["period_end"]) > policy.period_start_microseconds
                ):
                    _conflict()
                existing = await _get_budget(connection, policy.policy_id)
                if existing is not None and existing != policy:
                    _conflict()
                if existing is None:
                    await _insert_budget(connection, policy)
                await _advance_budget_pointer(connection, policy, active)
                await _insert_operation(
                    connection,
                    scope,
                    operation_id,
                    "budget",
                    policy.policy_id,
                    request_digest,
                    policy.created_at_microseconds,
                )
            return policy  # noqa: TRY300 -- Commit is owned by the transaction context.
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def register_canary(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        canary: DriftCanary,
    ) -> DriftCanary:
        """Register one canary only against exact current profile/space/generation authority."""
        target_digest = _digest(canary.document)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_canary_authority(connection, canary)
                if await _replay_operation(
                    connection,
                    operation_id,
                    "canary",
                    canary.brain_id,
                    target_digest,
                    request_digest,
                ):
                    existing = await _get_canary(connection, canary.canary_id)
                    if existing != canary:
                        _conflict()
                    return canary
                existing = await _get_canary(connection, canary.canary_id)
                if existing is not None and existing != canary:
                    _conflict()
                if existing is None:
                    await _insert_canary(connection, canary)
                await _insert_operation(
                    connection,
                    scope,
                    operation_id,
                    "canary",
                    target_digest,
                    request_digest,
                    canary.created_at_microseconds,
                )
            return canary  # noqa: TRY300 -- Commit is owned by the transaction context.
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def get_pricing(self, snapshot_id: str) -> PricingSnapshot | None:
        """Load one exact immutable pricing version."""
        try:
            async with self._store.engine.connect() as connection:
                return await _get_pricing(connection, snapshot_id)
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def get_active_pricing(
        self,
        brain_id: str,
        profile_id: str,
        profile_version: int,
        at_microseconds: int,
    ) -> PricingSnapshot | None:
        """Load the exact catalog version effective at dispatch time."""
        try:
            async with self._store.engine.connect() as connection:
                row = await _active_pricing(connection, profile_id)
                if (
                    row is None
                    or _string(row["brain_id"]) != brain_id
                    or int(row["profile_version"]) != profile_version
                    or not int(row["effective_from"])
                    <= at_microseconds
                    < int(row["effective_until"])
                ):
                    return None
                return _pricing(row)
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def reserve_budget(
        self,
        request: ProviderBudgetReservationRequest,
    ) -> BudgetAdmission:
        """Serialize exact estimate reservation or configured queue/degrade outcome."""
        try:
            async with _write_transaction(self._store) as connection:
                existing = await _reservation(connection, request.operation_id)
                if existing is not None:
                    if (
                        _blob(existing["request_digest"]).hex() != request.request_digest
                        or _string(existing["brain_id"]) != request.brain_id
                        or _string(existing["profile_id"]) != request.profile_id
                        or int(existing["profile_version"]) != request.profile_version
                        or _blob(existing["pricing_snapshot_id"]).hex()
                        != request.pricing_snapshot_id
                        or int(existing["estimated_micros"]) != request.estimated_cost_micros
                    ):
                        _conflict()
                    return _admission(existing)
                pricing_row = await _active_pricing(connection, request.profile_id)
                budget_row = await _active_budget(connection, request.profile_id)
                if (
                    pricing_row is None
                    or budget_row is None
                    or _blob(pricing_row["snapshot_id"]).hex() != request.pricing_snapshot_id
                    or _string(pricing_row["brain_id"]) != request.brain_id
                    or int(pricing_row["profile_version"]) != request.profile_version
                    or not int(pricing_row["effective_from"])
                    <= request.requested_at_microseconds
                    < int(pricing_row["effective_until"])
                    or _string(budget_row["brain_id"]) != request.brain_id
                    or int(budget_row["profile_version"]) != request.profile_version
                    or _string(budget_row["currency"]) != _string(pricing_row["currency"])
                    or not int(budget_row["period_start"])
                    <= request.requested_at_microseconds
                    < int(budget_row["period_end"])
                ):
                    _conflict()
                policy = _budget(budget_row)
                account = await _budget_account(connection, policy.policy_id)
                if account is None:
                    _conflict()
                admission = policy.admit(
                    spent_micros=int(account["spent_micros"]),
                    reserved_micros=int(account["reserved_micros"]),
                    estimate_micros=request.estimated_cost_micros,
                )
                await connection.execute(
                    text(
                        "INSERT INTO provider_budget_reservations "
                        "(operation_id,brain_id,profile_id,profile_version,policy_id,"
                        "pricing_snapshot_id,request_digest,decision,degraded_channels_json,"
                        "state,estimated_micros,reserved_micros,actual_micros,created_at,"
                        "reconciled_at,schema_version) "
                        "VALUES (:operation,:brain,:profile,:profile_version,:policy,:pricing,"
                        ":request,:decision,:channels,:state,:estimate,:reserved,NULL,:created,"
                        "NULL,1)"
                    ),
                    {
                        "brain": request.brain_id,
                        "channels": _json_bytes(list(admission.degraded_channels)),
                        "created": request.requested_at_microseconds,
                        "decision": admission.decision.value,
                        "estimate": request.estimated_cost_micros,
                        "operation": request.operation_id,
                        "policy": bytes.fromhex(policy.policy_id),
                        "pricing": bytes.fromhex(request.pricing_snapshot_id),
                        "profile": request.profile_id,
                        "profile_version": request.profile_version,
                        "request": bytes.fromhex(request.request_digest),
                        "reserved": admission.reserved_micros,
                        "state": admission.decision.value,
                    },
                )
                if admission.decision is BudgetDecision.RESERVED:
                    await connection.execute(
                        text(
                            "UPDATE provider_budget_accounts "
                            "SET reserved_micros=reserved_micros+:amount,"
                            "version=version+1,updated_at=:updated WHERE policy_id=:policy"
                        ),
                        {
                            "amount": admission.reserved_micros,
                            "policy": bytes.fromhex(policy.policy_id),
                            "updated": request.requested_at_microseconds,
                        },
                    )
                else:
                    await _budget_alert(
                        connection,
                        request,
                        policy,
                        admission,
                    )
            return admission  # noqa: TRY300 -- Commit is owned by the transaction context.
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def record_and_reconcile(self, fact: ProviderOperationFact) -> None:
        """Append one fact and reconcile its exact reservation once."""
        try:
            async with _write_transaction(self._store) as connection:
                existing = await _fact_by_operation(connection, fact.operation_id)
                if existing is not None:
                    if _blob(existing["fact_digest"]).hex() != fact.fact_digest:
                        _conflict()
                    return
                reservation = await _reservation(connection, fact.operation_id)
                if (
                    reservation is None
                    or _string(reservation["state"]) != "reserved"
                    or _string(reservation["brain_id"]) != fact.brain_id
                    or _string(reservation["profile_id"]) != fact.profile_id
                    or int(reservation["profile_version"]) != fact.profile_version
                    or _blob(reservation["pricing_snapshot_id"]).hex() != fact.pricing_snapshot_id
                    or int(reservation["estimated_micros"]) != fact.estimated_cost_micros
                ):
                    _conflict()
                await _insert_fact(connection, fact)
                await connection.execute(
                    text(
                        "UPDATE provider_budget_reservations SET state='reconciled',"
                        "actual_micros=:actual,reconciled_at=:reconciled "
                        "WHERE operation_id=:operation AND state='reserved'"
                    ),
                    {
                        "actual": fact.actual_cost_micros,
                        "operation": fact.operation_id,
                        "reconciled": fact.occurred_at_microseconds,
                    },
                )
                policy_id = _blob(reservation["policy_id"])
                reserved = int(reservation["reserved_micros"])
                await connection.execute(
                    text(
                        "UPDATE provider_budget_accounts "
                        "SET spent_micros=spent_micros+:actual,"
                        "reserved_micros=reserved_micros-:reserved,"
                        "version=version+1,updated_at=:updated WHERE policy_id=:policy"
                    ),
                    {
                        "actual": fact.actual_cost_micros,
                        "policy": policy_id,
                        "reserved": reserved,
                        "updated": fact.occurred_at_microseconds,
                    },
                )
                account = await _budget_account(connection, policy_id.hex())
                policy = await _get_budget(connection, policy_id.hex())
                if (
                    account is None
                    or policy is None
                    or int(account["spent_micros"]) > policy.limit_micros
                ):
                    if policy is None:
                        _conflict()
                    await _reconciliation_alert(connection, fact, policy)
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def get_canary(
        self,
        scope: AuthorizedScope,
        canary_id: str,
    ) -> DriftCanary | None:
        """Return one exact Brain-scoped canary without cross-Brain disclosure."""
        try:
            async with self._store.engine.connect() as connection:
                row = await _canary_row(connection, canary_id)
                if row is None or _string(row["brain_id"]) != scope.brain_id.value:
                    return None
                return _canary(row)
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def record_drift(
        self,
        observation: DriftObservation,
        evaluation: DriftEvaluation,
    ) -> None:
        """Append comparison evidence and irreversibly suspend generation writes."""
        try:
            async with _write_transaction(self._store) as connection:
                await _record_drift_transaction(connection, observation, evaluation)
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def claim_due(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderDriftProbeLease | None:
        """Atomically recover expiry and claim at most one due active canary."""
        if now_microseconds < 0 or lease_until_microseconds <= now_microseconds:
            raise ProviderObservabilityValidationError(_ERR_INPUT)
        try:
            async with _write_transaction(self._store) as connection:
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT c.*,s.next_probe_at,s.version AS state_version "
                                "FROM provider_drift_probe_state s "
                                "JOIN provider_drift_canaries c "
                                "ON c.canary_id=s.canary_id "
                                "WHERE s.state='active' AND s.next_probe_at<=:now "
                                "AND (s.lease_owner IS NULL OR s.lease_until<=:now) "
                                "ORDER BY s.next_probe_at,c.canary_id LIMIT 1"
                            ),
                            {"now": now_microseconds},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    return None
                version = int(row["state_version"])
                result = await connection.execute(
                    text(
                        "UPDATE provider_drift_probe_state SET lease_owner=:owner,"
                        "lease_until=:lease,version=version+1,updated_at=:updated "
                        "WHERE canary_id=:canary AND version=:version "
                        "AND state='active' AND next_probe_at<=:updated "
                        "AND (lease_owner IS NULL OR lease_until<=:updated)"
                    ),
                    {
                        "canary": _string(row["canary_id"]),
                        "lease": lease_until_microseconds,
                        "owner": owner,
                        "updated": now_microseconds,
                        "version": version,
                    },
                )
                if result.rowcount != 1:
                    _conflict()
                return ProviderDriftProbeLease(
                    canary=_canary(row),
                    owner=owner,
                    lease_until_microseconds=lease_until_microseconds,
                    state_version=version + 1,
                )
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def complete_probe(
        self,
        lease: ProviderDriftProbeLease,
        observation: DriftObservation,
        evaluation: DriftEvaluation,
    ) -> None:
        """Record one observation only for the exact current lease owner/version."""
        try:
            async with _write_transaction(self._store) as connection:
                await _require_probe_lease(connection, lease)
                await _record_drift_transaction(connection, observation, evaluation)
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def release_probe(
        self,
        lease: ProviderDriftProbeLease,
        retry_at_microseconds: int,
        released_at_microseconds: int,
    ) -> None:
        """Release one owner-bound lease to a finite retry time."""
        if released_at_microseconds < 0 or retry_at_microseconds <= released_at_microseconds:
            raise ProviderObservabilityValidationError(_ERR_INPUT)
        try:
            async with _write_transaction(self._store) as connection:
                await _require_probe_lease(connection, lease)
                result = await connection.execute(
                    text(
                        "UPDATE provider_drift_probe_state SET next_probe_at=:retry,"
                        "lease_owner=NULL,lease_until=NULL,version=version+1,"
                        "updated_at=:released WHERE canary_id=:canary "
                        "AND version=:version AND lease_owner=:owner"
                    ),
                    {
                        "canary": lease.canary.canary_id,
                        "owner": lease.owner,
                        "released": released_at_microseconds,
                        "retry": retry_at_microseconds,
                        "version": lease.state_version,
                    },
                )
                if result.rowcount != 1:
                    _conflict()
        except ProviderObservabilityConflictError:
            raise
        except IntegrityError as error:
            raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def assert_generation_writable(
        self,
        brain_id: str,
        space_id: str,
        generation_id: str,
    ) -> None:
        """Deny a semantic write after any recorded drift suspension."""
        try:
            async with self._store.engine.connect() as connection:
                suspended = (
                    await connection.execute(
                        text(
                            "SELECT 1 FROM provider_generation_write_suspensions "
                            "WHERE brain_id=:brain AND space_id=:space "
                            "AND generation_id=:generation"
                        ),
                        {
                            "brain": brain_id,
                            "generation": generation_id,
                            "space": space_id,
                        },
                    )
                ).scalar_one_or_none()
            if suspended is not None:
                _suspended()
        except ProviderDriftSuspendedError:
            raise
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error

    async def status(
        self,
        scope: AuthorizedScope,
        observed_at_microseconds: int,
    ) -> ProviderStatusSnapshot:
        """Aggregate health, circuits, queues, retries, usage, budgets, and generations."""
        if observed_at_microseconds < 0:
            raise ProviderObservabilityValidationError(_ERR_INPUT)
        try:
            async with self._store.engine.connect() as connection:
                health = await _health_status(
                    connection,
                    scope.brain_id.value,
                )
                queues = await _queue_status(connection, scope.brain_id.value)
                budgets = await _budget_status(connection, scope.brain_id.value)
                generations = await _generation_status(
                    connection,
                    scope.brain_id.value,
                    observed_at_microseconds,
                )
                alert_count = int(
                    (
                        await connection.execute(
                            text(
                                "SELECT COUNT(*) FROM provider_observability_alerts "
                                "WHERE brain_id=:brain AND state='active'"
                            ),
                            {"brain": scope.brain_id.value},
                        )
                    ).scalar_one()
                )
                retry_facts = int(
                    (
                        await connection.execute(
                            text(
                                "SELECT COUNT(*) FROM provider_operation_facts "
                                "WHERE brain_id=:brain AND outcome='retry_scheduled'"
                            ),
                            {"brain": scope.brain_id.value},
                        )
                    ).scalar_one()
                )
            return ProviderStatusSnapshot(
                brain_id=scope.brain_id.value,
                observed_at_microseconds=observed_at_microseconds,
                health=health,
                queues=queues,
                budgets=budgets,
                generations=generations,
                retry_count=queues.retry_scheduled + retry_facts,
                dead_letter_count=queues.dead_lettered,
                active_alert_count=alert_count,
            )
        except SQLAlchemyError as error:
            raise ProviderObservabilityDependencyError(_ERR_STORAGE) from error


async def _insert_pricing(
    connection: AsyncConnection,
    snapshot: PricingSnapshot,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_pricing_snapshots "
            "(snapshot_id,brain_id,profile_id,profile_version,catalog_version,currency,"
            "operation,request_micros,input_micros_per_million,"
            "output_micros_per_million,effective_from,effective_until,created_at,"
            "schema_version) VALUES "
            "(:id,:brain,:profile,:profile_version,:version,:currency,:operation,"
            ":request,:input,:output,:effective_from,:effective_until,:created,1)"
        ),
        {
            "brain": snapshot.brain_id,
            "created": snapshot.created_at_microseconds,
            "currency": snapshot.currency,
            "effective_from": snapshot.effective_from_microseconds,
            "effective_until": snapshot.effective_until_microseconds,
            "id": bytes.fromhex(snapshot.snapshot_id),
            "input": snapshot.input_micros_per_million,
            "operation": snapshot.operation.value,
            "output": snapshot.output_micros_per_million,
            "profile": snapshot.profile_id,
            "profile_version": snapshot.profile_version,
            "request": snapshot.request_micros,
            "version": snapshot.version,
        },
    )


async def _advance_pricing_pointer(
    connection: AsyncConnection,
    snapshot: PricingSnapshot,
    active: RowMapping | None,
) -> None:
    if active is None:
        await connection.execute(
            text(
                "INSERT INTO active_provider_pricing "
                "(profile_id,profile_version,snapshot_id,catalog_version,pointer_version,"
                "updated_at,schema_version) VALUES (:profile,:profile_version,:snapshot,"
                ":catalog,1,:updated,1)"
            ),
            {
                "catalog": snapshot.version,
                "profile": snapshot.profile_id,
                "profile_version": snapshot.profile_version,
                "snapshot": bytes.fromhex(snapshot.snapshot_id),
                "updated": snapshot.created_at_microseconds,
            },
        )
        return
    await connection.execute(
        text(
            "UPDATE active_provider_pricing SET profile_version=:profile_version,"
            "snapshot_id=:snapshot,catalog_version=:catalog,"
            "pointer_version=pointer_version+1,updated_at=:updated WHERE profile_id=:profile"
        ),
        {
            "catalog": snapshot.version,
            "profile": snapshot.profile_id,
            "profile_version": snapshot.profile_version,
            "snapshot": bytes.fromhex(snapshot.snapshot_id),
            "updated": snapshot.created_at_microseconds,
        },
    )


async def _insert_budget(
    connection: AsyncConnection,
    policy: ProviderBudgetPolicy,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_budget_policies "
            "(policy_id,brain_id,profile_id,profile_version,policy_version,currency,"
            "limit_micros,behavior,degraded_channels_json,period_start,period_end,"
            "created_at,schema_version) VALUES "
            "(:id,:brain,:profile,:profile_version,:version,:currency,:limit,:behavior,"
            ":channels,:start,:end,:created,1)"
        ),
        {
            "behavior": policy.behavior.value,
            "brain": policy.brain_id,
            "channels": _json_bytes(list(policy.degraded_channels)),
            "created": policy.created_at_microseconds,
            "currency": policy.currency,
            "end": policy.period_end_microseconds,
            "id": bytes.fromhex(policy.policy_id),
            "limit": policy.limit_micros,
            "profile": policy.profile_id,
            "profile_version": policy.profile_version,
            "start": policy.period_start_microseconds,
            "version": policy.version,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO provider_budget_accounts "
            "(policy_id,spent_micros,reserved_micros,version,updated_at,schema_version) "
            "VALUES (:policy,0,0,1,:updated,1)"
        ),
        {
            "policy": bytes.fromhex(policy.policy_id),
            "updated": policy.created_at_microseconds,
        },
    )


async def _advance_budget_pointer(
    connection: AsyncConnection,
    policy: ProviderBudgetPolicy,
    active: RowMapping | None,
) -> None:
    if active is None:
        await connection.execute(
            text(
                "INSERT INTO active_provider_budget_policies "
                "(profile_id,profile_version,policy_id,policy_version,pointer_version,"
                "updated_at,schema_version) VALUES "
                "(:profile,:profile_version,:policy,:version,1,:updated,1)"
            ),
            {
                "policy": bytes.fromhex(policy.policy_id),
                "profile": policy.profile_id,
                "profile_version": policy.profile_version,
                "updated": policy.created_at_microseconds,
                "version": policy.version,
            },
        )
        return
    await connection.execute(
        text(
            "UPDATE active_provider_budget_policies "
            "SET profile_version=:profile_version,policy_id=:policy,"
            "policy_version=:version,pointer_version=pointer_version+1,"
            "updated_at=:updated WHERE profile_id=:profile"
        ),
        {
            "policy": bytes.fromhex(policy.policy_id),
            "profile": policy.profile_id,
            "profile_version": policy.profile_version,
            "updated": policy.created_at_microseconds,
            "version": policy.version,
        },
    )


async def _insert_canary(
    connection: AsyncConnection,
    canary: DriftCanary,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_drift_canaries "
            "(canary_id,brain_id,profile_id,profile_version,space_id,generation_id,"
            "capability_attestation_id,revision_fingerprint,canary_set_digest,"
            "vector_fingerprint,canary_item_ids_json,norms_json,distance_order_json,"
            "norm_tolerance_ppm,maximum_order_inversions,interval_microseconds,"
            "created_at,schema_version) "
            "VALUES (:canary,:brain,:profile,:profile_version,:space,:generation,"
            ":attestation,:revision,:canary_set,:vector,:item_ids,:norms,:ordering,"
            ":tolerance,:inversions,:interval,:created,1)"
        ),
        {
            "attestation": canary.capability_attestation_id,
            "brain": canary.brain_id,
            "canary": canary.canary_id,
            "canary_set": bytes.fromhex(canary.canary_set_digest),
            "created": canary.created_at_microseconds,
            "generation": canary.generation_id,
            "interval": canary.interval_microseconds,
            "inversions": canary.maximum_order_inversions,
            "item_ids": _json_bytes(list(canary.canary_item_ids)),
            "norms": _json_bytes(list(canary.norms_micros)),
            "ordering": _json_bytes(list(canary.distance_order)),
            "profile": canary.profile_id,
            "profile_version": canary.profile_version,
            "revision": bytes.fromhex(canary.revision_fingerprint),
            "space": canary.space_id,
            "tolerance": canary.norm_tolerance_ppm,
            "vector": bytes.fromhex(canary.vector_fingerprint),
        },
    )
    await connection.execute(
        text(
            "INSERT INTO provider_drift_probe_state "
            "(canary_id,state,next_probe_at,lease_owner,lease_until,"
            "last_observation_digest,version,updated_at,schema_version) "
            "VALUES (:canary,'active',:next,NULL,NULL,NULL,1,:updated,1)"
        ),
        {
            "canary": canary.canary_id,
            "next": canary.next_probe_at_microseconds,
            "updated": canary.created_at_microseconds,
        },
    )


async def _insert_fact(
    connection: AsyncConnection,
    fact: ProviderOperationFact,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_operation_facts "
            "(fact_digest,operation_id,brain_id,profile_id,profile_version,space_id,"
            "generation_id,pricing_snapshot_id,operation,outcome,error_code,"
            "request_count,item_count,input_units,output_units,request_bytes,"
            "response_bytes,attempt_count,latency_microseconds,estimated_cost_micros,"
            "actual_cost_micros,cache_hit,deduplicated,occurred_at,schema_version) VALUES "
            "(:digest,:operation_id,:brain,:profile,:profile_version,:space,:generation,"
            ":pricing,:operation,:outcome,:error,:requests,:items,:input,:output,"
            ":request_bytes,:response_bytes,:attempts,:latency,:estimated,:actual,"
            ":cache_hit,:deduplicated,:occurred,1)"
        ),
        {
            "actual": fact.actual_cost_micros,
            "attempts": fact.attempt_count,
            "brain": fact.brain_id,
            "cache_hit": fact.cache_hit,
            "deduplicated": fact.deduplicated,
            "digest": bytes.fromhex(fact.fact_digest),
            "error": None if fact.error_code is None else fact.error_code.value,
            "estimated": fact.estimated_cost_micros,
            "generation": fact.generation_id,
            "input": fact.input_units,
            "items": fact.item_count,
            "latency": fact.latency_microseconds,
            "occurred": fact.occurred_at_microseconds,
            "operation": fact.operation.value,
            "operation_id": fact.operation_id,
            "outcome": fact.outcome.value,
            "output": fact.output_units,
            "pricing": bytes.fromhex(fact.pricing_snapshot_id),
            "profile": fact.profile_id,
            "profile_version": fact.profile_version,
            "request_bytes": fact.request_bytes,
            "requests": fact.request_count,
            "response_bytes": fact.response_bytes,
            "space": fact.space_id,
        },
    )


async def _record_drift_transaction(
    connection: AsyncConnection,
    observation: DriftObservation,
    evaluation: DriftEvaluation,
) -> None:
    canary = await _get_canary(connection, observation.canary_id)
    if canary is None or DriftEvaluator.evaluate(canary, observation) != evaluation:
        _conflict()
    existing = (
        (
            await connection.execute(
                text(
                    "SELECT verdict,reason_code FROM provider_drift_observations "
                    "WHERE observation_digest=:digest"
                ),
                {"digest": bytes.fromhex(observation.digest)},
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing is not None:
        if (
            _string(existing["verdict"]) != evaluation.verdict.value
            or _optional_string(existing["reason_code"]) != evaluation.reason_code
        ):
            _conflict()
        return
    await _insert_observation(connection, observation, evaluation)
    next_probe = observation.observed_at_microseconds + canary.interval_microseconds
    state = "suspended" if evaluation.verdict is DriftVerdict.DRIFTED else "active"
    await connection.execute(
        text(
            "UPDATE provider_drift_probe_state SET state=:state,"
            "next_probe_at=:next,lease_owner=NULL,lease_until=NULL,"
            "last_observation_digest=:digest,version=version+1,"
            "updated_at=:updated WHERE canary_id=:canary"
        ),
        {
            "canary": canary.canary_id,
            "digest": bytes.fromhex(observation.digest),
            "next": next_probe,
            "state": state,
            "updated": observation.observed_at_microseconds,
        },
    )
    if evaluation.verdict is DriftVerdict.DRIFTED:
        await _suspend_generation(
            connection,
            canary,
            observation,
            evaluation,
        )


async def _require_probe_lease(
    connection: AsyncConnection,
    lease: ProviderDriftProbeLease,
) -> None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT state,lease_owner,lease_until,version "
                    "FROM provider_drift_probe_state WHERE canary_id=:canary"
                ),
                {"canary": lease.canary.canary_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or _string(row["state"]) != "active"
        or _optional_string(row["lease_owner"]) != lease.owner
        or int(row["lease_until"]) != lease.lease_until_microseconds
        or int(row["version"]) != lease.state_version
    ):
        _conflict()


async def _insert_observation(
    connection: AsyncConnection,
    observation: DriftObservation,
    evaluation: DriftEvaluation,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_drift_observations "
            "(observation_digest,canary_id,revision_fingerprint,vector_fingerprint,"
            "canary_item_ids_json,norms_json,distance_order_json,verdict,reason_code,"
            "observed_at,schema_version) "
            "VALUES (:digest,:canary,:revision,:vector,:item_ids,:norms,:ordering,"
            ":verdict,:reason,:observed,1)"
        ),
        {
            "canary": observation.canary_id,
            "digest": bytes.fromhex(observation.digest),
            "item_ids": _json_bytes(list(observation.canary_item_ids)),
            "norms": _json_bytes(list(observation.norms_micros)),
            "observed": observation.observed_at_microseconds,
            "ordering": _json_bytes(list(observation.distance_order)),
            "reason": evaluation.reason_code,
            "revision": bytes.fromhex(observation.revision_fingerprint),
            "vector": bytes.fromhex(observation.vector_fingerprint),
            "verdict": evaluation.verdict.value,
        },
    )


async def _suspend_generation(
    connection: AsyncConnection,
    canary: DriftCanary,
    observation: DriftObservation,
    evaluation: DriftEvaluation,
) -> None:
    if evaluation.reason_code is None:
        _conflict()
    existing = (
        (
            await connection.execute(
                text(
                    "SELECT observation_digest,reason_code "
                    "FROM provider_generation_write_suspensions WHERE generation_id=:generation"
                ),
                {"generation": canary.generation_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing is None:
        await connection.execute(
            text(
                "INSERT INTO provider_generation_write_suspensions "
                "(generation_id,brain_id,space_id,observation_digest,reason_code,"
                "suspended_at,requires_new_space,schema_version) VALUES "
                "(:generation,:brain,:space,:observation,:reason,:suspended,1,1)"
            ),
            {
                "brain": canary.brain_id,
                "generation": canary.generation_id,
                "observation": bytes.fromhex(observation.digest),
                "reason": evaluation.reason_code,
                "space": canary.space_id,
                "suspended": observation.observed_at_microseconds,
            },
        )
        evidence = observation.digest
    else:
        evidence = _blob(existing["observation_digest"]).hex()
    alert_digest = _digest(
        {
            "code": "provider_model_drift",
            "evidence_digest": evidence,
            "generation_id": canary.generation_id,
        }
    )
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO provider_observability_alerts "
            "(alert_digest,brain_id,profile_id,generation_id,severity,code,"
            "evidence_digest,created_at,state,schema_version) VALUES "
            "(:alert,:brain,:profile,:generation,'critical','provider_model_drift',"
            ":evidence,:created,'active',1)"
        ),
        {
            "alert": bytes.fromhex(alert_digest),
            "brain": canary.brain_id,
            "created": observation.observed_at_microseconds,
            "evidence": bytes.fromhex(evidence),
            "generation": canary.generation_id,
            "profile": canary.profile_id,
        },
    )


async def _budget_alert(
    connection: AsyncConnection,
    request: ProviderBudgetReservationRequest,
    policy: ProviderBudgetPolicy,
    admission: BudgetAdmission,
) -> None:
    code = (
        "provider_budget_queued"
        if admission.decision is BudgetDecision.QUEUED
        else "provider_budget_degraded"
    )
    alert_digest = _digest(
        {
            "code": code,
            "operation_id": request.operation_id,
            "policy_id": policy.policy_id,
        }
    )
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO provider_observability_alerts "
            "(alert_digest,brain_id,profile_id,generation_id,severity,code,"
            "evidence_digest,created_at,state,schema_version) VALUES "
            "(:alert,:brain,:profile,NULL,'warning',:code,:evidence,:created,'active',1)"
        ),
        {
            "alert": bytes.fromhex(alert_digest),
            "brain": request.brain_id,
            "code": code,
            "created": request.requested_at_microseconds,
            "evidence": bytes.fromhex(request.request_digest),
            "profile": request.profile_id,
        },
    )


async def _reconciliation_alert(
    connection: AsyncConnection,
    fact: ProviderOperationFact,
    policy: ProviderBudgetPolicy,
) -> None:
    alert_digest = _digest(
        {
            "code": "provider_budget_reconciled_overrun",
            "fact_digest": fact.fact_digest,
            "policy_id": policy.policy_id,
        }
    )
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO provider_observability_alerts "
            "(alert_digest,brain_id,profile_id,generation_id,severity,code,"
            "evidence_digest,created_at,state,schema_version) VALUES "
            "(:alert,:brain,:profile,:generation,'critical',"
            "'provider_budget_reconciled_overrun',:evidence,:created,'active',1)"
        ),
        {
            "alert": bytes.fromhex(alert_digest),
            "brain": fact.brain_id,
            "created": fact.occurred_at_microseconds,
            "evidence": bytes.fromhex(fact.fact_digest),
            "generation": fact.generation_id,
            "profile": fact.profile_id,
        },
    )


async def _require_profile(
    connection: AsyncConnection,
    brain_id: str,
    profile_id: str,
    profile_version: int,
) -> None:
    current = (
        await connection.execute(
            text(
                "SELECT 1 FROM provider_profiles "
                "WHERE id=:profile AND brain_id=:brain AND version=:version "
                "AND status='active'"
            ),
            {
                "brain": brain_id,
                "profile": profile_id,
                "version": profile_version,
            },
        )
    ).scalar_one_or_none()
    if current is None:
        _conflict()


async def _require_canary_authority(
    connection: AsyncConnection,
    canary: DriftCanary,
) -> None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT p.active_probe_id,e.profile_id,e.capability_attestation_id,"
                    "g.brain_id,g.space_id,g.state,a.generation_id "
                    "FROM provider_profiles p "
                    "JOIN embedding_spaces e ON e.profile_id=p.id "
                    "JOIN embedding_index_generations g ON g.space_id=e.id "
                    "LEFT JOIN active_embedding_generations a "
                    "ON a.brain_id=g.brain_id AND a.space_id=e.id "
                    "AND a.generation_id=g.id "
                    "WHERE p.id=:profile AND p.brain_id=:brain AND p.version=:version "
                    "AND p.status='active' AND e.id=:space AND g.id=:generation"
                ),
                {
                    "brain": canary.brain_id,
                    "generation": canary.generation_id,
                    "profile": canary.profile_id,
                    "space": canary.space_id,
                    "version": canary.profile_version,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or _string(row["active_probe_id"]) != canary.capability_attestation_id
        or _string(row["capability_attestation_id"]) != canary.capability_attestation_id
        or _string(row["state"]) != "active"
        or row["generation_id"] is None
    ):
        _conflict()


async def _replay_operation(  # noqa: PLR0913 -- Exact replay binds every authority coordinate.
    connection: AsyncConnection,
    operation_id: str,
    kind: str,
    brain_id: str,
    target_digest: str,
    request_digest: str,
) -> bool:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT brain_id,operation_kind,target_digest,request_digest "
                    "FROM provider_observability_operations WHERE operation_id=:operation"
                ),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return False
    if (
        _string(row["brain_id"]) != brain_id
        or _string(row["operation_kind"]) != kind
        or _blob(row["target_digest"]).hex() != target_digest
        or _blob(row["request_digest"]).hex() != request_digest
    ):
        _conflict()
    return True


async def _insert_operation(  # noqa: PLR0913 -- Receipt fields are explicit audit authority.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    kind: str,
    target_digest: str,
    request_digest: str,
    completed_at: int,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_observability_operations "
            "(operation_id,brain_id,operation_kind,target_digest,request_digest,"
            "principal_id,scope_fingerprint,completed_at,schema_version) VALUES "
            "(:operation,:brain,:kind,:target,:request,:principal,:scope,:completed,1)"
        ),
        {
            "brain": scope.brain_id.value,
            "completed": completed_at,
            "kind": kind,
            "operation": operation_id,
            "principal": scope.principal_id.value,
            "request": bytes.fromhex(request_digest),
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "target": bytes.fromhex(target_digest),
        },
    )


async def _get_pricing(
    connection: AsyncConnection,
    snapshot_id: str,
) -> PricingSnapshot | None:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_pricing_snapshots WHERE snapshot_id=:snapshot"),
                {"snapshot": bytes.fromhex(snapshot_id)},
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _pricing(row)


async def _get_budget(
    connection: AsyncConnection,
    policy_id: str,
) -> ProviderBudgetPolicy | None:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_budget_policies WHERE policy_id=:policy"),
                {"policy": bytes.fromhex(policy_id)},
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _budget(row)


async def _get_canary(
    connection: AsyncConnection,
    canary_id: str,
) -> DriftCanary | None:
    row = await _canary_row(connection, canary_id)
    return None if row is None else _canary(row)


async def _canary_row(
    connection: AsyncConnection,
    canary_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT c.*,s.next_probe_at FROM provider_drift_canaries c "
                    "JOIN provider_drift_probe_state s ON s.canary_id=c.canary_id "
                    "WHERE c.canary_id=:canary"
                ),
                {"canary": canary_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _active_pricing(
    connection: AsyncConnection,
    profile_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT p.*,a.pointer_version FROM active_provider_pricing a "
                    "JOIN provider_pricing_snapshots p ON p.snapshot_id=a.snapshot_id "
                    "WHERE a.profile_id=:profile"
                ),
                {"profile": profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _active_budget(
    connection: AsyncConnection,
    profile_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT p.*,a.pointer_version FROM active_provider_budget_policies a "
                    "JOIN provider_budget_policies p ON p.policy_id=a.policy_id "
                    "WHERE a.profile_id=:profile"
                ),
                {"profile": profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _budget_account(
    connection: AsyncConnection,
    policy_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM provider_budget_accounts WHERE policy_id=:policy"),
                {"policy": bytes.fromhex(policy_id)},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _reservation(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM provider_budget_reservations WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _fact_by_operation(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT fact_digest FROM provider_operation_facts WHERE operation_id=:operation"
                ),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


def _pricing(row: RowMapping) -> PricingSnapshot:
    return PricingSnapshot(
        snapshot_id=_blob(row["snapshot_id"]).hex(),
        brain_id=_string(row["brain_id"]),
        profile_id=_string(row["profile_id"]),
        profile_version=int(row["profile_version"]),
        version=int(row["catalog_version"]),
        currency=_string(row["currency"]),
        operation=ProviderOperation(_string(row["operation"])),
        request_micros=int(row["request_micros"]),
        input_micros_per_million=int(row["input_micros_per_million"]),
        output_micros_per_million=int(row["output_micros_per_million"]),
        effective_from_microseconds=int(row["effective_from"]),
        effective_until_microseconds=int(row["effective_until"]),
        created_at_microseconds=int(row["created_at"]),
    )


def _budget(row: RowMapping) -> ProviderBudgetPolicy:
    return ProviderBudgetPolicy(
        policy_id=_blob(row["policy_id"]).hex(),
        brain_id=_string(row["brain_id"]),
        profile_id=_string(row["profile_id"]),
        profile_version=int(row["profile_version"]),
        version=int(row["policy_version"]),
        currency=_string(row["currency"]),
        limit_micros=int(row["limit_micros"]),
        behavior=BudgetExhaustionBehavior(_string(row["behavior"])),
        degraded_channels=_strings(_json(row["degraded_channels_json"])),
        period_start_microseconds=int(row["period_start"]),
        period_end_microseconds=int(row["period_end"]),
        created_at_microseconds=int(row["created_at"]),
    )


def _canary(row: RowMapping) -> DriftCanary:
    return DriftCanary(
        canary_id=_string(row["canary_id"]),
        brain_id=_string(row["brain_id"]),
        profile_id=_string(row["profile_id"]),
        profile_version=int(row["profile_version"]),
        space_id=_string(row["space_id"]),
        generation_id=_string(row["generation_id"]),
        capability_attestation_id=_string(row["capability_attestation_id"]),
        revision_fingerprint=_blob(row["revision_fingerprint"]).hex(),
        canary_set_digest=_blob(row["canary_set_digest"]).hex(),
        vector_fingerprint=_blob(row["vector_fingerprint"]).hex(),
        canary_item_ids=_strings(_json(row["canary_item_ids_json"])),
        norms_micros=_integers(_json(row["norms_json"])),
        distance_order=_strings(_json(row["distance_order_json"])),
        norm_tolerance_ppm=int(row["norm_tolerance_ppm"]),
        maximum_order_inversions=int(row["maximum_order_inversions"]),
        interval_microseconds=int(row["interval_microseconds"]),
        next_probe_at_microseconds=int(row["next_probe_at"]),
        created_at_microseconds=int(row["created_at"]),
    )


def _admission(row: RowMapping) -> BudgetAdmission:
    decision = BudgetDecision(_string(row["decision"]))
    channels = _strings(_json(row["degraded_channels_json"]))
    return BudgetAdmission(decision, int(row["reserved_micros"]), channels)


async def _health_status(
    connection: AsyncConnection,
    brain_id: str,
) -> tuple[ProviderHealth, ...]:
    profiles = (
        (
            await connection.execute(
                text(
                    "SELECT id,version FROM provider_profiles "
                    "WHERE brain_id=:brain AND status='active' ORDER BY id"
                ),
                {"brain": brain_id},
            )
        )
        .mappings()
        .all()
    )
    facts = (
        (
            await connection.execute(
                text(
                    "SELECT profile_id,request_count,item_count,input_units,output_units,"
                    "actual_cost_micros,latency_microseconds,error_code,outcome "
                    "FROM provider_operation_facts WHERE brain_id=:brain "
                    "ORDER BY occurred_at DESC LIMIT :limit"
                ),
                {"brain": brain_id, "limit": _MAX_STATUS_FACTS},
            )
        )
        .mappings()
        .all()
    )
    by_profile: dict[str, list[RowMapping]] = defaultdict(list)
    for fact in facts:
        by_profile[_string(fact["profile_id"])].append(fact)
    suspensions = {
        _string(row[0])
        for row in (
            await connection.execute(
                text(
                    "SELECT c.profile_id FROM provider_generation_write_suspensions s "
                    "JOIN provider_drift_canaries c ON c.generation_id=s.generation_id "
                    "WHERE c.brain_id=:brain"
                ),
                {"brain": brain_id},
            )
        ).all()
    }
    circuits = (
        (
            await connection.execute(
                text(
                    "SELECT profile_id,state,COUNT(*) AS count "
                    "FROM provider_endpoint_circuits GROUP BY profile_id,state"
                )
            )
        )
        .mappings()
        .all()
    )
    circuit_map: dict[str, dict[str, int]] = defaultdict(dict)
    for row in circuits:
        circuit_map[_string(row["profile_id"])][_string(row["state"])] = int(row["count"])
    result: list[ProviderHealth] = []
    for profile in profiles:
        profile_id = _string(profile["id"])
        rows = by_profile[profile_id]
        errors: dict[ProviderErrorCode, int] = defaultdict(int)
        for row in rows:
            code = _optional_string(row["error_code"])
            if code is not None:
                errors[ProviderErrorCode(code)] += 1
        latencies = sorted(int(row["latency_microseconds"]) for row in rows)
        states = circuit_map[profile_id]
        if profile_id in suspensions:
            status = ProviderHealthStatus.SUSPENDED
        elif not rows or (states.get("open", 0) and states.get("closed", 0) == 0):
            status = ProviderHealthStatus.UNAVAILABLE
        elif errors or states.get("open", 0) or states.get("half_open", 0):
            status = ProviderHealthStatus.DEGRADED
        else:
            status = ProviderHealthStatus.HEALTHY
        result.append(
            ProviderHealth(
                profile_id=profile_id,
                profile_version=int(profile["version"]),
                status=status,
                circuit_counts=(
                    states.get("closed", 0),
                    states.get("open", 0),
                    states.get("half_open", 0),
                ),
                requests=sum(int(row["request_count"]) for row in rows),
                items=sum(int(row["item_count"]) for row in rows),
                input_units=sum(int(row["input_units"]) for row in rows),
                output_units=sum(int(row["output_units"]) for row in rows),
                cost_micros=sum(int(row["actual_cost_micros"]) for row in rows),
                latency_p50_microseconds=_percentile(latencies, 50),
                latency_p95_microseconds=_percentile(latencies, 95),
                latency_p99_microseconds=_percentile(latencies, 99),
                safe_errors=tuple(sorted(errors.items(), key=lambda item: str(item[0]))),
            )
        )
    return tuple(result)


async def _queue_status(
    connection: AsyncConnection,
    brain_id: str,
) -> ProviderQueueStatus:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT state,COUNT(*) AS count,MIN(enqueued_at) AS oldest "
                    "FROM provider_work_items WHERE brain_id=:brain GROUP BY state"
                ),
                {"brain": brain_id},
            )
        )
        .mappings()
        .all()
    )
    counts = {_string(row["state"]): int(row["count"]) for row in rows}
    oldest_candidates = [
        int(row["oldest"])
        for row in rows
        if _string(row["state"]) == "queued" and row["oldest"] is not None
    ]
    return ProviderQueueStatus(
        queued=counts.get("queued", 0),
        leased=counts.get("leased", 0),
        retry_scheduled=counts.get("retry_scheduled", 0),
        failed=counts.get("failed", 0),
        dead_lettered=counts.get("failed", 0),
        oldest_queued_at_microseconds=(min(oldest_candidates) if oldest_candidates else None),
    )


async def _budget_status(
    connection: AsyncConnection,
    brain_id: str,
) -> tuple[ProviderBudgetStatus, ...]:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT p.*,a.spent_micros,a.reserved_micros "
                    "FROM active_provider_budget_policies active "
                    "JOIN provider_budget_policies p ON p.policy_id=active.policy_id "
                    "JOIN provider_budget_accounts a ON a.policy_id=p.policy_id "
                    "WHERE p.brain_id=:brain ORDER BY p.profile_id"
                ),
                {"brain": brain_id},
            )
        )
        .mappings()
        .all()
    )
    return tuple(
        ProviderBudgetStatus(
            profile_id=_string(row["profile_id"]),
            policy_id=_blob(row["policy_id"]).hex(),
            currency=_string(row["currency"]),
            limit_micros=int(row["limit_micros"]),
            spent_micros=int(row["spent_micros"]),
            reserved_micros=int(row["reserved_micros"]),
            remaining_micros=max(
                0,
                int(row["limit_micros"]) - int(row["spent_micros"]) - int(row["reserved_micros"]),
            ),
            behavior=BudgetExhaustionBehavior(_string(row["behavior"])),
        )
        for row in rows
    )


async def _generation_status(
    connection: AsyncConnection,
    brain_id: str,
    observed_at: int,
) -> tuple[ProviderGenerationStatus, ...]:
    rows = (
        (
            await connection.execute(
                text(
                    "SELECT active.space_id,active.generation_id,e.descriptor_json,"
                    "s.reason_code,m.source_generation_id AS rollback_generation_id "
                    "FROM active_embedding_generations active "
                    "JOIN embedding_spaces e ON e.id=active.space_id "
                    "LEFT JOIN provider_generation_write_suspensions s "
                    "ON s.generation_id=active.generation_id "
                    "LEFT JOIN embedding_generation_migrations m "
                    "ON m.target_generation_id=active.generation_id AND m.state='active' "
                    "AND m.rollback_until>:observed "
                    "WHERE active.brain_id=:brain ORDER BY active.space_id"
                ),
                {"brain": brain_id, "observed": observed_at},
            )
        )
        .mappings()
        .all()
    )
    result: list[ProviderGenerationStatus] = []
    seen: set[str] = set()
    for row in rows:
        space_id = _string(row["space_id"])
        if space_id in seen:
            continue
        seen.add(space_id)
        reason = _optional_string(row["reason_code"])
        descriptor = _json(row["descriptor_json"])
        descriptor_map = _mapping(descriptor)
        pin_state = (
            GenerationPinState.DRIFT_SUSPECTED
            if reason is not None
            else (
                GenerationPinState.PINNED
                if descriptor_map.get("model_revision") is not None
                or descriptor_map.get("model_weight_digest") is not None
                else GenerationPinState.UNPINNED
            )
        )
        result.append(
            ProviderGenerationStatus(
                space_id=space_id,
                active_generation_id=_string(row["generation_id"]),
                rollback_generation_id=_optional_string(row["rollback_generation_id"]),
                pin_state=pin_state,
                write_suspended=reason is not None,
                suspension_reason=reason,
            )
        )
    return tuple(result)


def _percentile(values: Sequence[int], percentile: int) -> int:
    if not values:
        return 0
    index = max(0, (len(values) * percentile + 99) // 100 - 1)
    return values[index]


def _json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderObservabilityValidationError(_ERR_INPUT) from error


def _json(value: object) -> object:
    try:
        return json.loads(_blob(value))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderObservabilityConflictError(_ERR_CONFLICT) from error


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        _conflict()
    mapping = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in mapping):
        _conflict()
    return cast("Mapping[str, object]", mapping)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        _conflict()
    items = cast("list[object]", value)
    if any(not isinstance(item, str) for item in items):
        _conflict()
    return tuple(cast("list[str]", items))


def _integers(value: object) -> tuple[int, ...]:
    if not isinstance(value, list):
        _conflict()
    items = cast("list[object]", value)
    if any(not isinstance(item, int) or isinstance(item, bool) for item in items):
        _conflict()
    return tuple(cast("list[int]", items))


def _string(value: object) -> str:
    if not isinstance(value, str):
        _conflict()
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _string(value)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    return _conflict()


def _digest(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _conflict() -> Never:
    raise ProviderObservabilityConflictError(_ERR_CONFLICT)


def _suspended() -> Never:
    raise ProviderDriftSuspendedError(_ERR_SUSPENDED)


@asynccontextmanager
async def _write_transaction(
    store: SqliteCoreStore,
) -> AsyncIterator[AsyncConnection]:
    async with store.write_lock, store.engine.connect() as connection:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            await connection.rollback()
            raise
        else:
            await connection.commit()
