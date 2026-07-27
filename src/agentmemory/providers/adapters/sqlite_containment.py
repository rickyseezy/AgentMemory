"""PRO-009 canonical SQLite egress-policy, permit, and runtime evidence adapter."""

# ruff: noqa: C901, TRY301

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, cast

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.containment import (
    ContentTaint,
    EgressDestination,
    ProviderEgressDecisionFact,
    ProviderEgressOperationContext,
    ProviderEgressPermit,
    ProviderEgressPolicy,
    ProviderEgressRequest,
    ProviderEgressRoute,
    ProviderRuntimeFact,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentAuthorizationError,
    ProviderContainmentConflictError,
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.idempotency import ProviderOperationRequest
    from agentmemory.providers.domain.profile_ports import ProviderGatewayRequest
    from agentmemory.providers.domain.resilience import ProviderEndpointAttestation

_ERR_AUTHORIZATION = "provider containment action is not authorized"
_ERR_CONFLICT = "provider containment conflicts with immutable history"
_ERR_INTEGRITY = "provider containment storage failed integrity verification"
_ERR_STORAGE = "provider containment storage is unavailable"
_ERR_DENIED = "provider egress is denied"
_MANAGE_ACTION = "provider.containment.manage"
_READ_ACTION = "provider.containment.read"
_ADMIN_ROLES = frozenset({"owner", "admin"})
_READ_ROLES = _ADMIN_ROLES | frozenset({"auditor"})


class SqliteProviderContainmentRepository:
    """Serialize policy publication and final per-operation egress authorization."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical single-writer SQLite store."""
        self._store = store

    async def publish(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        policy: ProviderEgressPolicy,
        published_at_microseconds: int,
    ) -> ProviderEgressPolicy:
        """Publish or exactly replay one immutable policy and active pointer."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize_scope(
                    connection,
                    scope,
                    _MANAGE_ACTION,
                    _ADMIN_ROLES,
                    published_at_microseconds,
                )
                existing_operation = await _operation(connection, operation_id)
                if existing_operation is not None:
                    if (
                        str(existing_operation["brain_id"]) != scope.brain_id.value
                        or _blob(existing_operation["request_digest"]).hex() != request_digest
                    ):
                        raise ProviderContainmentConflictError(_ERR_CONFLICT)
                    replay = await _policy_by_id(
                        connection,
                        str(existing_operation["policy_id"]),
                    )
                    if replay is None:
                        raise ProviderContainmentConflictError(_ERR_INTEGRITY)
                    return replay
                if (
                    policy.brain_id != scope.brain_id.value
                    or policy.security_epoch != scope.security_epoch
                ):
                    raise ProviderContainmentAuthorizationError(_ERR_AUTHORIZATION)
                current = await _active_policy_row(connection, policy.brain_id)
                expected_version = 1 if current is None else int(current["version"]) + 1
                if policy.version != expected_version:
                    raise ProviderContainmentConflictError(_ERR_CONFLICT)
                await _verify_policy_profiles(connection, policy)
                await connection.execute(
                    text(
                        "INSERT INTO provider_egress_policies "
                        "(id,brain_id,version,security_epoch,classification_ceiling,policy_digest,"
                        "document_json,attestation_id,attestation_digest,valid_from,valid_until,"
                        "created_at,schema_version) VALUES "
                        "(:id,:brain,:version,:epoch,:classification,:digest,:document,"
                        ":attestation,:attestation_digest,:valid_from,:valid_until,:created,1)"
                    ),
                    {
                        "attestation": policy.attestation_id,
                        "attestation_digest": bytes.fromhex(policy.attestation_digest),
                        "brain": policy.brain_id,
                        "classification": policy.classification_ceiling.value,
                        "created": published_at_microseconds,
                        "digest": bytes.fromhex(policy.digest),
                        "document": canonical_bytes(policy.document),
                        "epoch": policy.security_epoch,
                        "id": policy.policy_id,
                        "valid_from": policy.valid_from_microseconds,
                        "valid_until": policy.valid_until_microseconds,
                        "version": policy.version,
                    },
                )
                if current is None:
                    await connection.execute(
                        text(
                            "INSERT INTO active_provider_egress_policies "
                            "(brain_id,policy_id,policy_version,pointer_version,updated_at,"
                            "schema_version) VALUES (:brain,:policy,:version,1,:at,1)"
                        ),
                        {
                            "at": published_at_microseconds,
                            "brain": policy.brain_id,
                            "policy": policy.policy_id,
                            "version": policy.version,
                        },
                    )
                else:
                    changed = await connection.execute(
                        text(
                            "UPDATE active_provider_egress_policies SET policy_id=:policy,"
                            "policy_version=:version,pointer_version=pointer_version+1,"
                            "updated_at=:at WHERE brain_id=:brain AND policy_id=:current"
                        ),
                        {
                            "at": published_at_microseconds,
                            "brain": policy.brain_id,
                            "current": str(current["id"]),
                            "policy": policy.policy_id,
                            "version": policy.version,
                        },
                    )
                    if changed.rowcount != 1:
                        raise ProviderContainmentConflictError(_ERR_CONFLICT)
                await connection.execute(
                    text(
                        "INSERT INTO provider_egress_operations "
                        "(operation_id,brain_id,policy_id,request_digest,principal_id,"
                        "scope_fingerprint,completed_at,schema_version) VALUES "
                        "(:operation,:brain,:policy,:request,:principal,:scope,:at,1)"
                    ),
                    {
                        "at": published_at_microseconds,
                        "brain": policy.brain_id,
                        "operation": operation_id,
                        "policy": policy.policy_id,
                        "principal": scope.principal_id.value,
                        "request": bytes.fromhex(request_digest),
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                    },
                )
                return policy
        except (
            ProviderContainmentAuthorizationError,
            ProviderContainmentConflictError,
            ProviderContainmentValidationError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderContainmentConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error

    async def get(
        self,
        scope: AuthorizedScope,
        requested_at_microseconds: int,
    ) -> ProviderEgressPolicy | None:
        """Return one active policy only under current Brain-wide authority."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize_scope(
                    connection,
                    scope,
                    _READ_ACTION,
                    _READ_ROLES,
                    requested_at_microseconds,
                )
                row = await _active_policy_row(connection, scope.brain_id.value)
                if row is None:
                    return None
                return _policy(row)
        except (
            ProviderContainmentAuthorizationError,
            ProviderContainmentConflictError,
        ):
            raise
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderContainmentConflictError(_ERR_INTEGRITY) from error

    async def authorize(
        self,
        request: ProviderEgressRequest,
        now_microseconds: int,
    ) -> ProviderEgressPermit:
        """Recheck policy/profile/model and persist a permit before socket acquisition."""
        try:
            async with _write_transaction(self._store) as connection:
                row = await _active_policy_row(connection, request.brain_id)
                if row is None:
                    raise ProviderContainmentDeniedError(_ERR_DENIED)
                policy = _policy(row)
                await _verify_request_profile(connection, request)
                permit = policy.authorize(request, now_microseconds=now_microseconds)
                await _persist_permit(connection, permit)
                return permit
        except (
            ProviderContainmentDeniedError,
            ProviderContainmentValidationError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderContainmentConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderContainmentConflictError(_ERR_INTEGRITY) from error

    async def authorize_probe(
        self,
        request: ProviderGatewayRequest,
        now_microseconds: int,
    ) -> ProviderEgressPermit:
        """Authorize a fixed public canary against one exact draft profile route."""
        try:
            async with _write_transaction(self._store) as connection:
                policy_row = await _active_policy_row(connection, request.brain_id)
                if policy_row is None:
                    raise ProviderContainmentDeniedError(_ERR_DENIED)
                policy = _policy(policy_row)
                profile, route_attestation, route_revision = await _probe_profile(
                    connection,
                    request,
                )
                route = _provisional_probe_route(
                    policy,
                    request,
                    route_attestation,
                    route_revision,
                )
                data_policy = require_object(profile["data_policy"])
                quota = require_object(profile["quota"])
                budget = require_object(profile["budget"])
                limits = require_object(profile["limits"])
                body_digest = hashlib.sha256(request.body).hexdigest()
                authorization = ProviderEgressRequest(
                    operation_id=request.operation_id,
                    brain_id=request.brain_id,
                    project_id=None,
                    profile_id=request.profile_id,
                    profile_version=request.profile_version,
                    profile_attestation_id=route_attestation,
                    model_revision=route_revision,
                    purpose=request.purpose,
                    operation_type=request.operation_type,
                    destination=route.destination,
                    taint=ContentTaint(
                        classification=Classification.PUBLIC,
                        private_block=False,
                        secret_bearing=False,
                    ),
                    retention_days=_integer(data_policy, "retention_days"),
                    training_allowed=_boolean(data_policy, "training_allowed"),
                    policy_version=policy.version,
                    security_epoch=policy.security_epoch,
                    quota_requests_per_minute=_integer(quota, "requests_per_minute"),
                    quota_tokens_per_minute=_integer(quota, "tokens_per_minute"),
                    budget_monthly_micros=_integer(budget, "monthly_micros"),
                    request_bytes=len(request.body),
                    maximum_response_bytes=request.max_response_bytes,
                    timeout_milliseconds=min(
                        request.timeout_milliseconds,
                        _integer(limits, "timeout_milliseconds"),
                    ),
                    content_digests=(body_digest,),
                    wire_request_digest=body_digest,
                    token_count=max(
                        1,
                        min(
                            len(request.body),
                            _integer(limits, "max_request_tokens"),
                        ),
                    ),
                    estimated_cost_micros=0,
                )
                permit = policy.authorize(
                    authorization,
                    now_microseconds=now_microseconds,
                )
                await _persist_permit(connection, permit)
                return permit
        except (
            ProviderContainmentDeniedError,
            ProviderContainmentValidationError,
        ):
            raise
        except IntegrityError as error:
            raise ProviderContainmentConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderContainmentConflictError(_ERR_INTEGRITY) from error

    async def record(self, fact: ProviderRuntimeFact) -> None:
        """Append one idempotent content-free runtime fact."""
        fact_digest = hashlib.sha256(canonical_bytes(fact.document)).digest()
        try:
            async with _write_transaction(self._store) as connection:
                await connection.execute(
                    text(
                        "INSERT INTO provider_runtime_facts "
                        "(fact_digest,operation_id,adapter_image_digest,outcome_code,"
                        "runtime_milliseconds,cleanup_digest,occurred_at,schema_version) "
                        "VALUES (:digest,:operation,:image,:outcome,:runtime,:cleanup,:at,1) "
                        "ON CONFLICT(fact_digest) DO NOTHING"
                    ),
                    {
                        "at": fact.occurred_at_microseconds,
                        "cleanup": bytes.fromhex(fact.cleanup_digest),
                        "digest": fact_digest,
                        "image": bytes.fromhex(fact.adapter_image_digest),
                        "operation": fact.operation_id,
                        "outcome": fact.outcome_code,
                        "runtime": fact.runtime_milliseconds,
                    },
                )
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error

    async def record_egress(self, fact: ProviderEgressDecisionFact) -> None:
        """Append one idempotent content-free gateway decision."""
        fact_digest = hashlib.sha256(canonical_bytes(fact.document)).digest()
        try:
            async with _write_transaction(self._store) as connection:
                await connection.execute(
                    text(
                        "INSERT INTO provider_egress_decisions "
                        "(fact_digest,permit_digest,operation_id,destination_fingerprint,"
                        "outcome_code,request_bytes,response_bytes,status_code,occurred_at,"
                        "schema_version) VALUES "
                        "(:digest,:permit,:operation,:destination,:outcome,:request_bytes,"
                        ":response_bytes,:status,:at,1) "
                        "ON CONFLICT(fact_digest) DO NOTHING"
                    ),
                    {
                        "at": fact.occurred_at_microseconds,
                        "destination": bytes.fromhex(fact.destination_fingerprint),
                        "digest": fact_digest,
                        "operation": fact.operation_id,
                        "outcome": fact.outcome_code,
                        "permit": bytes.fromhex(fact.permit_digest),
                        "request_bytes": fact.request_bytes,
                        "response_bytes": fact.response_bytes,
                        "status": fact.status_code,
                    },
                )
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error


class SqliteProviderEgressOperationContextResolver:
    """Resolve an exact active route and current governed profile coordinates."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical single-writer SQLite store for read-only resolution."""
        self._store = store

    async def resolve(
        self,
        endpoint: ProviderEndpointAttestation,
        operation: ProviderOperationRequest,
    ) -> ProviderEgressOperationContext:
        """Return current content-free context or deny every stale combination."""
        try:
            async with self._store.engine.connect() as connection:
                policy_row = await _active_policy_row(connection, operation.brain_id)
                if policy_row is None:
                    raise ProviderContainmentDeniedError(_ERR_DENIED)
                policy = _policy(policy_row)
                routes = tuple(
                    route
                    for route in policy.allowed_routes
                    if (
                        route.profile_id == endpoint.profile_id
                        and route.profile_version == endpoint.profile_version
                        and route.profile_attestation_id == endpoint.capability_attestation_id
                        and route.model_revision == endpoint.output_contract.model_revision
                        and route.operation_type == endpoint.output_contract.operation.value
                        and route.purpose == endpoint.output_contract.purpose.value
                    )
                )
                if len(routes) != 1:
                    raise ProviderContainmentDeniedError(_ERR_DENIED)
                route = routes[0]
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT profile.version,profile.status,profile.document_json,"
                                "evidence.evidence_id,evidence.model_revision,"
                                "capability.adapter_digest,capability.endpoint_fingerprint,"
                                "capability.configuration_digest "
                                "FROM provider_profiles AS profile "
                                "JOIN provider_probe_evidence AS evidence "
                                "ON evidence.evidence_id=profile.active_probe_id "
                                "JOIN provider_capability_attestations AS capability "
                                "ON capability.attestation_id=evidence.evidence_id "
                                "AND capability.profile_id=profile.id "
                                "WHERE profile.id=:profile AND profile.brain_id=:brain"
                            ),
                            {"brain": operation.brain_id, "profile": endpoint.profile_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise ProviderContainmentDeniedError(_ERR_DENIED)
                configuration = require_object(
                    require_object(loads(_blob(row["document_json"])))["configuration"]
                )
                data_policy = require_object(configuration["data_policy"])
                quota = require_object(configuration["quota"])
                budget = require_object(configuration["budget"])
                limits = require_object(configuration["limits"])
                if (
                    operation.profile_id != endpoint.profile_id
                    or operation.model_revision != endpoint.output_contract.model_revision
                    or int(row["version"]) != endpoint.profile_version
                    or str(row["status"]) != "active"
                    or str(row["evidence_id"]) != endpoint.capability_attestation_id
                    or str(row["model_revision"]) != endpoint.output_contract.model_revision
                    or str(row["adapter_digest"]) != endpoint.adapter_digest
                    or str(row["endpoint_fingerprint"]) != endpoint.endpoint_fingerprint
                    or str(row["configuration_digest"]) != endpoint.configuration_digest
                    or configuration.get("operation") != endpoint.output_contract.operation.value
                    or endpoint.output_contract.purpose.value
                    not in cast("list[object]", configuration.get("purposes", []))
                    or str(data_policy.get("residency")) != route.destination.region
                ):
                    raise ProviderContainmentDeniedError(_ERR_DENIED)
                return ProviderEgressOperationContext(
                    project_id=operation.project_id,
                    destination=route.destination,
                    private_block=operation.private_block,
                    secret_bearing=operation.secret_bearing,
                    retention_days=_integer(data_policy, "retention_days"),
                    training_allowed=_boolean(data_policy, "training_allowed"),
                    policy_version=policy.version,
                    security_epoch=policy.security_epoch,
                    quota_requests_per_minute=_integer(quota, "requests_per_minute"),
                    quota_tokens_per_minute=_integer(quota, "tokens_per_minute"),
                    budget_monthly_micros=_integer(budget, "monthly_micros"),
                    maximum_response_bytes=policy.maximum_response_bytes,
                    timeout_milliseconds=min(
                        _integer(limits, "timeout_milliseconds"),
                        policy.maximum_timeout_milliseconds,
                    ),
                    token_count=operation.token_count,
                    estimated_cost_micros=operation.estimated_cost_micros,
                )
        except ProviderContainmentDeniedError:
            raise
        except SQLAlchemyError as error:
            raise ProviderContainmentDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderContainmentConflictError(_ERR_INTEGRITY) from error


async def _authorize_scope(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    action: str,
    roles: frozenset[str],
    at_microseconds: int,
) -> None:
    if scope.action != action or scope.role.value not in roles or at_microseconds < 0:
        raise ProviderContainmentAuthorizationError(_ERR_AUTHORIZATION)
    found = (
        await connection.execute(
            text(
                "SELECT 1 FROM installation_state AS installation "
                "JOIN brains AS brain JOIN principals AS principal "
                "ON principal.id=:principal JOIN scope_grants AS grant "
                "ON grant.principal_id=principal.id AND grant.brain_id=brain.id "
                "WHERE brain.id=:brain AND brain.status='active' AND principal.status='active' "
                "AND installation.singleton_key='local' "
                "AND CAST(installation.security_epoch AS INTEGER)=:epoch "
                "AND grant.role IN ('owner','admin') AND grant.project_id IS NULL "
                "AND grant.repository_id IS NULL AND grant.valid_from<=:at "
                "AND (grant.valid_to IS NULL OR grant.valid_to>:at) LIMIT 1"
            ),
            {
                "at": at_microseconds,
                "brain": scope.brain_id.value,
                "epoch": scope.security_epoch,
                "principal": scope.principal_id.value,
            },
        )
    ).scalar_one_or_none()
    if found is None:
        raise ProviderContainmentAuthorizationError(_ERR_AUTHORIZATION)


async def _verify_policy_profiles(
    connection: AsyncConnection,
    policy: ProviderEgressPolicy,
) -> None:
    for profile_id in policy.allowed_profile_ids:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT id,status,document_json FROM provider_profiles "
                        "WHERE brain_id=:brain AND id=:profile"
                    ),
                    {"brain": policy.brain_id, "profile": profile_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise ProviderContainmentConflictError(_ERR_CONFLICT)
    for route in policy.allowed_routes:
        if route.profile_id not in policy.allowed_profile_ids:
            raise ProviderContainmentConflictError(_ERR_CONFLICT)
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT profile.version,profile.status,profile.document_json,"
                        "profile.active_probe_id,"
                        "evidence.model_revision FROM provider_profiles AS profile "
                        "LEFT JOIN provider_probe_evidence AS evidence "
                        "ON evidence.evidence_id=profile.active_probe_id "
                        "WHERE profile.id=:profile AND profile.brain_id=:brain"
                    ),
                    {"brain": policy.brain_id, "profile": route.profile_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise ProviderContainmentConflictError(_ERR_CONFLICT)
        configuration = require_object(
            require_object(loads(_blob(row["document_json"])))["configuration"]
        )
        data_policy = require_object(configuration["data_policy"])
        configuration_digest = hashlib.sha256(canonical_bytes(configuration)).hexdigest()
        active_route = (
            str(row["status"]) == "active"
            and str(row["active_probe_id"]) == route.profile_attestation_id
            and str(row["model_revision"]) == route.model_revision
        )
        provisional_probe_route = (
            str(row["status"]) == "draft"
            and row["active_probe_id"] is None
            and route.profile_attestation_id == configuration_digest
            and route.model_revision == configuration.get("model_id")
        )
        if (
            int(row["version"]) != route.profile_version
            or not (active_route or provisional_probe_route)
            or configuration.get("operation") != route.operation_type
            or route.purpose not in cast("list[object]", configuration.get("purposes", []))
            or data_policy.get("residency") != route.destination.region
        ):
            raise ProviderContainmentConflictError(_ERR_CONFLICT)
        document = require_object(loads(_blob(row["document_json"])))
        configuration = require_object(document["configuration"])
        if (
            configuration.get("execution_class") != "remote"
            or not set(policy.allowed_purposes).issubset(
                cast("list[object]", configuration.get("purposes", []))
            )
            or configuration.get("operation") not in policy.allowed_operation_types
        ):
            raise ProviderContainmentConflictError(_ERR_CONFLICT)


async def _verify_request_profile(
    connection: AsyncConnection,
    request: ProviderEgressRequest,
) -> None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT profile.version,profile.status,profile.document_json,"
                    "profile.active_probe_id,"
                    "evidence.model_revision FROM provider_profiles AS profile "
                    "LEFT JOIN provider_probe_evidence AS evidence "
                    "ON evidence.evidence_id=profile.active_probe_id "
                    "WHERE profile.id=:profile AND profile.brain_id=:brain"
                ),
                {"brain": request.brain_id, "profile": request.profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ProviderContainmentDeniedError(_ERR_DENIED)
    document = require_object(loads(_blob(row["document_json"])))
    configuration = require_object(document["configuration"])
    data_policy = require_object(configuration.get("data_policy"))
    quota = require_object(configuration.get("quota"))
    budget = require_object(configuration.get("budget"))
    if (
        str(row["status"]) != "active"
        or int(row["version"]) != request.profile_version
        or str(row["active_probe_id"]) != request.profile_attestation_id
        or str(row["model_revision"]) != request.model_revision
        or configuration.get("execution_class") != "remote"
        or request.purpose not in cast("list[object]", configuration.get("purposes", []))
        or configuration.get("operation") != request.operation_type
        or int(cast("int", data_policy.get("retention_days"))) != request.retention_days
        or bool(data_policy.get("training_allowed")) != request.training_allowed
        or str(data_policy.get("residency")) != request.destination.region
        or int(cast("int", quota.get("requests_per_minute"))) != request.quota_requests_per_minute
        or int(cast("int", quota.get("tokens_per_minute"))) != request.quota_tokens_per_minute
        or int(cast("int", budget.get("monthly_micros"))) != request.budget_monthly_micros
    ):
        raise ProviderContainmentDeniedError(_ERR_DENIED)


async def _probe_profile(
    connection: AsyncConnection,
    request: ProviderGatewayRequest,
) -> tuple[dict[str, object], str, str]:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT version,status,active_probe_id,document_json "
                    "FROM provider_profiles WHERE id=:profile AND brain_id=:brain"
                ),
                {"brain": request.brain_id, "profile": request.profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ProviderContainmentDeniedError(_ERR_DENIED)
    document = require_object(loads(_blob(row["document_json"])))
    configuration = require_object(document["configuration"])
    configuration_digest = hashlib.sha256(canonical_bytes(configuration)).hexdigest()
    draft_probe = request.operation_id.startswith("profile-probe:")
    drift_probe = request.operation_id.startswith("drift-probe:")
    exact_operation = request.operation_id in {
        f"profile-probe:{request.profile_id}:{request.profile_version}:{request.purpose}",
        f"drift-probe:{request.profile_id}:{request.profile_version}:{request.purpose}",
    }
    active_probe_id = None if row["active_probe_id"] is None else str(row["active_probe_id"])
    if (
        not exact_operation
        or draft_probe == drift_probe
        or int(row["version"]) != request.profile_version
        or configuration_digest != request.configuration_digest
        or configuration.get("brain_id") != request.brain_id
        or configuration.get("adapter_id") != request.adapter_id
        or configuration.get("model_id") != request.model_id
        or configuration.get("operation") != request.operation_type
        or request.purpose not in cast("list[object]", configuration.get("purposes", []))
        or configuration.get("endpoint_policy_ref") != request.endpoint_policy_ref
        or configuration.get("secret_ref") != request.secret_ref
        or configuration.get("execution_class") != "remote"
    ):
        raise ProviderContainmentDeniedError(_ERR_DENIED)
    if draft_probe:
        if str(row["status"]) != "draft" or active_probe_id is not None:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        return configuration, configuration_digest, request.model_id
    if str(row["status"]) != "active" or active_probe_id is None:
        raise ProviderContainmentDeniedError(_ERR_DENIED)
    evidence = (
        (
            await connection.execute(
                text(
                    "SELECT evidence_json FROM provider_probe_evidence "
                    "WHERE evidence_id=:evidence AND profile_id=:profile"
                ),
                {"evidence": active_probe_id, "profile": request.profile_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if evidence is None:
        raise ProviderContainmentDeniedError(_ERR_DENIED)
    result = require_object(loads(_blob(evidence["evidence_json"])))
    return configuration, active_probe_id, _string(result, "model_revision")


def _provisional_probe_route(
    policy: ProviderEgressPolicy,
    request: ProviderGatewayRequest,
    profile_attestation_id: str,
    model_revision: str,
) -> ProviderEgressRoute:
    routes = tuple(
        route
        for route in policy.allowed_routes
        if (
            route.profile_id == request.profile_id
            and route.profile_version == request.profile_version
            and route.profile_attestation_id == profile_attestation_id
            and route.model_revision == model_revision
            and route.operation_type == request.operation_type
            and route.purpose == request.purpose
            and (
                request.path == route.destination.path_prefix
                or request.path.startswith(f"{route.destination.path_prefix}/")
            )
        )
    )
    if len(routes) != 1:
        raise ProviderContainmentDeniedError(_ERR_DENIED)
    return routes[0]


async def _persist_permit(
    connection: AsyncConnection,
    permit: ProviderEgressPermit,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_egress_permits "
            "(permit_digest,operation_id,brain_id,policy_id,policy_version,"
            "security_epoch,request_digest,destination_fingerprint,document_json,"
            "issued_at,expires_at,schema_version) VALUES "
            "(:permit,:operation,:brain,:policy,:version,:epoch,:request,"
            ":destination,:document,:issued,:expires,1)"
        ),
        {
            "brain": permit.brain_id,
            "destination": bytes.fromhex(permit.destination.fingerprint),
            "document": canonical_bytes(permit.document),
            "epoch": permit.security_epoch,
            "expires": permit.expires_at_microseconds,
            "issued": permit.issued_at_microseconds,
            "operation": permit.operation_id,
            "permit": bytes.fromhex(permit.digest),
            "policy": permit.policy_id,
            "request": bytes.fromhex(permit.request_digest),
            "version": permit.policy_version,
        },
    )


async def _operation(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT brain_id,policy_id,request_digest "
                    "FROM provider_egress_operations WHERE operation_id=:operation"
                ),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _active_policy_row(
    connection: AsyncConnection,
    brain_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT policy.* FROM active_provider_egress_policies AS active "
                    "JOIN provider_egress_policies AS policy ON policy.id=active.policy_id "
                    "AND policy.brain_id=active.brain_id "
                    "AND policy.version=active.policy_version WHERE active.brain_id=:brain"
                ),
                {"brain": brain_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _policy_by_id(
    connection: AsyncConnection,
    policy_id: str,
) -> ProviderEgressPolicy | None:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_egress_policies WHERE id=:policy"),
                {"policy": policy_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _policy(row)


def _policy(row: RowMapping) -> ProviderEgressPolicy:
    document = require_object(loads(_blob(row["document_json"])))
    destinations = tuple(
        EgressDestination(
            scheme=_string(value, "scheme"),
            hostname=_string(value, "hostname"),
            port=_integer(value, "port"),
            region=_string(value, "region"),
            path_prefix=_string(value, "path_prefix"),
        )
        for value in (
            require_object(item) for item in cast("list[object]", document["allowed_destinations"])
        )
    )
    policy = ProviderEgressPolicy(
        policy_id=_string(document, "policy_id"),
        brain_id=_string(document, "brain_id"),
        version=_integer(document, "version"),
        security_epoch=_integer(document, "security_epoch"),
        classification_ceiling=Classification(_string(document, "classification_ceiling")),
        allowed_destinations=destinations,
        allowed_profile_ids=_strings(document, "allowed_profile_ids"),
        allowed_purposes=_strings(document, "allowed_purposes"),
        allowed_operation_types=_strings(document, "allowed_operation_types"),
        allowed_routes=tuple(
            _route(require_object(value))
            for value in cast("list[object]", document["allowed_routes"])
        ),
        maximum_retention_days=_integer(document, "maximum_retention_days"),
        training_allowed=_boolean(document, "training_allowed"),
        maximum_request_bytes=_integer(document, "maximum_request_bytes"),
        maximum_response_bytes=_integer(document, "maximum_response_bytes"),
        maximum_timeout_milliseconds=_integer(document, "maximum_timeout_milliseconds"),
        maximum_requests_per_minute=_integer(document, "maximum_requests_per_minute"),
        maximum_tokens_per_minute=_integer(document, "maximum_tokens_per_minute"),
        maximum_monthly_cost_micros=_integer(document, "maximum_monthly_cost_micros"),
        attestation_id=_string(document, "attestation_id"),
        attestation_digest=_string(document, "attestation_digest"),
        valid_from_microseconds=_integer(document, "valid_from_microseconds"),
        valid_until_microseconds=_integer(document, "valid_until_microseconds"),
    )
    if _blob(row["policy_digest"]).hex() != policy.digest or _blob(
        row["document_json"]
    ) != canonical_bytes(policy.document):
        raise ProviderContainmentConflictError(_ERR_INTEGRITY)
    return policy


def _route(document: dict[str, object]) -> ProviderEgressRoute:
    destination = require_object(document["destination"])
    return ProviderEgressRoute(
        profile_id=_string(document, "profile_id"),
        profile_version=_integer(document, "profile_version"),
        profile_attestation_id=_string(document, "profile_attestation_id"),
        model_revision=_string(document, "model_revision"),
        operation_type=_string(document, "operation_type"),
        purpose=_string(document, "purpose"),
        destination=EgressDestination(
            scheme=_string(destination, "scheme"),
            hostname=_string(destination, "hostname"),
            port=_integer(destination, "port"),
            region=_string(destination, "region"),
            path_prefix=_string(destination, "path_prefix"),
        ),
    )


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError
    return value


def _integer(document: dict[str, object], key: str) -> int:
    value = document[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _boolean(document: dict[str, object], key: str) -> bool:
    value = document[key]
    if not isinstance(value, bool):
        raise TypeError
    return value


def _strings(document: dict[str, object], key: str) -> tuple[str, ...]:
    values = document[key]
    if not isinstance(values, list):
        raise TypeError
    items = cast("list[object]", values)
    if any(not isinstance(value, str) for value in items):
        raise TypeError
    return tuple(cast("list[str]", items))


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode()
    raise TypeError


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
