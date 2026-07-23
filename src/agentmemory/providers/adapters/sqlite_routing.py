"""PRO-005 SQLite repository for routing policies, restrictions, and decisions."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.errors import (
    ProviderRoutingAuthorizationError,
    ProviderRoutingConflictError,
    ProviderRoutingDependencyError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    ProviderOperation,
    ProviderProfileStatus,
)
from agentmemory.providers.domain.routing import (
    ProviderCorpus,
    ProviderRouteRule,
    ProviderRouteSelector,
    ProviderRoutingGuard,
    ProviderRoutingPolicy,
    ProviderWorkload,
    RepositoryRoutingRestriction,
    RoutableProviderProfile,
    RouteDecision,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_AUTHORIZATION = "provider routing storage action is not authorized"
_ERR_CONFLICT = "provider routing conflicts with immutable history"
_ERR_INTEGRITY = "provider routing storage failed integrity verification"
_ERR_STORAGE = "provider routing storage is unavailable"
_WRITE_ACTIONS = frozenset({"provider.route.publish", "provider.route.restrict"})
_RESOLVE_ACTION = "provider.route.resolve"
_WRITE_ROLES = frozenset({"owner", "admin"})
_RESOLVE_ROLES = frozenset({"owner", "admin", "editor", "adapter", "worker"})
_PRECEDENCE_LENGTH = 2


class SqliteProviderRoutingRepository:
    """Own the append-only relational routing authority."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical SQLite writer."""
        self._store = store

    async def current_policy(
        self,
        scope: AuthorizedScope,
        requested_at: datetime,
    ) -> ProviderRoutingPolicy | None:
        """Load and verify the latest published Brain policy."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, requested_at)
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM provider_routing_policies "
                                "WHERE brain_id=:brain ORDER BY version DESC LIMIT 1"
                            ),
                            {"brain": scope.brain_id.value},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                return None if row is None else await _decode_policy(connection, row)
        except ProviderRoutingAuthorizationError, ProviderRoutingConflictError:
            raise
        except SQLAlchemyError as error:
            raise ProviderRoutingDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderRoutingConflictError(_ERR_INTEGRITY) from error

    async def profiles(
        self,
        scope: AuthorizedScope,
        profile_ids: tuple[str, ...],
        requested_at: datetime,
    ) -> tuple[RoutableProviderProfile, ...]:
        """Read current profile capability projections under fresh authority."""
        if not profile_ids:
            return ()
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, requested_at)
                statement = text(
                    "SELECT profile.id,profile.brain_id,profile.status,profile.version,"
                    "profile.active_probe_id,profile.document_json,"
                    "EXISTS(SELECT 1 FROM provider_capability_attestations AS attestation "
                    "WHERE attestation.attestation_id=profile.active_probe_id "
                    "AND attestation.profile_id=profile.id) AS active_attestation "
                    "FROM provider_profiles AS profile "
                    "WHERE profile.brain_id=:brain AND profile.id IN :profiles"
                ).bindparams(bindparam("profiles", expanding=True))
                rows = (
                    (
                        await connection.execute(
                            statement,
                            {
                                "brain": scope.brain_id.value,
                                "profiles": profile_ids,
                            },
                        )
                    )
                    .mappings()
                    .all()
                )
                values = tuple(
                    sorted(
                        (_decode_profile(row) for row in rows),
                        key=lambda value: value.profile_id,
                    )
                )
                if len(values) != len(profile_ids):
                    raise ProviderRoutingAuthorizationError(  # noqa: TRY301
                        _ERR_AUTHORIZATION
                    )
                return values
        except ProviderRoutingAuthorizationError, ProviderRoutingConflictError:
            raise
        except SQLAlchemyError as error:
            raise ProviderRoutingDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderRoutingConflictError(_ERR_INTEGRITY) from error

    async def publish_policy(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        expected_current_version: int,
        policy: ProviderRoutingPolicy,
    ) -> ProviderRoutingPolicy:
        """Atomically publish, audit, and emit one immutable policy revision."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, policy.created_at)
                replay = await _operation_row(connection, operation_id)
                if replay is not None:
                    return await _replay_policy(
                        connection,
                        replay,
                        scope,
                        request_digest,
                    )
                current = await _current_version(
                    connection,
                    "provider_routing_policies",
                    scope.brain_id.value,
                )
                if (
                    policy.brain_id != scope.brain_id.value
                    or current != expected_current_version
                    or policy.version != current + 1
                ):
                    raise ProviderRoutingConflictError(_ERR_CONFLICT)  # noqa: TRY301
                await _insert_policy(connection, scope, policy)
                await _insert_operation(
                    connection,
                    operation_id,
                    "policy",
                    scope.brain_id.value,
                    request_digest,
                    policy.policy_id,
                    policy.version,
                    policy.digest,
                    policy.created_at,
                )
                await _append_command_evidence(
                    connection,
                    scope,
                    operation_id,
                    "policy",
                    policy.policy_id,
                    policy.digest,
                    policy.version,
                    policy.created_at,
                )
                return policy
        except ProviderRoutingAuthorizationError, ProviderRoutingConflictError:
            raise
        except IntegrityError as error:
            raise ProviderRoutingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderRoutingDependencyError(_ERR_STORAGE) from error

    async def current_restriction(
        self,
        scope: AuthorizedScope,
        repository_id: str,
        requested_at: datetime,
    ) -> RepositoryRoutingRestriction | None:
        """Load and verify the latest repository filter."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(connection, scope, requested_at)
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM provider_repository_route_restrictions "
                                "WHERE brain_id=:brain AND repository_id=:repository "
                                "ORDER BY version DESC LIMIT 1"
                            ),
                            {
                                "brain": scope.brain_id.value,
                                "repository": repository_id,
                            },
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                return None if row is None else _decode_restriction(row)
        except ProviderRoutingAuthorizationError, ProviderRoutingConflictError:
            raise
        except SQLAlchemyError as error:
            raise ProviderRoutingDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderRoutingConflictError(_ERR_INTEGRITY) from error

    async def publish_restriction(  # noqa: PLR0913 -- Repository transaction coordinates.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        expected_current_version: int,
        restriction: RepositoryRoutingRestriction,
        created_at: datetime,
    ) -> RepositoryRoutingRestriction:
        """Atomically publish, audit, and emit one immutable repository filter."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, created_at)
                replay = await _operation_row(connection, operation_id)
                if replay is not None:
                    _validate_operation(replay, scope, "restriction", request_digest)
                    row = (
                        (
                            await connection.execute(
                                text(
                                    "SELECT * FROM "
                                    "provider_repository_route_restrictions "
                                    "WHERE restriction_id=:id"
                                ),
                                {"id": str(replay["result_id"])},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        raise ProviderRoutingConflictError(_ERR_INTEGRITY)  # noqa: TRY301
                    value = _decode_restriction(row)
                    _validate_result(replay, value.version, value.digest)
                    return value
                current = (
                    await connection.execute(
                        text(
                            "SELECT COALESCE(MAX(version),0) FROM "
                            "provider_repository_route_restrictions "
                            "WHERE brain_id=:brain AND repository_id=:repository"
                        ),
                        {
                            "brain": scope.brain_id.value,
                            "repository": restriction.repository_id,
                        },
                    )
                ).scalar_one()
                if (
                    restriction.brain_id != scope.brain_id.value
                    or int(current) != expected_current_version
                    or restriction.version != int(current) + 1
                ):
                    raise ProviderRoutingConflictError(_ERR_CONFLICT)  # noqa: TRY301
                await connection.execute(
                    text(
                        "INSERT INTO provider_repository_route_restrictions "
                        "(restriction_id,brain_id,repository_id,version,restriction_digest,"
                        "document_json,principal_id,grant_version,authorization_policy_version,"
                        "security_epoch,scope_fingerprint,created_at,schema_version) VALUES "
                        "(:id,:brain,:repository,:version,:digest,:document,:principal,:grant,"
                        ":policy,:epoch,:scope,:at,1)"
                    ),
                    {
                        "at": _micros(created_at),
                        "brain": restriction.brain_id,
                        "digest": restriction.digest,
                        "document": canonical_bytes(restriction.document),
                        "epoch": scope.security_epoch,
                        "grant": scope.grant_version,
                        "id": restriction.restriction_id,
                        "policy": scope.policy_version,
                        "principal": scope.principal_id.value,
                        "repository": restriction.repository_id,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "version": restriction.version,
                    },
                )
                await _insert_operation(
                    connection,
                    operation_id,
                    "restriction",
                    scope.brain_id.value,
                    request_digest,
                    restriction.restriction_id,
                    restriction.version,
                    restriction.digest,
                    created_at,
                )
                await _append_command_evidence(
                    connection,
                    scope,
                    operation_id,
                    "restriction",
                    restriction.restriction_id,
                    restriction.digest,
                    restriction.version,
                    created_at,
                )
                return restriction
        except ProviderRoutingAuthorizationError, ProviderRoutingConflictError:
            raise
        except IntegrityError as error:
            raise ProviderRoutingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderRoutingDependencyError(_ERR_STORAGE) from error

    async def record_decision(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        cache_key: str,
        decision: RouteDecision,
        decided_at: datetime,
    ) -> RouteDecision:
        """Append or replay one content-free decision under current authority."""
        cache_digest = hashlib.sha256(cache_key.encode()).hexdigest()
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, decided_at)
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT * FROM provider_route_decisions "
                                "WHERE operation_id=:operation"
                            ),
                            {"operation": operation_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is not None:
                    replay = _decode_decision(row)
                    if (
                        str(row["brain_id"]) != scope.brain_id.value
                        or str(row["cache_key_digest"]) != cache_digest
                        or replay != decision
                    ):
                        raise ProviderRoutingConflictError(_ERR_CONFLICT)  # noqa: TRY301
                    return replay
                await connection.execute(
                    text(
                        "INSERT INTO provider_route_decisions "
                        "(operation_id,brain_id,policy_id,rule_id,profile_id,profile_version,"
                        "cache_key_digest,request_digest,decision_json,principal_id,grant_version,"
                        "authorization_policy_version,security_epoch,decided_at,schema_version) "
                        "VALUES (:operation,:brain,:policy_id,:rule,:profile,:profile_version,"
                        ":cache,:request,:document,:principal,:grant,:policy_version,:epoch,:at,1)"
                    ),
                    {
                        "at": _micros(decided_at),
                        "brain": scope.brain_id.value,
                        "cache": cache_digest,
                        "document": canonical_bytes(decision.document),
                        "epoch": scope.security_epoch,
                        "grant": scope.grant_version,
                        "operation": operation_id,
                        "policy_id": decision.policy_id,
                        "policy_version": scope.policy_version,
                        "principal": scope.principal_id.value,
                        "profile": decision.profile_id,
                        "profile_version": decision.profile_version,
                        "request": decision.request_digest,
                        "rule": decision.rule_id,
                    },
                )
                return decision
        except ProviderRoutingAuthorizationError, ProviderRoutingConflictError:
            raise
        except IntegrityError as error:
            raise ProviderRoutingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise ProviderRoutingDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise ProviderRoutingConflictError(_ERR_INTEGRITY) from error


async def _authorize(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    at: datetime,
) -> None:
    action = scope.action
    write = action in _WRITE_ACTIONS
    allowed_roles = _WRITE_ROLES if write else _RESOLVE_ROLES
    if (
        (not write and action != _RESOLVE_ACTION)
        or scope.role.value not in allowed_roles
        or scope.principal_id.value == ""
    ):
        raise ProviderRoutingAuthorizationError(_ERR_AUTHORIZATION)
    statement = (
        text(
            "SELECT 1 FROM brains AS brain JOIN principals AS principal "
            "ON principal.id=:principal JOIN scope_grants AS grant "
            "ON grant.principal_id=principal.id AND grant.brain_id=brain.id "
            "WHERE brain.id=:brain AND brain.status='active' "
            "AND principal.status='active' AND grant.role=:role "
            "AND grant.project_id IS NULL AND grant.repository_id IS NULL "
            "AND grant.valid_from<=:at "
            "AND (grant.valid_to IS NULL OR grant.valid_to>:at) LIMIT 1"
        )
        if write
        else text(
            "SELECT 1 FROM brains AS brain JOIN principals AS principal "
            "ON principal.id=:principal JOIN scope_grants AS grant "
            "ON grant.principal_id=principal.id AND grant.brain_id=brain.id "
            "WHERE brain.id=:brain AND brain.status='active' "
            "AND principal.status='active' AND grant.role=:role "
            "AND grant.valid_from<=:at "
            "AND (grant.valid_to IS NULL OR grant.valid_to>:at) LIMIT 1"
        )
    )
    authorized = (
        await connection.execute(
            statement,
            {
                "at": _micros(at),
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
                "role": scope.role.value,
            },
        )
    ).scalar_one_or_none()
    if authorized is None:
        raise ProviderRoutingAuthorizationError(_ERR_AUTHORIZATION)


async def _insert_policy(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    policy: ProviderRoutingPolicy,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_routing_policies "
            "(policy_id,brain_id,version,policy_digest,guard_json,document_json,"
            "principal_id,grant_version,authorization_policy_version,security_epoch,"
            "scope_fingerprint,created_at,schema_version) VALUES "
            "(:id,:brain,:version,:digest,:guard,:document,:principal,:grant,:policy,"
            ":epoch,:scope,:at,1)"
        ),
        {
            "at": _micros(policy.created_at),
            "brain": policy.brain_id,
            "digest": policy.digest,
            "document": canonical_bytes(policy.document),
            "epoch": scope.security_epoch,
            "grant": scope.grant_version,
            "guard": canonical_bytes(policy.guard.document),
            "id": policy.policy_id,
            "policy": scope.policy_version,
            "principal": scope.principal_id.value,
            "scope": bytes.fromhex(scope.scope_fingerprint),
            "version": policy.version,
        },
    )
    for rule in policy.rules:
        await connection.execute(
            text(
                "INSERT INTO provider_route_rules "
                "(rule_id,policy_id,profile_id,profile_version,profile_snapshot_digest,"
                "operation,selector_json,project_specificity,dimension_specificity,enabled,"
                "reason,schema_version) VALUES (:rule,:policy,:profile,:version,:digest,"
                ":operation,:selector,:project,:dimensions,:enabled,:reason,1)"
            ),
            {
                "digest": rule.profile_snapshot_digest,
                "dimensions": rule.selector.precedence[1],
                "enabled": rule.enabled,
                "operation": rule.operation.value,
                "policy": policy.policy_id,
                "profile": rule.profile_id,
                "project": rule.selector.precedence[0],
                "reason": rule.reason,
                "rule": rule.rule_id,
                "selector": canonical_bytes(rule.selector.document),
                "version": rule.profile_version,
            },
        )


async def _decode_policy(
    connection: AsyncConnection,
    row: RowMapping,
) -> ProviderRoutingPolicy:
    document = require_object(loads(_blob(row["document_json"])))
    guard_document = require_object(document["guard"])
    rules_raw = document["rules"]
    if not isinstance(rules_raw, list):
        raise TypeError
    policy = ProviderRoutingPolicy(
        policy_id=_string(document["policy_id"]),
        brain_id=_string(document["brain_id"]),
        version=_integer(document["version"]),
        guard=_decode_guard(guard_document),
        rules=tuple(
            sorted(
                (_decode_rule(require_object(value)) for value in cast("list[object]", rules_raw)),
                key=lambda value: value.rule_id,
            )
        ),
        created_at=_instant(document["created_at"]),
    )
    rule_rows = (
        (
            await connection.execute(
                text(
                    "SELECT rule_id,profile_id,profile_version,profile_snapshot_digest,"
                    "operation,selector_json,project_specificity,dimension_specificity,"
                    "enabled,reason FROM provider_route_rules WHERE policy_id=:policy "
                    "ORDER BY rule_id"
                ),
                {"policy": policy.policy_id},
            )
        )
        .mappings()
        .all()
    )
    if (
        policy.policy_id != str(row["policy_id"])
        or policy.brain_id != str(row["brain_id"])
        or policy.version != int(row["version"])
        or policy.digest != str(row["policy_digest"])
        or policy.guard.document != require_object(loads(_blob(row["guard_json"])))
        or len(rule_rows) != len(policy.rules)
    ):
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    for stored, rule in zip(rule_rows, policy.rules, strict=True):
        if (
            str(stored["rule_id"]) != rule.rule_id
            or str(stored["profile_id"]) != rule.profile_id
            or int(stored["profile_version"]) != rule.profile_version
            or str(stored["profile_snapshot_digest"]) != rule.profile_snapshot_digest
            or str(stored["operation"]) != rule.operation.value
            or require_object(loads(_blob(stored["selector_json"]))) != rule.selector.document
            or (
                int(stored["project_specificity"]),
                int(stored["dimension_specificity"]),
            )
            != rule.selector.precedence
            or bool(stored["enabled"]) is not rule.enabled
            or str(stored["reason"]) != rule.reason
        ):
            raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    return policy


def _decode_rule(document: dict[str, object]) -> ProviderRouteRule:
    return ProviderRouteRule(
        rule_id=_string(document["rule_id"]),
        profile_id=_string(document["profile_id"]),
        profile_version=_integer(document["profile_version"]),
        profile_snapshot_digest=_string(document["profile_snapshot_digest"]),
        operation=ProviderOperation(_string(document["operation"])),
        selector=_decode_selector(require_object(document["selector"])),
        enabled=_boolean(document["enabled"]),
        reason=_string(document["reason"]),
    )


def _decode_selector(document: dict[str, object]) -> ProviderRouteSelector:
    return ProviderRouteSelector(
        project_id=_optional_string(document.get("project_id")),
        corpus=_optional_enum(ProviderCorpus, document.get("corpus")),
        language=_optional_string(document.get("language")),
        classification=_optional_enum(Classification, document.get("classification")),
        purpose=_optional_enum(CanonicalPurpose, document.get("purpose")),
        workload=_optional_enum(ProviderWorkload, document.get("workload")),
    )


def _decode_guard(document: dict[str, object]) -> ProviderRoutingGuard:
    return ProviderRoutingGuard(
        allow_remote=_boolean(document["allow_remote"]),
        allowed_remote_residencies=_strings(document["allowed_remote_residencies"]),
        remote_classification_ceiling=Classification(
            _string(document["remote_classification_ceiling"])
        ),
    )


def _decode_restriction(row: RowMapping) -> RepositoryRoutingRestriction:
    document = require_object(loads(_blob(row["document_json"])))
    value = RepositoryRoutingRestriction(
        restriction_id=_string(document["restriction_id"]),
        brain_id=_string(document["brain_id"]),
        repository_id=_string(document["repository_id"]),
        version=_integer(document["version"]),
        allow_remote=_boolean(document["allow_remote"]),
        allowed_remote_residencies=_strings(document["allowed_remote_residencies"]),
        remote_classification_ceiling=Classification(
            _string(document["remote_classification_ceiling"])
        ),
        allowed_profile_ids=_strings(document["allowed_profile_ids"]),
        allowed_purposes=tuple(
            CanonicalPurpose(item) for item in _strings(document["allowed_purposes"])
        ),
        allowed_workloads=tuple(
            ProviderWorkload(item) for item in _strings(document["allowed_workloads"])
        ),
    )
    if (
        value.restriction_id != str(row["restriction_id"])
        or value.brain_id != str(row["brain_id"])
        or value.repository_id != str(row["repository_id"])
        or value.version != int(row["version"])
        or value.digest != str(row["restriction_digest"])
    ):
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    return value


def _decode_profile(row: RowMapping) -> RoutableProviderProfile:
    document = require_object(loads(_blob(row["document_json"])))
    configuration = require_object(document["configuration"])
    purposes = tuple(CanonicalPurpose(item) for item in _strings(configuration["purposes"]))
    execution = ProviderExecutionClass(_string(configuration["execution_class"]))
    data_raw = configuration.get("data_policy")
    residency = "local"
    if execution is ProviderExecutionClass.REMOTE:
        data = require_object(data_raw)
        residency = _string(data["residency"])
    raw = _blob(row["document_json"])
    stored_status = ProviderProfileStatus(_string(document["status"]))
    effective_status = stored_status
    if stored_status is ProviderProfileStatus.ACTIVE and (
        row["active_probe_id"] is None or not bool(row["active_attestation"])
    ):
        effective_status = ProviderProfileStatus.REPROBE_REQUIRED
    projection = RoutableProviderProfile(
        profile_id=_string(document["profile_id"]),
        version=_integer(document["version"]),
        snapshot_digest=hashlib.sha256(raw).hexdigest(),
        status=effective_status,
        operation=ProviderOperation(_string(configuration["operation"])),
        purposes=purposes,
        execution_class=execution,
        residency=residency,
    )
    if (
        projection.profile_id != str(row["id"])
        or _string(configuration["brain_id"]) != str(row["brain_id"])
        or stored_status.value != str(row["status"])
        or projection.version != int(row["version"])
    ):
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    return projection


def _decode_decision(row: RowMapping) -> RouteDecision:
    document = require_object(loads(_blob(row["decision_json"])))
    precedence = document["precedence"]
    if not isinstance(precedence, list):
        raise TypeError
    values = cast("list[object]", precedence)
    if len(values) != _PRECEDENCE_LENGTH:
        raise TypeError
    decision = RouteDecision(
        policy_id=_string(document["policy_id"]),
        policy_version=_integer(document["policy_version"]),
        rule_id=_string(document["rule_id"]),
        profile_id=_string(document["profile_id"]),
        profile_version=_integer(document["profile_version"]),
        profile_snapshot_digest=_string(document["profile_snapshot_digest"]),
        precedence=(_integer(values[0]), _integer(values[1])),
        reason=_string(document["reason"]),
        request_digest=_string(document["request_digest"]),
    )
    if (
        decision.policy_id != str(row["policy_id"])
        or decision.rule_id != str(row["rule_id"])
        or decision.profile_id != str(row["profile_id"])
        or decision.profile_version != int(row["profile_version"])
        or decision.request_digest != str(row["request_digest"])
    ):
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    return decision


async def _replay_policy(
    connection: AsyncConnection,
    operation: RowMapping,
    scope: AuthorizedScope,
    request_digest: str,
) -> ProviderRoutingPolicy:
    _validate_operation(operation, scope, "policy", request_digest)
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_routing_policies WHERE policy_id=:id"),
                {"id": str(operation["result_id"])},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    value = await _decode_policy(connection, row)
    _validate_result(operation, value.version, value.digest)
    return value


def _validate_operation(
    row: RowMapping,
    scope: AuthorizedScope,
    kind: str,
    request_digest: str,
) -> None:
    if (
        str(row["brain_id"]) != scope.brain_id.value
        or str(row["operation_kind"]) != kind
        or str(row["request_digest"]) != request_digest
    ):
        raise ProviderRoutingConflictError(_ERR_CONFLICT)


def _validate_result(row: RowMapping, version: int, digest: str) -> None:
    if int(row["result_version"]) != version or str(row["result_digest"]) != digest:
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)


async def _operation_row(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM provider_routing_operations WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _current_version(
    connection: AsyncConnection,
    table: str,
    brain_id: str,
) -> int:
    if table != "provider_routing_policies":
        raise ProviderRoutingConflictError(_ERR_INTEGRITY)
    return int(
        (
            await connection.execute(
                text(
                    "SELECT COALESCE(MAX(version),0) FROM provider_routing_policies "
                    "WHERE brain_id=:brain"
                ),
                {"brain": brain_id},
            )
        ).scalar_one()
    )


async def _insert_operation(  # noqa: PLR0913 -- Immutable receipt coordinates.
    connection: AsyncConnection,
    operation_id: str,
    kind: str,
    brain_id: str,
    request_digest: str,
    result_id: str,
    result_version: int,
    result_digest: str,
    completed_at: datetime,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_routing_operations "
            "(operation_id,operation_kind,brain_id,request_digest,result_id,result_version,"
            "result_digest,completed_at,schema_version) VALUES "
            "(:operation,:kind,:brain,:request,:result,:version,:digest,:at,1)"
        ),
        {
            "at": _micros(completed_at),
            "brain": brain_id,
            "digest": result_digest,
            "kind": kind,
            "operation": operation_id,
            "request": request_digest,
            "result": result_id,
            "version": result_version,
        },
    )


async def _append_command_evidence(  # noqa: PLR0913 -- Atomic evidence coordinates.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    kind: str,
    result_id: str,
    result_digest: str,
    version: int,
    completed_at: datetime,
) -> None:
    event_name = (
        "ProviderRoutingPolicyPublished"
        if kind == "policy"
        else "ProviderRepositoryRoutingRestricted"
    )
    slug = "policy-published" if kind == "policy" else "repository-restricted"
    operation_digest = hashlib.sha256(
        f"provider-routing-command.v1\0{kind}\0{operation_id}".encode()
    ).hexdigest()
    source_event_id = f"provider-routing-event-{operation_digest}"
    integration_event_id = f"provider-routing-outbox-{operation_digest}"
    topic = f"am.local.{scope.brain_id.value}.provider.routing-{slug}.v1"
    now = _micros(completed_at)
    payload = canonical_bytes(
        {
            "brain_id": scope.brain_id.value,
            "correlation_id": operation_id,
            "data": {
                "brain_id": scope.brain_id.value,
                "result_digest": result_digest,
                "result_id": result_id,
                "schema_version": 1,
                "version": version,
            },
            "datacontenttype": "application/json",
            "id": integration_event_id,
            "source": f"urn:agentmemory:brain:{scope.brain_id.value}:provider-routing",
            "specversion": "1.0",
            "subject": f"provider-routing/{result_id}",
            "time": completed_at.isoformat(),
            "type": topic,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO agent_events "
            "(event_id,brain_id,type,payload_hash,classification,occurred_at,ingested_at,"
            "payload_ref,schema_version) VALUES "
            "(:event,:brain,:type,:hash,'internal',:now,:now,NULL,1)"
        ),
        {
            "brain": scope.brain_id.value,
            "event": source_event_id,
            "hash": hashlib.sha256(payload).digest(),
            "now": now,
            "type": event_name,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) VALUES (:id,:source,:topic,:key,:payload,'ready',100,:now,0,NULL,"
            "NULL,NULL,:digest,NULL,:now,1)"
        ),
        {
            "digest": hashlib.sha256(payload).digest(),
            "id": integration_event_id,
            "key": result_id,
            "now": now,
            "payload": payload.decode(),
            "source": source_event_id,
            "topic": topic,
        },
    )
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = bytes(32) if previous is None else _blob(previous)
    fact = canonical_bytes(
        {
            "action": f"provider.route.{slug}",
            "actor_id": scope.principal_id.value,
            "brain_id": scope.brain_id.value,
            "operation_id": operation_id,
            "result_digest": result_digest,
            "result_id": result_id,
            "version": version,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:now,1)"
        ),
        {
            "action": f"provider.route.{slug}",
            "actor": scope.principal_id.value,
            "after": bytes.fromhex(result_digest),
            "before": bytes(32),
            "brain": scope.brain_id.value,
            "event": hashlib.sha256(previous_hash + fact).digest(),
            "key": f"provider.route.{kind}:{operation_id}",
            "now": now,
            "previous": previous_hash,
            "target": f"provider-routing:{result_id}",
        },
    )


def _optional_enum[EnumT: StrEnum](
    enum_type: type[EnumT],
    value: object,
) -> EnumT | None:
    return None if value is None else enum_type(_string(value))


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError
    return tuple(_string(item) for item in cast("list[object]", value))


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError
    return value


def _instant(value: object) -> datetime:
    return datetime.fromtimestamp(_integer(value) / 1_000_000, tz=UTC)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode()
    raise TypeError


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


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
