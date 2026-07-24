"""SQLite PRO-007 equivalence, circuit, and dispatch-evidence adapter."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import TYPE_CHECKING, Self, cast

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderResilienceConflictError,
    ProviderResilienceDependencyError,
    ProviderResilienceValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)
from agentmemory.providers.domain.resilience import (
    EquivalentEndpointSet,
    ProviderCircuitPermit,
    ProviderCircuitPolicy,
    ProviderCircuitSnapshot,
    ProviderCircuitState,
    ProviderDispatchFact,
    ProviderEndpointAttestation,
    ProviderOutputContract,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_STORAGE = "Provider resilience storage is unavailable"
_ERR_CONFLICT = "Provider resilience evidence diverged"
_ERR_INPUT = "provider resilience request is invalid"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class SqliteProviderResilienceRepository:
    """Persist immutable equivalence and atomically update endpoint circuits."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the shared canonical store."""
        self._store = store

    async def put(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        endpoints: EquivalentEndpointSet,
        created_at_microseconds: int,
    ) -> EquivalentEndpointSet:
        """Insert or exactly replay one complete equivalence attestation."""
        if (
            _OPERATION.fullmatch(operation_id) is None
            or _DIGEST.fullmatch(request_digest) is None
            or created_at_microseconds < 0
        ):
            raise ProviderResilienceValidationError(_ERR_INPUT)
        async with _WriteTransaction(self._store) as transaction:
            brain_id = await _validate_authority(transaction.connection, endpoints)
            if brain_id != scope.brain_id.value:
                raise ProviderResilienceConflictError(_ERR_CONFLICT)
            bound_set_id = (
                await transaction.connection.execute(
                    text(
                        "SELECT set_id FROM provider_equivalent_endpoint_sets "
                        "WHERE primary_profile_id=:profile "
                        "AND primary_profile_version=:version AND space_id=:space"
                    ),
                    {
                        "profile": endpoints.primary.profile_id,
                        "space": endpoints.primary.output_contract.space_id,
                        "version": endpoints.primary.profile_version,
                    },
                )
            ).scalar_one_or_none()
            if bound_set_id is not None and _bytes(bound_set_id).hex() != endpoints.set_id:
                raise ProviderResilienceConflictError(_ERR_CONFLICT)
            operation = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT brain_id,set_id,request_digest "
                            "FROM provider_equivalence_operations "
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
                    _string(operation["brain_id"]) != brain_id
                    or _bytes(operation["set_id"]).hex() != endpoints.set_id
                    or _bytes(operation["request_digest"]).hex() != request_digest
                ):
                    raise ProviderResilienceConflictError(_ERR_CONFLICT)
                existing = await _get_set(transaction.connection, endpoints.set_id)
                if existing != endpoints:
                    raise ProviderResilienceConflictError(_ERR_CONFLICT)
                await transaction.commit()
                return endpoints
            existing = await _get_set(transaction.connection, endpoints.set_id)
            if existing is not None:
                if existing != endpoints:
                    raise ProviderResilienceConflictError(_ERR_CONFLICT)
                await transaction.connection.execute(
                    text(
                        "INSERT INTO provider_equivalence_operations "
                        "(operation_id,brain_id,set_id,request_digest,principal_id,"
                        "scope_fingerprint,completed_at,schema_version) VALUES "
                        "(:operation,:brain,:set_id,:request,:principal,:scope,:completed,1)"
                    ),
                    {
                        "brain": brain_id,
                        "completed": created_at_microseconds,
                        "operation": operation_id,
                        "principal": scope.principal_id.value,
                        "request": _digest_bytes(request_digest),
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "set_id": _digest_bytes(endpoints.set_id),
                    },
                )
                await transaction.commit()
                return existing
            contract = endpoints.primary.output_contract
            await _insert_set(
                transaction.connection,
                endpoints,
                contract,
                created_at_microseconds,
            )
            await transaction.connection.execute(
                text(
                    "INSERT INTO provider_equivalence_operations "
                    "(operation_id,brain_id,set_id,request_digest,principal_id,"
                    "scope_fingerprint,completed_at,schema_version) VALUES "
                    "(:operation,:brain,:set_id,:request,:principal,:scope,:completed,1)"
                ),
                {
                    "brain": brain_id,
                    "completed": created_at_microseconds,
                    "operation": operation_id,
                    "principal": scope.principal_id.value,
                    "request": _digest_bytes(request_digest),
                    "scope": bytes.fromhex(scope.scope_fingerprint),
                    "set_id": _digest_bytes(endpoints.set_id),
                },
            )
            await transaction.commit()
        return endpoints

    async def get(
        self,
        scope: AuthorizedScope,
        set_id: str,
    ) -> EquivalentEndpointSet | None:
        """Load and revalidate one complete immutable endpoint set."""
        try:
            async with self._store.engine.connect() as connection:
                scoped = (
                    await connection.execute(
                        text(
                            "SELECT 1 FROM provider_equivalent_endpoint_sets s "
                            "JOIN provider_profiles p ON p.id=s.primary_profile_id "
                            "WHERE s.set_id=:set_id AND p.brain_id=:brain"
                        ),
                        {
                            "brain": scope.brain_id.value,
                            "set_id": _digest_bytes(set_id),
                        },
                    )
                ).scalar_one_or_none()
                return None if scoped is None else await _get_set(connection, set_id)
        except SQLAlchemyError as error:
            raise ProviderResilienceDependencyError(_ERR_STORAGE) from error

    async def resolve(
        self,
        brain_id: str,
        primary_profile_id: str,
        primary_profile_version: int,
        space_id: str,
    ) -> EquivalentEndpointSet | None:
        """Resolve one unambiguous provider/space revision for internal dispatch."""
        if primary_profile_version < 1:
            raise ProviderResilienceValidationError(_ERR_INPUT)
        try:
            async with self._store.engine.connect() as connection:
                set_id = (
                    await connection.execute(
                        text(
                            "SELECT s.set_id FROM provider_equivalent_endpoint_sets s "
                            "JOIN provider_profiles p ON p.id=s.primary_profile_id "
                            "JOIN embedding_spaces e ON e.id=s.space_id "
                            "WHERE p.brain_id=:brain AND e.brain_id=:brain "
                            "AND s.primary_profile_id=:profile "
                            "AND s.primary_profile_version=:version "
                            "AND s.space_id=:space"
                        ),
                        {
                            "brain": brain_id,
                            "profile": primary_profile_id,
                            "space": space_id,
                            "version": primary_profile_version,
                        },
                    )
                ).scalar_one_or_none()
                if set_id is None:
                    return None
                endpoints = await _get_set(connection, _bytes(set_id).hex())
                if (
                    endpoints is None
                    or await _validate_authority(connection, endpoints) != brain_id
                ):
                    raise ProviderResilienceConflictError(_ERR_CONFLICT)
                return endpoints
        except SQLAlchemyError as error:
            raise ProviderResilienceDependencyError(_ERR_STORAGE) from error

    async def acquire(
        self,
        endpoint: ProviderEndpointAttestation,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> ProviderCircuitPermit:
        """Atomically reserve the sole due half-open probe when required."""
        async with _WriteTransaction(self._store) as transaction:
            row = (
                (
                    await transaction.connection.execute(
                        text(
                            "SELECT * FROM provider_endpoint_circuits "
                            "WHERE endpoint_fingerprint=:endpoint"
                        ),
                        {"endpoint": endpoint.endpoint_fingerprint},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                snapshot = ProviderCircuitSnapshot.initial(endpoint.endpoint_fingerprint)
                await _insert_circuit(
                    transaction.connection,
                    endpoint,
                    snapshot,
                    now_microseconds,
                )
            else:
                if _bytes(row["endpoint_attestation_digest"]).hex() != endpoint.digest:
                    raise ProviderResilienceConflictError(_ERR_CONFLICT)
                snapshot = _circuit(row)
            permit = policy.acquire(snapshot, now_microseconds)
            if permit.snapshot != snapshot:
                await _update_circuit(
                    transaction.connection,
                    permit.snapshot,
                    snapshot.version,
                    now_microseconds,
                )
            await transaction.commit()
        return permit

    async def success(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        """Reset the current endpoint circuit after one permitted success."""
        await self._transition(permit, policy, None, now_microseconds)

    async def failure(
        self,
        permit: ProviderCircuitPermit,
        code: ProviderErrorCode,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        """Count one canonical failure against current serialized circuit state."""
        await self._transition(permit, policy, code, now_microseconds)

    async def abandon(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        now_microseconds: int,
    ) -> None:
        """Release only the exact currently reserved half-open probe."""
        if not permit.allowed:
            raise ProviderResilienceConflictError(_ERR_CONFLICT)
        async with _WriteTransaction(self._store) as transaction:
            current = await _current_circuit(
                transaction.connection,
                permit.snapshot.endpoint_fingerprint,
            )
            if (
                current.state is ProviderCircuitState.HALF_OPEN
                and current.version != permit.snapshot.version
            ):
                raise ProviderResilienceConflictError(_ERR_CONFLICT)
            updated = policy.after_abandon(current, now_microseconds)
            if updated != current:
                await _update_circuit(
                    transaction.connection,
                    updated,
                    current.version,
                    now_microseconds,
                )
            await transaction.commit()

    async def record(self, fact: ProviderDispatchFact) -> None:
        """Append one content-free idempotent endpoint attempt fact."""
        async with _WriteTransaction(self._store) as transaction:
            await transaction.connection.execute(
                text(
                    "INSERT INTO provider_dispatch_attempts "
                    "(fact_id,operation_key_sha256,endpoint_fingerprint,"
                    "endpoint_attestation_digest,attempt,fallback_ordinal,outcome_code,"
                    "occurred_at,schema_version) VALUES "
                    "(:fact,:operation,:endpoint,:attestation,:attempt,:ordinal,:outcome,"
                    ":occurred,1) ON CONFLICT(fact_id) DO NOTHING"
                ),
                {
                    "attempt": fact.attempt,
                    "attestation": bytes.fromhex(fact.endpoint.digest),
                    "endpoint": fact.endpoint.endpoint_fingerprint,
                    "fact": bytes.fromhex(fact.fact_id),
                    "occurred": fact.occurred_at_microseconds,
                    "operation": bytes.fromhex(fact.operation_key_sha256),
                    "ordinal": fact.fallback_ordinal,
                    "outcome": fact.outcome_code,
                },
            )
            await transaction.commit()

    async def _transition(
        self,
        permit: ProviderCircuitPermit,
        policy: ProviderCircuitPolicy,
        code: ProviderErrorCode | None,
        now_microseconds: int,
    ) -> None:
        if not permit.allowed:
            raise ProviderResilienceConflictError(_ERR_CONFLICT)
        async with _WriteTransaction(self._store) as transaction:
            current = await _current_circuit(
                transaction.connection,
                permit.snapshot.endpoint_fingerprint,
            )
            if (
                permit.snapshot.state is ProviderCircuitState.HALF_OPEN
                and current.version != permit.snapshot.version
            ):
                raise ProviderResilienceConflictError(_ERR_CONFLICT)
            updated = (
                policy.after_success(current, now_microseconds)
                if code is None
                else policy.after_failure(current, code, now_microseconds)
            )
            await _update_circuit(
                transaction.connection,
                updated,
                current.version,
                now_microseconds,
            )
            await transaction.commit()


async def _get_set(
    connection: AsyncConnection,
    set_id: str,
) -> EquivalentEndpointSet | None:
    row = (
        (
            await connection.execute(
                text("SELECT * FROM provider_equivalent_endpoint_sets WHERE set_id=:set_id"),
                {"set_id": _digest_bytes(set_id)},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    endpoint_rows = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM provider_equivalent_endpoints "
                    "WHERE set_id=:set_id ORDER BY ordinal"
                ),
                {"set_id": _digest_bytes(set_id)},
            )
        )
        .mappings()
        .all()
    )
    try:
        contract = _output_contract(_document(row["output_contract_json"]))
        endpoints = tuple(_endpoint(value, contract) for value in endpoint_rows)
        if (
            not endpoints
            or len(endpoints) != int(str(row["endpoint_count"]))
            or _bytes(row["space_fingerprint"]).hex() != contract.space_fingerprint
            or _bytes(row["output_contract_digest"]).hex() != contract.digest
            or any(
                _bytes(value["output_contract_digest"]).hex() != contract.digest
                for value in endpoint_rows
            )
        ):
            raise ProviderResilienceConflictError(_ERR_CONFLICT)
        result = EquivalentEndpointSet(endpoints[0], endpoints[1:])
    except (KeyError, TypeError, ValueError) as error:
        raise ProviderResilienceConflictError(_ERR_CONFLICT) from error
    if result.set_id != set_id:
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return result


async def _insert_set(
    connection: AsyncConnection,
    endpoints: EquivalentEndpointSet,
    contract: ProviderOutputContract,
    created_at_microseconds: int,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_equivalent_endpoint_sets "
            "(set_id,primary_profile_id,primary_profile_version,space_id,"
            "space_fingerprint,output_contract_digest,output_contract_json,"
            "endpoint_count,created_at,schema_version) VALUES "
            "(:set_id,:profile,:version,:space,:space_fingerprint,:contract_digest,"
            ":contract_json,:count,:created_at,1)"
        ),
        {
            "contract_digest": bytes.fromhex(contract.digest),
            "contract_json": _json(contract.document),
            "count": len(endpoints.endpoints),
            "created_at": created_at_microseconds,
            "profile": endpoints.primary.profile_id,
            "set_id": bytes.fromhex(endpoints.set_id),
            "space": contract.space_id,
            "space_fingerprint": bytes.fromhex(contract.space_fingerprint),
            "version": endpoints.primary.profile_version,
        },
    )
    for ordinal, endpoint in enumerate(endpoints.endpoints):
        await connection.execute(
            text(
                "INSERT INTO provider_equivalent_endpoints "
                "(set_id,ordinal,profile_id,profile_version,"
                "capability_attestation_id,endpoint_fingerprint,"
                "configuration_digest,adapter_digest,endpoint_attestation_digest,"
                "output_contract_digest,schema_version) VALUES "
                "(:set_id,:ordinal,:profile,:version,:capability,:endpoint,"
                ":configuration,:adapter,:attestation_digest,:contract_digest,1)"
            ),
            {
                "adapter": endpoint.adapter_digest,
                "attestation_digest": bytes.fromhex(endpoint.digest),
                "capability": endpoint.capability_attestation_id,
                "configuration": endpoint.configuration_digest,
                "contract_digest": bytes.fromhex(contract.digest),
                "endpoint": endpoint.endpoint_fingerprint,
                "ordinal": ordinal,
                "profile": endpoint.profile_id,
                "set_id": bytes.fromhex(endpoints.set_id),
                "version": endpoint.profile_version,
            },
        )


async def _validate_authority(
    connection: AsyncConnection,
    endpoints: EquivalentEndpointSet,
) -> str:
    contract = endpoints.primary.output_contract
    space = (
        (
            await connection.execute(
                text("SELECT * FROM embedding_spaces WHERE id=:space"),
                {"space": contract.space_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        space is None
        or _string(space["immutable_fingerprint"]) != contract.space_fingerprint
        or _string(space["model_revision"]) != contract.model_revision
        or int(str(space["dimension"])) != contract.dimension
        or _string(space["dtype"]) != (None if contract.dtype is None else contract.dtype.value)
        or _string(space["normalization"])
        != (None if contract.normalization is None else contract.normalization.value)
        or _string(space["similarity"])
        != (None if contract.similarity is None else contract.similarity.value)
        or _string(space["purpose"]) != contract.purpose.value
    ):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    brain_id = _string(space["brain_id"])
    for endpoint in endpoints.endpoints:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT p.brain_id,p.status,p.version,p.active_probe_id,"
                        "c.adapter_digest,c.endpoint_fingerprint,c.configuration_digest,"
                        "c.suite_digest,c.canary_digest,c.validation_digest,"
                        "e.model_revision,e.revision_fingerprint,e.operation,e.dimension,"
                        "e.dtype,e.purposes_json,e.evidence_json "
                        "FROM provider_profiles p "
                        "JOIN provider_capability_attestations c "
                        "ON c.profile_id=p.id AND c.attestation_id=:capability "
                        "JOIN provider_probe_evidence e "
                        "ON e.evidence_id=c.attestation_id "
                        "WHERE p.id=:profile"
                    ),
                    {
                        "capability": endpoint.capability_attestation_id,
                        "profile": endpoint.profile_id,
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise ProviderResilienceConflictError(_ERR_CONFLICT)
        evidence = _document(row["evidence_json"])
        purposes = _array(row["purposes_json"])
        if (
            _string(row["brain_id"]) != brain_id
            or _string(row["status"]) != "active"
            or int(str(row["version"])) != endpoint.profile_version
            or _string(row["active_probe_id"]) != endpoint.capability_attestation_id
            or _string(row["adapter_digest"]) != endpoint.adapter_digest
            or _string(row["endpoint_fingerprint"]) != endpoint.endpoint_fingerprint
            or _string(row["configuration_digest"]) != endpoint.configuration_digest
            or _string(row["suite_digest"]) != contract.suite_digest
            or _string(row["canary_digest"]) != contract.canary_digest
            or _string(row["validation_digest"]) != contract.validation_digest
            or _string(row["model_revision"]) != contract.model_revision
            or _string(row["revision_fingerprint"]) != contract.revision_fingerprint
            or _string(row["operation"]) != contract.operation.value
            or _optional_integer(row["dimension"]) != contract.dimension
            or row["dtype"] != (None if contract.dtype is None else contract.dtype.value)
            or contract.purpose.value not in purposes
            or evidence.get("normalization")
            != (None if contract.normalization is None else contract.normalization.value)
            or evidence.get("similarity")
            != (None if contract.similarity is None else contract.similarity.value)
        ):
            raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return brain_id


def _output_contract(document: dict[str, object]) -> ProviderOutputContract:
    return ProviderOutputContract(
        space_id=_string(document["space_id"]),
        space_fingerprint=_string(document["space_fingerprint"]),
        model_revision=_string(document["model_revision"]),
        revision_fingerprint=_string(document["revision_fingerprint"]),
        operation=ProviderOperation(_string(document["operation"])),
        purpose=CanonicalPurpose(_string(document["purpose"])),
        preprocessing_digest=_string(document["preprocessing_digest"]),
        dimension=_optional_integer(document["dimension"]),
        dtype=_optional_enum(VectorDtype, document["dtype"]),
        normalization=_optional_enum(VectorNormalization, document["normalization"]),
        similarity=_optional_enum(SimilarityMetric, document["similarity"]),
        suite_digest=_string(document["suite_digest"]),
        canary_digest=_string(document["canary_digest"]),
        validation_digest=_string(document["validation_digest"]),
    )


def _endpoint(
    row: RowMapping,
    contract: ProviderOutputContract,
) -> ProviderEndpointAttestation:
    endpoint = ProviderEndpointAttestation(
        profile_id=_string(row["profile_id"]),
        profile_version=int(str(row["profile_version"])),
        capability_attestation_id=_string(row["capability_attestation_id"]),
        endpoint_fingerprint=_string(row["endpoint_fingerprint"]),
        configuration_digest=_string(row["configuration_digest"]),
        adapter_digest=_string(row["adapter_digest"]),
        output_contract=contract,
    )
    if _bytes(row["endpoint_attestation_digest"]).hex() != endpoint.digest:
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return endpoint


async def _insert_circuit(
    connection: AsyncConnection,
    endpoint: ProviderEndpointAttestation,
    snapshot: ProviderCircuitSnapshot,
    now_microseconds: int,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO provider_endpoint_circuits "
            "(endpoint_fingerprint,profile_id,profile_version,"
            "endpoint_attestation_digest,state,consecutive_failures,window_started_at,"
            "open_until,probe_in_flight,version,updated_at,schema_version) VALUES "
            "(:endpoint,:profile,:profile_version,:attestation,:state,:failures,:window,"
            ":open_until,:probe,:version,:updated_at,1)"
        ),
        {
            "attestation": bytes.fromhex(endpoint.digest),
            "endpoint": snapshot.endpoint_fingerprint,
            "failures": snapshot.consecutive_failures,
            "open_until": snapshot.open_until_microseconds,
            "probe": snapshot.probe_in_flight,
            "profile": endpoint.profile_id,
            "profile_version": endpoint.profile_version,
            "state": snapshot.state.value,
            "updated_at": now_microseconds,
            "version": snapshot.version,
            "window": snapshot.window_started_at_microseconds,
        },
    )


async def _current_circuit(
    connection: AsyncConnection,
    endpoint_fingerprint: str,
) -> ProviderCircuitSnapshot:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM provider_endpoint_circuits WHERE endpoint_fingerprint=:endpoint"
                ),
                {"endpoint": endpoint_fingerprint},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return _circuit(row)


def _circuit(row: RowMapping) -> ProviderCircuitSnapshot:
    try:
        return ProviderCircuitSnapshot(
            endpoint_fingerprint=_string(row["endpoint_fingerprint"]),
            state=ProviderCircuitState(_string(row["state"])),
            consecutive_failures=int(str(row["consecutive_failures"])),
            window_started_at_microseconds=_optional_integer(row["window_started_at"]),
            open_until_microseconds=_optional_integer(row["open_until"]),
            probe_in_flight=bool(row["probe_in_flight"]),
            version=int(str(row["version"])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProviderResilienceConflictError(_ERR_CONFLICT) from error


async def _update_circuit(
    connection: AsyncConnection,
    snapshot: ProviderCircuitSnapshot,
    expected_version: int,
    now_microseconds: int,
) -> None:
    updated = await connection.execute(
        text(
            "UPDATE provider_endpoint_circuits SET state=:state,"
            "consecutive_failures=:failures,window_started_at=:window,"
            "open_until=:open_until,probe_in_flight=:probe,version=:version,"
            "updated_at=:updated_at WHERE endpoint_fingerprint=:endpoint "
            "AND version=:expected"
        ),
        {
            "endpoint": snapshot.endpoint_fingerprint,
            "expected": expected_version,
            "failures": snapshot.consecutive_failures,
            "open_until": snapshot.open_until_microseconds,
            "probe": snapshot.probe_in_flight,
            "state": snapshot.state.value,
            "updated_at": now_microseconds,
            "version": snapshot.version,
            "window": snapshot.window_started_at_microseconds,
        },
    )
    if updated.rowcount != 1:
        raise ProviderResilienceConflictError(_ERR_CONFLICT)


def _json(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _document(value: object) -> dict[str, object]:
    if not isinstance(value, bytes):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    loaded = cast("object", json.loads(value))
    if not isinstance(loaded, dict):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    mapping = cast("dict[object, object]", loaded)
    if not all(isinstance(key, str) for key in mapping):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return cast("dict[str, object]", mapping)


def _array(value: object) -> tuple[object, ...]:
    if not isinstance(value, bytes):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    loaded = cast("object", json.loads(value))
    if not isinstance(loaded, list):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return tuple(cast("list[object]", loaded))


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return value


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return value


def _digest_bytes(value: str) -> bytes:
    if _DIGEST.fullmatch(value) is None:
        raise ProviderResilienceValidationError(_ERR_INPUT)
    return bytes.fromhex(value)


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise ProviderResilienceConflictError(_ERR_CONFLICT)
    return value


def _optional_enum[EnumValue: StrEnum](
    enum_type: type[EnumValue],
    value: object,
) -> EnumValue | None:
    if value is None:
        return None
    return enum_type(_string(value))


class _WriteTransaction:
    """Short serialized PRO-007 transaction with typed storage failures."""

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
                raise ProviderResilienceDependencyError(_ERR_STORAGE) from error
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
            raise ProviderResilienceDependencyError(_ERR_STORAGE) from storage_error
        return None

    async def commit(self) -> None:
        try:
            await self.connection.commit()
        except SQLAlchemyError as error:
            raise ProviderResilienceDependencyError(_ERR_STORAGE) from error
        self._committed = True
