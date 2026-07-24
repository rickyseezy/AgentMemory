"""PRO-007 real SQLite equivalence, circuit, attempt, and failure tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.providers.adapters.sqlite_embedding_spaces import (
    SqliteEmbeddingSpaceRepository,
)
from agentmemory.providers.adapters.sqlite_operation_cache import (
    SqliteProviderOperationCache,
)
from agentmemory.providers.adapters.sqlite_resilience import (
    SqliteProviderResilienceRepository,
    _array,  # pyright: ignore[reportPrivateUsage]
    _bytes,  # pyright: ignore[reportPrivateUsage]
    _circuit,  # pyright: ignore[reportPrivateUsage]
    _digest_bytes,  # pyright: ignore[reportPrivateUsage]
    _document,  # pyright: ignore[reportPrivateUsage]
    _optional_enum,  # pyright: ignore[reportPrivateUsage]
    _optional_integer,  # pyright: ignore[reportPrivateUsage]
    _string,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderOperationConflictError,
    ProviderResilienceConflictError,
    ProviderResilienceValidationError,
)
from agentmemory.providers.domain.idempotency import ProviderClaimDisposition
from agentmemory.providers.domain.profiles import VectorDtype
from agentmemory.providers.domain.resilience import (
    EquivalentEndpointSet,
    ProviderCircuitPolicy,
    ProviderCircuitState,
    ProviderDispatchFact,
    ProviderEndpointAttestation,
    ProviderOutputContract,
)
from tests.core.support import NOW, FixedClock, bootstrap_request, digest, migrated_store
from tests.providers.test_ing002_sqlite_provider_idempotency import operation
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    manifest,
    probe_evidence,
    probe_result,
    remote_configuration,
    scope,
)
from tests.providers.test_pro004_sqlite_embedding_spaces import (
    attested_descriptor,
    candidates,
    seed_active_provider,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


async def _seed_endpoint(
    store: SqliteCoreStore,
) -> tuple[ProviderEndpointAttestation, EquivalentEndpointSet]:
    attestation_id = await seed_active_provider(store)
    embedding_space, generation = candidates(
        attestation_id,
        space_descriptor=attested_descriptor(),
    )
    spaces = SqliteEmbeddingSpaceRepository(store)
    await spaces.reserve(
        scope("provider.embedding_space.ensure"),
        "pro007-space-ensure",
        digest("pro007-space-request").value,
        embedding_space,
        generation,
    )
    await spaces.complete(
        scope("provider.embedding_space.ensure"),
        "pro007-space-ensure",
        generation.generation_id,
        NOW + timedelta(seconds=3),
    )
    configuration = remote_configuration()
    provider_manifest = manifest()
    result = probe_result()
    evidence = probe_evidence(
        at=NOW + timedelta(seconds=1),
        configuration=configuration,
        provider_manifest=provider_manifest,
        result=result,
    )
    assert result.dimension is not None
    assert result.dtype is not None
    assert result.normalization is not None
    assert result.similarity is not None
    contract = ProviderOutputContract(
        space_id=embedding_space.space_id,
        space_fingerprint=embedding_space.immutable_fingerprint,
        model_revision=result.model_revision,
        revision_fingerprint=result.revision_fingerprint,
        operation=result.operation,
        purpose=embedding_space.descriptor.purpose,
        preprocessing_digest=digest(embedding_space.descriptor.preprocessing_version).value,
        dimension=result.dimension,
        dtype=result.dtype,
        normalization=result.normalization,
        similarity=result.similarity,
        suite_digest=result.suite_digest,
        canary_digest=result.canary_digest,
        validation_digest=result.validation_digest,
    )
    endpoint = ProviderEndpointAttestation(
        profile_id=PROFILE_ID,
        profile_version=2,
        capability_attestation_id=evidence.evidence_id,
        endpoint_fingerprint=evidence.endpoint_fingerprint,
        configuration_digest=evidence.configuration_digest,
        adapter_digest=evidence.adapter_digest,
        output_contract=contract,
    )
    return endpoint, EquivalentEndpointSet(endpoint, ())


@pytest.mark.asyncio
@pytest.mark.integration
async def test_equivalence_set_round_trips_exactly_and_is_immutable(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    try:
        endpoint, endpoints = await _seed_endpoint(store)
        created_at = round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000)
        authorized = scope("provider.resilience.publish")
        request_digest = digest("pro007-equivalence-request").value
        assert (
            await repository.put(
                authorized,
                "pro007-equivalence-publish",
                request_digest,
                endpoints,
                created_at,
            )
            == endpoints
        )
        assert (
            await repository.put(
                authorized,
                "pro007-equivalence-publish-alias",
                request_digest,
                endpoints,
                created_at + 1,
            )
            == endpoints
        )
        assert (
            await repository.put(
                authorized,
                "pro007-equivalence-publish",
                request_digest,
                endpoints,
                created_at + 1,
            )
            == endpoints
        )
        assert (
            await repository.get(
                scope("provider.resilience.read"),
                endpoints.set_id,
            )
            == endpoints
        )
        assert (
            await repository.resolve(
                authorized.brain_id.value,
                endpoint.profile_id,
                endpoint.profile_version,
                endpoint.output_contract.space_id,
            )
            == endpoints
        )
        assert (
            await repository.get(
                scope("provider.resilience.read"),
                digest("missing-set").value,
            )
            is None
        )
        other_brain_scope = AuthorizedScope.create(
            brain_id=StableId("018f0000-0000-7000-8000-000000000999"),
            principal_id=authorized.principal_id,
            role=authorized.role,
            mode=authorized.mode,
            members=authorized.members,
            classification_ceiling=authorized.classification_ceiling,
            temporal_scope=authorized.temporal_scope,
            grant_version=authorized.grant_version,
            policy_version=authorized.policy_version,
            security_epoch=authorized.security_epoch,
            action="provider.resilience.read",
            purpose=authorized.purpose,
        )
        assert await repository.get(other_brain_scope, endpoints.set_id) is None
        assert (
            await repository.resolve(
                other_brain_scope.brain_id.value,
                endpoint.profile_id,
                endpoint.profile_version,
                endpoint.output_contract.space_id,
            )
            is None
        )

        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.put(
                authorized,
                "pro007-equivalence-publish",
                digest("divergent-request").value,
                endpoints,
                created_at + 2,
            )

        async with store.engine.connect() as connection:
            set_row = (
                await connection.execute(
                    text(
                        "SELECT endpoint_count,output_contract_digest "
                        "FROM provider_equivalent_endpoint_sets"
                    )
                )
            ).one()
            endpoint_row = (
                await connection.execute(
                    text(
                        "SELECT profile_id,endpoint_fingerprint,"
                        "endpoint_attestation_digest "
                        "FROM provider_equivalent_endpoints"
                    )
                )
            ).one()
            with pytest.raises(IntegrityError):
                await connection.execute(
                    text("UPDATE provider_equivalent_endpoints SET ordinal=1 WHERE set_id=:set_id"),
                    {"set_id": bytes.fromhex(endpoints.set_id)},
                )
        assert tuple(set_row) == (
            1,
            bytes.fromhex(endpoint.output_contract.digest),
        )
        assert tuple(endpoint_row) == (
            endpoint.profile_id,
            endpoint.endpoint_fingerprint,
            bytes.fromhex(endpoint.digest),
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_equivalence_repository_rejects_each_invalid_request_coordinate(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    try:
        _, endpoints = await _seed_endpoint(store)
        authorized = scope("provider.resilience.publish")
        created_at = round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000)
        invalid_requests = (
            ("invalid operation id!", digest("request").value, created_at),
            ("valid-operation", "not-a-digest", created_at),
            ("valid-operation", digest("request").value, -1),
        )
        for operation_id, request_digest, occurred_at in invalid_requests:
            with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
                await repository.put(
                    authorized,
                    operation_id,
                    request_digest,
                    endpoints,
                    occurred_at,
                )
        with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
            await repository.resolve(
                authorized.brain_id.value,
                endpoints.primary.profile_id,
                0,
                endpoints.primary.output_contract.space_id,
            )

        other_brain_scope = AuthorizedScope.create(
            brain_id=StableId("018f0000-0000-7000-8000-000000000999"),
            principal_id=authorized.principal_id,
            role=authorized.role,
            mode=authorized.mode,
            members=authorized.members,
            classification_ceiling=authorized.classification_ceiling,
            temporal_scope=authorized.temporal_scope,
            grant_version=authorized.grant_version,
            policy_version=authorized.policy_version,
            security_epoch=authorized.security_epoch,
            action=authorized.action,
            purpose=authorized.purpose,
        )
        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.put(
                other_brain_scope,
                "wrong-brain",
                digest("wrong-brain").value,
                endpoints,
                created_at,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_circuit_state_is_durable_half_open_single_probe_and_recoverable(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    policy = ProviderCircuitPolicy(
        failure_threshold=2,
        failure_window_microseconds=1_000,
        open_microseconds=100,
    )
    try:
        endpoint, _ = await _seed_endpoint(store)
        first = await repository.acquire(endpoint, policy, 10)
        assert first.allowed
        await repository.failure(first, ProviderErrorCode.TIMEOUT, policy, 11)
        second = await repository.acquire(endpoint, policy, 12)
        await repository.failure(
            second,
            ProviderErrorCode.TRANSIENT_UPSTREAM,
            policy,
            13,
        )
        denied = await repository.acquire(endpoint, policy, 112)
        assert not denied.allowed
        probe = await repository.acquire(endpoint, policy, 113)
        assert probe.allowed
        assert probe.snapshot.state is ProviderCircuitState.HALF_OPEN
        assert not (await repository.acquire(endpoint, policy, 113)).allowed
        await repository.success(probe, policy, 114)
        assert (await repository.acquire(endpoint, policy, 115)).allowed

        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT state,consecutive_failures,open_until,"
                        "probe_in_flight,version FROM provider_endpoint_circuits"
                    )
                )
            ).one()
        assert tuple(row[:4]) == ("closed", 0, None, False)
        assert int(row[4]) >= 4
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_circuit_rejects_denied_and_stale_permits_and_abandon_reopens_probe(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    policy = ProviderCircuitPolicy(
        failure_threshold=1,
        failure_window_microseconds=1_000,
        open_microseconds=100,
    )
    try:
        endpoint, _ = await _seed_endpoint(store)
        first = await repository.acquire(endpoint, policy, 10)
        await repository.failure(first, ProviderErrorCode.TIMEOUT, policy, 11)
        denied = await repository.acquire(endpoint, policy, 12)
        assert not denied.allowed
        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.abandon(denied, policy, 13)
        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.success(denied, policy, 13)

        probe = await repository.acquire(endpoint, policy, 111)
        await repository.abandon(probe, policy, 112)
        reopened = await repository.acquire(endpoint, policy, 112)
        assert not reopened.allowed

        next_probe = await repository.acquire(endpoint, policy, 212)
        await repository.success(next_probe, policy, 213)
        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.failure(
                next_probe,
                ProviderErrorCode.TIMEOUT,
                policy,
                214,
            )
    finally:
        await store.close()


def test_sqlite_resilience_deserializers_fail_closed_on_invalid_storage_values() -> None:
    conflict_values = (
        (_document, "not-bytes"),
        (_document, b"[]"),
        (_array, "not-bytes"),
        (_array, b"{}"),
        (_string, b"not-a-string"),
        (_bytes, "not-bytes"),
        (_optional_integer, "not-an-integer"),
    )
    for decoder, value in conflict_values:
        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            decoder(value)

    with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
        _digest_bytes("not-a-digest")
    assert _document(b'{"valid":true}') == {"valid": True}
    assert _array(b'["valid"]') == ("valid",)
    assert _optional_integer(None) is None
    assert _optional_enum(VectorDtype, None) is None
    assert _optional_enum(VectorDtype, "float32") is VectorDtype.FLOAT32
    with pytest.raises(ValueError, match="invalid-dtype"):
        _optional_enum(VectorDtype, "invalid-dtype")
    with pytest.raises(ProviderResilienceConflictError, match="diverged"):
        _circuit(cast("Any", {"state": "not-a-state"}))


@pytest.mark.asyncio
@pytest.mark.integration
async def test_dispatch_resolution_revalidates_current_profile_attestation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    try:
        endpoint, endpoints = await _seed_endpoint(store)
        authorized = scope("provider.resilience.publish")
        await repository.put(
            authorized,
            "pro007-stale-resolution",
            digest("pro007-stale-resolution-request").value,
            endpoints,
            round((NOW + timedelta(seconds=4)).timestamp() * 1_000_000),
        )
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE provider_profiles SET status='draft',active_probe_id=NULL "
                    "WHERE id=:profile"
                ),
                {"profile": endpoint.profile_id},
            )

        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.resolve(
                authorized.brain_id.value,
                endpoint.profile_id,
                endpoint.profile_version,
                endpoint.output_contract.space_id,
            )
        assert (
            await repository.get(
                scope("provider.resilience.read"),
                endpoints.set_id,
            )
            == endpoints
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_endpoint_fingerprint_cannot_be_rebound_to_different_attestation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    try:
        endpoint, _ = await _seed_endpoint(store)
        await repository.acquire(endpoint, ProviderCircuitPolicy.production(), 10)
        divergent = replace(
            endpoint,
            adapter_digest=digest("different-adapter").value,
        )
        with pytest.raises(ProviderResilienceConflictError, match="diverged"):
            await repository.acquire(
                divergent,
                ProviderCircuitPolicy.production(),
                11,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_dispatch_evidence_is_content_free_immutable_and_idempotent(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderResilienceRepository(store)
    try:
        endpoint, _ = await _seed_endpoint(store)
        fact = ProviderDispatchFact(
            operation_key_sha256=digest("operation-key").value,
            endpoint=endpoint,
            attempt=1,
            fallback_ordinal=0,
            outcome_code="started",
            occurred_at_microseconds=100,
        )
        await repository.record(fact)
        await repository.record(fact)
        async with store.engine.connect() as connection:
            rows = (
                await connection.execute(
                    text(
                        "SELECT fact_id,operation_key_sha256,endpoint_fingerprint,"
                        "outcome_code FROM provider_dispatch_attempts"
                    )
                )
            ).all()
            with pytest.raises(IntegrityError):
                await connection.execute(
                    text("UPDATE provider_dispatch_attempts SET outcome_code='succeeded'")
                )
        assert [tuple(row) for row in rows] == [
            (
                bytes.fromhex(fact.fact_id),
                bytes.fromhex(fact.operation_key_sha256),
                endpoint.endpoint_fingerprint,
                "started",
            )
        ]
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_permanent_provider_failure_replays_without_reclaim_or_duplicate_charge(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock(NOW))).execute(
            bootstrap_request()
        )
        cache = SqliteProviderOperationCache(store)
        now = round(NOW.timestamp() * 1_000_000)
        claimed = await cache.claim(operation(), "worker-1", now, now + 1_000_000)
        assert claimed.disposition is ProviderClaimDisposition.CLAIMED
        await cache.fail(
            claimed,
            ProviderErrorCode.AUTHENTICATION.value,
            now + 1,
        )
        replay = await cache.claim(operation(), "worker-2", now + 2, now + 1_000_002)
        assert replay.disposition is ProviderClaimDisposition.FAILED
        assert replay.failure_code == ProviderErrorCode.AUTHENTICATION.value

        conflicting = replace(
            operation(),
            operation_id="018f0000-0000-7000-8000-000000000603",
        )
        with pytest.raises(ProviderOperationConflictError):
            await cache.claim(conflicting, "worker-3", now + 3, now + 1_000_003)

        async with store.engine.connect() as connection:
            failure = (
                await connection.execute(
                    text("SELECT error_code,attempts FROM provider_operation_failures")
                )
            ).one()
            live_count = (
                await connection.execute(text("SELECT COUNT(*) FROM provider_operation_results"))
            ).scalar_one()
        assert tuple(failure) == (ProviderErrorCode.AUTHENTICATION.value, 1)
        assert int(live_count) == 0
    finally:
        await store.close()
