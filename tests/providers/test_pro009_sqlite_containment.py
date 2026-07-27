"""PRO-009 real SQLite policy, authorization, permit, and telemetry tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.providers.adapters.sqlite_containment import (
    SqliteProviderContainmentRepository,
    SqliteProviderEgressOperationContextResolver,
)
from agentmemory.providers.adapters.sqlite_profiles import SqliteProviderProfileRepository
from agentmemory.providers.domain.containment import (
    ProviderEgressDecisionFact,
    ProviderEgressPolicy,
    ProviderEgressRequest,
    ProviderEgressRoute,
    ProviderRuntimeFact,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentAuthorizationError,
    ProviderContainmentConflictError,
    ProviderContainmentDeniedError,
)
from agentmemory.providers.domain.profile_ports import ProviderGatewayRequest
from agentmemory.providers.domain.resilience import ProviderEndpointAttestation
from tests.core.support import BRAIN_ID, NOW, digest, migrated_store
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    manifest,
    probe_evidence,
    probe_result,
    remote_configuration,
    scope,
)
from tests.providers.test_pro004_sqlite_embedding_spaces import seed_active_provider
from tests.providers.test_pro007_resilience_domain import output_contract
from tests.providers.test_pro009_containment_application import operation
from tests.providers.test_pro009_containment_domain import destination, policy, request

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.providers.domain.profiles import ProviderProfileConfiguration

DRAFT_PROFILE_ID = "018f0000-0000-7000-8000-000000000919"


def _micros(seconds: int = 0) -> int:
    return round((NOW + timedelta(seconds=seconds)).timestamp() * 1_000_000)


def active_policy(
    *,
    version: int = 1,
    policy_id: str | None = None,
) -> ProviderEgressPolicy:
    profile_attestation_id = probe_evidence(
        at=NOW + timedelta(seconds=1),
    ).evidence_id
    return policy(
        policy_id=policy_id or "018f0000-0000-7000-8000-000000000902",
        brain_id=BRAIN_ID,
        version=version,
        security_epoch=1,
        allowed_profile_ids=(PROFILE_ID,),
        allowed_routes=(
            ProviderEgressRoute(
                profile_id=PROFILE_ID,
                profile_version=2,
                profile_attestation_id=profile_attestation_id,
                model_revision="text-embedding-3-large-2026-01-15",
                operation_type="embedding",
                purpose="retrieval_document",
                destination=destination(),
            ),
        ),
        maximum_retention_days=30,
        maximum_requests_per_minute=60,
        maximum_tokens_per_minute=250_000,
        maximum_monthly_cost_micros=50_000_000,
        valid_from_microseconds=_micros(2 + version),
        valid_until_microseconds=_micros(600),
    )


def authorized_request(**changes: object) -> ProviderEgressRequest:
    value = request(
        operation_id="018f0000-0000-7000-8000-000000000904",
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        profile_attestation_id=probe_evidence(
            at=NOW + timedelta(seconds=1),
        ).evidence_id,
        model_revision="text-embedding-3-large-2026-01-15",
        retention_days=30,
        policy_version=1,
        security_epoch=1,
        quota_requests_per_minute=60,
        quota_tokens_per_minute=250_000,
        budget_monthly_micros=50_000_000,
    )
    return replace(value, **cast("Any", changes))


def draft_configuration() -> ProviderProfileConfiguration:
    return remote_configuration(model_id="text-embedding-probe-draft")


def provisional_policy() -> ProviderEgressPolicy:
    configuration = draft_configuration()
    return policy(
        brain_id=BRAIN_ID,
        security_epoch=1,
        allowed_profile_ids=(DRAFT_PROFILE_ID,),
        allowed_routes=(
            ProviderEgressRoute(
                profile_id=DRAFT_PROFILE_ID,
                profile_version=1,
                profile_attestation_id=configuration.digest,
                model_revision=configuration.model_id,
                operation_type=configuration.operation.value,
                purpose=configuration.purposes[0].value,
                destination=destination(),
            ),
        ),
        maximum_retention_days=30,
        maximum_requests_per_minute=60,
        maximum_tokens_per_minute=250_000,
        maximum_monthly_cost_micros=50_000_000,
        valid_from_microseconds=_micros(2),
        valid_until_microseconds=_micros(600),
    )


def probe_request(**changes: object) -> ProviderGatewayRequest:
    configuration = draft_configuration()
    value = ProviderGatewayRequest(
        operation_id=(f"profile-probe:{DRAFT_PROFILE_ID}:1:{configuration.purposes[0].value}"),
        brain_id=BRAIN_ID,
        profile_id=DRAFT_PROFILE_ID,
        profile_version=1,
        configuration_digest=configuration.digest,
        adapter_id=configuration.adapter_id,
        model_id=configuration.model_id,
        operation_type=configuration.operation.value,
        purpose=configuration.purposes[0].value,
        endpoint_policy_ref=configuration.endpoint_policy_ref or "",
        secret_ref=configuration.secret_ref or "",
        method="POST",
        path=destination().path_prefix,
        body=b'{"input":["fixed public canary"],"model":"text-embedding-3-large"}',
        timeout_milliseconds=configuration.limits.timeout_milliseconds,
        max_response_bytes=4096,
    )
    return replace(value, **cast("Any", changes))


def drift_request(**changes: object) -> ProviderGatewayRequest:
    configuration = remote_configuration()
    purpose = configuration.purposes[0].value
    value = ProviderGatewayRequest(
        operation_id=f"drift-probe:{PROFILE_ID}:2:{purpose}",
        brain_id=BRAIN_ID,
        profile_id=PROFILE_ID,
        profile_version=2,
        configuration_digest=configuration.digest,
        adapter_id=configuration.adapter_id,
        model_id=configuration.model_id,
        operation_type=configuration.operation.value,
        purpose=purpose,
        endpoint_policy_ref=configuration.endpoint_policy_ref or "",
        secret_ref=configuration.secret_ref or "",
        method="POST",
        path=destination().path_prefix,
        body=b'{"input":["fixed public canary"],"model":"text-embedding-3-large"}',
        timeout_milliseconds=configuration.limits.timeout_milliseconds,
        max_response_bytes=4096,
    )
    return replace(value, **cast("Any", changes))


async def seed_draft_provider(store: SqliteCoreStore) -> None:
    await seed_active_provider(store)
    configuration = draft_configuration()
    await SqliteProviderProfileRepository(store).create(
        scope("provider.profile.create"),
        "pro009-draft-profile-create",
        DRAFT_PROFILE_ID,
        configuration,
        manifest().digest,
        NOW,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_draft_profile_probe_receives_only_a_provisional_policy_bound_permit(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    try:
        await seed_draft_provider(store)
        published = await repository.publish(
            scope("provider.containment.manage"),
            "pro009-provisional-policy",
            digest("pro009-provisional-policy").value,
            provisional_policy(),
            _micros(3),
        )

        value = await repository.authorize_probe(probe_request(), _micros(4))

        assert published == provisional_policy()
        assert value.profile_id == DRAFT_PROFILE_ID
        assert value.profile_version == 1
        configuration = draft_configuration()
        assert value.profile_attestation_id == configuration.digest
        assert value.model_revision == configuration.model_id
        assert value.destination == destination()
        assert value.wire_request_digest == digest_bytes(probe_request().body)
        async with store.engine.connect() as connection:
            document = (
                await connection.execute(
                    text(
                        "SELECT document_json FROM provider_egress_permits "
                        "WHERE permit_digest=:digest"
                    ),
                    {"digest": bytes.fromhex(value.digest)},
                )
            ).scalar_one()
        assert b"secret://" not in bytes(document)
        assert b"policy://" not in bytes(document)
        assert probe_request().body not in bytes(document)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_drift_probe_uses_capability_attested_policy_route(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    try:
        attestation_id = await seed_active_provider(store)
        await repository.publish(
            scope("provider.containment.manage"),
            "pro010-active-drift-policy",
            digest("pro010-active-drift-policy").value,
            active_policy(),
            _micros(3),
        )

        permit = await repository.authorize_probe(drift_request(), _micros(4))

        assert permit.profile_attestation_id == attestation_id
        assert permit.model_revision == probe_result().model_revision
        assert permit.operation_id.startswith("drift-probe:")
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_probe_authority_denies_every_draft_profile_or_route_substitution(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    try:
        await seed_draft_provider(store)
        await repository.publish(
            scope("provider.containment.manage"),
            "pro009-provisional-policy-denial",
            digest("pro009-provisional-policy-denial").value,
            provisional_policy(),
            _micros(3),
        )
        for changes in (
            {"profile_version": 2},
            {"configuration_digest": digest("substituted-configuration").value},
            {"adapter_id": "cohere"},
            {"model_id": "mutable-model"},
            {"operation_type": "reranking"},
            {"purpose": "retrieval_query"},
            {"endpoint_policy_ref": "policy://providers/substituted"},
            {"secret_ref": "secret://providers/substituted"},
            {"path": "/v1/rerank"},
        ):
            with pytest.raises(ProviderContainmentDeniedError, match="denied"):
                await repository.authorize_probe(
                    probe_request(**changes),
                    _micros(4),
                )
        async with store.engine.connect() as connection:
            count = (
                await connection.execute(text("SELECT COUNT(*) FROM provider_egress_permits"))
            ).scalar_one()
        assert count == 0
    finally:
        await store.close()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_policy_publication_replay_lookup_and_permit_are_canonical(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    try:
        await seed_active_provider(store)
        value = active_policy()
        published = await repository.publish(
            scope("provider.containment.manage"),
            "pro009-policy-publish",
            digest("policy-request").value,
            value,
            _micros(3),
        )
        assert published == value
        assert (
            await repository.publish(
                scope("provider.containment.manage"),
                "pro009-policy-publish",
                digest("policy-request").value,
                replace(value, policy_id="018f0000-0000-7000-8000-000000000999"),
                _micros(4),
            )
            == value
        )
        assert (
            await repository.get(
                scope("provider.containment.read"),
                _micros(4),
            )
            == value
        )

        permit = await repository.authorize(authorized_request(), _micros(5))
        assert permit.policy_id == value.policy_id
        assert permit.profile_id == PROFILE_ID
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT permit_digest,request_digest,destination_fingerprint,"
                        "document_json FROM provider_egress_permits"
                    )
                )
            ).one()
        assert bytes(row[0]).hex() == permit.digest
        assert bytes(row[1]).hex() == permit.request_digest
        assert bytes(row[2]).hex() == permit.destination.fingerprint
        assert b"payload" not in bytes(row[3])
        assert b"secret://" not in bytes(row[3])
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_content_free_gateway_decision_is_idempotently_persisted(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    fact = ProviderEgressDecisionFact(
        permit_digest=digest("permit").value,
        operation_id="pro009-egress-decision",
        destination_fingerprint=digest("destination").value,
        outcome_code="succeeded",
        request_bytes=128,
        response_bytes=256,
        status_code=200,
        occurred_at_microseconds=_micros(5),
    )
    try:
        await repository.record_egress(fact)
        await repository.record_egress(fact)
        async with store.engine.connect() as connection:
            rows = (
                await connection.execute(
                    text(
                        "SELECT operation_id,outcome_code,request_bytes,response_bytes,"
                        "status_code FROM provider_egress_decisions"
                    )
                )
            ).all()
        assert [tuple(row) for row in rows] == [
            ("pro009-egress-decision", "succeeded", 128, 256, 200)
        ]
        assert "secret-canary" not in str(fact.document)
        assert "credential" not in str(fact.document)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_operation_context_resolves_only_exact_active_route_and_attestation(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        attestation_id = await seed_active_provider(store)
        await SqliteProviderContainmentRepository(store).publish(
            scope("provider.containment.manage"),
            "pro009-policy-context",
            digest("policy-context").value,
            active_policy(),
            _micros(3),
        )
        configuration = remote_configuration()
        provider_manifest = manifest()
        result = probe_result()
        operation_value = replace(
            operation(),
            brain_id=BRAIN_ID,
            profile_id=PROFILE_ID,
            model_revision=result.model_revision,
            token_count=200,
            estimated_cost_micros=250,
        )
        endpoint_value = ProviderEndpointAttestation(
            profile_id=PROFILE_ID,
            profile_version=2,
            capability_attestation_id=attestation_id,
            endpoint_fingerprint=result.endpoint_fingerprint,
            configuration_digest=configuration.digest,
            adapter_digest=provider_manifest.implementation_digest,
            output_contract=output_contract(
                model_revision=result.model_revision,
                purpose=result.purposes[0],
                preprocessing_digest=operation_value.preprocessing_digest,
            ),
        )

        context_value = await SqliteProviderEgressOperationContextResolver(store).resolve(
            endpoint_value,
            operation_value,
        )

        assert context_value.destination == destination()
        assert context_value.policy_version == 1
        assert context_value.security_epoch == 1
        assert context_value.quota_requests_per_minute == 60
        assert context_value.quota_tokens_per_minute == 250_000
        assert context_value.budget_monthly_micros == 50_000_000
        assert context_value.token_count == 200
        assert context_value.estimated_cost_micros == 250

        with pytest.raises(ProviderContainmentDeniedError, match="denied"):
            await SqliteProviderEgressOperationContextResolver(store).resolve(
                replace(endpoint_value, endpoint_fingerprint=digest("stale").value),
                operation_value,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_policy_publication_is_versioned_and_immutable(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    try:
        await seed_active_provider(store)
        first = active_policy()
        await repository.publish(
            scope("provider.containment.manage"),
            "pro009-policy-one",
            digest("policy-one").value,
            first,
            _micros(3),
        )
        second = active_policy(
            version=2,
            policy_id="018f0000-0000-7000-8000-000000000905",
        )
        await repository.publish(
            scope("provider.containment.manage"),
            "pro009-policy-two",
            digest("policy-two").value,
            second,
            _micros(4),
        )
        assert await repository.get(scope("provider.containment.read"), _micros(5)) == second
        with pytest.raises(ProviderContainmentConflictError):
            await repository.publish(
                scope("provider.containment.manage"),
                "pro009-policy-stale",
                digest("policy-stale").value,
                replace(second, version=1),
                _micros(5),
            )
        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable provider containment"):
                await connection.execute(
                    text("UPDATE provider_egress_policies SET version=99 WHERE id=:policy"),
                    {"policy": first.policy_id},
                )
            with pytest.raises(IntegrityError, match="provider egress pointer"):
                await connection.execute(
                    text("DELETE FROM active_provider_egress_policies"),
                )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_final_authorization_rechecks_profile_policy_model_and_grant(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    try:
        await seed_active_provider(store)
        await repository.publish(
            scope("provider.containment.manage"),
            "pro009-policy-auth",
            digest("policy-auth").value,
            active_policy(),
            _micros(3),
        )
        for changed in (
            {"profile_version": 1},
            {"model_revision": "mutable-alias"},
            {"retention_days": 29},
            {"quota_requests_per_minute": 59},
            {"budget_monthly_micros": 49_000_000},
        ):
            with pytest.raises(ProviderContainmentDeniedError, match="denied"):
                await repository.authorize(authorized_request(**changed), _micros(5))
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:at"),
                {"at": _micros(5)},
            )
        with pytest.raises(ProviderContainmentAuthorizationError):
            await repository.get(scope("provider.containment.read"), _micros(6))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_runtime_telemetry_is_idempotent_and_content_free(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteProviderContainmentRepository(store)
    fact = ProviderRuntimeFact(
        operation_id="018f0000-0000-7000-8000-000000000904",
        adapter_image_digest=digest("image").value,
        outcome_code="succeeded",
        runtime_milliseconds=12,
        cleanup_digest=digest("cleanup").value,
        occurred_at_microseconds=_micros(5),
    )
    try:
        await repository.record(fact)
        await repository.record(fact)
        async with store.engine.connect() as connection:
            rows = (
                await connection.execute(
                    text(
                        "SELECT operation_id,adapter_image_digest,outcome_code,"
                        "runtime_milliseconds,cleanup_digest,occurred_at "
                        "FROM provider_runtime_facts"
                    )
                )
            ).all()
        assert len(rows) == 1
        assert tuple(rows[0]) == (
            fact.operation_id,
            bytes.fromhex(fact.adapter_image_digest),
            "succeeded",
            12,
            bytes.fromhex(fact.cleanup_digest),
            fact.occurred_at_microseconds,
        )
        assert "secret" not in repr(rows[0]).lower()
    finally:
        await store.close()
