"""PRO-005 real SQLite routing publication, replay, audit, and denial tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.providers.adapters.sqlite_profiles import SqliteProviderProfileRepository
from agentmemory.providers.adapters.sqlite_routing import (
    SqliteProviderRoutingRepository,
)
from agentmemory.providers.domain.errors import (
    ProviderRoutingAuthorizationError,
    ProviderRoutingConflictError,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose
from agentmemory.providers.domain.routing import (
    ProviderRouteRule,
    ProviderRouteSelector,
    ProviderRoutingGuard,
    ProviderRoutingPolicy,
    RepositoryRoutingRestriction,
)
from tests.core.support import NOW, FixedClock, bootstrap_request, migrated_store
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    REPOSITORY_ID,
    manifest,
    probe_evidence,
    remote_configuration,
    scope,
)
from tests.providers.test_pro005_routing_domain import (
    POLICY_ID,
    RESTRICTION_ID,
    RULE_ID,
    request,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO repositories "
                "(id,brain_id,vcs_type,root_fingerprint,primary_remote_fingerprint,status,"
                "created_at,updated_at) VALUES "
                "(:id,:brain,'git',:root,NULL,'active',:at,:at)"
            ),
            {
                "at": round(NOW.timestamp() * 1_000_000),
                "brain": bootstrap_request().brain_id.value,
                "id": REPOSITORY_ID,
                "root": hashlib.sha256(b"pro005-repository").digest(),
            },
        )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_sqlite_routing_history_is_replayable_audited_and_tamper_evident(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    profiles = SqliteProviderProfileRepository(store)
    routing = SqliteProviderRoutingRepository(store)
    configuration = remote_configuration()
    provider_manifest = manifest()
    try:
        await _seed(store)
        await profiles.create(
            scope("provider.profile.create"),
            "pro005-profile-create",
            PROFILE_ID,
            configuration,
            provider_manifest.digest,
            NOW,
        )
        active = await profiles.activate(
            scope("provider.profile.probe"),
            "pro005-profile-probe",
            1,
            probe_evidence(
                at=NOW + timedelta(seconds=1),
                configuration=configuration,
                provider_manifest=provider_manifest,
            ),
        )
        publish_scope = scope("provider.route.publish")
        projections = await routing.profiles(
            publish_scope,
            (PROFILE_ID,),
            NOW + timedelta(seconds=2),
        )
        assert projections[0].snapshot_digest == active.snapshot_digest
        guard = ProviderRoutingGuard(
            allow_remote=True,
            allowed_remote_residencies=("US",),
            remote_classification_ceiling=request().classification,
        )
        route_request = replace(
            request(),
            repository_id=REPOSITORY_ID,
            purpose=CanonicalPurpose.RETRIEVAL_QUERY,
        )
        route = ProviderRouteRule(
            rule_id=RULE_ID,
            profile_id=PROFILE_ID,
            profile_version=active.version,
            profile_snapshot_digest=active.snapshot_digest,
            operation=active.configuration.operation,
            selector=ProviderRouteSelector(
                project_id=route_request.project_id,
                corpus=route_request.corpus,
                language=route_request.language,
                classification=route_request.classification,
                purpose=route_request.purpose,
                workload=route_request.workload,
            ),
            enabled=True,
            reason="sqlite.route",
        )
        policy = ProviderRoutingPolicy(
            policy_id=POLICY_ID,
            brain_id=configuration.brain_id,
            version=1,
            guard=guard,
            rules=(route,),
            created_at=NOW + timedelta(seconds=2),
        )
        request_digest = "a" * 64
        published = await routing.publish_policy(
            publish_scope,
            "pro005-policy-publish",
            request_digest,
            0,
            policy,
        )
        assert (
            await routing.publish_policy(
                publish_scope,
                "pro005-policy-publish",
                request_digest,
                0,
                policy,
            )
            == published
        )
        with pytest.raises(ProviderRoutingConflictError):
            await routing.publish_policy(
                publish_scope,
                "pro005-policy-publish",
                "b" * 64,
                0,
                policy,
            )
        with pytest.raises(ProviderRoutingConflictError):
            await routing.publish_policy(
                publish_scope,
                "pro005-policy-wrong-version",
                "f" * 64,
                0,
                replace(
                    policy,
                    policy_id="018f0000-0000-7000-8000-000000000599",
                    version=2,
                ),
            )
        assert (
            await routing.current_policy(
                publish_scope,
                NOW + timedelta(seconds=3),
            )
            == policy
        )

        repository_filter = RepositoryRoutingRestriction(
            restriction_id=RESTRICTION_ID,
            brain_id=configuration.brain_id,
            repository_id=REPOSITORY_ID,
            version=1,
            allow_remote=True,
            allowed_remote_residencies=("US",),
            remote_classification_ceiling=route_request.classification,
            allowed_profile_ids=(PROFILE_ID,),
            allowed_purposes=(route_request.purpose,),
            allowed_workloads=(route_request.workload,),
        )
        restrict_scope = scope("provider.route.restrict")
        restricted = await routing.publish_restriction(
            restrict_scope,
            "pro005-restriction-publish",
            "c" * 64,
            0,
            repository_filter,
            NOW + timedelta(seconds=3),
        )
        assert (
            await routing.publish_restriction(
                restrict_scope,
                "pro005-restriction-publish",
                "c" * 64,
                0,
                repository_filter,
                NOW + timedelta(seconds=3),
            )
            == restricted
        )
        with pytest.raises(ProviderRoutingConflictError):
            await routing.publish_restriction(
                restrict_scope,
                "pro005-restriction-publish",
                "e" * 64,
                0,
                repository_filter,
                NOW + timedelta(seconds=3),
            )
        assert (
            await routing.current_restriction(
                restrict_scope,
                REPOSITORY_ID,
                NOW + timedelta(seconds=4),
            )
            == restricted
        )

        decision = policy.decide(route_request, projections, repository_filter)
        resolve_scope = scope("provider.route.resolve")
        recorded = await routing.record_decision(
            resolve_scope,
            "pro005-resolve-1",
            "provider-route:v1:" + "d" * 64,
            decision,
            NOW + timedelta(seconds=4),
        )
        assert (
            await routing.record_decision(
                resolve_scope,
                "pro005-resolve-1",
                "provider-route:v1:" + "d" * 64,
                decision,
                NOW + timedelta(seconds=4),
            )
            == recorded
        )

        async with store.engine.connect() as connection:
            counts = {
                table: int(
                    (
                        await connection.execute(
                            text(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
                        )
                    ).scalar_one()
                )
                for table in (
                    "provider_routing_policies",
                    "provider_route_rules",
                    "provider_repository_route_restrictions",
                    "provider_routing_operations",
                    "provider_route_decisions",
                )
            }
            outbox_count = int(
                (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM outbox_messages "
                            "WHERE topic LIKE 'am.local.%.provider.routing-%'"
                        )
                    )
                ).scalar_one()
            )
            audit_count = int(
                (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM audit_events WHERE action LIKE 'provider.route.%'"
                        )
                    )
                ).scalar_one()
            )
        assert counts == {
            "provider_routing_policies": 1,
            "provider_route_rules": 1,
            "provider_repository_route_restrictions": 1,
            "provider_routing_operations": 2,
            "provider_route_decisions": 1,
        }
        assert outbox_count == 2
        assert audit_count == 2

        async with store.engine.begin() as connection:
            await connection.execute(
                text("DROP TRIGGER trg_provider_capability_attestations_immutable_delete")
            )
            await connection.execute(
                text("DELETE FROM provider_capability_attestations WHERE profile_id=:profile"),
                {"profile": PROFILE_ID},
            )
        stale = await routing.profiles(
            publish_scope,
            (PROFILE_ID,),
            NOW + timedelta(seconds=4),
        )
        assert stale[0].status.value == "reprobe_required"
        with pytest.raises(ProviderRoutingAuthorizationError):
            await routing.profiles(
                publish_scope,
                ("018f0000-0000-7000-8000-000000000599",),
                NOW + timedelta(seconds=4),
            )

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable provider routing"):
                await connection.execute(text("UPDATE provider_routing_policies SET version=2"))
            with pytest.raises(IntegrityError, match="immutable provider routing"):
                await connection.execute(text("DELETE FROM provider_route_decisions"))

        expires = NOW + timedelta(seconds=5)
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:expires"),
                {"expires": round(expires.timestamp() * 1_000_000)},
            )
        with pytest.raises(ProviderRoutingAuthorizationError):
            await routing.current_policy(
                publish_scope,
                NOW + timedelta(seconds=6),
            )
    finally:
        await store.close()
