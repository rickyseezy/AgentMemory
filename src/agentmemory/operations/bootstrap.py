"""Production composition root for the PF-001 local Core."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
from neo4j import AsyncDriver, AsyncGraphDatabase

from agentmemory.operations.adapters.inbound.authentication import ApiAuthenticator
from agentmemory.operations.adapters.inbound.http_api import ApiDependencies, create_app
from agentmemory.operations.adapters.outbound.egress_attestation import (
    AuthenticatedEgressAttestationCheck,
)
from agentmemory.operations.adapters.outbound.key_access import InstallationKeyAccessCheck
from agentmemory.operations.adapters.outbound.local_provider import (
    LocalEmbeddingHttpAdapter,
    LocalExtractionHttpAdapter,
    LocalRerankingHttpAdapter,
)
from agentmemory.operations.adapters.outbound.neo4j_graph import Neo4jGraphAdapter
from agentmemory.operations.adapters.outbound.neo4j_projection_rebuild import (
    Neo4jProjectionGenerationAdapter,
    ProjectionGenerationRouter,
)
from agentmemory.operations.adapters.outbound.probes import FunctionalReadinessProbe
from agentmemory.operations.adapters.outbound.protected_file import read_protected_file, zero_secret
from agentmemory.operations.adapters.outbound.provider_checks import (
    LocalProviderIdentityCheck,
    LocalProviderSetCheck,
    SemanticWriteIndexRecallCheck,
)
from agentmemory.operations.adapters.outbound.readiness_status import SqliteReadinessStatusQuery
from agentmemory.operations.adapters.outbound.sqlite_checks import (
    SqliteActiveBrainResolver,
    SqliteReadinessChecks,
    SqliteSemanticSmokeStore,
)
from agentmemory.operations.adapters.outbound.sqlite_projection_rebuild import (
    SqliteProjectionRebuildAdapter,
)
from agentmemory.operations.adapters.outbound.sqlite_store import (
    SqliteCoreStore,
    SqliteRuntimePolicy,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.active_release import (
    ActiveReleaseTransactionHandler,
)
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.application.commands.projection_rebuild import (
    ProjectionRebuilder,
    StartProjectionRebuildHandler,
)
from agentmemory.operations.application.commands.verify_readiness import VerifyReadinessHandler
from agentmemory.operations.application.projection_worker import ProjectionRebuildWorker
from agentmemory.operations.application.runtime_readiness import RuntimeReadinessCoordinator
from agentmemory.operations.domain.readiness import ReadinessProbe
from agentmemory.operations.infrastructure.configuration import CoreSettings
from agentmemory.shared.clock import SystemClock

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastapi import FastAPI


@dataclass(slots=True)
class CoreContainer:
    """Own concrete runtime resources selected only in this composition root."""

    store: SqliteCoreStore
    neo4j_driver: AsyncDriver
    provider_client: httpx.AsyncClient

    async def close(self) -> None:
        """Close all pools during bounded graceful shutdown."""
        await self.provider_client.aclose()
        await self.neo4j_driver.close()
        await self.store.close()


def create_core_app(settings: CoreSettings | None = None) -> FastAPI:
    """Compose Core; the container network and Host policy enforce the trust boundary."""
    resolved = settings or CoreSettings.from_environment()
    clock = SystemClock()
    store = SqliteCoreStore.create(resolved.database_path, SqliteRuntimePolicy.production())
    neo4j_secret = read_protected_file(resolved.neo4j_password_file, frozenset({32}))
    try:
        # The official Neo4j 6.2 stub leaves the driver's **config untyped.
        neo4j_driver = AsyncGraphDatabase.driver(  # pyright: ignore[reportUnknownMemberType]
            resolved.neo4j_uri,
            auth=(resolved.neo4j_username, neo4j_secret.hex()),
            max_connection_pool_size=20,
            connection_timeout=5,
        )
    finally:
        zero_secret(neo4j_secret)
    provider_client = httpx.AsyncClient(
        timeout=httpx.Timeout(10, connect=3),
        limits=httpx.Limits(max_connections=12, max_keepalive_connections=6),
        follow_redirects=False,
        trust_env=False,
    )
    embeddings = LocalEmbeddingHttpAdapter(
        provider_client,
        resolved.embedding_url,
        resolved.embedding_model_id,
        resolved.embedding_model_revision,
        resolved.embedding_capability_file,
    )
    reranker = LocalRerankingHttpAdapter(
        provider_client,
        resolved.reranking_url,
        resolved.reranking_model_id,
        resolved.reranking_model_revision,
        resolved.reranking_capability_file,
    )
    extractor = LocalExtractionHttpAdapter(
        provider_client,
        resolved.extraction_url,
        resolved.extraction_model_id,
        resolved.extraction_model_revision,
        resolved.extraction_capability_file,
    )
    sqlite_checks = SqliteReadinessChecks(
        store,
        clock,
        resolved.state_directory,
        resolved.artifact_directory,
    )
    brains = SqliteActiveBrainResolver(store)
    graph = Neo4jGraphAdapter(neo4j_driver, resolved.neo4j_database, brains)
    key_check = InstallationKeyAccessCheck(resolved.installation_root_key_file, "v1")
    providers_check = LocalProviderSetCheck(embeddings, reranker, extractor)
    provider_identity_check = LocalProviderIdentityCheck(embeddings, reranker, extractor)
    semantic_check = SemanticWriteIndexRecallCheck(
        SqliteSemanticSmokeStore(store, clock),
        embeddings,
        graph,
    )
    egress_check = AuthenticatedEgressAttestationCheck(
        resolved.egress_attestation_file,
        resolved.attestation_hmac_key_file,
        clock,
    )
    probes = (
        FunctionalReadinessProbe(
            ReadinessProbe.SQLITE_INTEGRITY, sqlite_checks.sqlite_integrity, clock
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.MIGRATION_HEAD, sqlite_checks.migration_head, clock
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.WRITABLE_VOLUMES, sqlite_checks.writable_volumes, clock
        ),
        FunctionalReadinessProbe(ReadinessProbe.GRAPH_COMPATIBILITY, graph.verify, clock),
        FunctionalReadinessProbe(ReadinessProbe.KEY_ACCESS, key_check.verify, clock),
        FunctionalReadinessProbe(ReadinessProbe.AUDIT_APPEND, sqlite_checks.audit_append, clock),
        FunctionalReadinessProbe(
            ReadinessProbe.DELETION_GUARD, sqlite_checks.deletion_guard, clock
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.EXPIRED_LEASE_RECOVERY,
            sqlite_checks.expired_lease_recovery,
            clock,
        ),
        FunctionalReadinessProbe(ReadinessProbe.LOCAL_PROVIDERS, providers_check.verify, clock),
        FunctionalReadinessProbe(
            ReadinessProbe.SEMANTIC_WRITE_INDEX_RECALL,
            semantic_check.verify,
            clock,
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.DEFAULT_EGRESS_DENIED,
            egress_check.verify_default_denied,
            clock,
        ),
    )
    unit_of_work = SqliteUnitOfWorkFactory(store, clock)
    readiness = VerifyReadinessHandler(probes, unit_of_work, clock)
    projection_adapter = SqliteProjectionRebuildAdapter(store, clock)
    projection_generations = ProjectionGenerationRouter(
        projection_adapter,
        Neo4jProjectionGenerationAdapter(neo4j_driver, resolved.neo4j_database),
    )
    projection_worker = ProjectionRebuildWorker(
        projection_adapter,
        ProjectionRebuilder(
            projection_adapter,
            projection_adapter,
            projection_generations,
            projection_adapter,
        ),
    )
    runtime_probes = (
        FunctionalReadinessProbe(
            ReadinessProbe.SQLITE_INTEGRITY,
            sqlite_checks.sqlite_integrity,
            clock,
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.MIGRATION_HEAD,
            sqlite_checks.migration_head,
            clock,
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.WRITABLE_VOLUMES,
            sqlite_checks.writable_volumes,
            clock,
        ),
        FunctionalReadinessProbe(ReadinessProbe.GRAPH_COMPATIBILITY, graph.verify, clock),
        FunctionalReadinessProbe(ReadinessProbe.KEY_ACCESS, key_check.verify, clock),
        FunctionalReadinessProbe(
            ReadinessProbe.LOCAL_PROVIDERS,
            provider_identity_check.verify,
            clock,
        ),
        FunctionalReadinessProbe(
            ReadinessProbe.DEFAULT_EGRESS_DENIED,
            egress_check.verify_default_denied,
            clock,
        ),
    )
    dependencies = ApiDependencies(
        authenticator=ApiAuthenticator(resolved.api_credential_file),
        bootstrap=BootstrapLocalBrainHandler(unit_of_work),
        readiness=readiness,
        active_release=ActiveReleaseTransactionHandler(unit_of_work),
        runtime_readiness=RuntimeReadinessCoordinator(readiness, runtime_probes, clock),
        status_query=SqliteReadinessStatusQuery(store),
        projection_rebuild=StartProjectionRebuildHandler(
            projection_adapter,
            projection_adapter,
            projection_adapter,
        ),
        projection_rebuild_query=projection_adapter,
        allowed_hosts=frozenset(resolved.allowed_hosts),
    )
    container = CoreContainer(store, neo4j_driver, provider_client)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        del application
        stop = asyncio.Event()
        task: asyncio.Task[None] | None = None
        try:
            await store.observe_and_enforce_policy()
            task = asyncio.create_task(projection_worker.run(stop))
            yield
        finally:
            stop.set()
            if task is not None:
                await task
            await container.close()

    return create_app(dependencies, lifespan)
