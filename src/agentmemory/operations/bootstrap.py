"""Production composition root for the PF-001 local Core."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
from neo4j import AsyncDriver, AsyncGraphDatabase

from agentmemory import __version__
from agentmemory.graph.adapters.inbound.contradiction_http_api import (
    create_contract_contradiction_router,
    create_contradiction_router,
)
from agentmemory.graph.adapters.inbound.graph_integrity_http_api import (
    create_contract_graph_integrity_router,
    create_graph_integrity_router,
)
from agentmemory.graph.adapters.inbound.http_api import (
    create_contract_graph_router,
    create_graph_router,
)
from agentmemory.graph.adapters.inbound.temporal_truth_http_api import (
    create_contract_temporal_truth_router,
    create_temporal_truth_router,
)
from agentmemory.graph.adapters.outbound.neo4j_graph_integrity import (
    REGISTERED_GRAPH_MIGRATION_CHECKSUM,
    Neo4jGraphIntegrityAdapter,
)
from agentmemory.graph.adapters.outbound.neo4j_materialized_edges import (
    Neo4jMaterializedEdgeProjectionFactory,
)
from agentmemory.graph.adapters.outbound.neo4j_repository import Neo4jGraphRepositoryFactory
from agentmemory.graph.adapters.outbound.pf002_graph_rebuild import Pf002CanonicalGraphRebuild
from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.adapters.outbound.sqlite_contradictions import SqliteContradictionRepository
from agentmemory.graph.adapters.outbound.sqlite_graph_integrity import (
    SqliteGraphIntegrityJournal,
    SqliteGraphMigrationRepository,
)
from agentmemory.graph.adapters.outbound.sqlite_materialized_edges import (
    SqliteCanonicalAssertionProjectionSource,
    SqliteMaterializedEdgeAuthorization,
    SqliteMaterializedEdgeGenerationResolver,
    SqliteMaterializedEdgeIntegrityJournal,
    SqliteMaterializedEdgeIntegrityScopeSource,
    SqliteMaterializedEdgeWorkRepository,
)
from agentmemory.graph.adapters.outbound.sqlite_temporal_truth import (
    SqliteTemporalAssertionRepository,
    SqliteVcsRevisionRepository,
)
from agentmemory.graph.application.graph_integrity import (
    RepairGraphFindingHandler,
    RunGraphMigrationHandler,
    StartGraphMigrationHandler,
    ValidateGraphIntegrityHandler,
)
from agentmemory.graph.application.materialized_edge_worker import (
    MaterializedEdgeIntegrityWorker,
    MaterializedEdgeProjectionWorker,
)
from agentmemory.graph.application.materialized_edges import (
    MaterializeAssertionEdgeHandler,
    ValidateAssertionEdgesHandler,
)
from agentmemory.identity.adapters.inbound.http_api import (
    create_contract_identity_router,
    create_identity_router,
)
from agentmemory.identity.adapters.outbound.sqlite_checkout_observation import (
    SqliteCheckoutObservationUnitOfWorkFactory,
)
from agentmemory.identity.adapters.outbound.sqlite_identity import (
    SqliteCheckoutRepository,
    SqliteIdentityAuthorizationPolicy,
    SqliteProjectRepository,
    SqliteRepositoryIdentityRepository,
)
from agentmemory.identity.adapters.outbound.sqlite_repository_topology import (
    SqliteRepositoryLinkUnitOfWorkFactory,
    SqliteRepositoryTopologyReadRepository,
)
from agentmemory.identity.adapters.outbound.sqlite_retrieval_scope import (
    SqliteRelatedProjectGraph,
    SqliteRetrievalScopeAuthorizationRepository,
)
from agentmemory.identity.adapters.outbound.uuid7_identity import SystemUuid7IdentityGenerator
from agentmemory.identity.application.commands.confirm_repository_link import (
    ConfirmRepositoryLinkHandler,
)
from agentmemory.identity.application.commands.observe_checkout import ObserveCheckoutHandler
from agentmemory.identity.application.queries.discover_repository_topology import (
    DiscoverRepositoryTopologyHandler,
)
from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeHandler,
)
from agentmemory.identity.application.queries.resolve_workspace import (
    IdentityResolutionDependencies,
    ResolveWorkspaceHandler,
)
from agentmemory.indexing.adapters.inbound.api_topology_http_api import (
    create_api_topology_router,
    create_contract_api_topology_router,
)
from agentmemory.indexing.adapters.inbound.artifact_topology_http_api import (
    create_artifact_topology_router,
    create_contract_artifact_topology_router,
)
from agentmemory.indexing.adapters.inbound.content_policy_http_api import (
    create_content_policy_router,
    create_contract_content_policy_router,
)
from agentmemory.indexing.adapters.inbound.http_api import create_contract_indexing_router
from agentmemory.indexing.adapters.inbound.revision_history_http_api import (
    create_contract_revision_history_router,
    create_revision_history_router,
)
from agentmemory.indexing.adapters.inbound.source_navigation_http_api import (
    create_contract_source_navigation_router,
)
from agentmemory.indexing.adapters.outbound.api_topology_graph import (
    SourceRevisionTopologyLineageAdapter,
    SqliteConsumesAssertionAdapter,
)
from agentmemory.indexing.adapters.outbound.api_topology_plugins import (
    production_api_topology_plugins,
)
from agentmemory.indexing.adapters.outbound.artifact_topology_graph import (
    CanonicalArtifactTopologyProjection,
    SourceRevisionArtifactTopologyLineage,
)
from agentmemory.indexing.adapters.outbound.artifact_topology_plugins import (
    production_artifact_topology_parsers,
)
from agentmemory.indexing.adapters.outbound.sqlite_api_topology import (
    SqliteApiTopologyRepository,
)
from agentmemory.indexing.adapters.outbound.sqlite_artifact_topology import (
    SqliteArtifactTopologyRepository,
)
from agentmemory.indexing.adapters.outbound.sqlite_content_policy import (
    SqliteIndexContentPolicyAdapter,
    SqliteIndexPolicyProjection,
)
from agentmemory.indexing.adapters.outbound.sqlite_revision_history import (
    SqliteCommitGraphAdapter,
    SqliteSourceRevisionRepository,
)
from agentmemory.indexing.application.api_topology import (
    ExtractAndRegisterApiTopologyHandler,
    LinkApiTopologyHandler,
    RegisterApiTopologyBatchHandler,
)
from agentmemory.indexing.application.artifact_topology import (
    ExtractAndRegisterArtifactTopologyHandler,
    QueryArtifactTopologyHandler,
    RegisterArtifactTopologyBatchHandler,
)
from agentmemory.indexing.application.content_policy import (
    ActivateIndexPolicyHandler,
    GetIndexPolicyChangeHandler,
    PolicyReconciliationWorker,
)
from agentmemory.indexing.application.revision_history import (
    ProcessSourceRevisionHandler,
    QuerySourceRevisionHistoryHandler,
    RegisterEvidenceLineageHandler,
    SourceRevisionWorker,
)
from agentmemory.ingestion.adapters.inbound.backpressure_http_api import (
    create_backpressure_router,
    create_contract_backpressure_router,
)
from agentmemory.ingestion.adapters.inbound.capability_http_api import (
    create_adapter_capability_router,
    create_contract_adapter_capability_router,
)
from agentmemory.ingestion.adapters.inbound.http_api import (
    create_agent_event_router,
    create_contract_agent_event_router,
)
from agentmemory.ingestion.adapters.inbound.ordered_replay_http_api import (
    create_contract_ordered_replay_router,
    create_ordered_replay_router,
)
from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.payload_reader import InlineOnlyPayloadReader
from agentmemory.ingestion.adapters.outbound.sqlite_backpressure import (
    LocalDiskSpaceProbe,
    SqliteCaptureCapacityEnforcer,
    SqliteJobSchedulerAccessPolicy,
    SqliteJobSchedulerRepository,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capabilities import (
    SqliteAdapterCapabilityQueryRepository,
    SqliteAdapterCapabilityUnitOfWorkFactory,
    SystemIngestionIdentityGenerator,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAdapterCapabilityRegistry,
    SqliteAgentEventScopeResolver,
    SqliteAgentEventUnitOfWorkFactory,
)
from agentmemory.ingestion.adapters.outbound.sqlite_durable_processing import (
    SqliteCanonicalEventProjectionVerifier,
    SqliteDurableEventProcessingRepository,
)
from agentmemory.ingestion.adapters.outbound.sqlite_ordered_replay import (
    SqliteOrderedReplayAccessPolicy,
    SqliteOrderedReplayRepository,
)
from agentmemory.ingestion.adapters.outbound.sqlite_privacy import (
    SqliteCapturePolicyDecisionRepository,
    SqliteCapturePolicyRepository,
)
from agentmemory.ingestion.adapters.outbound.sqlite_schema_evolution import (
    SqliteCanonicalEventSourceReader,
)
from agentmemory.ingestion.application.adapter_capabilities import (
    GetAdapterCapabilitiesHandler,
    ListAdapterCapabilitiesHandler,
    ObserveAdapterCapabilitiesHandler,
    RegisterAgentAdapterHandler,
)
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
from agentmemory.ingestion.application.backpressure import (
    GetScheduledJobHandler,
    JobSchedulerWorker,
    ListDeadLettersHandler,
    ReplayDeadLetterHandler,
    ScheduledJobExecutorRegistry,
)
from agentmemory.ingestion.application.capture_agent_event import CaptureAgentEventHandler
from agentmemory.ingestion.application.durable_processing import (
    DurableEventProcessingHandler,
    DurableIngestionWorker,
)
from agentmemory.ingestion.application.ordered_replay import (
    GetOrderedReplayHandler,
    OrderedReplayExecutor,
    OrderedReplayWorker,
    StartOrderedReplayHandler,
)
from agentmemory.ingestion.application.privacy import CapturePolicyPipeline
from agentmemory.ingestion.domain.backpressure import QueueLimits, RetryPolicy
from agentmemory.memory.adapters.inbound.correction_http_api import (
    create_contract_memory_correction_router,
    create_memory_correction_router,
)
from agentmemory.memory.adapters.inbound.http_api import (
    create_contract_memory_router,
    create_memory_router,
)
from agentmemory.memory.adapters.inbound.lifecycle_http_api import (
    create_contract_memory_lifecycle_router,
    create_memory_lifecycle_router,
)
from agentmemory.memory.adapters.outbound.local_extractor import (
    LocalMemoryCandidateHttpAdapter,
)
from agentmemory.memory.adapters.outbound.memory_deletion import MemoryDeletionExecutor
from agentmemory.memory.adapters.outbound.sqlite_consolidation import (
    SqliteMemoryConsolidationAccessPolicy,
    SqliteMemoryConsolidationReceiptQuery,
    SqliteMemoryConsolidationUnitOfWorkFactory,
    SqliteTaskEvidenceQuery,
)
from agentmemory.memory.adapters.outbound.sqlite_correction import (
    SqliteMemoryCorrectionRepository,
    SqliteMemoryCorrectionUnitOfWorkFactory,
)
from agentmemory.memory.adapters.outbound.sqlite_deduplication import (
    SqliteMemoryDeduplicationRepository,
    SqliteMemoryDeduplicationUnitOfWorkFactory,
    SqliteSemanticMemoryCandidateFinder,
)
from agentmemory.memory.adapters.outbound.sqlite_lifecycle import (
    SqliteMemoryLifecycleRepository,
    SqliteMemoryLifecycleUnitOfWorkFactory,
)
from agentmemory.memory.adapters.outbound.sqlite_lineage_backfill import (
    SqliteTaskLineageBackfillRepository,
)
from agentmemory.memory.adapters.outbound.sqlite_provenance import SqliteMemoryRepository
from agentmemory.memory.adapters.outbound.sqlite_work import (
    SqliteMemoryConsolidationWorkRepository,
)
from agentmemory.memory.application.consolidate_task import ConsolidateTaskHandler
from agentmemory.memory.application.consolidation_worker import MemoryConsolidationWorker
from agentmemory.memory.application.correct_memory import CorrectMemoryHandler
from agentmemory.memory.application.deduplicate_memories import DeduplicateMemoriesHandler
from agentmemory.memory.application.explain_memory import ExplainMemoryHandler
from agentmemory.memory.application.lineage_backfill import TaskLineageBackfillWorker
from agentmemory.memory.application.memory_lifecycle import (
    ArchiveMemoryHandler,
    ForgetMemoryHandler,
    MemoryExpiryScheduler,
    PinMemoryHandler,
    SetMemoryExpiryHandler,
)
from agentmemory.memory.application.query_memory_corrections import (
    GetMemoryCorrectionHistoryHandler,
)
from agentmemory.memory.domain.consolidation import ExtractorIdentity, MemoryPromotionPolicy
from agentmemory.memory.domain.correction import MemoryPrecedencePolicy
from agentmemory.memory.domain.deduplication import MemoryCompatibilityPolicy
from agentmemory.memory.domain.work import MemoryWorkRetryPolicy
from agentmemory.operations.adapters.inbound.authentication import ApiAuthenticator
from agentmemory.operations.adapters.inbound.http_api import (
    ApiDependencies,
    create_app,
    export_openapi_schema,
)
from agentmemory.operations.adapters.outbound.egress_attestation import (
    AuthenticatedEgressAttestationCheck,
)
from agentmemory.operations.adapters.outbound.key_access import InstallationKeyAccessCheck
from agentmemory.operations.adapters.outbound.local_provider import (
    LocalEmbeddingHttpAdapter,
    LocalExtractionHttpAdapter,
    LocalRerankingHttpAdapter,
)
from agentmemory.operations.adapters.outbound.neo4j_graph import (
    NEO4J_SCHEMA_HEAD,
    Neo4jGraphAdapter,
)
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
from agentmemory.operations.adapters.outbound.qwen_profile_probe import QwenProfileProbeAdapter
from agentmemory.operations.adapters.outbound.readiness_status import SqliteReadinessStatusQuery
from agentmemory.operations.adapters.outbound.sqlite_checks import (
    EXPECTED_MIGRATION_HEAD,
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
from agentmemory.operations.domain.projection_rebuild import RebuildManifest
from agentmemory.operations.domain.readiness import ReadinessProbe
from agentmemory.operations.domain.value_objects import Sha256Digest
from agentmemory.operations.infrastructure.configuration import CoreSettings
from agentmemory.providers.adapters.builtins.cohere import CohereProviderAdapter
from agentmemory.providers.adapters.builtins.google import GoogleProviderAdapter
from agentmemory.providers.adapters.builtins.openai import OpenAIProviderAdapter
from agentmemory.providers.adapters.builtins.openai_compatible import (
    OpenAICompatibleProviderAdapter,
)
from agentmemory.providers.adapters.builtins.qwen_local import QwenLocalProviderAdapter
from agentmemory.providers.adapters.builtins.registry import CertifiedProviderAdapterRegistry
from agentmemory.providers.adapters.builtins.voyage import VoyageProviderAdapter
from agentmemory.providers.adapters.gateway_http import ProviderGatewayHttpTransport
from agentmemory.providers.adapters.profile_http_api import (
    create_contract_provider_profile_router,
    create_provider_profile_router,
)
from agentmemory.providers.adapters.profile_identity import (
    SystemProviderProfileIdentityGenerator,
)
from agentmemory.providers.adapters.sqlite_profiles import SqliteProviderProfileRepository
from agentmemory.providers.application.profiles import (
    CreateProviderProfileHandler,
    GetProviderProfileHandler,
    ProbeProviderHandler,
)
from agentmemory.retrieval.adapters.inbound.host_delivery import (
    CertifiedDeliveryAdapterRegistry,
)
from agentmemory.retrieval.adapters.inbound.http_api import (
    create_contract_retrieval_router,
    create_retrieval_router,
)
from agentmemory.retrieval.adapters.outbound.sqlite_briefing import (
    SqliteCodeRevisionQuery,
    SqliteContextInjectionRepository,
    SqliteMemoryBriefingRepository,
)
from agentmemory.retrieval.adapters.outbound.sqlite_continuity import (
    EmptyProcedureReadRepository,
    SqliteContinuityReadRepository,
)
from agentmemory.retrieval.application.start_session_briefing import (
    DeterministicBriefingRetrievalPipeline,
    StartSessionBriefingHandler,
)
from agentmemory.shared.clock import SystemClock

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fastapi import APIRouter, FastAPI


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


def create_core_app(  # noqa: PLR0915 -- Explicit outer composition root.
    settings: CoreSettings | None = None,
) -> FastAPI:
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
    memory_extractor_identity = ExtractorIdentity(
        resolved.memory_extractor_id,
        resolved.memory_extractor_version,
        resolved.extraction_model_id,
        resolved.extraction_model_revision,
        resolved.memory_candidate_schema,
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
    materialized_edge_projections = Neo4jMaterializedEdgeProjectionFactory(
        neo4j_driver,
        resolved.neo4j_database,
    )
    materialized_edge_source = SqliteCanonicalAssertionProjectionSource(store)
    materialized_edge_worker = MaterializedEdgeProjectionWorker(
        "core-edge-projection-v1",
        SqliteMaterializedEdgeWorkRepository(store),
        SqliteMaterializedEdgeAuthorization(store),
        SqliteMaterializedEdgeGenerationResolver(store),
        MaterializeAssertionEdgeHandler(
            materialized_edge_source,
            materialized_edge_projections,
        ),
        clock,
    )
    materialized_edge_integrity_worker = MaterializedEdgeIntegrityWorker(
        SqliteMaterializedEdgeIntegrityScopeSource(store),
        ValidateAssertionEdgesHandler(
            materialized_edge_source,
            materialized_edge_projections,
            SqliteMaterializedEdgeIntegrityJournal(store),
        ),
        clock,
    )
    durable_ingestion_worker = _create_durable_ingestion_worker(
        store,
        clock,
        resolved.installation_root_key_file,
    )
    ordered_replay_worker = _create_ordered_replay_worker(store, clock)
    source_revision_repository = SqliteSourceRevisionRepository(store, clock)
    content_policy_repository = SqliteIndexContentPolicyAdapter(store, clock)
    content_policy_worker = PolicyReconciliationWorker(
        content_policy_repository,
        SqliteIndexPolicyProjection(store),
        clock,
    )
    source_revision_worker = SourceRevisionWorker(
        ProcessSourceRevisionHandler(
            SqliteCommitGraphAdapter(store),
            source_revision_repository,
        ),
        source_revision_repository,
        clock,
    )
    memory_keys = SqliteWrappedBrainKeyProvider(
        store,
        resolved.installation_root_key_file,
        clock,
    )
    canonical_event_reader = SqliteCanonicalEventSourceReader(store, memory_keys)
    memory_evidence = SqliteTaskEvidenceQuery(
        store,
        canonical_event_reader,
    )
    memory_backfill_repository = SqliteTaskLineageBackfillRepository(
        store,
        canonical_event_reader,
        clock,
    )
    memory_backfill_worker = TaskLineageBackfillWorker(memory_backfill_repository)
    memory_deduplication = DeduplicateMemoriesHandler(
        SqliteMemoryDeduplicationRepository(store),
        SqliteSemanticMemoryCandidateFinder(store, embeddings),
        SqliteMemoryDeduplicationUnitOfWorkFactory(store),
        MemoryCompatibilityPolicy(),
        clock,
    )
    memory_worker = MemoryConsolidationWorker(
        SqliteMemoryConsolidationWorkRepository(store),
        ConsolidateTaskHandler(
            memory_evidence,
            LocalMemoryCandidateHttpAdapter(
                provider_client,
                resolved.extraction_url,
                resolved.extraction_capability_file,
            ),
            SqliteMemoryConsolidationAccessPolicy(store),
            SqliteMemoryConsolidationReceiptQuery(store),
            SqliteMemoryConsolidationUnitOfWorkFactory(store),
            MemoryPromotionPolicy.production(),
            clock,
        ),
        memory_extractor_identity,
        MemoryWorkRetryPolicy(),
        clock,
        memory_deduplication,
    )
    lifecycle_repository = SqliteMemoryLifecycleRepository(store)
    lifecycle_unit_of_work = SqliteMemoryLifecycleUnitOfWorkFactory(store)
    memory_expiry_scheduler = MemoryExpiryScheduler(
        lifecycle_repository,
        lifecycle_unit_of_work,
        clock,
    )
    memory_deletion = MemoryDeletionExecutor(
        store,
        neo4j_driver,
        resolved.neo4j_database,
        clock,
    )
    queue_limits = resolved.queue_limits
    storage_capacity = LocalDiskSpaceProbe(resolved.state_directory)
    scheduler_repository = SqliteJobSchedulerRepository(store, storage_capacity)
    scheduler_worker = JobSchedulerWorker(
        scheduler_repository,
        ScheduledJobExecutorRegistry({"governance.memory_deletion": memory_deletion}),
        RetryPolicy.default(),
        queue_limits,
        clock,
        "core-scheduler-v1",
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
    authenticator = ApiAuthenticator(resolved.api_credential_file)
    dependencies = ApiDependencies(
        authenticator=authenticator,
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
        tasks: tuple[asyncio.Task[None], ...] = ()
        try:
            await store.observe_and_enforce_policy()
            # Establish the immutable historical watermark before automatic
            # consolidation may claim any task snapshot.
            await memory_backfill_repository.start_or_resume()
            tasks = (
                asyncio.create_task(projection_worker.run(stop)),
                asyncio.create_task(materialized_edge_worker.run(stop)),
                asyncio.create_task(materialized_edge_integrity_worker.run(stop)),
                asyncio.create_task(durable_ingestion_worker.run(stop)),
                asyncio.create_task(ordered_replay_worker.run(stop)),
                asyncio.create_task(source_revision_worker.run(stop)),
                asyncio.create_task(content_policy_worker.run(stop)),
                asyncio.create_task(scheduler_worker.run(stop)),
                asyncio.create_task(memory_backfill_worker.run(stop)),
                asyncio.create_task(memory_worker.run(stop)),
                asyncio.create_task(memory_expiry_scheduler.run(stop)),
            )
            yield
        finally:
            stop.set()
            if tasks:
                await asyncio.gather(*tasks)
            await container.close()

    application = create_app(dependencies, lifespan)
    _include_identity_graph_and_retrieval_runtime_routers(
        application,
        store,
        clock,
        authenticator,
        resolved.installation_root_key_file,
        neo4j_driver,
        resolved.neo4j_database,
        resolved,
        projection_adapter,
        content_policy_repository,
        provider_client,
        embeddings,
        reranker,
    )
    application.include_router(
        create_memory_router(
            authenticator,
            ExplainMemoryHandler(SqliteMemoryRepository(store), clock),
            clock,
        )
    )
    correction_repository = SqliteMemoryCorrectionRepository(store)
    correction_policy = MemoryPrecedencePolicy()
    application.include_router(
        create_memory_correction_router(
            authenticator,
            CorrectMemoryHandler(
                correction_repository,
                SqliteMemoryCorrectionUnitOfWorkFactory(store),
                correction_policy,
                clock,
            ),
            GetMemoryCorrectionHistoryHandler(
                correction_repository,
                correction_policy,
                clock,
            ),
            clock,
        )
    )
    application.include_router(
        create_memory_lifecycle_router(
            authenticator,
            PinMemoryHandler(lifecycle_repository, lifecycle_unit_of_work, clock),
            ArchiveMemoryHandler(lifecycle_repository, lifecycle_unit_of_work, clock),
            SetMemoryExpiryHandler(lifecycle_repository, lifecycle_unit_of_work, clock),
            ForgetMemoryHandler(lifecycle_repository, lifecycle_unit_of_work, clock),
        )
    )
    _include_ingestion_runtime_routers(
        application,
        store,
        clock,
        authenticator,
        resolved.installation_root_key_file,
        queue_limits,
        storage_capacity,
    )
    return application


def _create_durable_ingestion_worker(
    store: SqliteCoreStore,
    clock: SystemClock,
    installation_root_key_file: Path,
) -> DurableIngestionWorker:
    """Compose the canonical verifier and durable SQLite queue behind ingestion ports."""
    repository = SqliteDurableEventProcessingRepository(store)
    verifier = SqliteCanonicalEventProjectionVerifier(
        store.engine,
        SqliteWrappedBrainKeyProvider(store, installation_root_key_file, clock),
    )
    return DurableIngestionWorker(
        repository,
        DurableEventProcessingHandler(repository, verifier, clock, "core-ingestion-v1"),
        clock,
    )


def _create_ordered_replay_worker(
    store: SqliteCoreStore,
    clock: SystemClock,
) -> OrderedReplayWorker:
    """Compose the shadow replay worker behind narrow ingestion ports."""
    repository = SqliteOrderedReplayRepository(store)
    access = SqliteOrderedReplayAccessPolicy(store)
    return OrderedReplayWorker(
        repository,
        OrderedReplayExecutor(access, repository, clock, "core-ordered-replay-v1"),
        clock,
    )


def export_core_openapi_schema() -> dict[str, object]:
    """Build the deterministic complete Core contract across bounded contexts."""
    return export_openapi_schema(
        (
            create_contract_identity_router(),
            create_contract_agent_event_router(),
            create_contract_adapter_capability_router(),
            create_contract_retrieval_router(),
            create_contract_indexing_router(),
            create_contract_revision_history_router(),
            create_contract_api_topology_router(),
            create_contract_artifact_topology_router(),
            create_contract_content_policy_router(),
            create_contract_source_navigation_router(),
            create_contract_graph_router(),
            create_contract_temporal_truth_router(),
            create_contract_contradiction_router(),
            create_contract_graph_integrity_router(),
            create_contract_memory_router(),
            create_contract_memory_correction_router(),
            create_contract_memory_lifecycle_router(),
            create_contract_ordered_replay_router(),
            create_contract_backpressure_router(),
            create_contract_provider_profile_router(),
        )
    )


def _create_adapter_capability_runtime_router(
    store: SqliteCoreStore,
    clock: SystemClock,
    authenticator: ApiAuthenticator,
) -> APIRouter:
    """Compose ADP-003 commands and queries outside the application factory body."""
    identities = SystemIngestionIdentityGenerator()
    unit_of_work = SqliteAdapterCapabilityUnitOfWorkFactory(
        store,
        clock,
        identities,
    )
    queries = SqliteAdapterCapabilityQueryRepository(store.engine)
    return create_adapter_capability_router(
        authenticator,
        RegisterAgentAdapterHandler(unit_of_work, identities, clock),
        ObserveAdapterCapabilitiesHandler(unit_of_work, identities, clock),
        ListAdapterCapabilitiesHandler(queries),
        GetAdapterCapabilitiesHandler(queries),
    )


def _include_identity_graph_and_retrieval_runtime_routers(  # noqa: PLR0913 -- Explicit composition.
    application: FastAPI,
    store: SqliteCoreStore,
    clock: SystemClock,
    authenticator: ApiAuthenticator,
    installation_root_key_file: Path,
    neo4j_driver: AsyncDriver,
    neo4j_database: str,
    settings: CoreSettings,
    projection_adapter: SqliteProjectionRebuildAdapter,
    content_policy_repository: SqliteIndexContentPolicyAdapter,
    provider_client: httpx.AsyncClient,
    embeddings: LocalEmbeddingHttpAdapter,
    reranker: LocalRerankingHttpAdapter,
) -> None:
    """Compose identity authorization once for identity and continuity query boundaries."""
    identity_authorization = SqliteIdentityAuthorizationPolicy(store.engine)
    retrieval_scope = ResolveRetrievalScopeHandler(
        SqliteRetrievalScopeAuthorizationRepository(store.engine),
        SqliteRelatedProjectGraph(store.engine),
    )
    application.include_router(
        create_content_policy_router(
            authenticator,
            retrieval_scope,
            ActivateIndexPolicyHandler(content_policy_repository),
            GetIndexPolicyChangeHandler(content_policy_repository),
            clock,
        )
    )
    gateway = ProviderGatewayHttpTransport(
        provider_client,
        settings.provider_gateway_url,
        settings.provider_gateway_capability_file,
    )
    provider_adapters = CertifiedProviderAdapterRegistry(
        (
            OpenAIProviderAdapter(gateway),
            CohereProviderAdapter(gateway),
            VoyageProviderAdapter(gateway),
            GoogleProviderAdapter(gateway),
            QwenLocalProviderAdapter(QwenProfileProbeAdapter(embeddings, reranker)),
            OpenAICompatibleProviderAdapter(gateway),
        )
    )
    provider_profiles = SqliteProviderProfileRepository(store)
    application.include_router(
        create_provider_profile_router(
            authenticator,
            retrieval_scope,
            CreateProviderProfileHandler(
                provider_profiles,
                provider_adapters,
                SystemProviderProfileIdentityGenerator(),
            ),
            ProbeProviderHandler(provider_profiles, provider_adapters),
            GetProviderProfileHandler(provider_profiles),
            clock,
        )
    )
    identity_router = create_identity_router(
        authenticator,
        ResolveWorkspaceHandler(
            IdentityResolutionDependencies(
                identity_authorization,
                SqliteProjectRepository(store.engine),
                SqliteCheckoutRepository(store.engine),
                SqliteRepositoryIdentityRepository(store.engine),
            )
        ),
        ObserveCheckoutHandler(
            SqliteCheckoutObservationUnitOfWorkFactory(store, clock),
            SystemUuid7IdentityGenerator(),
        ),
        DiscoverRepositoryTopologyHandler(
            identity_authorization,
            SqliteRepositoryTopologyReadRepository(store.engine),
        ),
        ConfirmRepositoryLinkHandler(
            SqliteRepositoryLinkUnitOfWorkFactory(store, clock),
            SystemUuid7IdentityGenerator(),
            clock,
        ),
        retrieval_scope,
    )
    application.include_router(identity_router)
    application.include_router(
        create_graph_router(
            authenticator,
            retrieval_scope,
            Neo4jGraphRepositoryFactory(neo4j_driver, neo4j_database),
            clock,
        )
    )
    vcs_revisions = SqliteVcsRevisionRepository(store, clock)
    application.include_router(
        create_temporal_truth_router(
            authenticator,
            retrieval_scope,
            SqliteTemporalAssertionRepository(store),
            vcs_revisions,
            vcs_revisions,
            clock,
        )
    )
    application.include_router(
        create_contradiction_router(
            authenticator,
            retrieval_scope,
            SqliteContradictionRepository(store, clock),
            clock,
        )
    )
    source_revision_repository = SqliteSourceRevisionRepository(store, clock)
    application.include_router(
        create_revision_history_router(
            authenticator,
            retrieval_scope,
            QuerySourceRevisionHistoryHandler(
                SqliteCommitGraphAdapter(store),
                source_revision_repository,
                clock,
            ),
            RegisterEvidenceLineageHandler(source_revision_repository),
            clock,
        )
    )
    topology_repository = SqliteApiTopologyRepository(store, clock)
    application.include_router(
        create_api_topology_router(
            authenticator,
            retrieval_scope,
            ExtractAndRegisterApiTopologyHandler(
                production_api_topology_plugins(),
                RegisterApiTopologyBatchHandler(topology_repository),
            ),
            LinkApiTopologyHandler(
                topology_repository,
                SqliteConsumesAssertionAdapter(store, SqliteAssertionRepositoryFactory(store)),
                SourceRevisionTopologyLineageAdapter(source_revision_repository),
            ),
            clock,
        )
    )
    artifact_topology_repository = SqliteArtifactTopologyRepository(store, clock)
    assertion_repositories = SqliteAssertionRepositoryFactory(store)
    application.include_router(
        create_artifact_topology_router(
            authenticator,
            retrieval_scope,
            ExtractAndRegisterArtifactTopologyHandler(
                production_artifact_topology_parsers(),
                RegisterArtifactTopologyBatchHandler(
                    artifact_topology_repository,
                    CanonicalArtifactTopologyProjection(
                        store,
                        Neo4jGraphRepositoryFactory(neo4j_driver, neo4j_database),
                        assertion_repositories,
                    ),
                    SourceRevisionArtifactTopologyLineage(source_revision_repository),
                ),
            ),
            QueryArtifactTopologyHandler(artifact_topology_repository),
            clock,
        )
    )
    graph_integrity = Neo4jGraphIntegrityAdapter(neo4j_driver, neo4j_database)
    graph_integrity_journal = SqliteGraphIntegrityJournal(store, clock)
    application.include_router(
        create_graph_integrity_router(
            authenticator,
            retrieval_scope,
            StartGraphMigrationHandler(
                SqliteGraphMigrationRepository(store, clock), graph_integrity
            ),
            RunGraphMigrationHandler(SqliteGraphMigrationRepository(store, clock), graph_integrity),
            ValidateGraphIntegrityHandler(graph_integrity, graph_integrity_journal),
            RepairGraphFindingHandler(
                graph_integrity_journal,
                graph_integrity,
                Pf002CanonicalGraphRebuild(
                    store,
                    clock,
                    StartProjectionRebuildHandler(
                        projection_adapter,
                        projection_adapter,
                        projection_adapter,
                    ),
                    _graph_rebuild_manifest(settings),
                ),
            ),
            clock,
        )
    )
    application.include_router(
        _create_retrieval_runtime_router(
            store,
            clock,
            authenticator,
            retrieval_scope,
            installation_root_key_file,
        )
    )


def _graph_rebuild_manifest(settings: CoreSettings) -> RebuildManifest:
    """Bind the internal GRA-006 repair path to this exact local release configuration."""
    providers = tuple(
        sorted(
            (
                f"embedding:{settings.embedding_model_id}@{settings.embedding_model_revision}",
                f"extractor:{settings.extraction_model_id}@{settings.extraction_model_revision}",
                f"reranker:{settings.reranking_model_id}@{settings.reranking_model_revision}",
            )
        )
    )
    identity = json.dumps(
        {
            "application": __version__,
            "graph_migration": REGISTERED_GRAPH_MIGRATION_CHECKSUM,
            "graph_schema": NEO4J_SCHEMA_HEAD,
            "providers": providers,
            "relational_schema": EXPECTED_MIGRATION_HEAD,
            "schema_version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return RebuildManifest(
        application_build=f"agentmemory@{__version__}",
        relational_schema=EXPECTED_MIGRATION_HEAD,
        graph_schema=NEO4J_SCHEMA_HEAD,
        parser_version="canonical-event-projection@1",
        extractor_version=(
            f"{settings.memory_extractor_id}@{settings.memory_extractor_version}:"
            f"{settings.extraction_model_revision}"
        ),
        provider_versions=providers,
        embedding_space=(
            f"{settings.embedding_model_id}@{settings.embedding_model_revision}:1024:cosine:v1"
        ),
        implementation_fingerprint=Sha256Digest.from_bytes(identity),
    )


def _create_retrieval_runtime_router(
    store: SqliteCoreStore,
    clock: SystemClock,
    authenticator: ApiAuthenticator,
    retrieval_scope: ResolveRetrievalScopeHandler,
    installation_root_key_file: Path,
) -> APIRouter:
    """Compose the host-neutral query and host delivery adapters at the outer boundary."""
    continuity = SqliteContinuityReadRepository(
        store.engine,
        SqliteWrappedBrainKeyProvider(store, installation_root_key_file, clock),
        clock,
    )
    handler = StartSessionBriefingHandler(
        continuity,
        SqliteMemoryBriefingRepository(store.engine, clock),
        SqliteCodeRevisionQuery(store.engine, clock),
        DeterministicBriefingRetrievalPipeline.production(),
        EmptyProcedureReadRepository(),
        SqliteContextInjectionRepository(store.engine),
    )
    return create_retrieval_router(
        authenticator,
        retrieval_scope,
        CertifiedDeliveryAdapterRegistry(handler),
        clock,
    )


def _include_ingestion_runtime_routers(  # noqa: PLR0913 -- Outer composition is explicit.
    application: FastAPI,
    store: SqliteCoreStore,
    clock: SystemClock,
    authenticator: ApiAuthenticator,
    installation_root_key_file: Path,
    queue_limits: QueueLimits,
    storage_capacity: LocalDiskSpaceProbe,
) -> None:
    """Compose and install all ingestion routers at the outermost boundary."""
    replay_repository = SqliteOrderedReplayRepository(store)
    replay_access = SqliteOrderedReplayAccessPolicy(store)
    application.include_router(
        create_ordered_replay_router(
            authenticator,
            StartOrderedReplayHandler(replay_access, replay_repository, clock),
            GetOrderedReplayHandler(replay_access, replay_repository, clock),
        )
    )
    scheduler_repository = SqliteJobSchedulerRepository(store, storage_capacity)
    scheduler_access = SqliteJobSchedulerAccessPolicy(store)
    application.include_router(
        create_backpressure_router(
            authenticator,
            GetScheduledJobHandler(scheduler_access, scheduler_repository, clock),
            ListDeadLettersHandler(scheduler_access, scheduler_repository, clock),
            ReplayDeadLetterHandler(
                scheduler_access,
                scheduler_repository,
                queue_limits,
                clock,
            ),
        )
    )
    application.include_router(
        _create_adapter_capability_runtime_router(store, clock, authenticator)
    )
    application.include_router(
        create_agent_event_router(
            authenticator,
            CaptureAgentEventHandler(
                SqliteAdapterCapabilityRegistry(store.engine),
                SqliteAgentEventScopeResolver(store.engine, clock),
                InlineOnlyPayloadReader(),
                CapturePolicyPipeline(SqliteCapturePolicyRepository(store)),
                SqliteCapturePolicyDecisionRepository(store),
                AppendAgentEventHandler(
                    CanonicalAgentEventEncoder(),
                    AesGcmAgentEventEncryptor(
                        SqliteWrappedBrainKeyProvider(
                            store,
                            installation_root_key_file,
                            clock,
                        )
                    ),
                    SqliteAgentEventUnitOfWorkFactory(
                        store,
                        clock,
                        SqliteCaptureCapacityEnforcer(storage_capacity, queue_limits),
                    ),
                ),
                clock,
            ),
        )
    )
