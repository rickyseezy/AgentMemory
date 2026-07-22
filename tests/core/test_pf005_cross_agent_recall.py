"""PF-005 real encrypted cross-project, cross-agent session recall acceptance test."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import text

from agentmemory.identity.adapters.outbound.sqlite_retrieval_scope import (
    SqliteRelatedProjectGraph,
    SqliteRetrievalScopeAuthorizationRepository,
)
from agentmemory.identity.application.queries.resolve_retrieval_scope import (
    ResolveRetrievalScopeHandler,
)
from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    SqliteWrappedBrainKeyProvider,
)
from agentmemory.ingestion.adapters.outbound.payload_reader import InlineOnlyPayloadReader
from agentmemory.ingestion.adapters.outbound.sqlite_capabilities import (
    SqliteAdapterCapabilityUnitOfWorkFactory,
    SystemIngestionIdentityGenerator,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAdapterCapabilityRegistry,
    SqliteAgentEventScopeResolver,
    SqliteAgentEventUnitOfWorkFactory,
)
from agentmemory.ingestion.adapters.outbound.sqlite_privacy import (
    SqliteCapturePolicyDecisionRepository,
    SqliteCapturePolicyRepository,
)
from agentmemory.ingestion.application.adapter_capabilities import (
    RegisterAgentAdapterCommand,
    RegisterAgentAdapterHandler,
)
from agentmemory.ingestion.application.append_agent_event import AppendAgentEventHandler
from agentmemory.ingestion.application.capture_agent_event import CaptureAgentEventHandler
from agentmemory.ingestion.application.privacy import CapturePolicyPipeline
from agentmemory.ingestion.domain.adapter_capability import AdapterCapabilityManifest
from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
)
from agentmemory.operations.adapters.inbound.session_authentication import (
    SessionCredentialAuthenticator,
)
from agentmemory.operations.adapters.outbound.sqlite_mcp_session import (
    SqliteMcpSessionRepository,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.operations.domain.mcp_session import McpGitCoverage, McpSessionRegistration
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.retrieval.adapters.inbound.host_delivery import (
    CertifiedDeliveryAdapterRegistry,
)
from agentmemory.retrieval.adapters.inbound.session_http_api import (
    create_session_retrieval_router,
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
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    INSTALLATION_ID,
    OWNER_ID,
    FixedClock,
    bootstrap_request,
    digest,
    migrated_store,
    write_secret,
)
from tests.ingestion.adp002_support import NOW
from tests.ingestion.capability_support import complete_availability

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_PROJECT_A = "019f4d50-4261-7902-b2a0-7c164ae2549f"
_REPOSITORY_A = "019f4d50-4262-7902-b2a0-7c164ae2549f"
_PROJECT_B = "019f4d50-4263-7902-b2a0-7c164ae2549f"
_REPOSITORY_B = "019f4d50-4264-7902-b2a0-7c164ae2549f"
_SESSION_A = "019f4d50-4265-7902-b2a0-7c164ae2549f"
_SESSION_B = "019f4d50-4266-7902-b2a0-7c164ae2549f"
_EVENT = "019f4d50-4267-7902-b2a0-7c164ae2549f"
_TASK = "019f4d50-4268-7902-b2a0-7c164ae2549f"
_ORDERING = "019f4d50-4269-7902-b2a0-7c164ae2549f"
_CORRELATION = "019f4d50-426a-7902-b2a0-7c164ae2549f"
_ADAPTER_DIGEST = hashlib.sha256(b"pf005-claude-adapter").hexdigest()
_SESSION_SECRET = b"01234567890123456789012345678901"


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_pf005_gemini_session_recalls_claude_work_from_another_directory(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-root-key"
    write_secret(key_file, b"k" * 32)
    clock = FixedClock(NOW + timedelta(seconds=10))
    try:
        await _seed_authority(store)
        await _capture_claude_decision(store, key_file)
        sessions = SqliteMcpSessionRepository(store)
        registration = _consumer_registration()
        await sessions.register(registration)
        registered = await sessions.get(Uuid7Id(_SESSION_B))
        assert registered is not None
        await sessions.save(
            registered,
            registered.begin(NOW + timedelta(seconds=1), timedelta(seconds=120)),
        )
        app = _session_recall_app(store, key_file, sessions, clock)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:9411",
        ) as client:
            response = await client.post(
                "/v1/session/recall:brief",
                json={"operation_id": "gemini-turn-1", "mode": "global"},
                headers={
                    "Authorization": f"Bearer {_SESSION_SECRET.hex()}",
                    "X-AgentMemory-Session-ID": _SESSION_B,
                },
            )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ready"
        assert body["consumer_host"] == "generic"
        assert [item["content"] for item in body["items"]] == [
            "The web frontend consumes the shared user API."
        ]
        assert body["items"][0]["provenance"] == {
            "producer_host": "claude_code",
            "model_id": "claude-sonnet",
            "adapter_id": "agentmemory.claude-code",
            "adapter_version": "1.0.0",
            "capture_method": "native",
        }
        assert body["items"][0]["evidence_event_id"] == _EVENT
        async with store.engine.connect() as connection:
            source_project = (
                await connection.execute(
                    text("SELECT project_id FROM agent_event_envelopes WHERE event_id=:event"),
                    {"event": _EVENT},
                )
            ).scalar_one()
            receipt_count = (
                await connection.execute(text("SELECT COUNT(*) FROM session_briefing_receipts"))
            ).scalar_one()
        assert source_project == _PROJECT_A
        assert registration.project_id is not None
        assert registration.project_id.value == _PROJECT_B
        assert receipt_count == 1
    finally:
        await store.close()


async def _seed_authority(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )
    now = round(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        for project, repository, suffix in (
            (_PROJECT_A, _REPOSITORY_A, b"a"),
            (_PROJECT_B, _REPOSITORY_B, b"b"),
        ):
            await connection.execute(
                text(
                    "INSERT INTO projects "
                    "(id,brain_id,name,manifest_key,status,version,created_at,updated_at,"
                    "schema_version) VALUES (:project,:brain,:name,:manifest,'active',1,"
                    ":now,:now,1)"
                ),
                {
                    "project": project,
                    "brain": BRAIN_ID,
                    "name": f"project-{suffix.decode()}",
                    "manifest": suffix * 32,
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO repositories "
                    "(id,brain_id,vcs_type,root_fingerprint,primary_remote_fingerprint,status,"
                    "created_at,updated_at,schema_version) VALUES "
                    "(:repository,:brain,'git',:root,NULL,'active',:now,:now,1)"
                ),
                {
                    "repository": repository,
                    "brain": BRAIN_ID,
                    "root": suffix * 32,
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO project_repositories "
                    "(project_id,repository_id,relation_type,created_at,updated_at,schema_version) "
                    "VALUES (:project,:repository,'primary',:now,:now,1)"
                ),
                {"project": project, "repository": repository, "now": now},
            )
    manifest = _manifest()
    identities = SystemIngestionIdentityGenerator()
    await RegisterAgentAdapterHandler(
        SqliteAdapterCapabilityUnitOfWorkFactory(store, FixedClock(NOW), identities),
        identities,
        FixedClock(NOW),
    ).execute(RegisterAgentAdapterCommand("pf005-register-claude", manifest))


def _manifest() -> AdapterCapabilityManifest:
    return AdapterCapabilityManifest.create(
        adapter_id="agentmemory.claude-code",
        adapter_version="1.0.0",
        adapter_digest=_ADAPTER_DIGEST,
        schema_major=1,
        supported_families=(EventFamily.TASK_COMPLETED,),
        evidence_availability=complete_availability(
            task_lifecycle=CaptureMethod.NATIVE,
        ),
    )


async def _capture_claude_decision(store: SqliteCoreStore, key_file: Path) -> None:
    payload = json.dumps(
        {
            "continuity": {
                "items": [
                    {
                        "content": "The web frontend consumes the shared user API.",
                        "kind": "decision",
                        "semantic_id": "frontend-user-api-relationship",
                    }
                ],
                "schema_version": 1,
            }
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    manifest = _manifest()
    event = AgentEvent.create(
        specversion="1.0",
        event_id=_EVENT,
        source="urn:agentmemory:adapter:agentmemory.claude-code",
        event_type=EventFamily.TASK_COMPLETED,
        subject=f"task/{_TASK}",
        occurred_at=NOW,
        datacontenttype="application/json",
        dataschema=EventFamily.TASK_COMPLETED.dataschema,
        identity=AgentEventIdentity(
            BRAIN_ID,
            OWNER_ID,
            _PROJECT_A,
            _REPOSITORY_A,
            None,
            None,
            None,
        ),
        provenance=AgentEventProvenance(
            "claude_code",
            manifest.adapter_id,
            manifest.adapter_version,
            manifest.adapter_digest,
            "claude-sonnet",
            _SESSION_A,
            _TASK,
            None,
            None,
            manifest.manifest_sha256,
            CaptureMethod.NATIVE,
            hashlib.sha256(payload).hexdigest(),
        ),
        correlation_id=_CORRELATION,
        causation_id=None,
        ordering_key=_ORDERING,
        sequence=1,
        classification=Classification.INTERNAL,
        retention_policy_id="default",
        capture_capabilities=(CaptureCapability.TASK_LIFECYCLE,),
        payload=AgentEventData(payload, hashlib.sha256(payload).hexdigest()),
        payload_reference=None,
    )
    clock = FixedClock(NOW)
    keys = SqliteWrappedBrainKeyProvider(store, key_file, clock)
    handler = CaptureAgentEventHandler(
        SqliteAdapterCapabilityRegistry(store.engine),
        SqliteAgentEventScopeResolver(store.engine, clock),
        InlineOnlyPayloadReader(),
        CapturePolicyPipeline(SqliteCapturePolicyRepository(store)),
        SqliteCapturePolicyDecisionRepository(store),
        AppendAgentEventHandler(
            CanonicalAgentEventEncoder(),
            AesGcmAgentEventEncryptor(keys),
            SqliteAgentEventUnitOfWorkFactory(store, clock),
        ),
        clock,
    )
    await handler.execute(event)


def _consumer_registration() -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=Uuid7Id(_SESSION_B),
        installation_id=Uuid7Id(INSTALLATION_ID),
        brain_id=Uuid7Id(BRAIN_ID),
        actor_id=Uuid7Id(OWNER_ID),
        grant_id=Uuid7Id(GRANT_ID),
        agent_id="gemini",
        workspace_fingerprint=digest("pf005-project-b-workspace"),
        device_identity="device:local",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=1,
        credential_digest=Sha256Digest(hashlib.sha256(_SESSION_SECRET).hexdigest()),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        project_id=Uuid7Id(_PROJECT_B),
        repository_id=Uuid7Id(_REPOSITORY_B),
    )


def _session_recall_app(
    store: SqliteCoreStore,
    key_file: Path,
    sessions: SqliteMcpSessionRepository,
    clock: FixedClock,
) -> FastAPI:
    keys = SqliteWrappedBrainKeyProvider(store, key_file, clock)
    handler = StartSessionBriefingHandler(
        SqliteContinuityReadRepository(store.engine, keys, clock),
        SqliteMemoryBriefingRepository(store.engine, clock),
        SqliteCodeRevisionQuery(store.engine, clock),
        DeterministicBriefingRetrievalPipeline.production(),
        EmptyProcedureReadRepository(),
        SqliteContextInjectionRepository(store.engine),
    )
    app = FastAPI()
    app.include_router(
        create_session_retrieval_router(
            SessionCredentialAuthenticator(sessions, clock),
            ResolveRetrievalScopeHandler(
                SqliteRetrievalScopeAuthorizationRepository(store.engine),
                SqliteRelatedProjectGraph(store.engine),
            ),
            CertifiedDeliveryAdapterRegistry(handler),
            clock,
        )
    )
    return app
