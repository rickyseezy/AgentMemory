"""GRA-002 canonical SQLite evidence and assertion integration tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
    ReconcileAssertionEvidenceCommand,
    ReconcileAssertionEvidenceHandler,
)
from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionEventType,
    AssertionEvidenceReference,
    AssertionEvidenceRevocation,
    AssertionExtractor,
    AssertionLifecycleEvent,
    AssertionPredicate,
    AssertionScope,
    AssertionStatus,
    AssertionTemporal,
    EvidenceKind,
    EvidenceRevocationReason,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphConflictError
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from tests.core.support import BRAIN_ID, OWNER_ID, migrated_store
from tests.identity.test_checkout_observation_sqlite import (
    PROJECT_ID,
    REPOSITORY_ID,
    _migration_config,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _seed_roots as seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
PROMPT_EVENT_ID = "018f0000-0000-7000-8000-000000000150"
ARTIFACT_EVENT_ID = "018f0000-0000-7000-8000-000000000151"
ARTIFACT_ID = "018f0000-0000-7000-8000-000000000160"
PROMPT_EVIDENCE_ID = "018f0000-0000-7000-8000-000000000170"
ARTIFACT_EVIDENCE_ID = "018f0000-0000-7000-8000-000000000171"
SPAN_EVIDENCE_ID = "018f0000-0000-7000-8000-000000000172"
ASSERTION_ID = "018f0000-0000-7000-8000-000000000180"
SUBJECT_ID = "018f0000-0000-7000-8000-000000000181"
OBJECT_ID = "018f0000-0000-7000-8000-000000000182"
ACTIVATED_EVENT_ID = "018f0000-0000-7000-8000-000000000190"
DISPUTED_EVENT_ID = "018f0000-0000-7000-8000-000000000191"
ARTIFACT_BYTES = b"frontend consumes user-api"


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_real_sources_activate_idempotently_and_revocation_disputes(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        await _seed_sources(store)
        factory = SqliteAssertionRepositoryFactory(
            store,
            lambda: UUID(DISPUTED_EVENT_ID),
        )

        catalog = factory.evidence_catalog(_scope("graph.assertion.evidence.register"))
        prompt = await catalog.register(
            AssertionEvidenceReference(
                PROMPT_EVIDENCE_ID,
                PROMPT_EVENT_ID,
                EvidenceKind.USER_STATEMENT,
            ),
            NOW,
        )
        assert (
            await catalog.register(
                AssertionEvidenceReference(
                    PROMPT_EVIDENCE_ID,
                    PROMPT_EVENT_ID,
                    EvidenceKind.USER_STATEMENT,
                ),
                NOW,
            )
            == prompt
        )
        artifact = await catalog.register(
            AssertionEvidenceReference(
                ARTIFACT_EVIDENCE_ID,
                ARTIFACT_EVENT_ID,
                EvidenceKind.ARTIFACT,
                ARTIFACT_ID,
            ),
            NOW,
        )
        span = await catalog.register(
            AssertionEvidenceReference(
                SPAN_EVIDENCE_ID,
                ARTIFACT_EVENT_ID,
                EvidenceKind.SOURCE_SPAN,
                ARTIFACT_ID,
                0,
                8,
            ),
            NOW,
        )
        assert artifact.source_digest == hashlib.sha256(ARTIFACT_BYTES).hexdigest()
        assert span.source_digest != artifact.source_digest

        candidate = _candidate()
        proposal = ProposeAssertionCommand(
            "assertion-propose-1",
            _scope("graph.assertion.propose"),
            candidate,
        )
        assert await ProposeAssertionHandler(factory).execute(proposal) == candidate
        assert await ProposeAssertionHandler(factory).execute(proposal) == candidate

        activation = ActivateAssertionCommand(
            "assertion-activate-1",
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
            _scope("graph.assertion.activate"),
            NOW + timedelta(seconds=1),
        )
        active = await ActivateAssertionHandler(factory).execute(activation)
        assert active.status is AssertionStatus.ACTIVE
        assert await ActivateAssertionHandler(factory).execute(activation) == active

        revocation = AssertionEvidenceRevocation(
            "assertion-evidence-revoke-1",
            PROMPT_EVIDENCE_ID,
            EvidenceRevocationReason.USER_RETRACTED,
            NOW + timedelta(seconds=2),
        )
        revocations = factory.evidence_catalog(_scope("graph.assertion.evidence.revoke"))
        disputed_rows = await revocations.revoke(revocation)
        assert await revocations.revoke(revocation) == disputed_rows
        with pytest.raises(GraphConflictError, match="conflicted"):
            await revocations.revoke(replace(revocation, reason=EvidenceRevocationReason.DELETED))
        assert len(disputed_rows) == 1
        disputed = disputed_rows[0]
        assert disputed.status is AssertionStatus.DISPUTED
        assert disputed.temporal.recorded_to == NOW + timedelta(seconds=2)
        stored = await factory.assertions(_scope("graph.assertion.reconcile")).get_assertion(
            ASSERTION_ID
        )
        assert stored == disputed

        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM assertion_candidates),"
                        "(SELECT COUNT(*) FROM assertion_lifecycle),"
                        "(SELECT COUNT(*) FROM assertion_evidence_snapshots),"
                        "(SELECT COUNT(*) FROM domain_events WHERE aggregate_type='assertion'),"
                        "(SELECT COUNT(*) FROM assertion_operations)"
                    )
                )
            ).one()
        assert tuple(counts) == (1, 2, 1, 2, 3)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_registration_rejects_wrong_kind_span_and_revoked_current_grant(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        await _seed_sources(store)
        factory = SqliteAssertionRepositoryFactory(store)
        catalog = factory.evidence_catalog(_scope("graph.assertion.evidence.register"))
        with pytest.raises(GraphConflictError, match="source"):
            await catalog.register(
                AssertionEvidenceReference(
                    PROMPT_EVIDENCE_ID,
                    ARTIFACT_EVENT_ID,
                    EvidenceKind.USER_STATEMENT,
                ),
                NOW,
            )
        with pytest.raises(GraphConflictError, match="source"):
            await catalog.register(
                AssertionEvidenceReference(
                    PROMPT_EVIDENCE_ID,
                    PROMPT_EVENT_ID,
                    EvidenceKind.EVENT,
                ),
                NOW - timedelta(days=1),
            )
        with pytest.raises(GraphConflictError, match="source"):
            await catalog.register(
                AssertionEvidenceReference(
                    SPAN_EVIDENCE_ID,
                    ARTIFACT_EVENT_ID,
                    EvidenceKind.SOURCE_SPAN,
                    ARTIFACT_ID,
                    0,
                    len(ARTIFACT_BYTES) + 1,
                ),
                NOW,
            )
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:at"),
                {"at": round((NOW - timedelta(seconds=1)).timestamp() * 1_000_000)},
            )
        with pytest.raises(GraphAuthorizationError, match="source"):
            await catalog.register(
                AssertionEvidenceReference(
                    PROMPT_EVIDENCE_ID,
                    PROMPT_EVENT_ID,
                    EvidenceKind.USER_STATEMENT,
                ),
                NOW,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_repository_guards_divergence_and_reconciles_tombstone_idempotently(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        await _seed_sources(store)
        factory = SqliteAssertionRepositoryFactory(store)
        await factory.evidence_catalog(_scope("graph.assertion.evidence.register")).register(
            AssertionEvidenceReference(
                PROMPT_EVIDENCE_ID,
                PROMPT_EVENT_ID,
                EvidenceKind.USER_STATEMENT,
            ),
            NOW,
        )
        candidate = _candidate()
        proposals = factory.assertions(_scope("graph.assertion.propose"))
        assert await proposals.propose("assertion-propose-a", candidate) == candidate
        assert await proposals.propose("assertion-propose-b", candidate) == candidate
        with pytest.raises(GraphConflictError, match="conflicted"):
            await proposals.propose(
                "assertion-propose-b",
                _candidate(predicate=AssertionPredicate.CALLS),
            )
        with pytest.raises(GraphAuthorizationError, match="action"):
            await factory.assertions(_scope("graph.assertion.evidence.register")).get_candidate(
                ASSERTION_ID
            )
        with pytest.raises(GraphAuthorizationError, match="action"):
            await factory.evidence(_scope("graph.assertion.propose")).resolve((), NOW)
        with pytest.raises(GraphAuthorizationError, match="action"):
            await factory.evidence_catalog(_scope("graph.assertion.propose")).register(
                AssertionEvidenceReference(
                    ARTIFACT_EVIDENCE_ID,
                    ARTIFACT_EVENT_ID,
                    EvidenceKind.EVENT,
                ),
                NOW,
            )
        assert (
            await factory.assertions(_scope("graph.assertion.activate")).get_candidate(
                "018f0000-0000-7000-8000-000000000199"
            )
            is None
        )

        active = await ActivateAssertionHandler(factory).execute(
            ActivateAssertionCommand(
                "assertion-activate-tombstone",
                ACTIVATED_EVENT_ID,
                ASSERTION_ID,
                _scope("graph.assertion.activate"),
                NOW + timedelta(seconds=1),
            )
        )
        premature_dispute = active.reconcile_evidence((), NOW + timedelta(seconds=2))
        premature_event = AssertionLifecycleEvent.create(
            event_id=DISPUTED_EVENT_ID,
            operation_id="assertion-premature-dispute",
            assertion=premature_dispute,
            event_type=AssertionEventType.DISPUTED,
            occurred_at=NOW + timedelta(seconds=2),
        )
        with pytest.raises(GraphConflictError, match="conflicted"):
            await factory.assertions(_scope("graph.assertion.reconcile")).dispute(
                "assertion-premature-dispute",
                premature_dispute,
                premature_event,
            )
        with pytest.raises(GraphConflictError, match="conflicted"):
            await factory.assertions(_scope("graph.assertion.reconcile")).dispute(
                "assertion-active-as-dispute",
                active,
                AssertionLifecycleEvent.create(
                    event_id="018f0000-0000-7000-8000-000000000193",
                    operation_id="assertion-active-as-dispute",
                    assertion=active,
                    event_type=AssertionEventType.ACTIVATED,
                    occurred_at=NOW + timedelta(seconds=2),
                ),
            )
        with pytest.raises(GraphConflictError, match="conflicted"):
            await factory.assertions(_scope("graph.assertion.activate")).activate(
                "assertion-disputed-as-active",
                premature_dispute,
                premature_event,
            )

        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO deletion_tombstones "
                    "(id,brain_id,target_type,target_id_hash,effective_at,purge_state,"
                    "restore_guard_version,created_at,schema_version) VALUES "
                    "(:id,:brain,'assertion_evidence',:target,:at,'tombstoned',1,:at,1)"
                ),
                {
                    "id": "018f0000-0000-7000-8000-000000000194",
                    "brain": BRAIN_ID,
                    "target": hashlib.sha256(PROMPT_EVIDENCE_ID.encode()).digest(),
                    "at": round((NOW + timedelta(seconds=2)).timestamp() * 1_000_000),
                },
            )
        command = ReconcileAssertionEvidenceCommand(
            "assertion-reconcile-tombstone",
            "018f0000-0000-7000-8000-000000000195",
            ASSERTION_ID,
            _scope("graph.assertion.reconcile"),
            NOW + timedelta(seconds=3),
        )
        handler = ReconcileAssertionEvidenceHandler(factory)
        disputed = await handler.execute(command)
        assert disputed.status is AssertionStatus.DISPUTED
        assert await handler.execute(command) == disputed
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_immutability_rejects_assertion_history_rewrite(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        await _seed_sources(store)
        catalog = SqliteAssertionRepositoryFactory(store).evidence_catalog(
            _scope("graph.assertion.evidence.register")
        )
        await catalog.register(
            AssertionEvidenceReference(
                PROMPT_EVIDENCE_ID,
                PROMPT_EVENT_ID,
                EvidenceKind.USER_STATEMENT,
            ),
            NOW,
        )
        with pytest.raises(IntegrityError, match="immutable"):
            async with store.engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE assertion_evidence_sources SET occurred_at=occurred_at+1 "
                        "WHERE evidence_id=:evidence"
                    ),
                    {"evidence": PROMPT_EVIDENCE_ID},
                )
    finally:
        await store.close()
    with pytest.raises(RuntimeError, match="GRA-002 downgrade refused"):
        command.downgrade(
            _migration_config(tmp_path / "agentmemory.sqlite3"),
            "0020_mem006_session_briefing",
        )


def _candidate(
    *, predicate: AssertionPredicate = AssertionPredicate.CONSUMES
) -> AssertionCandidate:
    return AssertionCandidate.create(
        candidate_id=ASSERTION_ID,
        subject_id=SUBJECT_ID,
        predicate=predicate,
        object_id=OBJECT_ID,
        scope=AssertionScope(
            BRAIN_ID,
            PROJECT_ID.value,
            REPOSITORY_ID.value,
            None,
            "internal",
        ),
        temporal=AssertionTemporal(NOW, None, NOW, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor(
            "graph.extractor",
            "1.0.0",
            "qwen3",
            "revision-1",
        ),
        evidence_ids=(PROMPT_EVIDENCE_ID,),
    )


def _scope(action: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(OWNER_ID),
        role=RetrievalRole.OWNER,
        mode=RetrievalScopeMode.SELECTED,
        members=(ScopeMember(PROJECT_ID, (REPOSITORY_ID,), ()),),
        classification_ceiling=Classification.INTERNAL,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="assertion_integration",
    )


async def _seed_sources(store: SqliteCoreStore) -> None:
    now = round(NOW.timestamp() * 1_000_000)
    artifact_digest = hashlib.sha256(ARTIFACT_BYTES).digest()
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO artifacts "
                "(id,brain_id,sha256,media_type,byte_length,encryption_key_ref,blob_uri,"
                "classification,created_at,updated_at,schema_version) VALUES "
                "(:id,:brain,:digest,'text/plain',:length,'key-1',:uri,'internal',:now,:now,1)"
            ),
            {
                "id": ARTIFACT_ID,
                "brain": BRAIN_ID,
                "digest": artifact_digest,
                "length": len(ARTIFACT_BYTES),
                "uri": f"cas://sha256/{artifact_digest.hex()}",
                "now": now,
            },
        )
        for index, (event_id, event_type, payload_ref) in enumerate(
            (
                (PROMPT_EVENT_ID, "agentmemory.prompt.received.v1", None),
                (ARTIFACT_EVENT_ID, "agentmemory.file.changed.v1", ARTIFACT_ID),
            ),
            start=1,
        ):
            canonical = hashlib.sha256(event_id.encode()).digest()
            await connection.execute(
                text(
                    "INSERT INTO agent_events "
                    "(event_id,brain_id,type,payload_hash,classification,occurred_at,ingested_at,"
                    "schema_version,payload_ref) VALUES "
                    "(:event,:brain,:type,:digest,'internal',:now,:now,1,:artifact)"
                ),
                {
                    "event": event_id,
                    "brain": BRAIN_ID,
                    "type": event_type,
                    "digest": canonical,
                    "now": now - index,
                    "artifact": payload_ref,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO agent_event_envelopes "
                    "(event_id,principal_id,project_id,repository_id,checkout_id,ordering_key,"
                    "sequence,correlation_id,causation_id,retention_policy_id,canonical_sha256,"
                    "envelope_version,algorithm,brain_key_id,data_key_id,payload_nonce,ciphertext,"
                    "wrapped_data_key_nonce,wrapped_data_key,aad_sha256,clock_skew_microseconds,"
                    "created_at,schema_version) VALUES "
                    "(:event,:principal,:project,:repository,NULL,:ordering,:sequence,:correlation,"
                    "NULL,'default',:canonical,1,'AES-256-GCM',:brain_key,:data_key,:nonce,"
                    ":ciphertext,:wrapped_nonce,:wrapped_key,:aad,0,:now,1)"
                ),
                {
                    "event": event_id,
                    "principal": OWNER_ID,
                    "project": PROJECT_ID.value,
                    "repository": REPOSITORY_ID.value,
                    "ordering": f"ordering-{index}",
                    "sequence": index,
                    "correlation": f"correlation-{index}",
                    "canonical": canonical,
                    "brain_key": f"brain-key-{index}",
                    "data_key": f"data-key-{index}",
                    "nonce": bytes([index]) * 12,
                    "ciphertext": b"ciphertext",
                    "wrapped_nonce": bytes([index + 2]) * 12,
                    "wrapped_key": bytes([index + 4]) * 48,
                    "aad": hashlib.sha256(f"aad-{index}".encode()).digest(),
                    "now": now - index,
                },
            )
