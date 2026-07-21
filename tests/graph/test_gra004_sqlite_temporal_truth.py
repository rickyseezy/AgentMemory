"""GRA-004 real SQLite bitemporal and branch-aware truth integration tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.graph.adapters.outbound.sqlite_assertions import (
    SqliteAssertionRepositoryFactory,
)
from agentmemory.graph.adapters.outbound.sqlite_temporal_truth import (
    SqliteTemporalAssertionRepository,
    SqliteVcsRevisionRepository,
)
from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
)
from agentmemory.graph.application.temporal_truth import (
    QueryTemporalAssertionsHandler,
    QueryTemporalAssertionsQuery,
    RecordVcsRevisionBatchCommand,
    RecordVcsRevisionBatchHandler,
)
from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionEvidenceReference,
    AssertionExtractor,
    AssertionPredicate,
    AssertionScope,
    AssertionTemporal,
    EvidenceKind,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
)
from agentmemory.graph.domain.temporal_truth import (
    EvidenceRevisionAnchor,
    EvidenceRevisionImpact,
    RevisionApplicability,
    TemporalAssertionCriteria,
    TruthCurrency,
    TruthTemporalScope,
    VcsRefObservation,
    VcsRevisionBatch,
    VcsRevisionNode,
    VcsRevisionSelector,
)
from agentmemory.identity.adapters.outbound.sqlite_checkout_observation import (
    SqliteCheckoutObservationUnitOfWorkFactory,
)
from agentmemory.identity.adapters.outbound.uuid7_identity import SystemUuid7IdentityGenerator
from agentmemory.identity.application.commands.observe_checkout import (
    ObserveCheckoutHandler,
)
from tests.core.support import BRAIN_ID, FixedClock, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    ACTIVATED_EVENT_ID,
    ARTIFACT_EVENT_ID,
    ARTIFACT_EVIDENCE_ID,
    ASSERTION_ID,
    NOW,
    OBJECT_ID,
    PROMPT_EVENT_ID,
    PROMPT_EVIDENCE_ID,
    SUBJECT_ID,
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
    _seed_sources,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    PROJECT_ID,
    REPOSITORY_ID,
)
from tests.identity.test_checkout_observation_sqlite import (
    _command as checkout_command,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    _seed_roots as seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.graph.domain.temporal_truth import TemporalAssertionResult
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

ROOT = "1" * 40
BASE = "2" * 40
MAIN_CHANGED = "3" * 40
FEATURE_TIP = "4" * 40
MERGE = "5" * 40
REWRITTEN = "6" * 40


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_branch_divergence_merge_force_push_and_historical_truth(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        checkout_id = await _seed_active_assertion(store)
        await _insert_anchor(store, checkout_id, BASE)
        revisions = SqliteVcsRevisionRepository(store, FixedClock(NOW + timedelta(hours=1)))
        recorder = RecordVcsRevisionBatchHandler(revisions)
        t0 = NOW + timedelta(seconds=10)
        initial = _batch(
            "vcs-initial",
            (VcsRevisionNode(ROOT, ()), VcsRevisionNode(BASE, (ROOT,))),
            (
                VcsRefObservation("feature/api", BASE, t0),
                VcsRefObservation("main", BASE, t0),
            ),
            (),
            t0,
        )
        assert (
            await recorder.execute(
                RecordVcsRevisionBatchCommand(_scope("graph.vcs.revision.record"), initial)
            )
            == initial.digest
        )
        assert (
            await recorder.execute(
                RecordVcsRevisionBatchCommand(_scope("graph.vcs.revision.record"), initial)
            )
            == initial.digest
        )

        t1 = NOW + timedelta(seconds=20)
        divergent = _batch(
            "vcs-divergent",
            (
                VcsRevisionNode(MAIN_CHANGED, (BASE,)),
                VcsRevisionNode(FEATURE_TIP, (BASE,)),
            ),
            (
                VcsRefObservation("feature/api", FEATURE_TIP, t1),
                VcsRefObservation("main", MAIN_CHANGED, t1),
            ),
            (EvidenceRevisionImpact(PROMPT_EVIDENCE_ID, MAIN_CHANGED, t1),),
            t1,
        )
        await recorder.execute(
            RecordVcsRevisionBatchCommand(_scope("graph.vcs.revision.record"), divergent)
        )
        query = QueryTemporalAssertionsHandler(SqliteTemporalAssertionRepository(store), revisions)

        main_results = await _query_branch(query, "main", t1 + timedelta(seconds=1))
        feature_results = await _query_branch(query, "feature/api", t1 + timedelta(seconds=1))
        assert main_results == ()
        assert len(feature_results) == 1
        feature_proof = feature_results[0].explanation.evidence_proofs[0]
        assert feature_proof.applicability is RevisionApplicability.REACHABLE
        assert feature_proof.invalidating_commit_shas == ()

        t2 = NOW + timedelta(seconds=30)
        merged = _batch(
            "vcs-merge",
            (VcsRevisionNode(MERGE, (MAIN_CHANGED, FEATURE_TIP)),),
            (VcsRefObservation("main", MERGE, t2),),
            (),
            t2,
        )
        await recorder.execute(
            RecordVcsRevisionBatchCommand(_scope("graph.vcs.revision.record"), merged)
        )
        assert await _query_branch(query, "main", t2 + timedelta(seconds=1)) == ()

        historical = await _query_branch(query, "main", t0 + timedelta(seconds=1))
        assert len(historical) == 1
        assert historical[0].explanation.currency is TruthCurrency.HISTORICAL
        assert historical[0].explanation.resolved_revision is not None
        assert historical[0].explanation.resolved_revision.commit_sha == BASE

        t3 = NOW + timedelta(seconds=40)
        rewritten = _batch(
            "vcs-force-push",
            (VcsRevisionNode(REWRITTEN, (ROOT,)),),
            (VcsRefObservation("main", REWRITTEN, t3),),
            (),
            t3,
        )
        await recorder.execute(
            RecordVcsRevisionBatchCommand(_scope("graph.vcs.revision.record"), rewritten)
        )
        resolved = await revisions.resolve(
            _scope("graph.assertion.truth.query"),
            VcsRevisionSelector(REPOSITORY_ID.value, branch_name="main"),
            t3 + timedelta(seconds=1),
        )
        assert resolved.commit_sha == REWRITTEN
        assert resolved.force_pushed
        assert await _query_branch(query, "main", t3 + timedelta(seconds=1)) == ()

        current = await query.execute(
            QueryTemporalAssertionsQuery(
                _scope("graph.assertion.truth.query"), TruthTemporalScope.current()
            ),
            t3 + timedelta(seconds=1),
        )
        assert len(current) == 1
        assert current[0].explanation.currency is TruthCurrency.CURRENT
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_evidence_registration_anchors_capture_time_checkout_revision(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        checkout = await _observe_checkout(store)
        await _seed_sources(store)
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE agent_event_envelopes SET checkout_id=:checkout WHERE event_id=:event"
                ),
                {"checkout": checkout, "event": ARTIFACT_EVENT_ID},
            )
        catalog = SqliteAssertionRepositoryFactory(store).evidence_catalog(
            _scope("graph.assertion.evidence.register")
        )
        await catalog.register(
            AssertionEvidenceReference(
                ARTIFACT_EVIDENCE_ID,
                ARTIFACT_EVENT_ID,
                EvidenceKind.ARTIFACT,
                "018f0000-0000-7000-8000-000000000160",
            ),
            NOW,
        )
        async with store.engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "SELECT checkout_id,commit_sha,branch_at_capture "
                        "FROM assertion_evidence_revision_anchors WHERE evidence_id=:evidence"
                    ),
                    {"evidence": ARTIFACT_EVIDENCE_ID},
                )
            ).one()
        assert tuple(row) == (checkout, "a" * 40, "main")
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_revision_batch_rejects_unknown_parent_and_divergent_replay(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await seed_roots(store)
        repository = SqliteVcsRevisionRepository(store, FixedClock(NOW))
        batch = _batch(
            "vcs-unknown",
            (VcsRevisionNode(BASE, (ROOT,)),),
            (),
            (),
            NOW,
        )
        scope = _scope("graph.vcs.revision.record")
        with pytest.raises(GraphConflictError, match="conflicts"):
            await repository.append(scope, batch)

        root = _batch("vcs-root", (VcsRevisionNode(ROOT, ()),), (), (), NOW)
        assert await repository.append(scope, root) == root.digest
        with pytest.raises(GraphConflictError, match="conflicts"):
            await repository.append(scope, replace(root, source_digest="d" * 64))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_half_open_valid_and_recorded_boundaries(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        valid_to = NOW + timedelta(seconds=5)
        await _seed_active_assertion(store, _temporal_candidate(NOW, valid_to, NOW))
        handler = QueryTemporalAssertionsHandler(
            SqliteTemporalAssertionRepository(store),
            SqliteVcsRevisionRepository(store, FixedClock(NOW + timedelta(hours=1))),
        )
        at_start = await _query_time(
            handler,
            valid_at=NOW,
            recorded_at=NOW + timedelta(seconds=1),
        )
        at_end = await _query_time(
            handler,
            valid_at=valid_to,
            recorded_at=NOW + timedelta(seconds=1),
        )
        before_recording = await _query_time(
            handler,
            valid_at=NOW,
            recorded_at=NOW + timedelta(seconds=1, microseconds=-1),
        )
        assert len(at_start) == 1
        assert at_end == ()
        assert before_recording == ()
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_retroactive_fact_appears_only_after_its_recorded_time(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        reality_time = NOW - timedelta(hours=12)
        await _seed_active_assertion(
            store,
            _temporal_candidate(NOW - timedelta(days=1), None, NOW),
        )
        handler = QueryTemporalAssertionsHandler(
            SqliteTemporalAssertionRepository(store),
            SqliteVcsRevisionRepository(store, FixedClock(NOW + timedelta(hours=1))),
        )
        before_known = await _query_time(
            handler,
            valid_at=reality_time,
            recorded_at=NOW,
        )
        after_known = await _query_time(
            handler,
            valid_at=reality_time,
            recorded_at=NOW + timedelta(seconds=1),
        )
        assert before_known == ()
        assert len(after_known) == 1
        assert after_known[0].explanation.currency is TruthCurrency.HISTORICAL
        assert after_known[0].explanation.valid_at == reality_time
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_sqlite_adapters_fail_closed_on_actions_scope_and_unknown_history(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        assertions = SqliteTemporalAssertionRepository(store)
        revisions = SqliteVcsRevisionRepository(store, FixedClock(NOW))
        criteria = TemporalAssertionCriteria(None, None, (), NOW, NOW, 1)
        with pytest.raises(GraphAuthorizationError, match="action"):
            await assertions.query(_scope("graph.read"), criteria)
        root = _batch("vcs-root-guard", (VcsRevisionNode(ROOT, ()),), (), (), NOW)
        with pytest.raises(GraphAuthorizationError, match="action"):
            await revisions.append(_scope("graph.read"), root)
        with pytest.raises(GraphAuthorizationError, match="scope"):
            await revisions.append(
                _scope("graph.vcs.revision.record"),
                replace(root, brain_id="018f0000-0000-7000-8000-000000000099"),
            )
        with pytest.raises(GraphAuthorizationError, match="action"):
            await revisions.resolve(
                _scope("graph.read"),
                VcsRevisionSelector(REPOSITORY_ID.value, commit_sha=ROOT),
                NOW,
            )

        await seed_roots(store)
        query_scope = _scope("graph.assertion.truth.query")
        with pytest.raises(GraphConflictError, match="not available"):
            await revisions.resolve(
                query_scope,
                VcsRevisionSelector(REPOSITORY_ID.value, commit_sha=ROOT),
                NOW,
            )
        await revisions.append(_scope("graph.vcs.revision.record"), root)
        with pytest.raises(GraphConflictError, match="not available"):
            await revisions.resolve(
                query_scope,
                VcsRevisionSelector(REPOSITORY_ID.value, commit_sha=BASE),
                NOW,
            )
        with pytest.raises(GraphConflictError, match="not available"):
            await revisions.resolve(
                query_scope,
                VcsRevisionSelector(REPOSITORY_ID.value, branch_name="missing"),
                NOW,
            )
        with pytest.raises(GraphConflictError, match="conflicts"):
            await revisions.append(
                _scope("graph.vcs.revision.record"),
                _batch(
                    "vcs-divergent-node",
                    (VcsRevisionNode(ROOT, (BASE,)),),
                    (),
                    (),
                    NOW,
                ),
            )
        resolved = await revisions.resolve(
            query_scope,
            VcsRevisionSelector(REPOSITORY_ID.value, commit_sha=ROOT),
            NOW,
        )
        anchor = EvidenceRevisionAnchor(
            PROMPT_EVIDENCE_ID,
            REPOSITORY_ID.value,
            "018f0000-0000-7000-8000-000000000030",
            ROOT,
            "main",
            NOW,
        )
        with pytest.raises(GraphIntegrityError, match="integrity"):
            await revisions.prove(
                query_scope,
                "018f0000-0000-7000-8000-000000000099",
                anchor,
                resolved,
                NOW,
            )
        with pytest.raises(GraphAuthorizationError, match="action"):
            await revisions.prove(
                _scope("graph.read"),
                PROMPT_EVIDENCE_ID,
                anchor,
                resolved,
                NOW,
            )
    finally:
        await store.close()


async def _seed_active_assertion(
    store: SqliteCoreStore,
    candidate: AssertionCandidate | None = None,
) -> str:
    await seed_roots(store)
    checkout_id = await _observe_checkout(store)
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
    selected = candidate or _candidate()
    await ProposeAssertionHandler(factory).execute(
        ProposeAssertionCommand(
            "assertion-propose-gra004",
            _scope("graph.assertion.propose"),
            selected,
        )
    )
    await ActivateAssertionHandler(factory).execute(
        ActivateAssertionCommand(
            "assertion-activate-gra004",
            ACTIVATED_EVENT_ID,
            ASSERTION_ID,
            _scope("graph.assertion.activate"),
            NOW + timedelta(seconds=1),
        )
    )
    return checkout_id


async def _observe_checkout(store: SqliteCoreStore) -> str:
    aggregate = await ObserveCheckoutHandler(
        SqliteCheckoutObservationUnitOfWorkFactory(store, FixedClock()),
        SystemUuid7IdentityGenerator(),
    ).execute(checkout_command("observe-gra004", "path-gra004"))
    return aggregate.checkout_id.value


async def _insert_anchor(store: SqliteCoreStore, checkout_id: str, commit_sha: str) -> None:
    at = round(NOW.timestamp() * 1_000_000)
    async with store.engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO assertion_evidence_revision_anchors "
                "(evidence_id,brain_id,repository_id,checkout_id,commit_sha,branch_at_capture,"
                "revision_observed_at,anchored_at,schema_version) VALUES "
                "(:evidence,:brain,:repository,:checkout,:commit,'main',:at,:at,1)"
            ),
            {
                "evidence": PROMPT_EVIDENCE_ID,
                "brain": BRAIN_ID,
                "repository": REPOSITORY_ID.value,
                "checkout": checkout_id,
                "commit": commit_sha,
                "at": at,
            },
        )


def _batch(
    operation_id: str,
    nodes: tuple[VcsRevisionNode, ...],
    refs: tuple[VcsRefObservation, ...],
    impacts: tuple[EvidenceRevisionImpact, ...],
    observed_at: datetime,
) -> VcsRevisionBatch:
    return VcsRevisionBatch(
        operation_id,
        BRAIN_ID,
        REPOSITORY_ID.value,
        nodes,
        refs,
        impacts,
        observed_at,
        "c" * 64,
    )


async def _query_branch(
    handler: QueryTemporalAssertionsHandler,
    branch: str,
    recorded_at: datetime,
) -> tuple[TemporalAssertionResult, ...]:
    return await handler.execute(
        QueryTemporalAssertionsQuery(
            _scope("graph.assertion.truth.query"),
            TruthTemporalScope.historical(
                as_of_recorded=recorded_at,
                revision=VcsRevisionSelector(REPOSITORY_ID.value, branch_name=branch),
            ),
            assertion_id=ASSERTION_ID,
            limit=1,
        ),
        recorded_at,
    )


async def _query_time(
    handler: QueryTemporalAssertionsHandler,
    *,
    valid_at: datetime,
    recorded_at: datetime,
) -> tuple[TemporalAssertionResult, ...]:
    return await handler.execute(
        QueryTemporalAssertionsQuery(
            _scope("graph.assertion.truth.query"),
            TruthTemporalScope.historical(
                as_of_valid=valid_at,
                as_of_recorded=recorded_at,
            ),
            assertion_id=ASSERTION_ID,
            limit=1,
        ),
        recorded_at,
    )


def _temporal_candidate(
    valid_from: datetime,
    valid_to: datetime | None,
    recorded_from: datetime,
) -> AssertionCandidate:
    return AssertionCandidate.create(
        candidate_id=ASSERTION_ID,
        subject_id=SUBJECT_ID,
        predicate=AssertionPredicate.CONSUMES,
        object_id=OBJECT_ID,
        scope=AssertionScope(
            BRAIN_ID,
            PROJECT_ID.value,
            REPOSITORY_ID.value,
            None,
            "internal",
        ),
        temporal=AssertionTemporal(valid_from, valid_to, recorded_from, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor(
            "graph.extractor",
            "1.0.0",
            "qwen3",
            "revision-1",
        ),
        evidence_ids=(PROMPT_EVIDENCE_ID,),
    )
