"""GRA-005 SQLite contradiction detection, replay, resolution, and policy tests."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.graph.adapters.outbound.sqlite_assertions import SqliteAssertionRepositoryFactory
from agentmemory.graph.adapters.outbound.sqlite_contradictions import SqliteContradictionRepository
from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
)
from agentmemory.graph.application.contradictions import (
    DetectContradictionsCommand,
    DetectContradictionsHandler,
    EvaluateContradictionsHandler,
    EvaluateContradictionsQuery,
    ResolveContradictionCommand,
    ResolveContradictionHandler,
)
from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionEvidenceReference,
    AssertionExtractor,
    AssertionPolarity,
    AssertionPredicate,
    AssertionScope,
    AssertionTemporal,
    EvidenceKind,
)
from agentmemory.graph.domain.contradictions import (
    ContradictionDecision,
    ContradictionResolutionOutcome,
    RetrievalAssertionCandidate,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphConflictError
from tests.core.support import BRAIN_ID, GRANT_ID, FixedClock, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    NOW,
    PROMPT_EVENT_ID,
    PROMPT_EVIDENCE_ID,
    _scope,  # pyright: ignore[reportPrivateUsage]
    _seed_sources,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    PROJECT_ID,
    REPOSITORY_ID,
    _seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

LEFT = "018f0000-0000-7000-8000-000000000280"
RIGHT = "018f0000-0000-7000-8000-000000000281"
SUBJECT = "018f0000-0000-7000-8000-000000000282"
OBJECT = "018f0000-0000-7000-8000-000000000283"
LEFT_EVENT = "018f0000-0000-7000-8000-000000000290"
RIGHT_EVENT = "018f0000-0000-7000-8000-000000000291"


@pytest.mark.asyncio
async def test_sqlite_detection_replay_and_unresolved_abstention(tmp_path: Path) -> None:
    store = await _store_with_conflicting_assertions(tmp_path)
    try:
        repository = SqliteContradictionRepository(store, FixedClock(NOW + timedelta(minutes=2)))
        command = DetectContradictionsCommand(
            "detect-polarity-1",
            _scope("graph.contradiction.detect"),
            REPOSITORY_ID.value,
            NOW + timedelta(minutes=2),
        )
        handler = DetectContradictionsHandler(repository)
        first = await handler.execute(command)
        assert len(first) == 1
        assert await handler.execute(command) == first
        assert first[0].evidence_ids == (PROMPT_EVIDENCE_ID,)

        result = await EvaluateContradictionsHandler(repository).execute(
            EvaluateContradictionsQuery(
                _scope("graph.contradiction.query"),
                (
                    RetrievalAssertionCandidate(LEFT, 10_000, authoritative=True),
                    RetrievalAssertionCandidate(RIGHT, 1, authoritative=True),
                ),
            )
        )
        assert result.decision is ContradictionDecision.UNKNOWN
        assert result.contradiction_ids == (first[0].id,)

        divergent = DetectContradictionsCommand(
            command.operation_id,
            command.scope,
            command.repository_id,
            NOW + timedelta(minutes=3),
        )
        with pytest.raises(GraphConflictError):
            await handler.execute(divergent)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_user_resolution_is_append_only_authorized_and_idempotent(
    tmp_path: Path,
) -> None:
    store = await _store_with_conflicting_assertions(tmp_path)
    try:
        repository = SqliteContradictionRepository(store, FixedClock(NOW + timedelta(minutes=2)))
        dispute = (
            await DetectContradictionsHandler(repository).execute(
                DetectContradictionsCommand(
                    "detect-polarity-2",
                    _scope("graph.contradiction.detect"),
                    REPOSITORY_ID.value,
                    NOW + timedelta(minutes=2),
                )
            )
        )[0]
        command = ResolveContradictionCommand(
            "resolve-polarity-1",
            _scope("graph.contradiction.resolve"),
            dispute.id,
            GRANT_ID,
            ContradictionResolutionOutcome.LEFT_ASSERTION,
            "user_confirmed",
            (PROMPT_EVIDENCE_ID,),
            NOW + timedelta(minutes=3),
        )
        handler = ResolveContradictionHandler(repository)
        resolved = await handler.execute(command)
        assert resolved.resolution is not None
        assert await handler.execute(command) == resolved

        result = await EvaluateContradictionsHandler(repository).execute(
            EvaluateContradictionsQuery(
                _scope("graph.contradiction.query"),
                (
                    RetrievalAssertionCandidate(LEFT, 1, authoritative=True),
                    RetrievalAssertionCandidate(RIGHT, 10_000, authoritative=True),
                ),
            )
        )
        assert result.decision is ContradictionDecision.CERTAIN
        assert result.selected_assertion_ids == (LEFT,)

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError):
                await connection.execute(
                    text(
                        "UPDATE graph_contradictions SET dimension='exclusive_object' "
                        "WHERE contradiction_id=:id"
                    ),
                    {"id": dispute.id},
                )
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_sqlite_repository_rejects_wrong_actions_before_candidate_reads(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        repository = SqliteContradictionRepository(store, FixedClock(NOW))
        with pytest.raises(GraphAuthorizationError):
            await repository.detection_candidates(
                _scope("graph.contradiction.query"), REPOSITORY_ID.value
            )
    finally:
        await store.close()


async def _store_with_conflicting_assertions(tmp_path: Path) -> SqliteCoreStore:
    store = migrated_store(tmp_path)
    await _seed_roots(store)
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
    for index, (assertion_id, event_id, polarity) in enumerate(
        (
            (LEFT, LEFT_EVENT, AssertionPolarity.POSITIVE),
            (RIGHT, RIGHT_EVENT, AssertionPolarity.NEGATIVE),
        ),
        start=1,
    ):
        candidate = _candidate(assertion_id, polarity)
        await ProposeAssertionHandler(factory).execute(
            ProposeAssertionCommand(
                f"propose-contradiction-{index}",
                _scope("graph.assertion.propose"),
                candidate,
            )
        )
        await ActivateAssertionHandler(factory).execute(
            ActivateAssertionCommand(
                f"activate-contradiction-{index}",
                event_id,
                assertion_id,
                _scope("graph.assertion.activate"),
                NOW + timedelta(minutes=1),
            )
        )
    return store


def _candidate(assertion_id: str, polarity: AssertionPolarity) -> AssertionCandidate:
    return AssertionCandidate.create(
        candidate_id=assertion_id,
        subject_id=SUBJECT,
        predicate=AssertionPredicate.CALLS,
        object_id=OBJECT,
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
        polarity=polarity,
    )
