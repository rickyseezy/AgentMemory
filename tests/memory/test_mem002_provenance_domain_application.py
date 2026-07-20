"""MEM-002 immutable provenance and authorized explanation behavior."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.memory.application.explain_memory import (
    ExplainMemoryHandler,
    ExplainMemoryQuery,
)
from agentmemory.memory.domain.consolidation import (
    ConfidenceDimensions,
    ExtractorIdentity,
    Memory,
    MemoryClass,
    MemoryProvenance,
    MemoryScope,
    MemoryStatus,
)
from agentmemory.memory.domain.errors import (
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)
from agentmemory.memory.domain.explanation import (
    EvidenceAvailability,
    MemoryEvidenceReference,
    MemoryExplanation,
    MemoryExplanationAccess,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.domain.ports import MemoryRepository

BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
ACTOR_ID = "018f0000-0000-7000-8000-000000000101"
GRANT_ID = "018f0000-0000-7000-8000-000000000102"
TASK_ID = "018f0000-0000-7000-8000-000000000201"
MEMORY_ID = "018f0000-0000-7000-8000-000000000401"
EVENT_ONE = "018f0000-0000-7000-8000-000000000301"
EVENT_TWO = "018f0000-0000-7000-8000-000000000302"
NOW = datetime(2026, 7, 21, 10, 0, tzinfo=UTC)
VALID_TO = NOW + timedelta(days=7)
RECORDED_TO = NOW + timedelta(days=8)


def _extractor() -> ExtractorIdentity:
    return ExtractorIdentity(
        "agentmemory.local-extractor",
        "1.0.0",
        "qwen3-4b",
        "qwen3-4b-q4_k_m-r1",
        "memory-candidates.v1",
    )


def _provenance() -> MemoryProvenance:
    return MemoryProvenance(
        actor_id=ACTOR_ID,
        agent_id="agentmemory.local-extractor",
        source_task_id=TASK_ID,
        created_by_event=EVENT_TWO,
        extractor=_extractor(),
        evidence_ids=(EVENT_ONE, EVENT_TWO),
        evidence_watermark_sha256="a" * 64,
        extractor_input_sha256="b" * 64,
        content_sha256=_content_sha256(),
        promotion_policy_version="memory-promotion.v1",
    )


def _content_sha256() -> str:
    document = {
        "memory_class": "decision",
        "scope": {
            "brain_id": BRAIN_ID,
            "checkout_id": None,
            "project_id": PROJECT_ID,
            "repository_id": REPOSITORY_ID,
        },
        "statement": "Projection rebuilds use immutable shadow generations.",
        "valid_from": "2026-07-21T10:00:00.000000Z",
        "valid_to": "2026-07-28T10:00:00.000000Z",
    }
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _memory(*, recorded_to: datetime | None = RECORDED_TO) -> Memory:
    return Memory.create(
        memory_id=MEMORY_ID,
        memory_class=MemoryClass.DECISION,
        scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
        status=MemoryStatus.ACTIVE,
        statement="Projection rebuilds use immutable shadow generations.",
        confidence=ConfidenceDimensions(9000, 9000, 9000),
        valid_from=NOW,
        valid_to=VALID_TO,
        recorded_from=NOW + timedelta(hours=1),
        recorded_to=recorded_to,
        provenance=_provenance(),
        classification="internal",
        retention_policy_id="default",
        aggregate_version=1,
    )


def _evidence(
    event_id: str,
    availability: EvidenceAvailability,
) -> MemoryEvidenceReference:
    available = availability is EvidenceAvailability.AVAILABLE
    return MemoryEvidenceReference(
        event_id=event_id,
        canonical_event_sha256="c" * 64,
        availability=availability,
        event_type="agentmemory.task.completed.v1" if available else None,
        occurred_at=NOW if available else None,
        resource_uri=f"memory://evidence/{event_id}" if available else None,
    )


def test_memory_create_requires_one_immutable_complete_provenance_value() -> None:
    memory = _memory()
    assert memory.provenance.actor_id == ACTOR_ID
    assert memory.provenance.agent_id == "agentmemory.local-extractor"
    assert memory.extractor.model_revision == "qwen3-4b-q4_k_m-r1"
    assert memory.evidence_ids == (EVENT_ONE, EVENT_TWO)
    assert len(memory.provenance.provenance_sha256) == 64
    with pytest.raises(FrozenInstanceError):
        memory.provenance.actor_id = GRANT_ID  # type: ignore[misc]
    with pytest.raises(MemoryValidationError) as captured:
        Memory.create(
            memory_id=MEMORY_ID,
            memory_class=MemoryClass.DECISION,
            scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
            status=MemoryStatus.ACTIVE,
            statement="Projection rebuilds use immutable shadow generations.",
            confidence=ConfidenceDimensions(9000, 9000, 9000),
            valid_from=NOW,
            valid_to=VALID_TO,
            recorded_from=NOW,
            recorded_to=None,
            provenance=None,
            classification="internal",
            retention_policy_id="default",
            aggregate_version=1,
        )
    assert captured.value.violations[0].field == "provenance"


_PROVENANCE_MUTATIONS: list[tuple[Callable[[MemoryProvenance], MemoryProvenance], str]] = [
    (lambda value: replace(value, actor_id="bad"), "provenance.actor_id"),
    (lambda value: replace(value, agent_id="Latest Agent"), "provenance.agent_id"),
    (
        lambda value: replace(value, evidence_watermark_sha256="0" * 64),
        "provenance.evidence_watermark_sha256",
    ),
    (
        lambda value: replace(value, extractor_input_sha256="short"),
        "provenance.extractor_input_sha256",
    ),
    (lambda value: replace(value, evidence_ids=()), "provenance.evidence_ids"),
    (lambda value: replace(value, content_sha256="e" * 64), "content_sha256"),
]


@pytest.mark.parametrize(("mutation", "field"), _PROVENANCE_MUTATIONS)
def test_provenance_rejects_missing_ambiguous_or_unbound_coordinates(
    mutation: Callable[[MemoryProvenance], MemoryProvenance],
    field: str,
) -> None:
    with pytest.raises(MemoryValidationError) as captured:
        _create_with_mutated_provenance(mutation)
    assert captured.value.violations[0].field == field


def _create_with_mutated_provenance(
    mutation: Callable[[MemoryProvenance], MemoryProvenance],
) -> Memory:
    return Memory.create(
        memory_id=MEMORY_ID,
        memory_class=MemoryClass.DECISION,
        scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
        status=MemoryStatus.ACTIVE,
        statement="Projection rebuilds use immutable shadow generations.",
        confidence=ConfidenceDimensions(9000, 9000, 9000),
        valid_from=NOW,
        valid_to=VALID_TO,
        recorded_from=NOW,
        recorded_to=None,
        provenance=mutation(_provenance()),
        classification="internal",
        retention_policy_id="default",
        aggregate_version=1,
    )


@pytest.mark.parametrize(
    ("valid_at", "recorded_at", "effective"),
    [
        (NOW, NOW + timedelta(hours=1), True),
        (VALID_TO - timedelta(microseconds=1), RECORDED_TO - timedelta(microseconds=1), True),
        (NOW - timedelta(microseconds=1), NOW + timedelta(hours=1), False),
        (VALID_TO, NOW + timedelta(hours=1), False),
        (NOW, NOW + timedelta(hours=1) - timedelta(microseconds=1), False),
        (NOW, RECORDED_TO, False),
    ],
)
def test_explanation_uses_inclusive_start_and_exclusive_end_temporal_boundaries(
    valid_at: datetime,
    recorded_at: datetime,
    *,
    effective: bool,
) -> None:
    explanation = MemoryExplanation.create(
        _memory(),
        (
            _evidence(EVENT_ONE, EvidenceAvailability.AVAILABLE),
            _evidence(EVENT_TWO, EvidenceAvailability.PURGED),
        ),
        valid_at,
        recorded_at,
    )
    assert explanation.effective is effective
    assert explanation.evidence[1].availability is EvidenceAvailability.PURGED


def test_explanation_requires_exact_evidence_lineage_and_labels_missing_sources() -> None:
    missing = _evidence(EVENT_TWO, EvidenceAvailability.MISSING)
    explanation = MemoryExplanation.create(
        _memory(recorded_to=None),
        (_evidence(EVENT_ONE, EvidenceAvailability.AVAILABLE), missing),
        NOW,
        NOW + timedelta(days=20),
    )
    assert explanation.effective
    assert explanation.evidence[1].event_type is None
    with pytest.raises(MemoryValidationError):
        MemoryExplanation.create(
            _memory(),
            (_evidence(EVENT_ONE, EvidenceAvailability.AVAILABLE),),
            NOW,
            NOW + timedelta(hours=1),
        )


class _Clock:
    def now(self) -> datetime:
        return NOW + timedelta(days=1)


class _Repository:
    def __init__(self, result: MemoryExplanation | None) -> None:
        self.result = result
        self.calls: list[tuple[object, ...]] = []

    async def explain_authorized(
        self,
        access: object,
    ) -> MemoryExplanation | None:
        assert isinstance(access, MemoryExplanationAccess)
        self.calls.append(
            (
                access.memory_id,
                access.brain_id,
                access.actor_id,
                access.grant_id,
                access.authorized_at,
                access.valid_at,
                access.recorded_at,
            )
        )
        return self.result


@pytest.mark.asyncio
async def test_handler_passes_exact_authority_and_temporal_query_to_repository() -> None:
    expected = MemoryExplanation.create(
        _memory(),
        (
            _evidence(EVENT_ONE, EvidenceAvailability.AVAILABLE),
            _evidence(EVENT_TWO, EvidenceAvailability.PURGED),
        ),
        NOW,
        NOW + timedelta(hours=1),
    )
    repository = _Repository(expected)
    handler = ExplainMemoryHandler(repository, _Clock())
    query = ExplainMemoryQuery(
        MEMORY_ID,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        NOW,
        NOW + timedelta(hours=1),
        NOW,
    )
    assert await handler.execute(query) == expected
    assert repository.calls == [
        (
            MEMORY_ID,
            BRAIN_ID,
            ACTOR_ID,
            GRANT_ID,
            NOW + timedelta(days=1),
            NOW,
            NOW + timedelta(hours=1),
        )
    ]


@pytest.mark.asyncio
async def test_handler_collapses_absence_and_unauthorized_existence() -> None:
    repository: MemoryRepository = _Repository(None)
    handler = ExplainMemoryHandler(repository, _Clock())
    query = ExplainMemoryQuery(
        MEMORY_ID,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        NOW,
        NOW,
        NOW,
    )
    with pytest.raises(MemoryEvidenceNotFoundError):
        await handler.execute(query)
