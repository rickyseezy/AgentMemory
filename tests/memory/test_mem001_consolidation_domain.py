"""MEM-001 evidence, candidate, promotion, and active-memory domain tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.memory.domain.consolidation import (
    ExtractorIdentity,
    MemoryCandidateBatch,
    MemoryClass,
    MemoryPromotionPolicy,
    MemoryScope,
    PromotionDisposition,
    TaskEvidence,
    TaskEvidenceBundle,
)
from agentmemory.memory.domain.errors import MemoryValidationError

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.domain.consolidation import Memory

BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
TASK_ID = "018f0000-0000-7000-8000-000000000201"
ACTOR_ID = "018f0000-0000-7000-8000-000000000101"
EVENT_ONE = "018f0000-0000-7000-8000-000000000301"
EVENT_TWO = "018f0000-0000-7000-8000-000000000302"
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


def scope() -> MemoryScope:
    return MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)


def evidence(
    event_id: str,
    event_type: str,
    payload: bytes,
    *,
    occurred_at: datetime = NOW,
    classification: str = "internal",
) -> TaskEvidence:
    return TaskEvidence(
        event_id=event_id,
        task_id=TASK_ID,
        scope=scope(),
        event_type=event_type,
        occurred_at=occurred_at,
        classification=classification,
        retention_policy_id="default",
        payload=payload,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        canonical_event_sha256="a" * 64,
    )


def bundle(*, terminal: str = "agentmemory.task.completed.v1") -> TaskEvidenceBundle:
    return TaskEvidenceBundle.create(
        TASK_ID,
        scope(),
        (
            evidence(EVENT_ONE, "agentmemory.test.completed.v1", b'{"passed":true}'),
            evidence(
                EVENT_TWO,
                terminal,
                b'{"summary":"Implemented deterministic projection rebuild"}',
                occurred_at=NOW + timedelta(seconds=1),
            ),
        ),
    )


def extractor() -> ExtractorIdentity:
    return ExtractorIdentity(
        "agentmemory.local-extractor",
        "1.0.0",
        "qwen3-4b",
        "qwen3-4b-q4_k_m-r1",
        "memory-candidates.v1",
    )


def candidate_document(
    source: TaskEvidenceBundle,
    *,
    memory_class: str = "decision",
    evidence_ids: list[str] | None = None,
    evidence_support: int = 9000,
    statement: str = "Projection rebuilds use immutable shadow generations.",
) -> bytes:
    value = {
        "candidates": [
            {
                "candidate_key": "projection-rebuild-shadow-generation",
                "confidence": {
                    "evidence_support": evidence_support,
                    "extraction_quality": 9000,
                    "source_reliability": 9000,
                },
                "evidence_ids": evidence_ids or [EVENT_ONE, EVENT_TWO],
                "memory_class": memory_class,
                "scope": {
                    "brain_id": BRAIN_ID,
                    "checkout_id": None,
                    "project_id": PROJECT_ID,
                    "repository_id": REPOSITORY_ID,
                },
                "statement": statement,
                "valid_from": "2026-07-20T12:00:00.000000Z",
                "valid_to": None,
            }
        ],
        "input_sha256": source.extractor_input_sha256,
        "schema": "agentmemory.memory-candidates.v1",
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _add_unknown_field(raw: bytes) -> bytes:
    return raw.replace(b'"schema":', b'"unknown":1,"schema":')


def _duplicate_candidates(raw: bytes) -> bytes:
    return raw.replace(b'"candidates":', b'"candidates":[],"candidates":')


def _invent_memory_class(raw: bytes) -> bytes:
    return raw.replace(b'"decision"', b'"invented"')


def _change_input_digest(raw: bytes) -> bytes:
    return raw.replace(b'"input_sha256":"', b'"input_sha256":"f')


def _inject_nonfinite_confidence(raw: bytes) -> bytes:
    return raw.replace(b'"evidence_support":9000', b'"evidence_support":NaN')


def _make_statement_noncanonical(raw: bytes) -> bytes:
    return raw.replace(b"Projection rebuilds", b"  Projection rebuilds")


def _unsupported_document(source: TaskEvidenceBundle) -> bytes:
    return candidate_document(
        source,
        evidence_ids=["018f0000-0000-7000-8000-000000000399"],
    )


def _low_confidence_document(source: TaskEvidenceBundle) -> bytes:
    return candidate_document(source, evidence_support=7999)


def _preference_without_explicit_evidence(source: TaskEvidenceBundle) -> bytes:
    return candidate_document(
        source,
        memory_class="preference",
        evidence_ids=[EVENT_ONE],
    )


_MEMORY_MUTATIONS: list[tuple[Callable[[Memory], Memory], str]] = [
    (
        lambda item: replace(item, provenance=replace(item.provenance, evidence_ids=())),
        "provenance.evidence_ids",
    ),
    (lambda item: replace(item, aggregate_version=2), "aggregate_version"),
    (lambda item: replace(item, classification="unknown"), "classification"),
    (lambda item: replace(item, recorded_to=item.recorded_from), "recorded_to"),
    (lambda item: replace(item, statement=f"{item.statement} "), "statement"),
    (lambda item: replace(item, content_sha256="f" * 64), "content_sha256"),
]


def test_completed_and_checkpointed_tasks_build_deterministic_bounded_evidence() -> None:
    completed = bundle()
    checkpointed = bundle(terminal="agentmemory.task.checkpointed.v1")
    assert completed.terminal_event_id == EVENT_TWO
    assert (
        completed.extractor_input_sha256
        == hashlib.sha256(completed.extractor_input_bytes).hexdigest()
    )
    assert completed.watermark_sha256 != checkpointed.watermark_sha256
    assert completed.classification == "internal"


@pytest.mark.parametrize(
    "events",
    [
        (),
        (evidence(EVENT_ONE, "agentmemory.test.completed.v1", b"{}"),),
        (
            evidence(EVENT_TWO, "agentmemory.task.completed.v1", b"{}"),
            evidence(EVENT_ONE, "agentmemory.test.completed.v1", b"{}"),
        ),
    ],
)
def test_evidence_bundle_rejects_empty_nonterminal_and_noncanonical_order(
    events: tuple[TaskEvidence, ...],
) -> None:
    with pytest.raises(MemoryValidationError):
        TaskEvidenceBundle.create(TASK_ID, scope(), events)


def test_candidate_batch_decodes_strict_schema_and_preserves_evidence_binding() -> None:
    source = bundle()
    decoded = MemoryCandidateBatch.decode(candidate_document(source), source.extractor_input_sha256)
    assert len(decoded.candidates) == 1
    candidate = decoded.candidates[0]
    assert candidate.memory_class is MemoryClass.DECISION
    assert candidate.evidence_ids == (EVENT_ONE, EVENT_TWO)
    assert candidate.content_sha256 == hashlib.sha256(candidate.canonical_content).hexdigest()


@pytest.mark.parametrize(
    "mutate",
    [
        _add_unknown_field,
        _duplicate_candidates,
        _invent_memory_class,
        _change_input_digest,
        _inject_nonfinite_confidence,
        _make_statement_noncanonical,
    ],
)
def test_candidate_batch_rejects_unknown_duplicate_malformed_or_noncanonical_output(
    mutate: Callable[[bytes], bytes],
) -> None:
    source = bundle()
    raw = mutate(candidate_document(source))
    with pytest.raises(MemoryValidationError):
        MemoryCandidateBatch.decode(raw, source.extractor_input_sha256)


def test_promotion_policy_accepts_supported_candidate_with_class_specific_threshold() -> None:
    source = bundle()
    candidate = MemoryCandidateBatch.decode(
        candidate_document(source), source.extractor_input_sha256
    ).candidates[0]
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    assert decision.disposition is PromotionDisposition.PROMOTE
    memory = candidate.activate(decision, source, extractor(), ACTOR_ID, NOW + timedelta(seconds=2))
    assert memory.status.value == "active"
    assert memory.evidence_ids == (EVENT_ONE, EVENT_TWO)
    assert memory.source_task_id == TASK_ID
    assert memory.created_by_event == EVENT_TWO
    assert memory.classification == "internal"


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        (
            _unsupported_document,
            "unsupported_evidence",
        ),
        (
            _low_confidence_document,
            "below_class_threshold",
        ),
        (
            _preference_without_explicit_evidence,
            "missing_explicit_preference_evidence",
        ),
    ],
)
def test_promotion_policy_rejects_unsupported_low_confidence_and_unproven_model_text(
    document: Callable[[TaskEvidenceBundle], bytes],
    reason: str,
) -> None:
    source = bundle()
    candidate = MemoryCandidateBatch.decode(
        document(source), source.extractor_input_sha256
    ).candidates[0]
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    assert decision.disposition is PromotionDisposition.REJECT
    assert decision.reason_code == reason
    with pytest.raises(MemoryValidationError):
        candidate.activate(decision, source, extractor(), ACTOR_ID, NOW)


def test_memory_identity_is_stable_for_same_task_watermark_extractor_and_candidate() -> None:
    source = bundle()
    candidate = MemoryCandidateBatch.decode(
        candidate_document(source), source.extractor_input_sha256
    ).candidates[0]
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    first = candidate.activate(decision, source, extractor(), ACTOR_ID, NOW)
    second = candidate.activate(decision, source, extractor(), ACTOR_ID, NOW + timedelta(days=1))
    assert first.memory_id == second.memory_id
    assert first.recorded_from != second.recorded_from


def test_derived_memory_inherits_maximum_classification_of_complete_extractor_input() -> None:
    source = TaskEvidenceBundle.create(
        TASK_ID,
        scope(),
        (
            evidence(
                EVENT_ONE,
                "agentmemory.test.completed.v1",
                b'{"passed":true}',
                classification="public",
            ),
            evidence(
                EVENT_TWO,
                "agentmemory.task.completed.v1",
                b'{"summary":"restricted task"}',
                occurred_at=NOW + timedelta(seconds=1),
                classification="restricted",
            ),
        ),
    )
    candidate = MemoryCandidateBatch.decode(
        candidate_document(
            source,
            memory_class="episode",
            evidence_ids=[EVENT_ONE],
        ),
        source.extractor_input_sha256,
    ).candidates[0]
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    memory = candidate.activate(decision, source, extractor(), ACTOR_ID, NOW + timedelta(seconds=2))
    assert source.classification == "restricted"
    assert memory.classification == "restricted"


@pytest.mark.parametrize(
    ("mutation", "field"),
    _MEMORY_MUTATIONS,
)
def test_memory_aggregate_rejects_forged_active_snapshots(
    mutation: Callable[[Memory], Memory],
    field: str,
) -> None:
    source = bundle()
    candidate = MemoryCandidateBatch.decode(
        candidate_document(source), source.extractor_input_sha256
    ).candidates[0]
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    memory = candidate.activate(decision, source, extractor(), ACTOR_ID, NOW + timedelta(seconds=2))
    with pytest.raises(MemoryValidationError) as failure:
        mutation(memory)
    assert failure.value.code_for(field) is not None
