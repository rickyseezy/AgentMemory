"""MEM-001 language-neutral golden extraction and promotion corpus."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, cast

from agentmemory.memory.domain.consolidation import (
    MemoryCandidateBatch,
    MemoryPromotionPolicy,
    TaskEvidenceBundle,
)
from tests.memory.test_mem001_consolidation_domain import (
    EVENT_ONE,
    EVENT_TWO,
    NOW,
    TASK_ID,
    evidence,
    scope,
)

if TYPE_CHECKING:
    from agentmemory.memory.domain.consolidation import JsonValue

_CORPUS = Path(__file__).parents[1] / "golden" / "mem001" / "extraction-v1.json"
_UNSUPPORTED_EVENT = "018f0000-0000-7000-8000-000000000399"


def test_language_neutral_golden_corpus_covers_every_class_and_rejection_rule() -> None:
    corpus = cast("dict[str, JsonValue]", json.loads(_CORPUS.read_bytes()))
    assert corpus["schema"] == "agentmemory.mem001-extraction-golden.v1"
    cases = cast("list[dict[str, JsonValue]]", corpus["cases"])
    observed_classes: set[str] = set()
    observed_rejections: set[str] = set()
    for case in cases:
        source = _source(cast("list[str]", case["evidence_types"]))
        candidate_spec = cast("dict[str, JsonValue]", case["candidate"])
        memory_class = str(candidate_spec["memory_class"])
        observed_classes.add(memory_class)
        output = _candidate_output(str(case["id"]), source, candidate_spec)
        candidate = MemoryCandidateBatch.decode(
            output,
            source.extractor_input_sha256,
        ).candidates[0]
        decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
        expected = cast("dict[str, JsonValue]", case["expected"])
        assert decision.disposition.value == expected["disposition"], case["id"]
        assert decision.reason_code == expected["reason"], case["id"]
        if decision.disposition.value == "reject":
            observed_rejections.add(decision.reason_code)

    assert observed_classes == {
        "decision",
        "constraint",
        "procedure",
        "preference",
        "lesson",
        "episode",
        "unresolved_work",
    }
    assert observed_rejections == {
        "unsupported_evidence",
        "insufficient_evidence",
        "below_class_threshold",
        "missing_explicit_preference_evidence",
        "missing_outcome_evidence",
        "completed_task_cannot_be_unresolved",
    }


def _source(event_types: list[str]) -> TaskEvidenceBundle:
    event_ids = (EVENT_ONE, EVENT_TWO)
    items = tuple(
        evidence(
            event_ids[index],
            event_type,
            json.dumps(
                {"observation": event_type},
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            occurred_at=NOW + timedelta(seconds=index),
        )
        for index, event_type in enumerate(event_types)
    )
    return TaskEvidenceBundle.create(TASK_ID, scope(), items)


def _candidate_output(
    case_id: str,
    source: TaskEvidenceBundle,
    specification: dict[str, JsonValue],
) -> bytes:
    evidence_indexes = cast("list[int]", specification["evidence"])
    evidence_ids = [
        _UNSUPPORTED_EVENT if index == 99 else source.evidence[index].event_id
        for index in evidence_indexes
    ]
    document = {
        "candidates": [
            {
                "candidate_key": case_id,
                "confidence": {
                    "evidence_support": specification["support"],
                    "extraction_quality": specification["extraction"],
                    "source_reliability": specification["reliability"],
                },
                "evidence_ids": sorted(evidence_ids),
                "memory_class": specification["memory_class"],
                "scope": dict(source.scope.canonical),
                "statement": f"Golden memory candidate {case_id}.",
                "valid_from": "2026-07-20T12:00:00.000000Z",
                "valid_to": None,
            }
        ],
        "input_sha256": source.extractor_input_sha256,
        "schema": "agentmemory.memory-candidates.v1",
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
