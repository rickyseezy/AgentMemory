# pyright: reportPrivateUsage=false
"""MEM-001 adversarial value-object, policy, and commit boundary tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import timedelta, timezone
from functools import partial
from typing import TYPE_CHECKING, cast

import pytest

import agentmemory.memory.domain.consolidation as consolidation_module
from agentmemory.memory.domain.consolidation import (
    CandidateRejection,
    ConfidenceDimensions,
    ConsolidationCommit,
    ConsolidationResult,
    ExtractorIdentity,
    ExtractorRequest,
    ExtractorResponse,
    MemoryCandidateBatch,
    MemoryClass,
    MemoryPromotionPolicy,
    MemoryScope,
    TaskEvidence,
    TaskEvidenceBundle,
    consolidation_idempotency_key,
    derive_evidence_watermark,
    validate_consolidation_command_actor,
    validate_consolidation_command_time,
    validate_consolidation_command_trace,
)
from agentmemory.memory.domain.errors import MemoryValidationError
from tests.memory.test_mem001_consolidation_application import (
    ACTOR_ID,
    CAUSATION_ID,
    CORRELATION_ID,
    GRANT_ID,
)
from tests.memory.test_mem001_consolidation_domain import (
    BRAIN_ID,
    EVENT_ONE,
    EVENT_TWO,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
    TASK_ID,
    bundle,
    candidate_document,
    evidence,
    extractor,
    scope,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.domain.consolidation import JsonValue, Memory, MemoryCandidate


def _document(source: TaskEvidenceBundle) -> dict[str, JsonValue]:
    return cast("dict[str, JsonValue]", json.loads(candidate_document(source)))


def _encode(document: dict[str, JsonValue]) -> bytes:
    return json.dumps(document, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()


def _candidate(source: TaskEvidenceBundle | None = None) -> MemoryCandidate:
    resolved = source or bundle()
    return MemoryCandidateBatch.decode(
        candidate_document(resolved),
        resolved.extractor_input_sha256,
    ).candidates[0]


def _active_memory(source: TaskEvidenceBundle | None = None) -> Memory:
    resolved = source or bundle()
    candidate = _candidate(resolved)
    decision = MemoryPromotionPolicy.production().evaluate(candidate, resolved)
    return candidate.activate(
        decision,
        resolved,
        extractor(),
        ACTOR_ID,
        NOW + timedelta(seconds=2),
    )


_EVIDENCE_MUTATIONS: list[tuple[Callable[[TaskEvidence], TaskEvidence], str]] = [
    (lambda item: replace(item, event_type="invalid"), "evidence.event_type"),
    (lambda item: replace(item, classification="secret"), "evidence.classification"),
    (lambda item: replace(item, payload=b""), "evidence.payload"),
    (lambda item: replace(item, payload_sha256="f" * 64), "evidence.payload_sha256"),
    (
        lambda item: replace(
            item,
            payload=b'{"b":1,"a":2}',
            payload_sha256=hashlib.sha256(b'{"b":1,"a":2}').hexdigest(),
        ),
        "evidence.payload",
    ),
]


_BATCH_MUTATIONS: list[tuple[Callable[[dict[str, JsonValue]], None], str]] = [
    (lambda value: value.update(schema="agentmemory.memory-candidates.v2"), "unsupported"),
    (lambda value: value.update(candidates={}), "count_invalid"),
    (
        lambda value: value.update(candidates=cast("list[JsonValue]", value["candidates"]) * 33),
        "count_invalid",
    ),
]


def _commit(memory: Memory | None = None) -> ConsolidationCommit:
    source = bundle()
    item = memory or _active_memory(source)
    identity = extractor()
    key = consolidation_idempotency_key(TASK_ID, source.watermark_sha256, identity.fingerprint)
    return ConsolidationCommit(
        "mem001-boundary",
        ACTOR_ID,
        GRANT_ID,
        CORRELATION_ID,
        CAUSATION_ID,
        key,
        TASK_ID,
        scope(),
        source.watermark_sha256,
        source.extractor_input_sha256,
        identity,
        EVENT_TWO,
        "memory-promotion.v1",
        source.classification,
        source.retention_policy_id,
        (item,),
        (),
        NOW + timedelta(seconds=1),
        NOW + timedelta(seconds=2),
    )


def _assert_violation(call: Callable[[], object], field: str, code: str) -> None:
    with pytest.raises(MemoryValidationError) as failure:
        call()
    assert failure.value.code_for(field) == code


def test_derivation_and_wire_helpers_match_fixed_compatibility_vectors() -> None:
    source = bundle()
    identity = extractor()
    records = tuple(
        (item.event_id, item.event_type, item.canonical_event_sha256) for item in source.evidence
    )
    assert (
        derive_evidence_watermark(records)
        == "a173e60a13393c03df1481a5c0935d91f9ec2bd3986b5825702087f563bae79c"
    )
    assert (
        consolidation_idempotency_key(
            source.task_id,
            source.watermark_sha256,
            identity.fingerprint,
        )
        == "1426cecc3a54fac4ef8dd8db2a3d28dee32b87ec9b9ea6ee3e832f5739814f5e"
    )
    assert (
        consolidation_module._memory_id(
            source,
            identity,
            "projection-rebuild-shadow-generation",
            "b" * 64,
        )
        == "019f7f65-b9e8-7573-9e5e-bac2377663b3"
    )
    assert consolidation_module._length_framed(("a", "é")) == bytes.fromhex(
        "000000016100000002c3a9"
    )
    assert (
        consolidation_module._result_digest(
            ("a" * 64, source.task_id, "b" * 64, "c" * 64),
            ("018f0000-0000-7000-8000-000000000501",),
            2,
        )
        == "f9acf73ebfcc95aca518762eabcdb24db6b80c96e0db22176eea9668aa575e13"
    )
    assert consolidation_module._canonical_json({"é": [1, True, None], "a": "x"}) == (
        b'{"a":"x","\xc3\xa9":[1,true,null]}'
    )


def test_evidence_watermark_rejects_each_invalid_coordinate_with_exact_reason() -> None:
    valid = (EVENT_ONE, "agentmemory.test.completed.v1", "a" * 64)
    _assert_violation(lambda: derive_evidence_watermark(()), "evidence_watermark", "empty")
    _assert_violation(
        lambda: derive_evidence_watermark((("invalid", valid[1], valid[2]),)),
        "evidence_watermark.event_id",
        "invalid_uuid7",
    )
    _assert_violation(
        lambda: derive_evidence_watermark(((valid[0], "invalid", valid[2]),)),
        "evidence_watermark.event_type",
        "invalid",
    )
    _assert_violation(
        lambda: derive_evidence_watermark(((valid[0], valid[1], "0" * 64),)),
        "evidence_watermark.canonical_sha256",
        "invalid_digest",
    )
    _assert_violation(
        lambda: derive_evidence_watermark((valid, valid)),
        "evidence_watermark",
        "duplicate",
    )


def test_command_validators_bind_every_actor_trace_and_time_coordinate() -> None:
    validate_consolidation_command_actor("operation-1", ACTOR_ID, GRANT_ID)
    validate_consolidation_command_trace(CORRELATION_ID, CAUSATION_ID, TASK_ID, EVENT_TWO)
    validate_consolidation_command_time(NOW, NOW + timedelta(seconds=1))
    for call, field, code in (
        (
            lambda: validate_consolidation_command_actor("INVALID", ACTOR_ID, GRANT_ID),
            "operation_id",
            "invalid_token",
        ),
        (
            lambda: validate_consolidation_command_actor("operation-1", "invalid", GRANT_ID),
            "actor_id",
            "invalid_uuid7",
        ),
        (
            lambda: validate_consolidation_command_actor("operation-1", ACTOR_ID, "invalid"),
            "grant_id",
            "invalid_uuid7",
        ),
        (
            lambda: validate_consolidation_command_trace(
                "invalid", CAUSATION_ID, TASK_ID, EVENT_TWO
            ),
            "correlation_id",
            "invalid_uuid7",
        ),
        (
            lambda: validate_consolidation_command_trace(
                CORRELATION_ID, "invalid", TASK_ID, EVENT_TWO
            ),
            "causation_id",
            "invalid_uuid7",
        ),
        (
            lambda: validate_consolidation_command_trace(
                CORRELATION_ID, CAUSATION_ID, "invalid", EVENT_TWO
            ),
            "task_id",
            "invalid_uuid7",
        ),
        (
            lambda: validate_consolidation_command_trace(
                CORRELATION_ID, CAUSATION_ID, TASK_ID, "invalid"
            ),
            "terminal_event_id",
            "invalid_uuid7",
        ),
        (
            lambda: validate_consolidation_command_time(
                NOW.replace(tzinfo=None), NOW + timedelta(seconds=1)
            ),
            "requested_at",
            "not_utc",
        ),
        (
            lambda: validate_consolidation_command_time(NOW, NOW.replace(tzinfo=None)),
            "deadline",
            "not_utc",
        ),
        (
            lambda: validate_consolidation_command_time(NOW, NOW),
            "deadline",
            "not_after_request",
        ),
    ):
        _assert_violation(call, field, code)


def test_strict_json_and_primitive_decoders_preserve_exact_contract() -> None:
    assert consolidation_module._decode_json(b'{"a":1}', "payload", 7) == {"a": 1}
    _assert_violation(
        lambda: consolidation_module._decode_json(b"", "payload", 7),
        "payload",
        "size_invalid",
    )
    _assert_violation(
        lambda: consolidation_module._decode_json(b"12345678", "payload", 7),
        "payload",
        "size_invalid",
    )
    _assert_violation(
        lambda: consolidation_module._decode_json(b'{"a":1,"a":2}', "payload", 64),
        "payload",
        "duplicate_key",
    )
    _assert_violation(
        lambda: consolidation_module._decode_json(b"NaN", "payload", 64),
        "payload",
        "non_finite",
    )
    _assert_violation(
        lambda: consolidation_module._decode_json(b"{", "payload", 64),
        "payload",
        "invalid_json",
    )
    _assert_violation(
        lambda: consolidation_module._decode_json(b'"\xff"', "payload", 64),
        "payload",
        "invalid_json",
    )
    _assert_violation(
        lambda: consolidation_module._canonical_json(float("nan")),
        "json",
        "invalid_value",
    )
    assert consolidation_module._require_object({"a": 1}, "object") == {"a": 1}
    _assert_violation(
        lambda: consolidation_module._require_object([], "object"),
        "object",
        "object_required",
    )
    consolidation_module._require_exact_fields({"a": 1}, {"a"}, "fields")
    _assert_violation(
        lambda: consolidation_module._require_exact_fields({"a": 1}, {"b"}, "fields"),
        "fields",
        "fields_invalid",
    )
    assert consolidation_module._require_string("value", "name") == "value"
    _assert_violation(
        lambda: consolidation_module._require_string(1, "name"),
        "name",
        "string_required",
    )


def test_candidate_nested_decoders_bind_exact_parent_fields_and_values() -> None:
    document = _document(bundle())
    raw_candidate = cast("list[JsonValue]", document["candidates"])[0]
    candidate = consolidation_module._candidate(raw_candidate, 0)
    assert candidate.candidate_key == "projection-rebuild-shadow-generation"
    assert candidate.memory_class is MemoryClass.DECISION
    assert candidate.statement == "Projection rebuilds use immutable shadow generations."
    assert dict(candidate.scope.canonical) == dict(scope().canonical)
    assert candidate.confidence.canonical == {
        "evidence_support": 9000,
        "extraction_quality": 9000,
        "source_reliability": 9000,
    }
    assert candidate.valid_from == NOW
    assert candidate.valid_to is None
    assert candidate.evidence_ids == (EVENT_ONE, EVENT_TWO)

    scope_document: dict[str, JsonValue] = {
        "brain_id": BRAIN_ID,
        "checkout_id": None,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }
    assert consolidation_module._scope(scope_document, "candidate") == scope()
    _assert_violation(
        lambda: consolidation_module._scope({**scope_document, "checkout_id": 1}, "candidate"),
        "candidate.scope.checkout_id",
        "string_or_null_required",
    )
    confidence_document: dict[str, JsonValue] = {
        "evidence_support": 1,
        "extraction_quality": 3,
        "source_reliability": 2,
    }
    assert consolidation_module._confidence(confidence_document, "candidate").canonical == {
        "evidence_support": 1,
        "extraction_quality": 3,
        "source_reliability": 2,
    }
    for name in confidence_document:
        invalid = dict(confidence_document)
        invalid[name] = True
        _assert_violation(
            partial(consolidation_module._confidence, invalid, "candidate"),
            f"candidate.confidence.{name}",
            "integer_required",
        )


def test_time_uuid_digest_token_and_text_primitives_are_exact() -> None:
    text = "2026-07-20T12:00:00.000000Z"
    assert consolidation_module._parse_time(text, "when") == NOW
    assert consolidation_module._format_time(NOW) == text
    _assert_violation(
        lambda: consolidation_module._parse_time("2026-07-20T12:00:00Z", "when"),
        "when",
        "invalid_timestamp",
    )
    _assert_violation(
        lambda: consolidation_module._parse_time("2026-07-20T12:00:00.00000Z", "when"),
        "when",
        "non_canonical",
    )
    _assert_violation(
        lambda: consolidation_module._format_time(NOW.replace(tzinfo=None)),
        "timestamp",
        "not_utc",
    )
    consolidation_module._require_uuid7(EVENT_ONE, "identity")
    for invalid in ("invalid", EVENT_ONE.upper(), "550e8400-e29b-41d4-a716-446655440000"):
        _assert_violation(
            partial(consolidation_module._require_uuid7, invalid, "identity"),
            "identity",
            "invalid_uuid7",
        )
    consolidation_module._require_digest("a" * 64, "digest")
    for invalid in ("a" * 63, "A" * 64, "0" * 64):
        _assert_violation(
            partial(consolidation_module._require_digest, invalid, "digest"),
            "digest",
            "invalid_digest",
        )
    consolidation_module._require_token("valid-token.v1", "token")
    _assert_violation(
        lambda: consolidation_module._require_token("INVALID", "token"),
        "token",
        "invalid_token",
    )
    consolidation_module._require_bounded_text("valid", "text", 5)
    for invalid in ("", "longer", "bad\n"):
        _assert_violation(
            partial(consolidation_module._require_bounded_text, invalid, "text", 5),
            "text",
            "invalid_text",
        )


def test_scope_confidence_and_extractor_identity_reject_noncanonical_coordinates() -> None:
    assert (
        MemoryScope(
            BRAIN_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            "018f0000-0000-7000-8000-000000000030",
        ).checkout_id
        is not None
    )
    for values in ((True, 1, 1), (-1, 1, 1), (1, 10_001, 1)):
        with pytest.raises(MemoryValidationError):
            ConfidenceDimensions(*values)
    with pytest.raises(MemoryValidationError) as semver:
        replace(extractor(), extractor_version="latest")
    assert semver.value.code_for("extractor.extractor_version") == "invalid_semver"
    with pytest.raises(MemoryValidationError) as schema:
        replace(extractor(), output_schema="memory-candidates.v2")
    assert schema.value.code_for("extractor.output_schema") == "unsupported"


@pytest.mark.parametrize(
    ("mutation", "field"),
    _EVIDENCE_MUTATIONS,
)
def test_task_evidence_rejects_malformed_or_unauthenticated_payloads(
    mutation: Callable[[TaskEvidence], TaskEvidence],
    field: str,
) -> None:
    item = evidence(EVENT_ONE, "agentmemory.test.completed.v1", b"{}")
    with pytest.raises(MemoryValidationError) as failure:
        mutation(item)
    assert failure.value.code_for(field) is not None


def test_evidence_bundle_rejects_cross_scope_retention_and_oversized_snapshots() -> None:
    first = evidence(EVENT_ONE, "agentmemory.test.completed.v1", b"{}")
    terminal = evidence(
        EVENT_TWO,
        "agentmemory.task.completed.v1",
        b"{}",
        occurred_at=NOW + timedelta(seconds=1),
    )
    with pytest.raises(MemoryValidationError) as retention:
        TaskEvidenceBundle.create(
            TASK_ID,
            scope(),
            (first, replace(terminal, retention_policy_id="long_term")),
        )
    assert retention.value.code_for("evidence") == "retention_mismatch"

    other_scope = MemoryScope(
        BRAIN_ID,
        PROJECT_ID,
        "018f0000-0000-7000-8000-000000000021",
        None,
    )
    with pytest.raises(MemoryValidationError) as scoped:
        TaskEvidenceBundle.create(TASK_ID, other_scope, (first, terminal))
    assert scoped.value.code_for("evidence") == "scope_mismatch"

    payload = json.dumps({"value": "x" * 59_980}, separators=(",", ":")).encode()
    items = tuple(
        evidence(
            f"018f0000-0000-7000-8000-{index:012x}",
            ("agentmemory.task.completed.v1" if index == 18 else "agentmemory.test.completed.v1"),
            payload,
            occurred_at=NOW + timedelta(seconds=index),
        )
        for index in range(1, 19)
    )
    with pytest.raises(MemoryValidationError) as oversized:
        TaskEvidenceBundle.create(TASK_ID, scope(), items)
    assert oversized.value.code_for("evidence") == "bytes_exceeded"


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("valid_to", "2026-07-21T12:00:00.000000Z", None),
        ("valid_to", "2026-07-20T12:00:00.000000Z", "not_after_start"),
        ("evidence_ids", [], "not_canonical"),
        ("evidence_ids", [EVENT_ONE, EVENT_ONE], "not_canonical"),
        ("evidence_ids", 1, "array_required"),
        ("confidence", {"evidence_support": True}, "fields_invalid"),
        ("valid_from", "not-a-time", "invalid_timestamp"),
    ],
)
def test_candidate_schema_enforces_temporal_evidence_and_confidence_boundaries(
    field: str,
    value: JsonValue,
    expected: str | None,
) -> None:
    source = bundle()
    document = _document(source)
    candidate = cast("dict[str, JsonValue]", cast("list[JsonValue]", document["candidates"])[0])
    candidate[field] = value
    if expected is None:
        decoded = MemoryCandidateBatch.decode(_encode(document), source.extractor_input_sha256)
        assert decoded.candidates[0].valid_to is not None
        return
    with pytest.raises(MemoryValidationError) as failure:
        MemoryCandidateBatch.decode(_encode(document), source.extractor_input_sha256)
    assert any(item.code == expected for item in failure.value.violations)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    _BATCH_MUTATIONS,
)
def test_candidate_batch_rejects_unsupported_schema_and_unbounded_shape(
    mutation: Callable[[dict[str, JsonValue]], None],
    expected: str,
) -> None:
    source = bundle()
    document = _document(source)
    mutation(document)
    with pytest.raises(MemoryValidationError) as failure:
        MemoryCandidateBatch.decode(_encode(document), source.extractor_input_sha256)
    assert any(item.code == expected for item in failure.value.violations)


def test_policy_covers_scope_evidence_count_lesson_and_unresolved_work_rules() -> None:
    policy = MemoryPromotionPolicy.production()
    source = bundle()
    decision = policy.evaluate(
        replace(_candidate(source), scope=replace(scope(), checkout_id=None)), source
    )
    assert decision.disposition.value == "promote"

    different_scope = MemoryScope(
        BRAIN_ID,
        PROJECT_ID,
        "018f0000-0000-7000-8000-000000000021",
        None,
    )
    assert policy.evaluate(
        replace(_candidate(source), scope=different_scope), source
    ).reason_code == ("scope_mismatch")
    assert (
        policy.evaluate(
            replace(_candidate(source), evidence_ids=(EVENT_ONE,)),
            source,
        ).reason_code
        == "insufficient_evidence"
    )

    lesson_document = candidate_document(source, memory_class="lesson")
    lesson = MemoryCandidateBatch.decode(
        lesson_document,
        source.extractor_input_sha256,
    ).candidates[0]
    assert policy.evaluate(lesson, source).disposition.value == "promote"
    no_outcome = TaskEvidenceBundle.create(
        TASK_ID,
        scope(),
        (
            evidence(EVENT_ONE, "agentmemory.tool.completed.v1", b"{}"),
            evidence(
                EVENT_TWO,
                "agentmemory.task.completed.v1",
                b"{}",
                occurred_at=NOW + timedelta(seconds=1),
            ),
        ),
    )
    missing_outcome = MemoryCandidateBatch.decode(
        candidate_document(no_outcome, memory_class="lesson"),
        no_outcome.extractor_input_sha256,
    ).candidates[0]
    assert policy.evaluate(missing_outcome, no_outcome).reason_code == "missing_outcome_evidence"

    unresolved = MemoryCandidateBatch.decode(
        candidate_document(source, memory_class="unresolved_work", evidence_ids=[EVENT_TWO]),
        source.extractor_input_sha256,
    ).candidates[0]
    assert policy.evaluate(unresolved, source).reason_code == "completed_task_cannot_be_unresolved"
    checkpoint = bundle(terminal="agentmemory.task.checkpointed.v1")
    checkpointed = MemoryCandidateBatch.decode(
        candidate_document(
            checkpoint,
            memory_class="unresolved_work",
            evidence_ids=[EVENT_TWO],
        ),
        checkpoint.extractor_input_sha256,
    ).candidates[0]
    assert policy.evaluate(checkpointed, checkpoint).disposition.value == "promote"


@pytest.mark.parametrize("field", ["evidence_support", "source_reliability", "extraction_quality"])
def test_policy_rejects_each_confidence_dimension_below_class_threshold(field: str) -> None:
    source = bundle()
    candidate = _candidate(source)
    confidence = replace(candidate.confidence, **{field: 0})
    decision = MemoryPromotionPolicy.production().evaluate(
        replace(candidate, confidence=confidence),
        source,
    )
    assert decision.reason_code == "below_class_threshold"


def test_extractor_request_and_response_reject_unbound_or_oversized_bytes() -> None:
    source = bundle()
    key = consolidation_idempotency_key(TASK_ID, source.watermark_sha256, extractor().fingerprint)
    request = ExtractorRequest(
        "mem001-boundary",
        key,
        TASK_ID,
        source.extractor_input_bytes,
        source.extractor_input_sha256,
        source.classification,
        "memory_consolidation",
        NOW + timedelta(minutes=1),
        extractor(),
    )
    with pytest.raises(MemoryValidationError):
        replace(request, input_sha256="f" * 64)
    with pytest.raises(MemoryValidationError) as classification:
        replace(request, classification="secret")
    assert classification.value.code_for("classification") == "unsupported"
    with pytest.raises(MemoryValidationError) as purpose:
        replace(request, purpose="chat")
    assert purpose.value.code_for("purpose") == "unsupported"

    output = candidate_document(source)
    response = ExtractorResponse(
        request.operation_id,
        request.idempotency_key,
        request.task_id,
        request.input_sha256,
        request.extractor,
        output,
        hashlib.sha256(output).hexdigest(),
    )
    assert response.matches(request)
    assert replace(response, operation_id="different").matches(request) is False
    with pytest.raises(MemoryValidationError) as digest:
        replace(response, output_sha256="f" * 64)
    assert digest.value.code_for("output_bytes") == "digest_mismatch"


def test_consolidation_result_and_commit_reject_divergent_persisted_state() -> None:
    commit = _commit()
    result = commit.result
    mutations: tuple[Callable[[], ConsolidationResult], ...] = (
        lambda: replace(result, memory_ids=(result.memory_ids[0], result.memory_ids[0])),
        lambda: replace(result, promoted=0),
        lambda: replace(result, result_sha256="f" * 64),
    )
    for mutation in mutations:
        with pytest.raises(MemoryValidationError):
            mutation()

    with pytest.raises(MemoryValidationError) as key:
        replace(commit, idempotency_key="f" * 64)
    assert key.value.code_for("idempotency_key") == "mismatch"
    with pytest.raises(MemoryValidationError) as time:
        replace(commit, completed_at=commit.requested_at - timedelta(microseconds=1))
    assert time.value.code_for("completed_at") == "before_request"
    with pytest.raises(MemoryValidationError) as lineage:
        replace(
            commit,
            memories=(replace(commit.memories[0], retention_policy_id="different"),),
        )
    assert lineage.value.code_for("memories") == "lineage_mismatch"
    with pytest.raises(MemoryValidationError) as duplicate_memory:
        replace(commit, memories=(commit.memories[0], commit.memories[0]))
    assert duplicate_memory.value.code_for("memories") == "duplicate_identity"

    rejection = CandidateRejection("a" * 64, MemoryClass.DECISION, "b" * 64, "unsupported")
    empty_commit = replace(commit, memories=(), rejections=(rejection,))
    assert empty_commit.result.rejected == 1
    with pytest.raises(MemoryValidationError) as duplicate_rejection:
        replace(empty_commit, rejections=(rejection, rejection))
    assert duplicate_rejection.value.code_for("rejections") == "duplicate_identity"


def test_validation_errors_are_deduplicated_sorted_and_queryable() -> None:
    violation = MemoryValidationError.single("field", "invalid")
    assert violation.code_for("field") == "invalid"
    assert violation.code_for("other") is None
    with pytest.raises(ValueError, match="at least one memory field violation"):
        MemoryValidationError(())


def test_consolidation_result_constructor_rejects_negative_rejection_count() -> None:
    result = _commit().result
    with pytest.raises(MemoryValidationError):
        ConsolidationResult(
            result.idempotency_key,
            result.task_id,
            result.evidence_watermark_sha256,
            result.extractor_fingerprint,
            result.memory_ids,
            result.promoted,
            -1,
            result.result_sha256,
        )


def test_extractor_identity_fingerprint_changes_for_every_immutable_coordinate() -> None:
    identity = extractor()
    variants = (
        replace(identity, extractor_id="agentmemory.other-extractor"),
        replace(identity, extractor_version="1.0.1"),
        replace(identity, model_id="qwen3-8b"),
        replace(identity, model_revision="qwen3-4b-q4_k_m-r2"),
    )
    assert all(item.fingerprint != identity.fingerprint for item in variants)
    assert len({item.fingerprint for item in variants}) == len(variants)


def test_non_utc_times_and_invalid_uuid_token_digest_are_content_free() -> None:
    naive = NOW.replace(tzinfo=None)
    with pytest.raises(MemoryValidationError) as time:
        replace(_candidate(), valid_from=naive)
    assert time.value.code_for("candidate.valid_from") == "not_utc"
    with pytest.raises(MemoryValidationError) as uuid:
        MemoryScope("not-a-uuid", PROJECT_ID, REPOSITORY_ID, None)
    assert uuid.value.code_for("scope.brain_id") == "invalid_uuid7"
    with pytest.raises(MemoryValidationError) as token:
        replace(extractor(), extractor_id="Invalid Token")
    assert token.value.code_for("extractor.extractor_id") == "invalid_token"
    with pytest.raises(MemoryValidationError) as digest:
        consolidation_idempotency_key(TASK_ID, "0" * 64, extractor().fingerprint)
    assert digest.value.code_for("evidence_watermark_sha256") == "invalid_digest"


def test_valid_to_and_recorded_to_accept_strictly_later_utc_boundaries() -> None:
    candidate = _candidate()
    bounded = replace(candidate, valid_to=candidate.valid_from + timedelta(microseconds=1))
    source = bundle()
    decision = MemoryPromotionPolicy.production().evaluate(bounded, source)
    memory = bounded.activate(decision, source, extractor(), ACTOR_ID, NOW + timedelta(seconds=2))
    recorded = replace(memory, recorded_to=memory.recorded_from + timedelta(microseconds=1))
    assert recorded.valid_to is not None
    assert recorded.recorded_to is not None


def test_task_evidence_accepts_all_supported_classifications() -> None:
    for classification in ("public", "internal", "confidential", "restricted", "local_only"):
        item = evidence(
            EVENT_ONE,
            "agentmemory.test.completed.v1",
            b"{}",
            classification=classification,
        )
        assert item.classification == classification


def test_extractor_model_identifier_rejects_control_characters() -> None:
    with pytest.raises(MemoryValidationError) as failure:
        ExtractorIdentity(
            "agentmemory.local-extractor",
            "1.0.0",
            "model\nsecret",
            "revision",
            "memory-candidates.v1",
        )
    assert failure.value.code_for("extractor.model_id") == "invalid_text"


def test_candidate_batch_rejects_non_object_root_and_non_string_fields() -> None:
    source = bundle()
    with pytest.raises(MemoryValidationError):
        MemoryCandidateBatch.decode(b"[]", source.extractor_input_sha256)
    document = _document(source)
    candidate = cast("dict[str, JsonValue]", cast("list[JsonValue]", document["candidates"])[0])
    candidate["statement"] = 7
    with pytest.raises(MemoryValidationError):
        MemoryCandidateBatch.decode(_encode(document), source.extractor_input_sha256)


def test_task_evidence_rejects_invalid_json_and_duplicate_keys() -> None:
    for raw in (b"{", b'{"a":1,"a":2}'):
        with pytest.raises(MemoryValidationError):
            evidence(EVENT_ONE, "agentmemory.test.completed.v1", raw)


def test_zero_candidate_batch_is_valid_and_deterministic() -> None:
    source = bundle()
    document = _document(source)
    document["candidates"] = []
    batch = MemoryCandidateBatch.decode(_encode(document), source.extractor_input_sha256)
    assert batch.candidates == ()


def test_memory_candidate_activation_rejects_unsupported_evidence_even_with_forged_receipt() -> (
    None
):
    source = bundle()
    candidate = replace(
        _candidate(source),
        memory_class=MemoryClass.EPISODE,
        evidence_ids=("018f0000-0000-7000-8000-000000000399",),
    )
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    forged = replace(decision, disposition=type(decision.disposition).PROMOTE)
    with pytest.raises(MemoryValidationError) as failure:
        candidate.activate(
            forged,
            source,
            extractor(),
            ACTOR_ID,
            NOW + timedelta(seconds=2),
        )
    assert failure.value.code_for("promotion") == "unsupported_evidence"


def test_evidence_order_tie_breaks_by_canonical_event_identifier() -> None:
    first = evidence(EVENT_ONE, "agentmemory.test.completed.v1", b"{}")
    terminal = evidence(EVENT_TWO, "agentmemory.task.completed.v1", b"{}")
    snapshot = TaskEvidenceBundle.create(TASK_ID, scope(), (first, terminal))
    assert snapshot.evidence == (first, terminal)


def test_extractor_response_match_checks_each_operation_coordinate() -> None:
    source = bundle()
    key = consolidation_idempotency_key(TASK_ID, source.watermark_sha256, extractor().fingerprint)
    request = ExtractorRequest(
        "mem001-boundary",
        key,
        TASK_ID,
        source.extractor_input_bytes,
        source.extractor_input_sha256,
        "internal",
        "memory_consolidation",
        NOW + timedelta(minutes=1),
        extractor(),
    )
    output = candidate_document(source)
    response = ExtractorResponse(
        request.operation_id,
        request.idempotency_key,
        request.task_id,
        request.input_sha256,
        request.extractor,
        output,
        hashlib.sha256(output).hexdigest(),
    )
    variants = (
        replace(response, operation_id="other"),
        replace(response, idempotency_key="f" * 64),
        replace(response, task_id="018f0000-0000-7000-8000-000000000202"),
        replace(response, input_sha256="f" * 64),
        replace(response, extractor=replace(extractor(), model_revision="revision-r2")),
    )
    assert all(item.matches(request) is False for item in variants)


def test_utc_offset_other_than_zero_is_rejected() -> None:
    non_utc = NOW.astimezone(timezone(timedelta(hours=1)))
    with pytest.raises(MemoryValidationError):
        replace(_candidate(), valid_from=non_utc)
