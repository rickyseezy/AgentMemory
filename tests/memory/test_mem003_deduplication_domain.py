"""TDD acceptance tests for MEM-003 deterministic compatibility and merge planning."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.memory.domain.consolidation import (
    ConfidenceDimensions,
    ExtractorIdentity,
    Memory,
    MemoryCandidate,
    MemoryClass,
    MemoryPromotionPolicy,
    MemoryScope,
    TaskEvidence,
    TaskEvidenceBundle,
)
from agentmemory.memory.domain.deduplication import (
    DeduplicationCommit,
    DeduplicationMode,
    DeduplicationResult,
    MemoryCompatibilityPolicy,
    MemoryDeduplicationProfile,
    MemoryMergePlan,
    MemoryPolarity,
    SemanticMemoryCandidate,
    canonical_subject,
    cosine_similarity_basis_points,
    deduplication_idempotency_key,
    validate_deduplication_coordinate,
)
from agentmemory.memory.domain.errors import MemoryValidationError

NOW = datetime(2026, 7, 21, 10, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
PROJECT_ID = "018f0000-0000-7000-8000-000000000002"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000003"
TASK_ID = "018f0000-0000-7000-8000-000000000004"
ACTOR_ID = "018f0000-0000-7000-8000-000000000005"
EVIDENCE_ONE = "018f0000-0000-7000-8000-000000000006"
EVIDENCE_TWO = "018f0000-0000-7000-8000-000000000007"


def test_exact_equivalents_merge_first_and_retain_all_evidence_and_redirects() -> None:
    first = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    second = _profile(_memory("Use PostgreSQL", EVIDENCE_TWO, NOW + timedelta(minutes=1)))
    semantic = SemanticMemoryCandidate(
        replace(second, content_sha256="a" * 64),
        10_000,
    )

    plan = MemoryMergePlan.create(
        first,
        (second,),
        (semantic,),
        MemoryCompatibilityPolicy(),
    )

    assert plan is not None
    assert plan.mode is DeduplicationMode.EXACT
    assert plan.survivor.memory_id == first.memory_id
    assert plan.source_ids == (second.memory_id,)
    assert plan.evidence_ids == (EVIDENCE_ONE, EVIDENCE_TWO)
    assert len(plan.result_sha256) == 64


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("Use PostgreSQL for persistence", "Postgres should be used for persistence"),
        ("Utilize Redis cache", "Redis is used as the cache"),
    ],
)
def test_paraphrase_golden_corpus_merges_only_after_semantic_threshold(
    left: str,
    right: str,
) -> None:
    target = _profile(_memory(left, EVIDENCE_ONE, NOW))
    candidate = _profile(_memory(right, EVIDENCE_TWO, NOW + timedelta(minutes=1)))
    assert target.subject_key == candidate.subject_key
    assert target.content_sha256 != candidate.content_sha256
    assert (
        MemoryMergePlan.create(
            target,
            (),
            (SemanticMemoryCandidate(candidate, 8999),),
            MemoryCompatibilityPolicy(),
        )
        is None
    )
    plan = MemoryMergePlan.create(
        target,
        (),
        (SemanticMemoryCandidate(candidate, 9000),),
        MemoryCompatibilityPolicy(),
    )
    assert plan is not None
    assert plan.mode is DeduplicationMode.SEMANTIC


def test_opposite_polarity_and_scope_or_time_mismatch_never_merge() -> None:
    target = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    negated = _profile(_memory("Do not use PostgreSQL", EVIDENCE_TWO, NOW + timedelta(minutes=1)))
    other_scope = replace(
        negated, polarity=target.polarity, scope=replace(target.scope, checkout_id=TASK_ID)
    )
    other_time = replace(negated, polarity=target.polarity, valid_from=NOW + timedelta(days=1))
    policy = MemoryCompatibilityPolicy()

    assert target.subject_key == negated.subject_key
    assert target.polarity is MemoryPolarity.AFFIRMED
    assert negated.polarity is MemoryPolarity.NEGATED
    for candidate in (negated, other_scope, other_time):
        assert (
            MemoryMergePlan.create(
                target,
                (),
                (SemanticMemoryCandidate(candidate, 10_000),),
                policy,
            )
            is None
        )


@given(st.sampled_from(["Use PostgreSQL", " USE  POSTGRESQL ", "Use Postgre\uff33QL"]))
def test_subject_normalization_is_stable_for_compatible_unicode_and_spacing(statement: str) -> None:
    subject, polarity = canonical_subject(statement)
    expected, _ = canonical_subject("Use PostgreSQL")
    assert subject == expected
    assert polarity is MemoryPolarity.AFFIRMED


def test_similarity_rejects_nonfinite_zero_or_wrong_dimension_vectors() -> None:
    assert cosine_similarity_basis_points((1.0, 0.0), (1.0, 0.0)) == 10_000
    assert cosine_similarity_basis_points((1.0, 0.0), (0.0, 1.0)) == 0
    for left, right in (
        ((), ()),
        ((1.0,), (1.0, 2.0)),
        ((0.0,), (0.0,)),
        ((float("nan"),), (1.0,)),
    ):
        with pytest.raises(MemoryValidationError):
            cosine_similarity_basis_points(left, right)
    maximum_dimension = (1.0,) * 65_536
    assert cosine_similarity_basis_points(maximum_dimension, maximum_dimension) == 10_000


def test_polarity_and_idempotency_coordinates_are_exact_and_ordered() -> None:
    _, polarity = canonical_subject("Do not never avoid PostgreSQL")
    assert polarity is MemoryPolarity.NEGATED
    expected = hashlib.sha256(
        json.dumps(
            {
                "brain_id": BRAIN_ID,
                "memory_id": TASK_ID,
                "operation_id": EVIDENCE_ONE,
            },
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert deduplication_idempotency_key(EVIDENCE_ONE, TASK_ID, BRAIN_ID) == expected
    with pytest.raises(MemoryValidationError) as error:
        deduplication_idempotency_key("018f0000-0000-6000-8000-000000000001", TASK_ID, BRAIN_ID)
    assert error.value.code_for("operation_id") == "invalid_uuid7"


def test_compatibility_policy_cannot_be_unversioned_or_weakened() -> None:
    with pytest.raises(MemoryValidationError):
        MemoryCompatibilityPolicy(policy_version="memory-compatibility.v2")
    with pytest.raises(MemoryValidationError):
        MemoryCompatibilityPolicy(semantic_threshold_basis_points=8999)
    with pytest.raises(MemoryValidationError):
        MemoryCompatibilityPolicy(semantic_threshold_basis_points=True)


def test_profile_and_candidate_boundaries_reject_ambiguous_persisted_data() -> None:
    profile = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    valid_until = replace(profile, valid_to=profile.valid_from + timedelta(seconds=1))
    assert valid_until.valid_to is not None

    invalid_profiles = (
        {"compatibility_policy_version": "memory-compatibility.v2"},
        {"classification": "secret"},
        {"evidence_ids": ()},
        {"valid_to": profile.valid_from},
        {"aggregate_version": 0},
    )
    for changes in invalid_profiles:
        with pytest.raises(MemoryValidationError):
            replace(profile, **changes)

    with pytest.raises(MemoryValidationError):
        SemanticMemoryCandidate(profile, similarity_basis_points=True)
    with pytest.raises(MemoryValidationError):
        SemanticMemoryCandidate(profile, 10_001)


def test_exact_fingerprint_and_merge_plan_integrity_fail_closed() -> None:
    target = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    candidate = _profile(_memory("Use PostgreSQL", EVIDENCE_TWO, NOW + timedelta(seconds=1)))
    altered = replace(candidate, content_sha256="a" * 64)
    decision = MemoryCompatibilityPolicy().evaluate(
        target,
        SemanticMemoryCandidate(altered, 10_000),
        DeduplicationMode.EXACT,
    )
    assert not decision.compatible
    assert decision.reason_code == "exact_fingerprint_mismatch"

    with pytest.raises(MemoryValidationError):
        MemoryMergePlan(target, (), target.evidence_ids, DeduplicationMode.EXACT, "wrong")
    with pytest.raises(MemoryValidationError):
        MemoryMergePlan(
            target,
            (candidate, candidate),
            tuple(sorted((*target.evidence_ids, *candidate.evidence_ids))),
            DeduplicationMode.EXACT,
            "memory-compatibility.v1",
        )
    with pytest.raises(MemoryValidationError):
        MemoryMergePlan(
            target,
            (candidate,),
            target.evidence_ids,
            DeduplicationMode.EXACT,
            "memory-compatibility.v1",
        )
    with pytest.raises(MemoryValidationError):
        MemoryMergePlan.create(
            target,
            (candidate,) * 257,
            (),
            MemoryCompatibilityPolicy(),
        )


def test_deduplication_result_rejects_noncanonical_identity_sets() -> None:
    target = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    result = DeduplicationResult.create("a" * 64, target, None, "memory-compatibility.v1")
    with pytest.raises(MemoryValidationError):
        replace(result, merged_memory_ids=(target.memory_id, target.memory_id))
    with pytest.raises(MemoryValidationError):
        replace(result, merged_memory_ids=(target.memory_id,))
    with pytest.raises(MemoryValidationError):
        replace(result, evidence_ids=(EVIDENCE_ONE, EVIDENCE_ONE))


def test_coordinate_content_and_time_validators_reject_noncanonical_values() -> None:
    profile = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    with pytest.raises(MemoryValidationError):
        validate_deduplication_coordinate("018f0000-0000-6000-8000-000000000001", "coordinate")
    with pytest.raises(MemoryValidationError):
        replace(profile, content_sha256="0" * 64)
    with pytest.raises(MemoryValidationError):
        replace(profile, retention_policy_id="not valid")
    with pytest.raises(MemoryValidationError):
        replace(profile, valid_from=NOW.replace(tzinfo=None))
    with pytest.raises(MemoryValidationError):
        canonical_subject("the and or")


def test_deduplication_commit_binds_time_scope_policy_and_result() -> None:
    target = _profile(_memory("Use PostgreSQL", EVIDENCE_ONE, NOW))
    candidate = _profile(_memory("Use PostgreSQL", EVIDENCE_TWO, NOW + timedelta(seconds=1)))
    plan = MemoryMergePlan.create(target, (candidate,), (), MemoryCompatibilityPolicy())
    assert plan is not None
    result = DeduplicationResult.create("a" * 64, target, plan, plan.policy_version)
    commit = DeduplicationCommit(
        "018f0000-0000-7000-8000-000000000010",
        ACTOR_ID,
        "018f0000-0000-7000-8000-000000000011",
        BRAIN_ID,
        "018f0000-0000-7000-8000-000000000012",
        "018f0000-0000-7000-8000-000000000013",
        target,
        plan,
        result,
        NOW,
        NOW,
    )
    invalid_commits = (
        {"completed_at": NOW - timedelta(seconds=1)},
        {"brain_id": "018f0000-0000-7000-8000-000000000099"},
        {"result": replace(result, policy_version="memory-compatibility.v2")},
        {"result": replace(result, result_sha256="b" * 64)},
    )
    for changes in invalid_commits:
        with pytest.raises(MemoryValidationError):
            replace(commit, **changes)


def _profile(memory: Memory) -> MemoryDeduplicationProfile:
    return MemoryDeduplicationProfile.from_memory(memory)


def _memory(statement: str, evidence_id: str, recorded_at: datetime) -> Memory:
    scope = MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)
    extractor = ExtractorIdentity(
        "agentmemory.local-extractor",
        "1.0.0",
        "Qwen/Qwen3-4B-GGUF-Q4_K_M",
        "revision",
        "memory-candidates.v1",
    )
    payload = b'{"status":"complete"}'
    evidence = TaskEvidence(
        evidence_id,
        TASK_ID,
        scope,
        "agentmemory.task.completed.v1",
        NOW,
        "internal",
        "default",
        payload,
        hashlib.sha256(payload).hexdigest(),
        "b" * 64,
    )
    source = TaskEvidenceBundle.create(TASK_ID, scope, (evidence,))
    candidate = MemoryCandidate(
        "decision-storage",
        MemoryClass.EPISODE,
        statement.strip(),
        scope,
        ConfidenceDimensions(9000, 9000, 9000),
        NOW,
        None,
        (evidence_id,),
    )
    decision = MemoryPromotionPolicy.production().evaluate(candidate, source)
    return candidate.activate(decision, source, extractor, ACTOR_ID, recorded_at)
