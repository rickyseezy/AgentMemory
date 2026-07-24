"""PRO-008 live embedding-generation migration domain invariants."""

from __future__ import annotations

from dataclasses import replace
from itertools import pairwise

import pytest

from agentmemory.providers.domain import migration as migration_domain
from agentmemory.providers.domain.errors import EmbeddingMigrationValidationError
from agentmemory.providers.domain.migration import (
    EmbeddingGenerationMigration,
    EmbeddingMigrationPolicy,
    EmbeddingMigrationState,
    EmbeddingMigrationValidation,
    MigrationContent,
    MigrationContentPage,
    MigrationProgress,
    migration_request_digest,
)
from agentmemory.providers.domain.migration_ports import GenerationWriteTarget
from tests.core.support import digest

MIGRATION_ID = "018f0000-0000-7000-8000-000000000801"
BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
SOURCE_SPACE_ID = "018f0000-0000-7000-8000-000000000501"
SOURCE_GENERATION_ID = "018f0000-0000-7000-8000-000000000111"
TARGET_SPACE_ID = "018f0000-0000-7000-8000-000000000502"
TARGET_GENERATION_ID = "018f0000-0000-7000-8000-000000000112"


def migration(**changes: object) -> EmbeddingGenerationMigration:
    values: dict[str, object] = {
        "migration_id": MIGRATION_ID,
        "brain_id": BRAIN_ID,
        "source_space_id": SOURCE_SPACE_ID,
        "source_space_fingerprint": digest("source-space").value,
        "source_generation_id": SOURCE_GENERATION_ID,
        "target_space_id": TARGET_SPACE_ID,
        "target_space_fingerprint": digest("target-space").value,
        "target_generation_id": TARGET_GENERATION_ID,
        "source_watermark": 100,
        "progress": MigrationProgress(
            backfill_cursor=0,
            catchup_watermark=100,
            catchup_cursor=100,
        ),
        "state": EmbeddingMigrationState.PLANNED,
        "validation_digest": None,
        "rollback_until_microseconds": None,
        "source_retired_at_microseconds": None,
        "source_deleted_at_microseconds": None,
        "resume_state": None,
        "version": 1,
        "created_at_microseconds": 1_000,
        "updated_at_microseconds": 1_000,
    }
    values.update(changes)
    return EmbeddingGenerationMigration(**values)  # type: ignore[arg-type]


def passing_validation(**changes: object) -> EmbeddingMigrationValidation:
    values: dict[str, object] = {
        "canonical_count": 100,
        "target_count": 100,
        "covered_count": 100,
        "missing_count": 0,
        "stale_count": 0,
        "duplicate_count": 0,
        "privacy_violation_count": 0,
        "quality_score_micros": 950_000,
        "baseline_quality_score_micros": 940_000,
        "p95_latency_microseconds": 100_000,
        "baseline_p95_latency_microseconds": 100_000,
        "shadow_sample_count": 1_000,
        "shadow_mismatch_count": 0,
        "evidence_digest": digest("validation-evidence").value,
    }
    values.update(changes)
    return EmbeddingMigrationValidation(**values)  # type: ignore[arg-type]


def test_migration_state_machine_allows_only_the_reviewed_live_sequence() -> None:
    sequence = (
        EmbeddingMigrationState.PLANNED,
        EmbeddingMigrationState.BUILDING,
        EmbeddingMigrationState.BACKFILLING,
        EmbeddingMigrationState.DUAL_WRITE,
        EmbeddingMigrationState.CATCHING_UP,
        EmbeddingMigrationState.VALIDATING,
        EmbeddingMigrationState.SHADOWING,
        EmbeddingMigrationState.READY,
    )
    for current, target in pairwise(sequence):
        current.require_transition(target)
    EmbeddingMigrationState.ACTIVE.require_transition(EmbeddingMigrationState.ROLLED_BACK)

    for current in sequence[:-2]:
        current.require_transition(EmbeddingMigrationState.FAILED)
    with pytest.raises(EmbeddingMigrationValidationError, match="transition"):
        EmbeddingMigrationState.PLANNED.require_transition(EmbeddingMigrationState.ACTIVE)
    with pytest.raises(EmbeddingMigrationValidationError, match="transition"):
        EmbeddingMigrationState.FAILED.require_transition(EmbeddingMigrationState.BUILDING)
    with pytest.raises(EmbeddingMigrationValidationError, match="transition"):
        EmbeddingMigrationState.ROLLED_BACK.require_transition(EmbeddingMigrationState.ACTIVE)


def test_pause_captures_and_resumes_the_exact_nonterminal_phase() -> None:
    planned = migration()
    paused = planned.transition(
        EmbeddingMigrationState.PAUSED,
        at_microseconds=1_001,
    )
    assert paused.resume_state is EmbeddingMigrationState.PLANNED
    assert paused.resume(at_microseconds=1_002).state is EmbeddingMigrationState.PLANNED
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        planned.resume(at_microseconds=1_002)


def test_write_target_rejects_noncanonical_generation_coordinates() -> None:
    with pytest.raises(EmbeddingMigrationValidationError, match="target is invalid"):
        GenerationWriteTarget("bad", digest("space").value, TARGET_GENERATION_ID)


def test_production_policy_retains_rollback_generation_for_thirty_five_days() -> None:
    assert (
        EmbeddingMigrationPolicy.production().rollback_window_microseconds
        == 35 * 24 * 60 * 60 * 1_000_000
    )


@pytest.mark.parametrize(
    "changed",
    [
        {"backfill_cursor": -1},
        {"backfill_cursor": 101},
        {"catchup_watermark": 99},
        {"catchup_cursor": 99},
        {"catchup_cursor": 101},
    ],
)
def test_progress_rejects_nonmonotonic_or_out_of_range_cursors(
    changed: dict[str, int],
) -> None:
    values = {
        "backfill_cursor": 100,
        "catchup_watermark": 100,
        "catchup_cursor": 100,
    }
    values.update(changed)
    with pytest.raises(EmbeddingMigrationValidationError, match="progress"):
        MigrationProgress(**values)


@pytest.mark.parametrize(
    "changed",
    [
        {"migration_id": "not-a-uuid"},
        {"brain_id": "not-a-uuid"},
        {"source_space_id": TARGET_SPACE_ID},
        {"source_generation_id": TARGET_GENERATION_ID},
        {"source_space_fingerprint": "not-a-digest"},
        {"source_watermark": -1},
        {"version": 0},
        {"created_at_microseconds": -1},
        {"updated_at_microseconds": 999},
    ],
)
def test_migration_rejects_ambiguous_identity_or_time(changed: dict[str, object]) -> None:
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        migration(**changed)


def test_migration_requires_completed_backfill_before_dual_write_and_evidence_for_ready() -> None:
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        migration(
            state=EmbeddingMigrationState.DUAL_WRITE,
            progress=MigrationProgress(
                backfill_cursor=99,
                catchup_watermark=100,
                catchup_cursor=100,
            ),
        )
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        migration(
            state=EmbeddingMigrationState.READY,
            progress=MigrationProgress(
                backfill_cursor=100,
                catchup_watermark=110,
                catchup_cursor=110,
            ),
        )
    ready = migration(
        state=EmbeddingMigrationState.READY,
        progress=MigrationProgress(
            backfill_cursor=100,
            catchup_watermark=110,
            catchup_cursor=110,
        ),
        validation_digest=digest("validation").value,
    )
    assert ready.state is EmbeddingMigrationState.READY


def test_active_requires_future_rollback_anchor_and_rolled_back_retains_it() -> None:
    ready = migration(
        state=EmbeddingMigrationState.READY,
        progress=MigrationProgress(100, 110, 110),
        validation_digest=digest("validation").value,
        updated_at_microseconds=2_000,
        version=8,
    )
    active = ready.activate(
        at_microseconds=2_100,
        rollback_until_microseconds=3_100,
    )
    assert active.rollback_eligible(3_099)
    assert not active.rollback_eligible(3_100)
    assert not active.deletion_eligible(3_099)
    assert active.deletion_eligible(3_100)
    rolled_back = active.transition(
        EmbeddingMigrationState.ROLLED_BACK,
        at_microseconds=2_200,
    )
    assert rolled_back.rollback_until_microseconds == 3_100

    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        ready.activate(
            at_microseconds=2_100,
            rollback_until_microseconds=2_100,
        )


@pytest.mark.parametrize(
    ("changed", "outcome"),
    [
        ({}, "pass"),
        ({"target_count": 99}, "fail"),
        ({"covered_count": 99}, "fail"),
        ({"missing_count": 1}, "fail"),
        ({"stale_count": 1}, "fail"),
        ({"duplicate_count": 1}, "fail"),
        ({"privacy_violation_count": 1}, "fail"),
        ({"quality_score_micros": 899_999}, "fail"),
        ({"p95_latency_microseconds": 125_001}, "fail"),
        ({"shadow_sample_count": 99}, "fail"),
        ({"shadow_mismatch_count": 1}, "fail"),
    ],
)
def test_validation_independently_blocks_each_cutover_regression(
    changed: dict[str, int],
    outcome: str,
) -> None:
    policy = EmbeddingMigrationPolicy.production()
    assert passing_validation(**changed).passes(policy) is (outcome == "pass")


def test_validation_and_policy_reject_invalid_metrics_or_unbounded_thresholds() -> None:
    assert (
        passing_validation().digest
        == "080494b7266b2b7e0a87fd33e7934fc61dfe773b174286996c19620d40056d73"
    )
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        passing_validation(canonical_count=-1)
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        replace(EmbeddingMigrationPolicy.production(), minimum_coverage_micros=1_000_001)
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        replace(EmbeddingMigrationPolicy.production(), rollback_window_microseconds=0)


def test_request_digest_binds_every_migration_identity_coordinate() -> None:
    baseline = migration_request_digest(
        brain_id=BRAIN_ID,
        source_space_id=SOURCE_SPACE_ID,
        source_generation_id=SOURCE_GENERATION_ID,
        target_space_id=TARGET_SPACE_ID,
        target_generation_id=TARGET_GENERATION_ID,
        source_watermark=100,
    )
    assert baseline == "69001db15497039cfa14d7407495bf5f4536636ed3b078f06456274414ff6765"
    assert baseline == migration_request_digest(
        brain_id=BRAIN_ID,
        source_space_id=SOURCE_SPACE_ID,
        source_generation_id=SOURCE_GENERATION_ID,
        target_space_id=TARGET_SPACE_ID,
        target_generation_id=TARGET_GENERATION_ID,
        source_watermark=100,
    )
    assert baseline != migration_request_digest(
        brain_id=BRAIN_ID,
        source_space_id=SOURCE_SPACE_ID,
        source_generation_id=SOURCE_GENERATION_ID,
        target_space_id=TARGET_SPACE_ID,
        target_generation_id=TARGET_GENERATION_ID,
        source_watermark=101,
    )


def test_canonical_digest_rejects_nan_and_normalizes_key_order_and_unicode() -> None:
    expected = "216011ca5855bdb868f7a60d3651f216b1f0e7d6231224c0b24121efce2235b5"
    assert (
        migration_domain._digest(  # pyright: ignore[reportPrivateUsage]
            {"z": "mémoire", "a": 1}
        )
        == expected
    )
    assert (
        migration_domain._digest(  # pyright: ignore[reportPrivateUsage]
            {"a": 1, "z": "mémoire"}
        )
        == expected
    )
    with pytest.raises(ValueError, match="Out of range float values"):
        migration_domain._digest(  # pyright: ignore[reportPrivateUsage]
            {"value": float("nan")}
        )


def test_request_digest_accepts_zero_watermark_and_rejects_ambiguous_coordinates() -> None:
    assert (
        migration_request_digest(
            brain_id=BRAIN_ID,
            source_space_id=SOURCE_SPACE_ID,
            source_generation_id=SOURCE_GENERATION_ID,
            target_space_id=TARGET_SPACE_ID,
            target_generation_id=TARGET_GENERATION_ID,
            source_watermark=0,
        )
        == "e4caf1e0f1c1ceb845674344a5ff7072657df813a509ee955d45f7fab1cc8e5c"
    )
    assert (
        migration_request_digest(
            brain_id=BRAIN_ID,
            source_space_id=SOURCE_SPACE_ID,
            source_generation_id=SOURCE_GENERATION_ID,
            target_space_id=TARGET_SPACE_ID,
            target_generation_id=TARGET_GENERATION_ID,
            source_watermark=2**63 - 1,
        )
        == "af56bb52b069707ef4018abd4b17915d30a05844c1dfaaa8a1e6951acc1e6fd4"
    )
    invalid_changes = (
        {"target_space_id": SOURCE_SPACE_ID},
        {"target_generation_id": SOURCE_GENERATION_ID},
        {"source_watermark": -1},
        {"source_watermark": 2**63},
    )
    for changes in invalid_changes:
        values: dict[str, object] = {
            "brain_id": BRAIN_ID,
            "source_space_id": SOURCE_SPACE_ID,
            "source_generation_id": SOURCE_GENERATION_ID,
            "target_space_id": TARGET_SPACE_ID,
            "target_generation_id": TARGET_GENERATION_ID,
            "source_watermark": 100,
        }
        values.update(changes)
        with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
            migration_request_digest(**values)  # type: ignore[arg-type]


def test_content_pages_transitions_and_request_digest_reject_invalid_boundaries() -> None:
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        MigrationContent(
            sequence=0,
            source_entity_id=MIGRATION_ID,
            source_content_hash=digest("content").value,
            content_ref="cas://canonical/1",
            classification="internal",
        )
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        MigrationContentPage((), next_cursor=0, complete=False)
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        migration().transition(
            EmbeddingMigrationState.BUILDING,
            at_microseconds=999,
        )
    active = migration(
        state=EmbeddingMigrationState.ACTIVE,
        progress=MigrationProgress(100, 100, 100),
        validation_digest=digest("validation").value,
        rollback_until_microseconds=2_000,
    )
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        active.transition(
            EmbeddingMigrationState.ROLLED_BACK,
            at_microseconds=2_000,
        )
    with pytest.raises(EmbeddingMigrationValidationError, match="input is invalid"):
        migration_request_digest(
            brain_id="invalid",
            source_space_id=SOURCE_SPACE_ID,
            source_generation_id=SOURCE_GENERATION_ID,
            target_space_id=TARGET_SPACE_ID,
            target_generation_id=TARGET_GENERATION_ID,
            source_watermark=100,
        )
