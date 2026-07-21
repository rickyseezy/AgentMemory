"""GRA-006 graph migration and integrity policy acceptance tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, cast

import pytest

from agentmemory.graph.domain.errors import GraphValidationError
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityObservation,
    GraphIntegrityPolicy,
    GraphMigrationRun,
    GraphMigrationState,
    GraphProjectionKind,
    GraphRepairAction,
    GraphRepairPolicy,
    IntegrityFindingKind,
)

NOW = datetime(2026, 7, 21, 15, tzinfo=UTC)
BRAIN = "019f54bb-1111-7111-8111-111111111111"
PROJECT = "019f54bb-2222-7222-8222-222222222222"
REPOSITORY = "019f54bb-3333-7333-8333-333333333333"
PROJECTION = "019f54bb-4444-7444-8444-444444444444"
CANONICAL = "019f54bb-5555-7555-8555-555555555555"
GENERATION = "a" * 64
CURRENT_GENERATION = "b" * 64
CHECKSUM = "c" * 64


def test_migration_run_resumes_monotonically_without_duplicate_counts() -> None:
    run = GraphMigrationRun.start(
        operation_id="graph-migration-1",
        brain_id=BRAIN,
        migration_id="gra006-backfill-v1",
        migration_checksum=CHECKSUM,
        source_watermark=10,
        batch_size=4,
        started_at=NOW,
    )
    assert run.state is GraphMigrationState.RUNNING
    assert run.cursor == 0

    checkpoint = run.checkpoint(next_cursor=4, scanned=4, changed=3, quarantined=1, at=NOW)
    assert checkpoint.cursor == 4
    assert checkpoint.scanned_count == 4
    assert checkpoint.changed_count == 3
    assert checkpoint.quarantined_count == 1
    assert checkpoint.checkpoint(4, 4, 3, 1, NOW) == checkpoint

    validating = checkpoint.checkpoint(10, 6, 2, 0, NOW).begin_validation(NOW)
    complete = validating.complete(NOW)
    assert complete.state is GraphMigrationState.COMPLETED
    assert complete.cursor == 10
    with pytest.raises(GraphValidationError, match="migration"):
        complete.checkpoint(11, 1, 1, 0, NOW)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"canonical_supported": False}, IntegrityFindingKind.UNSUPPORTED_ASSERTION),
        ({"canonical_id": None}, IntegrityFindingKind.ORPHAN_EDGE),
        (
            {"projection_kind": GraphProjectionKind.VECTOR, "canonical_id": None},
            IntegrityFindingKind.ORPHAN_VECTOR,
        ),
        ({"temporal_valid": False}, IntegrityFindingKind.INVALID_TEMPORAL_RANGE),
        ({"scope_matches": False}, IntegrityFindingKind.SCOPE_MISMATCH),
        ({"generation_id": GENERATION}, IntegrityFindingKind.STALE_GENERATION),
    ],
)
def test_integrity_policy_finds_every_required_corruption_type(
    changes: dict[str, object], expected: IntegrityFindingKind
) -> None:
    observation = replace(_observation(), **cast("dict[str, Any]", changes))
    findings = GraphIntegrityPolicy.evaluate((observation,), CURRENT_GENERATION, NOW)
    assert expected in {finding.kind for finding in findings}
    assert all(finding.projection_id == PROJECTION for finding in findings)


def test_clean_projection_has_no_findings_and_duplicate_input_fails_closed() -> None:
    clean = _observation()
    assert GraphIntegrityPolicy.evaluate((clean,), CURRENT_GENERATION, NOW) == ()
    with pytest.raises(GraphValidationError, match="integrity"):
        GraphIntegrityPolicy.evaluate((clean, clean), CURRENT_GENERATION, NOW)


def test_repair_policy_never_silently_deletes_canonical_history() -> None:
    orphan = GraphIntegrityPolicy.evaluate(
        (replace(_observation(), canonical_id=None),), CURRENT_GENERATION, NOW
    )[0]
    missing_support = GraphIntegrityPolicy.evaluate(
        (replace(_observation(), canonical_supported=False),), CURRENT_GENERATION, NOW
    )[0]
    assert GraphRepairPolicy.plan(orphan).action is GraphRepairAction.QUARANTINE
    assert GraphRepairPolicy.plan(missing_support).action is GraphRepairAction.SHADOW_WRITE

    with pytest.raises(GraphValidationError, match="approval"):
        GraphRepairPolicy.plan(orphan, destructive=True)
    with pytest.raises(GraphValidationError, match="rebuild"):
        GraphRepairPolicy.plan(orphan, destructive=True, approval_id=CANONICAL)
    destructive = GraphRepairPolicy.plan(
        orphan,
        destructive=True,
        approval_id=CANONICAL,
        canonical_rebuild_verified=True,
    )
    assert destructive.action is GraphRepairAction.DESTRUCTIVE_REBUILD
    assert destructive.approval_id == CANONICAL


def test_graph_integrity_values_reject_noncanonical_runtime_inputs() -> None:
    with pytest.raises(GraphValidationError, match="migration"):
        GraphMigrationRun.start(
            operation_id="graph-migration-1",
            brain_id=BRAIN,
            migration_id="UPPER CASE",
            migration_checksum=CHECKSUM,
            source_watermark=1,
            batch_size=1,
            started_at=NOW,
        )
    with pytest.raises(GraphValidationError, match="integrity"):
        replace(_observation(), generation_id="latest")
    with pytest.raises(GraphValidationError, match="integrity"):
        GraphIntegrityPolicy.evaluate((_observation(),), "0" * 64, NOW)


@pytest.mark.load
def test_integrity_policy_scans_ten_thousand_projections_with_bounded_latency() -> None:
    observations = tuple(
        replace(
            _observation(),
            projection_id=hashlib.sha256(f"projection-{index}".encode()).hexdigest(),
            generation_id=GENERATION,
        )
        for index in range(10_000)
    )
    started = perf_counter()
    findings = GraphIntegrityPolicy.evaluate(observations, CURRENT_GENERATION, NOW)
    elapsed = perf_counter() - started
    assert len(findings) == 10_000
    assert {item.kind for item in findings} == {IntegrityFindingKind.STALE_GENERATION}
    assert elapsed < 10


def _observation() -> GraphIntegrityObservation:
    return GraphIntegrityObservation(
        projection_id=PROJECTION,
        projection_kind=GraphProjectionKind.EDGE,
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        canonical_id=CANONICAL,
        canonical_supported=True,
        temporal_valid=True,
        scope_matches=True,
        generation_id=CURRENT_GENERATION,
        projection_digest="d" * 64,
    )
