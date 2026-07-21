"""TDD specifications for IDX-002 deterministic plans and run checkpoints."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.indexing.domain.errors import IndexingValidationError
from agentmemory.indexing.domain.incremental import (
    CurrentIndexUnit,
    IndexFingerprint,
    IndexOperationKind,
    IndexOperationReason,
    IndexPlan,
    IndexProjectionEvent,
    IndexRun,
    IndexRunState,
    PriorIndexedUnit,
    VcsDelta,
    VcsDeltaKind,
    freshness_p95_seconds,
)

if TYPE_CHECKING:
    from collections.abc import Callable

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fingerprint(version: str = "tree-sitter-0.26.0") -> IndexFingerprint:
    return IndexFingerprint(
        version,
        "grammar-commit-1",
        _digest("queries"),
        _digest("extraction-config"),
        "privacy-v1",
    )


def _current(
    path: str,
    content: str,
    *,
    fingerprint: IndexFingerprint | None = None,
    generated: bool = False,
) -> CurrentIndexUnit:
    selected = fingerprint or _fingerprint()
    digest = _digest(content)
    return CurrentIndexUnit(
        path,
        digest,
        len(content.encode()),
        selected.cache_key(path, digest),
        generated,
    )


def _prior(current: CurrentIndexUnit, semantic: tuple[str, ...] = ()) -> PriorIndexedUnit:
    return PriorIndexedUnit(
        current.relative_path,
        _digest(f"file:{current.relative_path}"),
        _digest(f"revision:{current.relative_path}:{current.content_digest}"),
        current.content_digest,
        current.cache_key,
        tuple(sorted(semantic)),
    )


@given(
    changed_index=st.integers(min_value=0, max_value=39),
    suffix=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        min_size=1,
        max_size=12,
    ),
)
def test_property_one_changed_hash_rebuilds_only_one_unit(changed_index: int, suffix: str) -> None:
    current = tuple(_current(f"src/module_{index}.py", f"value = {index}\n") for index in range(40))
    previous = tuple(_prior(item) for item in current)
    changed = list(current)
    changed[changed_index] = _current(
        current[changed_index].relative_path,
        f"value = {changed_index}\n# {suffix}",
    )

    plan = IndexPlan.create(previous, tuple(reversed(changed)), (), include_generated=True)

    assert plan.changed_count == 1
    assert sum(item.kind is IndexOperationKind.MODIFY for item in plan.operations) == 1
    assert sum(item.kind is IndexOperationKind.REUSE for item in plan.operations) == 39
    assert tuple(item.relative_path for item in plan.operations) == tuple(
        sorted(item.relative_path for item in plan.operations)
    )


def test_parser_or_policy_fingerprint_change_forces_rebuild_with_identical_blob() -> None:
    old = _current("src/service.ts", "export const value = 1")
    new = _current(
        "src/service.ts",
        "export const value = 1",
        fingerprint=_fingerprint("tree-sitter-0.27.0"),
    )

    operation = IndexPlan.create((_prior(old),), (new,), (), include_generated=True).operations[0]

    assert operation.kind is IndexOperationKind.MODIFY
    assert operation.reason is IndexOperationReason.FINGERPRINT_CHANGED


def test_rename_copy_delete_and_generated_policy_have_closed_operations() -> None:
    renamed_old = _current("src/old.py", "def renamed(): pass")
    copied_old = _current("src/source.py", "def copied(): pass")
    deleted_old = _current("src/deleted.py", "gone = True")
    generated_old = _current("generated/client.py", "client = 1")
    renamed_new = _current("src/new.py", "def renamed(): pass")
    copied_new = _current("src/copied.py", "def copied(): pass")
    generated_new = _current("generated/client.py", "client = 2", generated=True)
    plan = IndexPlan.create(
        tuple(_prior(item) for item in (renamed_old, copied_old, deleted_old, generated_old)),
        (renamed_new, copied_old, copied_new, generated_new),
        (
            VcsDelta(VcsDeltaKind.RENAME, "src/new.py", "src/old.py"),
            VcsDelta(VcsDeltaKind.COPY, "src/copied.py", "src/source.py"),
            VcsDelta(VcsDeltaKind.DELETE, "src/deleted.py"),
            VcsDelta(VcsDeltaKind.MODIFY, "generated/client.py"),
        ),
        include_generated=False,
    )
    by_path = {item.relative_path: item for item in plan.operations}

    assert by_path["src/new.py"].kind is IndexOperationKind.RENAME
    assert by_path["src/new.py"].previous_path == "src/old.py"
    assert by_path["src/copied.py"].kind is IndexOperationKind.ADD
    assert by_path["src/copied.py"].reason is IndexOperationReason.COPIED_CONTENT
    assert by_path["src/copied.py"].previous_path == "src/source.py"
    assert by_path["src/source.py"].kind is IndexOperationKind.REUSE
    assert by_path["src/deleted.py"].kind is IndexOperationKind.DELETE
    assert by_path["generated/client.py"].reason is IndexOperationReason.GENERATED_EXCLUDED
    assert (
        plan.digest
        == IndexPlan.create(
            tuple(
                reversed(
                    tuple(
                        _prior(item)
                        for item in (renamed_old, copied_old, deleted_old, generated_old)
                    )
                )
            ),
            tuple(reversed((renamed_new, copied_old, copied_new, generated_new))),
            tuple(
                reversed(
                    (
                        VcsDelta(VcsDeltaKind.RENAME, "src/new.py", "src/old.py"),
                        VcsDelta(VcsDeltaKind.COPY, "src/copied.py", "src/source.py"),
                        VcsDelta(VcsDeltaKind.DELETE, "src/deleted.py"),
                        VcsDelta(VcsDeltaKind.MODIFY, "generated/client.py"),
                    )
                )
            ),
            include_generated=False,
        ).digest
    )


def test_invalid_or_ambiguous_diff_inputs_fail_closed() -> None:
    current = _current("src/new.py", "value = 1")
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        IndexPlan.create(
            (),
            (current,),
            (VcsDelta(VcsDeltaKind.RENAME, "src/new.py", "src/missing.py"),),
            include_generated=True,
        )
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        IndexPlan.create((), (current, current), (), include_generated=True)


def _queued_run(plan: IndexPlan) -> IndexRun:
    return IndexRun.queue(
        operation_id="index-run-1",
        brain_id="brain-1",
        project_id="project-1",
        repository_id="repository-1",
        base_snapshot_id=_digest("base"),
        target_snapshot_id=_digest("target"),
        target_commit_id="abcdef1",
        working_digest=_digest("working"),
        implementation_fingerprint=_fingerprint().digest,
        plan=plan,
        detected_at=NOW,
    )


def test_run_checkpoints_every_operation_and_reports_freshness() -> None:
    unit = _current("src/service.py", "value = 1")
    changed = _current("src/service.py", "value = 2")
    plan = IndexPlan.create((_prior(unit),), (changed,), (), include_generated=True)
    run = _queued_run(plan).begin(NOW + timedelta(seconds=1))

    run = run.checkpoint(plan.operations[0], failed=False, at=NOW + timedelta(seconds=2))
    run = run.finish(NOW + timedelta(seconds=3))

    assert run.state is IndexRunState.COMPLETED
    assert run.indexed_count == 1
    assert run.reused_count == run.deleted_count == run.failed_count == 0
    assert run.freshness_seconds == 3
    assert freshness_p95_seconds((1.0, 2.0, 3.0, 29.0, 4.0)) == 29.0


def test_run_cancellation_is_acknowledged_only_at_operation_boundary() -> None:
    plan = IndexPlan.create((), (_current("src/new.py", "value = 1"),), (), include_generated=True)
    run = _queued_run(plan).begin(NOW + timedelta(seconds=1))
    cancelling = run.request_cancel(NOW + timedelta(seconds=2))

    assert cancelling.state is IndexRunState.CANCELLING
    assert cancelling.cancel(NOW + timedelta(seconds=3)).state is IndexRunState.CANCELLED
    with pytest.raises(IndexingValidationError, match="run is invalid"):
        cancelling.checkpoint(plan.operations[0], failed=False, at=NOW + timedelta(seconds=3))


def test_projection_event_carries_exact_bounded_invalidation_and_reembedding_sets() -> None:
    event = IndexProjectionEvent(
        _digest("run"),
        _digest("operation"),
        0,
        _digest("snapshot"),
        (_digest("old-revision"),),
        (_digest("new-revision"),),
        (_digest("changed-symbol"),),
        (_digest("dependent-fact"),),
        (_digest("assertion-evidence"),),
        (_digest("changed-symbol"),),
        NOW,
    )

    assert len(event.id) == 64
    with pytest.raises(IndexingValidationError, match="projection event is invalid"):
        IndexProjectionEvent(
            event.run_id,
            event.operation_id,
            0,
            event.snapshot_id,
            (),
            (),
            (event.affected_semantic_ids[0], event.affected_semantic_ids[0]),
            (),
            (),
            (),
            NOW,
        )


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute.py",
        "../escape.py",
        "src/../escape.py",
        "src\\windows.py",
        "src/null\x00.py",
        "./src/service.py",
        f"src/{'x' * 4096}",
    ],
)
def test_source_paths_are_canonical_bounded_posix_paths(path: str) -> None:
    digest = _digest("content")

    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        CurrentIndexUnit(path, digest, 1, digest)


@pytest.mark.parametrize("byte_length", [-1, True, 1.5])
def test_current_units_reject_invalid_lengths(byte_length: object) -> None:
    digest = _digest("content")

    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        CurrentIndexUnit("src/service.py", digest, cast("int", byte_length), digest)


def test_incremental_value_objects_reject_ambiguous_coordinates() -> None:
    digest = _digest("content")
    valid = _current("src/service.py", "value = 1")

    with pytest.raises(IndexingValidationError, match="cache identity is invalid"):
        IndexFingerprint("bad version!", "grammar-1", digest, digest, "privacy-v1")
    with pytest.raises(IndexingValidationError, match="cache identity is invalid"):
        IndexFingerprint("parser-1", "grammar-1", "not-a-digest", digest, "privacy-v1")
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        PriorIndexedUnit("src/service.py", digest, digest, digest, digest, (digest, digest))
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        CurrentIndexUnit("src/service.py", digest, 1, digest, generated=cast("bool", 1))
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        VcsDelta(VcsDeltaKind.RENAME, "src/new.py")
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        VcsDelta(VcsDeltaKind.MODIFY, "src/service.py", "src/old.py")
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        VcsDelta(VcsDeltaKind.COPY, "src/service.py", "src/service.py")
    with pytest.raises(IndexingValidationError, match="plan is invalid"):
        IndexPlan.create((), (valid,), (), include_generated=cast("bool", 1))


def test_add_operation_rejects_each_invalid_coordinate() -> None:
    add = IndexPlan.create(
        (), (_current("src/service.py", "value = 1"),), (), include_generated=True
    ).operations[0]
    invalid: tuple[Callable[[], object], ...] = (
        lambda: replace(add, ordinal=-1),
        lambda: replace(add, ordinal=True),
        lambda: replace(add, kind=cast("IndexOperationKind", "add")),
        lambda: replace(add, reason=cast("IndexOperationReason", "new_content")),
        lambda: replace(add, relative_path="../escape.py"),
        lambda: replace(add, content_digest=None),
        lambda: replace(add, cache_key=None),
        lambda: replace(add, previous_path="src/old.py"),
        lambda: replace(add, generated=cast("bool", 1)),
    )

    for build in invalid:
        with pytest.raises(IndexingValidationError, match="plan is invalid"):
            build()


def test_operation_shapes_require_complete_previous_coordinates() -> None:
    current = _current("src/service.py", "value = 1")
    prior = _prior(current)
    reuse = IndexPlan.create((prior,), (current,), (), include_generated=True).operations[0]

    invalid: tuple[Callable[[], object], ...] = (
        lambda: replace(reuse, previous_source_file_id=None),
        lambda: replace(reuse, previous_file_revision_id=None),
        lambda: replace(reuse, previous_path="src/old.py"),
    )
    for build in invalid:
        with pytest.raises(IndexingValidationError, match="plan is invalid"):
            build()


def test_run_identity_progress_and_terminal_invariants_fail_closed() -> None:
    plan = IndexPlan.create(
        (), (_current("src/service.py", "value = 1"),), (), include_generated=True
    )
    queued = _queued_run(plan)
    invalid_changes = (
        {"id": "not-a-digest"},
        {"operation_id": "contains spaces"},
        {"brain_id": ""},
        {"project_id": "contains spaces"},
        {"repository_id": "x" * 129},
        {"target_snapshot_id": "not-a-digest"},
        {"target_commit_id": "contains spaces"},
        {"total_operations": True},
        {"changed_operations": 2},
        {"cursor": 2},
        {"cursor": 1, "indexed_count": 0},
        {"updated_at": NOW - timedelta(microseconds=1)},
        {"state": "queued"},
        {"completed_at": NOW},
        {"state": IndexRunState.COMPLETED, "completed_at": NOW},
        {"failure_code": "unexpected"},
        {
            "state": IndexRunState.FAILED,
            "completed_at": NOW,
            "failure_code": "bad code",
        },
    )

    for changes in invalid_changes:
        with pytest.raises(IndexingValidationError, match="run is invalid"):
            replace(queued, **changes)


def test_run_lifecycle_counts_each_outcome_and_is_idempotent() -> None:
    added = _current("src/added.py", "added = 1")
    reused = _current("src/reused.py", "reused = 1")
    deleted = _current("src/deleted.py", "deleted = 1")
    plan = IndexPlan.create(
        (_prior(reused), _prior(deleted)),
        (added, reused),
        (),
        include_generated=True,
    )
    run = _queued_run(plan)
    running = run.begin(NOW + timedelta(seconds=1))
    assert running.begin(NOW + timedelta(seconds=2)) is running

    for ordinal, operation in enumerate(plan.operations):
        running = running.checkpoint(
            operation,
            failed=ordinal == 0,
            at=NOW + timedelta(seconds=2 + ordinal),
        )

    assert running.failed_count == 1
    assert running.deleted_count == 1
    assert running.reused_count == 1
    assert running.indexed_count == 0
    completed = running.finish(NOW + timedelta(seconds=5))
    assert completed.request_cancel(NOW + timedelta(seconds=6)) is completed

    failed = run.fail("source-unavailable", NOW + timedelta(seconds=1))
    assert failed.fail("source-unavailable", NOW + timedelta(seconds=2)) is failed
    assert failed.freshness_seconds == 1


@pytest.mark.parametrize("values", [(), (-1.0,), (float("nan"),), (float("inf"),)])
def test_freshness_p95_rejects_missing_or_invalid_samples(values: tuple[float, ...]) -> None:
    with pytest.raises(IndexingValidationError, match="run is invalid"):
        freshness_p95_seconds(values)


def test_freshness_p95_uses_nearest_rank_at_boundaries() -> None:
    assert freshness_p95_seconds((0.0,)) == 0.0
    assert freshness_p95_seconds(tuple(float(value) for value in range(1, 21))) == 19.0


def test_cache_and_event_identities_are_exact_and_stable() -> None:
    fingerprint = _fingerprint()
    content_digest = _digest("value = 1")

    assert fingerprint.digest == "db1acd6fa7dfb4a8dabee0614d893d5a309be798975cd3d1edb7c034d05fb6b8"
    assert (
        fingerprint.cache_key("src/service.py", content_digest)
        == "9867e934ba58436cd9523faf96a36fdb7709d2bb6edd0409d7c037aa34894201"
    )
