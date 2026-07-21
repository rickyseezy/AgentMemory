"""IDX-002 published one-file-change freshness workload."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import cast

from agentmemory.indexing.domain.incremental import (
    CurrentIndexUnit,
    IndexOperationKind,
    IndexPlan,
    PriorIndexedUnit,
    freshness_p95_seconds,
)

_PROFILE = Path("deploy/index-freshness-profile.v1.json")


def test_one_file_change_plan_meets_published_p95_freshness_profile() -> None:
    profile = cast("dict[str, object]", json.loads(_PROFILE.read_text()))
    file_count = int(cast("int", profile["repository_file_count"]))
    warmups = int(cast("int", profile["warmup_runs"]))
    measured = int(cast("int", profile["measured_runs"]))
    maximum = float(cast("float", profile["freshness_p95_seconds_max"]))
    previous = tuple(_prior(index) for index in range(file_count))
    current = tuple(
        _current(index, changed=index == file_count // 2) for index in range(file_count)
    )

    durations: list[float] = []
    for iteration in range(warmups + measured):
        started = time.perf_counter()
        plan = IndexPlan.create(previous, current, (), include_generated=True)
        duration = time.perf_counter() - started
        changed = tuple(
            item for item in plan.operations if item.kind is not IndexOperationKind.REUSE
        )
        assert len(changed) == int(cast("int", profile["changed_file_count"]))
        if iteration >= warmups:
            durations.append(duration)

    assert freshness_p95_seconds(tuple(durations)) < maximum


def _prior(index: int) -> PriorIndexedUnit:
    identity = f"{index:064x}"
    return PriorIndexedUnit(
        f"src/file_{index:05d}.py",
        identity,
        f"{index + 1:064x}",
        f"{index + 2:064x}",
        f"{index + 3:064x}",
        (f"{index + 4:064x}",),
    )


def _current(index: int, *, changed: bool) -> CurrentIndexUnit:
    offset = 100_000 if changed else 0
    return CurrentIndexUnit(
        f"src/file_{index:05d}.py",
        f"{index + 2 + offset:064x}",
        100,
        f"{index + 3 + offset:064x}",
        generated=False,
    )
