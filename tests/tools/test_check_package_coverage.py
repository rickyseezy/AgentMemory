"""Tests for the fail-closed Python coverage policy."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools.check_package_coverage import (
    CoveragePolicyError,
    Thresholds,
    discover_production_files,
    evaluate_coverage,
    load_coverage_report,
    package_for,
    parse_changed_lines,
)


def _write_report(path: Path, files: dict[str, dict[str, object]]) -> None:
    path.write_text(json.dumps({"meta": {"branch_coverage": True}, "files": files}))


def _coverage(
    *,
    executed: list[int],
    missing: list[int],
    executed_branches: list[list[int]] | None = None,
    missing_branches: list[list[int]] | None = None,
) -> dict[str, object]:
    return {
        "executed_lines": executed,
        "missing_lines": missing,
        "executed_branches": executed_branches or [],
        "missing_branches": missing_branches or [],
    }


def test_load_report_rejects_missing_branch_measurement(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"meta": {"branch_coverage": False}, "files": {}}))

    with pytest.raises(CoveragePolicyError, match="branch coverage was not enabled"):
        load_coverage_report(report)


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        json.dumps([]),
        json.dumps({"meta": {"branch_coverage": True}}),
        json.dumps(
            {
                "meta": {"branch_coverage": True},
                "files": {
                    "src/agentmemory/a.py": _coverage(
                        executed=[1],
                        missing=[],
                        executed_branches=[[1]],
                    )
                },
            }
        ),
    ],
)
def test_load_report_rejects_malformed_or_incomplete_data(
    tmp_path: Path,
    payload: str,
) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(payload)

    with pytest.raises(CoveragePolicyError):
        load_coverage_report(report)


def test_load_report_accepts_coverage_synthetic_exit_arcs(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    _write_report(
        report,
        {
            "apps/daemon/main.py": _coverage(
                executed=[1],
                missing=[],
                missing_branches=[[1, -1]],
            )
        },
    )

    loaded = load_coverage_report(report)

    assert loaded[Path("apps/daemon/main.py")].missing_branches == frozenset({(1, -1)})


def test_discovery_excludes_only_generated_vendor_and_cache(tmp_path: Path) -> None:
    expected = {
        Path("src/agentmemory/a.py"),
        Path("apps/daemon/main.py"),
        Path("adapters/example/plugin.py"),
    }
    for relative in expected | {
        Path("src/agentmemory/generated/schema.py"),
        Path("apps/daemon/vendor/library.py"),
        Path("apps/daemon/__pycache__/main.py"),
    }:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("pass\n")

    discovered = discover_production_files(
        tmp_path,
        (Path("src/agentmemory"), Path("apps"), Path("adapters")),
    )

    assert discovered == expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (Path("src/agentmemory/domain/value.py"), "agentmemory"),
        (Path("apps/daemon/main.py"), "apps/daemon"),
        (Path("apps/__init__.py"), "apps"),
        (Path("adapters/claude/plugin.py"), "adapters/claude"),
    ],
)
def test_package_grouping_is_a_stable_distribution_boundary(
    path: Path,
    expected: str,
) -> None:
    assert (
        package_for(
            path,
            (Path("src/agentmemory"), Path("apps"), Path("adapters")),
        )
        == expected
    )


def test_evaluation_rejects_an_omitted_production_file(tmp_path: Path) -> None:
    report_path = tmp_path / "coverage.json"
    _write_report(
        report_path,
        {"src/agentmemory/a.py": _coverage(executed=[1], missing=[])},
    )
    report = load_coverage_report(report_path)

    result = evaluate_coverage(
        report,
        {Path("src/agentmemory/a.py"), Path("src/agentmemory/unseen.py")},
        (Path("src/agentmemory"),),
        Thresholds(line=80, branch=80, changed=90),
        {},
    )

    assert result.failures == (
        "coverage data is missing for production file src/agentmemory/unseen.py",
    )


def test_evaluation_enforces_line_and_branch_thresholds_independently(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "coverage.json"
    _write_report(
        report_path,
        {
            "src/agentmemory/a.py": _coverage(
                executed=list(range(1, 9)),
                missing=[9, 10],
                executed_branches=[[2, 3]],
                missing_branches=[[2, 4], [5, 6]],
            )
        },
    )

    result = evaluate_coverage(
        load_coverage_report(report_path),
        {Path("src/agentmemory/a.py")},
        (Path("src/agentmemory"),),
        Thresholds(line=80, branch=80, changed=90),
        {},
    )

    assert not any("line coverage" in failure for failure in result.failures)
    assert result.failures == ("package agentmemory branch coverage 33.33% is below 80.00% (1/3)",)


def test_changed_code_requires_line_and_branch_coverage(tmp_path: Path) -> None:
    report_path = tmp_path / "coverage.json"
    _write_report(
        report_path,
        {
            "src/agentmemory/a.py": _coverage(
                executed=[1, 2, 3, 4, 5, 6, 7, 8, 10],
                missing=[9],
                executed_branches=[[2, 3]],
                missing_branches=[[2, 4]],
            )
        },
    )

    result = evaluate_coverage(
        load_coverage_report(report_path),
        {Path("src/agentmemory/a.py")},
        (Path("src/agentmemory"),),
        Thresholds(line=80, branch=50, changed=90),
        {Path("src/agentmemory/a.py"): frozenset({2, 9})},
    )

    assert result.failures == (
        "changed line coverage 50.00% is below 90.00% (1/2)",
        "changed branch coverage 50.00% is below 90.00% (1/2)",
    )


def test_changed_non_executable_lines_do_not_create_a_false_failure(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "coverage.json"
    _write_report(
        report_path,
        {"src/agentmemory/a.py": _coverage(executed=[1], missing=[])},
    )

    result = evaluate_coverage(
        load_coverage_report(report_path),
        {Path("src/agentmemory/a.py")},
        (Path("src/agentmemory"),),
        Thresholds(line=100, branch=100, changed=100),
        {Path("src/agentmemory/a.py"): frozenset({99})},
    )

    assert result.failures == ()
    assert result.changed_lines.percent == 100
    assert result.changed_branches.percent == 100


def test_parse_changed_lines_handles_multiple_files_and_zero_length_hunks() -> None:
    diff = """\
diff --git a/src/agentmemory/a.py b/src/agentmemory/a.py
--- a/src/agentmemory/a.py
+++ b/src/agentmemory/a.py
@@ -1,0 +2,2 @@
+first
+second
diff --git a/apps/daemon/main.py b/apps/daemon/main.py
--- a/apps/daemon/main.py
+++ b/apps/daemon/main.py
@@ -4,1 +4,0 @@
-deleted
@@ -8,1 +8,1 @@
-old
+new
"""

    assert parse_changed_lines(diff) == {
        Path("src/agentmemory/a.py"): frozenset({2, 3}),
        Path("apps/daemon/main.py"): frozenset({8}),
    }


def test_thresholds_reject_values_outside_percentage_range() -> None:
    with pytest.raises(CoveragePolicyError, match="between 0 and 100"):
        Thresholds(line=101, branch=80, changed=90)
