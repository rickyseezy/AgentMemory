"""Enforce fail-closed Python package and changed-code coverage policy."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, cast

type JSONValue = None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]

DEFAULT_SOURCE_ROOTS: Final = (
    Path("src/agentmemory"),
    Path("apps"),
    Path("adapters"),
)
EXCLUDED_PARTS: Final = frozenset({"generated", "vendor", "__pycache__"})
HUNK_PATTERN: Final = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
PERCENT_MAX: Final = 100
BRANCH_ARITY: Final = 2


class CoveragePolicyError(ValueError):
    """Raised when coverage evidence is missing, malformed, or unverifiable."""


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Coverage percentages required by repository policy."""

    line: float
    branch: float
    changed: float

    def __post_init__(self) -> None:
        """Reject nonsensical percentages before evaluating evidence."""
        for value in (self.line, self.branch, self.changed):
            if not 0 <= value <= PERCENT_MAX:
                message = "coverage thresholds must be between 0 and 100"
                raise CoveragePolicyError(message)


@dataclass(frozen=True, slots=True)
class Ratio:
    """A covered/total pair with explicit empty-set behavior."""

    covered: int
    total: int

    @property
    def percent(self) -> float:
        """Return 100 percent for an empty executable set."""
        if self.total == 0:
            return 100.0
        return self.covered * 100 / self.total


@dataclass(frozen=True, slots=True)
class FileCoverage:
    """Normalized executable coverage for one production file."""

    covered_lines: frozenset[int]
    missing_lines: frozenset[int]
    covered_branches: frozenset[tuple[int, int]]
    missing_branches: frozenset[tuple[int, int]]

    @property
    def executable_lines(self) -> frozenset[int]:
        """Return every measured executable statement."""
        return self.covered_lines | self.missing_lines

    @property
    def branches(self) -> frozenset[tuple[int, int]]:
        """Return every measured branch arc."""
        return self.covered_branches | self.missing_branches


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Deterministic coverage policy result."""

    failures: tuple[str, ...]
    package_lines: dict[str, Ratio]
    package_branches: dict[str, Ratio]
    changed_lines: Ratio
    changed_branches: Ratio


def _positive_ints(value: object, *, field: str, file_name: str) -> frozenset[int]:
    if not isinstance(value, list):
        message = f"{file_name}: {field} must be a list of positive integers"
        raise CoveragePolicyError(message)
    items = cast("list[JSONValue]", value)
    if any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in items):
        message = f"{file_name}: {field} must be a list of positive integers"
        raise CoveragePolicyError(message)
    return frozenset(cast("list[int]", items))


def _branches(
    value: object,
    *,
    field: str,
    file_name: str,
) -> frozenset[tuple[int, int]]:
    if not isinstance(value, list):
        message = f"{file_name}: {field} must be a list"
        raise CoveragePolicyError(message)
    branch_values = cast("list[JSONValue]", value)
    result: set[tuple[int, int]] = set()
    for branch in branch_values:
        branch_items = branch if isinstance(branch, list) else []
        if (
            not isinstance(branch, list)
            or len(branch_items) != BRANCH_ARITY
            or not isinstance(branch_items[0], int)
            or isinstance(branch_items[0], bool)
            or branch_items[0] <= 0
            or not isinstance(branch_items[1], int)
            or isinstance(branch_items[1], bool)
            or branch_items[1] == 0
        ):
            message = f"{file_name}: {field} entries must be valid [from, to] pairs"
            raise CoveragePolicyError(message)
        integer_branch = cast("list[int]", branch_items)
        result.add((integer_branch[0], integer_branch[1]))
    return frozenset(result)


def _relative_path(raw_path: str) -> Path:
    pure = PurePosixPath(raw_path)
    if pure.is_absolute() or ".." in pure.parts or raw_path == "":
        message = f"coverage contains unsafe path {raw_path!r}"
        raise CoveragePolicyError(message)
    return Path(*pure.parts)


def load_coverage_report(path: Path) -> dict[Path, FileCoverage]:
    """Load and strictly normalize a Coverage.py JSON report."""
    try:
        raw = cast("JSONValue", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        message = f"cannot read coverage report {path}: {error}"
        raise CoveragePolicyError(message) from error
    if not isinstance(raw, dict):
        message = "coverage report root must be an object"
        raise CoveragePolicyError(message)
    meta = raw.get("meta")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        message = "coverage report is invalid or branch coverage was not enabled"
        raise CoveragePolicyError(message)
    raw_files = raw.get("files")
    if not isinstance(raw_files, dict):
        message = "coverage report files must be an object"
        raise CoveragePolicyError(message)

    result: dict[Path, FileCoverage] = {}
    for raw_name, raw_file in raw_files.items():
        if not isinstance(raw_file, dict):
            message = "coverage file entries must map paths to objects"
            raise CoveragePolicyError(message)
        file_name = _relative_path(raw_name)
        if file_name in result:
            message = f"coverage contains duplicate normalized path {file_name.as_posix()}"
            raise CoveragePolicyError(message)
        coverage = FileCoverage(
            covered_lines=_positive_ints(
                raw_file.get("executed_lines"),
                field="executed_lines",
                file_name=raw_name,
            ),
            missing_lines=_positive_ints(
                raw_file.get("missing_lines"),
                field="missing_lines",
                file_name=raw_name,
            ),
            covered_branches=_branches(
                raw_file.get("executed_branches"),
                field="executed_branches",
                file_name=raw_name,
            ),
            missing_branches=_branches(
                raw_file.get("missing_branches"),
                field="missing_branches",
                file_name=raw_name,
            ),
        )
        if coverage.covered_lines & coverage.missing_lines:
            message = f"{raw_name}: a line cannot be both covered and missing"
            raise CoveragePolicyError(message)
        if coverage.covered_branches & coverage.missing_branches:
            message = f"{raw_name}: a branch cannot be both covered and missing"
            raise CoveragePolicyError(message)
        result[file_name] = coverage
    return result


def discover_production_files(repository: Path, source_roots: tuple[Path, ...]) -> set[Path]:
    """Discover every checked-in production Python source under configured roots."""
    discovered: set[Path] = set()
    for root in source_roots:
        absolute_root = repository / root
        if not absolute_root.exists():
            continue
        for candidate in absolute_root.rglob("*.py"):
            relative = candidate.relative_to(repository)
            if EXCLUDED_PARTS.isdisjoint(relative.parts):
                discovered.add(relative)
    return discovered


def package_for(path: Path, source_roots: tuple[Path, ...]) -> str:
    """Map a file to its independently released first-party package boundary."""
    for root in source_roots:
        try:
            remainder = path.relative_to(root)
        except ValueError:
            continue
        if root.parts and root.parts[0] == "src":
            return root.as_posix().removeprefix("src/")
        if len(remainder.parts) > 1:
            return (root / remainder.parts[0]).as_posix()
        return root.as_posix()
    message = f"production file is outside configured source roots: {path.as_posix()}"
    raise CoveragePolicyError(message)


def _ratio_for_files(
    report: dict[Path, FileCoverage],
    files: set[Path],
    *,
    branches: bool,
) -> Ratio:
    covered = 0
    total = 0
    for file_name in files:
        coverage = report[file_name]
        if branches:
            covered += len(coverage.covered_branches)
            total += len(coverage.branches)
        else:
            covered += len(coverage.covered_lines)
            total += len(coverage.executable_lines)
    return Ratio(covered=covered, total=total)


def evaluate_coverage(
    report: dict[Path, FileCoverage],
    production_files: set[Path],
    source_roots: tuple[Path, ...],
    thresholds: Thresholds,
    changed_lines: dict[Path, frozenset[int]],
) -> Evaluation:
    """Evaluate package and changed-code thresholds without trusting report totals."""
    failures = [
        f"coverage data is missing for production file {file_name.as_posix()}"
        for file_name in sorted(production_files - report.keys())
    ]
    measured_files = production_files & report.keys()
    packages: dict[str, set[Path]] = defaultdict(set)
    for file_name in measured_files:
        packages[package_for(file_name, source_roots)].add(file_name)

    package_lines: dict[str, Ratio] = {}
    package_branches: dict[str, Ratio] = {}
    for package in sorted(packages):
        line_ratio = _ratio_for_files(report, packages[package], branches=False)
        branch_ratio = _ratio_for_files(report, packages[package], branches=True)
        package_lines[package] = line_ratio
        package_branches[package] = branch_ratio
        if line_ratio.percent < thresholds.line:
            failures.append(
                f"package {package} line coverage {line_ratio.percent:.2f}% is below "
                f"{thresholds.line:.2f}% ({line_ratio.covered}/{line_ratio.total})"
            )
        if branch_ratio.percent < thresholds.branch:
            failures.append(
                f"package {package} branch coverage {branch_ratio.percent:.2f}% is below "
                f"{thresholds.branch:.2f}% ({branch_ratio.covered}/{branch_ratio.total})"
            )

    changed_line_covered = 0
    changed_line_total = 0
    changed_branch_covered = 0
    changed_branch_total = 0
    for file_name, lines in changed_lines.items():
        if file_name not in production_files:
            continue
        coverage = report.get(file_name)
        if coverage is None:
            continue
        eligible_lines = coverage.executable_lines & lines
        changed_line_total += len(eligible_lines)
        changed_line_covered += len(coverage.covered_lines & eligible_lines)
        eligible_branches = {branch for branch in coverage.branches if branch[0] in lines}
        changed_branch_total += len(eligible_branches)
        changed_branch_covered += len(coverage.covered_branches & eligible_branches)

    changed_line_ratio = Ratio(changed_line_covered, changed_line_total)
    changed_branch_ratio = Ratio(changed_branch_covered, changed_branch_total)
    if changed_line_ratio.percent < thresholds.changed:
        failures.append(
            f"changed line coverage {changed_line_ratio.percent:.2f}% is below "
            f"{thresholds.changed:.2f}% "
            f"({changed_line_ratio.covered}/{changed_line_ratio.total})"
        )
    if changed_branch_ratio.percent < thresholds.changed:
        failures.append(
            f"changed branch coverage {changed_branch_ratio.percent:.2f}% is below "
            f"{thresholds.changed:.2f}% "
            f"({changed_branch_ratio.covered}/{changed_branch_ratio.total})"
        )
    return Evaluation(
        failures=tuple(failures),
        package_lines=package_lines,
        package_branches=package_branches,
        changed_lines=changed_line_ratio,
        changed_branches=changed_branch_ratio,
    )


def parse_changed_lines(diff: str) -> dict[Path, frozenset[int]]:
    """Parse new-side line numbers from a zero-context unified Git diff."""
    changed: dict[Path, set[int]] = defaultdict(set)
    current: Path | None = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = _relative_path(line.removeprefix("+++ b/"))
            continue
        match = HUNK_PATTERN.match(line)
        if match is None or current is None:
            continue
        start = int(match.group(1))
        length = int(match.group(2) or "1")
        changed[current].update(range(start, start + length))
    return {path: frozenset(lines) for path, lines in changed.items()}


def _git_executable() -> str:
    executable = shutil.which("git")
    if executable is None:
        message = "Git is required to measure changed-code coverage"
        raise CoveragePolicyError(message)
    return executable


def _resolve_base(repository: Path, explicit: str | None) -> str:
    candidates = (
        explicit,
        os.environ.get("COVERAGE_BASE_SHA"),
        os.environ.get("GITHUB_BASE_SHA"),
        f"origin/{os.environ['GITHUB_BASE_REF']}" if os.environ.get("GITHUB_BASE_REF") else None,
        "HEAD^",
    )
    for candidate in candidates:
        if candidate is None:
            continue
        result = subprocess.run(  # noqa: S603
            [_git_executable(), "rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}"],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return candidate
        if explicit is not None:
            break
    message = "cannot resolve a Git base commit for changed-code coverage"
    raise CoveragePolicyError(message)


def changed_lines_from_git(
    repository: Path,
    source_roots: tuple[Path, ...],
    base: str | None,
) -> dict[Path, frozenset[int]]:
    """Read changed new-side lines from the selected base through the working tree."""
    resolved_base = _resolve_base(repository, base)
    command = [
        _git_executable(),
        "diff",
        "--no-ext-diff",
        "--no-color",
        "--unified=0",
        "--diff-filter=ACMR",
        resolved_base,
        "--",
        *(root.as_posix() for root in source_roots),
    ]
    result = subprocess.run(  # noqa: S603
        command,
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "git diff failed"
        raise CoveragePolicyError(detail)
    return parse_changed_lines(result.stdout)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Coverage.py JSON report")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    parser.add_argument("--base", help="Git base revision for changed-code coverage")
    parser.add_argument("--line", type=float, default=80, help="package line threshold")
    parser.add_argument("--branch", type=float, default=80, help="package branch threshold")
    parser.add_argument("--changed", type=float, default=80, help="changed-code threshold")
    parser.add_argument(
        "--source-root",
        action="append",
        type=Path,
        dest="source_roots",
        help="production source root (repeatable)",
    )
    return parser


def _require_production_files(production: set[Path]) -> None:
    if not production:
        message = "no production Python files were discovered"
        raise CoveragePolicyError(message)


def main(argv: list[str] | None = None) -> int:
    """Run the coverage policy and return a process exit status."""
    arguments = _parser().parse_args(argv)
    try:
        thresholds = Thresholds(arguments.line, arguments.branch, arguments.changed)
        repository = arguments.root.resolve(strict=True)
        source_roots = tuple(arguments.source_roots or DEFAULT_SOURCE_ROOTS)
        report_path = arguments.report
        if not report_path.is_absolute():
            report_path = repository / report_path
        report = load_coverage_report(report_path)
        production = discover_production_files(repository, source_roots)
        _require_production_files(production)
        changed = changed_lines_from_git(repository, source_roots, arguments.base)
        evaluation = evaluate_coverage(
            report,
            production,
            source_roots,
            thresholds,
            changed,
        )
    except (CoveragePolicyError, OSError) as error:
        sys.stderr.write(f"coverage policy error: {error}\n")
        return 2

    for package in sorted(evaluation.package_lines):
        lines = evaluation.package_lines[package]
        branches = evaluation.package_branches[package]
        sys.stdout.write(
            f"{package}: lines {lines.percent:.2f}% ({lines.covered}/{lines.total}), "
            f"branches {branches.percent:.2f}% ({branches.covered}/{branches.total})\n"
        )
    sys.stdout.write(
        "changed code: "
        f"lines {evaluation.changed_lines.percent:.2f}% "
        f"({evaluation.changed_lines.covered}/{evaluation.changed_lines.total}), "
        f"branches {evaluation.changed_branches.percent:.2f}% "
        f"({evaluation.changed_branches.covered}/{evaluation.changed_branches.total})\n"
    )
    if evaluation.failures:
        for failure in evaluation.failures:
            sys.stderr.write(f"FAIL: {failure}\n")
        return 1
    sys.stdout.write("coverage policy passed\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
