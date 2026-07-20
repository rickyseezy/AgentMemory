"""Enforce the Python critical-domain mutation score from bounded Mutmut evidence."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import cast

_MAX_META_BYTES = 8 * 1024 * 1024
_MAX_PERCENT = 100.0


class MutationEvidenceError(ValueError):
    """Reject absent, unsafe, incomplete, or malformed mutation evidence."""


@dataclass(frozen=True, slots=True)
class MutationScore:
    """One deterministic aggregate over completed Mutmut results."""

    killed: int
    survived: int

    @property
    def total(self) -> int:
        """Return the number of completed mutants."""
        return self.killed + self.survived

    @property
    def percent(self) -> float:
        """Return killed mutants as a percentage of all completed mutants."""
        return self.killed * 100 / self.total


def load_score(directory: Path) -> MutationScore:
    """Load every regular bounded Mutmut metadata record without following links."""
    if directory.is_symlink() or not directory.is_dir():
        msg = "mutation evidence directory is missing or unsafe"
        raise MutationEvidenceError(msg)
    metadata = sorted(directory.rglob("*.py.meta"))
    if not metadata:
        msg = "mutation evidence contains no metadata"
        raise MutationEvidenceError(msg)
    results: dict[str, int] = {}
    for path in metadata:
        for mutant, exit_code in _load_metadata(path).items():
            if mutant in results:
                msg = "mutation result identity is duplicated"
                raise MutationEvidenceError(msg)
            results[mutant] = exit_code
    killed = sum(exit_code != 0 for exit_code in results.values())
    return MutationScore(killed=killed, survived=len(results) - killed)


def main(argv: list[str] | None = None) -> int:
    """Validate evidence and enforce the configured minimum score."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--minimum", type=float, default=80.0)
    arguments = parser.parse_args(argv)
    if arguments.minimum < 0 or arguments.minimum > _MAX_PERCENT:
        sys.stderr.write("mutation threshold must be between 0 and 100\n")
        return 2
    try:
        score = load_score(arguments.directory)
    except MutationEvidenceError as error:
        sys.stderr.write(f"mutation evidence error: {error}\n")
        return 1
    sys.stdout.write(
        f"Python mutation score {score.percent:.2f}% "
        f"({score.killed}/{score.total}; {score.survived} survived)\n"
    )
    if score.percent < arguments.minimum:
        sys.stderr.write(f"Python mutation score is below {arguments.minimum:.2f}%\n")
        return 1
    return 0


def _load_metadata(path: Path) -> dict[str, int]:
    if path.is_symlink() or not path.is_file():
        msg = "mutation metadata path is unsafe"
        raise MutationEvidenceError(msg)
    size = path.stat().st_size
    if size < 1 or size > _MAX_META_BYTES:
        msg = "mutation metadata size is invalid"
        raise MutationEvidenceError(msg)
    try:
        document = cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        msg = "mutation metadata cannot be decoded"
        raise MutationEvidenceError(msg) from error
    if not isinstance(document, dict):
        msg = "mutation metadata root is invalid"
        raise MutationEvidenceError(msg)
    mapping = cast("dict[object, object]", document)
    raw = mapping.get("exit_code_by_key")
    durations = mapping.get("durations_by_key")
    estimates = mapping.get("estimated_durations_by_key")
    type_errors = mapping.get("type_check_error_by_key")
    if not isinstance(raw, dict) or not raw:
        msg = "mutation metadata has no completed results"
        raise MutationEvidenceError(msg)
    if (
        not isinstance(durations, dict)
        or not isinstance(estimates, dict)
        or not isinstance(type_errors, dict)
        or type_errors
    ):
        msg = "mutation metadata is incomplete"
        raise MutationEvidenceError(msg)
    duration_values = cast("dict[object, object]", durations)
    estimate_values = cast("dict[object, object]", estimates)
    results: dict[str, int] = {}
    raw_results = cast("dict[object, object]", raw)
    if set(raw_results) != set(duration_values) or set(raw_results) != set(estimate_values):
        msg = "mutation metadata is incomplete"
        raise MutationEvidenceError(msg)
    for mutant, exit_code in raw_results.items():
        if not isinstance(mutant, str) or not mutant or not isinstance(exit_code, int):
            msg = "mutation result is malformed"
            raise MutationEvidenceError(msg)
        results[mutant] = exit_code
    return results


if __name__ == "__main__":
    raise SystemExit(main())
