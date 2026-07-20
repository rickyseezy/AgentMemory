"""Fail-closed Python mutation evidence gate tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from tools.check_python_mutation import load_score, main

if TYPE_CHECKING:
    from pathlib import Path


def _evidence(root: Path, results: dict[str, int]) -> Path:
    path = root / "src" / "sample.py.meta"
    path.parent.mkdir(parents=True)
    durations = dict.fromkeys(results, 0.1)
    path.write_text(
        json.dumps(
            {
                "exit_code_by_key": results,
                "durations_by_key": durations,
                "estimated_durations_by_key": durations,
                "type_check_error_by_key": {},
            }
        ),
        encoding="utf-8",
    )
    return root


def test_mutation_gate_accepts_exact_eighty_percent(tmp_path: Path) -> None:
    directory = _evidence(tmp_path, {f"mutant-{index}": int(index < 8) for index in range(10)})
    score = load_score(directory)
    assert score.killed == 8
    assert score.survived == 2
    assert score.percent == 80
    assert main([str(directory), "--minimum", "80"]) == 0


def test_mutation_gate_rejects_low_score_and_missing_evidence(tmp_path: Path) -> None:
    directory = _evidence(tmp_path / "low", {"killed": 1, "survived": 0})
    assert main([str(directory), "--minimum", "80"]) == 1
    assert main([str(tmp_path / "missing"), "--minimum", "80"]) == 1
    assert main([str(directory), "--minimum", "101"]) == 2


def test_mutation_gate_rejects_malformed_or_duplicate_evidence(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed"
    path = malformed / "sample.py.meta"
    path.parent.mkdir()
    path.write_text("{}", encoding="utf-8")
    assert main([str(malformed)]) == 1
    duplicate = tmp_path / "duplicate"
    _evidence(duplicate / "one", {"same": 1})
    _evidence(duplicate / "two", {"same": 1})
    assert main([str(duplicate)]) == 1
