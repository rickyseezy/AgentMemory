"""Fail-closed deterministic Python mutation shard tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from mutmut.__main__ import cli
from mutmut.configuration import Config
from tools.python_mutation_shards import (
    MutationShardError,
    build_plan,
    main,
    run_shard,
    verify_evidence,
    write_manifest,
)

if TYPE_CHECKING:
    from pathlib import Path


def _project(root: Path, *, patterns: list[str] | None = None) -> Path:
    source = root / "src" / "agentmemory"
    source.mkdir(parents=True)
    (source / "large.py").write_text("value = 1\n" * 20, encoding="utf-8")
    (source / "medium.py").write_text("value = 2\n" * 10, encoding="utf-8")
    (source / "small.py").write_text("value = 3\n", encoding="utf-8")
    selected = patterns or ["*large.py", "*medium.py", "*small.py"]
    quoted = ", ".join(json.dumps(pattern) for pattern in selected)
    (root / "pyproject.toml").write_text(
        f'[tool.mutmut]\nsource_paths = ["src/agentmemory"]\nonly_mutate = [{quoted}]\n',
        encoding="utf-8",
    )
    return root


def _metadata(directory: Path, source: str, results: dict[str, int]) -> None:
    path = directory / f"{source}.meta"
    path.parent.mkdir(parents=True, exist_ok=True)
    timings = dict.fromkeys(results, 0.1)
    path.write_text(
        json.dumps(
            {
                "exit_code_by_key": results,
                "durations_by_key": timings,
                "estimated_durations_by_key": timings,
                "type_check_error_by_key": {},
            }
        ),
        encoding="utf-8",
    )


def _complete_evidence(project: Path, evidence: Path, *, killed: int, survived: int) -> None:
    plan = build_plan(project, 2)
    remaining_killed = killed
    remaining_survived = survived
    for shard in plan.shards:
        directory = evidence / f"shard-{shard.index}"
        write_manifest(directory, plan, shard.index)
        for file_index, source in enumerate(shard.files):
            results: dict[str, int] = {}
            if file_index == 0:
                results.update(
                    {f"killed-{shard.index}-{index}": 1 for index in range(remaining_killed)}
                )
                results.update(
                    {f"survived-{shard.index}-{index}": 0 for index in range(remaining_survived)}
                )
                remaining_killed = 0
                remaining_survived = 0
            _metadata(directory, source, results)


def test_plan_is_balanced_deterministic_and_exhaustive(tmp_path: Path) -> None:
    project = _project(tmp_path)
    first = build_plan(project, 2)
    second = build_plan(project, 2)
    assert first == second
    assert first.digest.startswith("sha256:")
    assert {pattern for shard in first.shards for pattern in shard.patterns} == {
        "*large.py",
        "*medium.py",
        "*small.py",
    }
    assert {file for shard in first.shards for file in shard.files} == {
        "src/agentmemory/large.py",
        "src/agentmemory/medium.py",
        "src/agentmemory/small.py",
    }
    assert max(shard.weight for shard in first.shards) == 20
    assert min(shard.weight for shard in first.shards) == 11


def test_aggregate_accepts_exact_eighty_percent_and_cli(tmp_path: Path) -> None:
    project = _project(tmp_path / "project")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _complete_evidence(project, evidence, killed=8, survived=2)
    assert verify_evidence(project, evidence, 2, 80).startswith("Python mutation score 80.00%")
    assert (
        main(
            [
                "verify",
                "--project-root",
                str(project),
                "--evidence",
                str(evidence),
                "--shard-count",
                "2",
                "--minimum",
                "80",
            ]
        )
        == 0
    )


def test_aggregate_rejects_low_score_stale_duplicate_and_missing_evidence(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path / "project")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _complete_evidence(project, evidence, killed=7, survived=3)
    with pytest.raises(MutationShardError, match="below"):
        verify_evidence(project, evidence, 2, 80)

    manifest = evidence / "shard-0" / "python-mutation-shard.json"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["plan_digest"] = "sha256:" + ("0" * 64)
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(MutationShardError, match="current source plan"):
        verify_evidence(project, evidence, 2, 0)

    manifest.unlink()
    with pytest.raises(MutationShardError, match="exactly one manifest"):
        verify_evidence(project, evidence, 2, 0)


def test_plan_rejects_invalid_counts_paths_patterns_and_overlap(tmp_path: Path) -> None:
    project = _project(tmp_path / "project")
    for count in (0, 65, 4):
        with pytest.raises(MutationShardError):
            build_plan(project, count)

    overlapping = _project(
        tmp_path / "overlap",
        patterns=["*large.py", "*agentmemory/*.py"],
    )
    with pytest.raises(MutationShardError, match="overlapping"):
        build_plan(overlapping, 1)

    missing = _project(tmp_path / "missing", patterns=["*absent.py"])
    with pytest.raises(MutationShardError, match="matches no source"):
        build_plan(missing, 1)

    unsafe = _project(tmp_path / "unsafe")
    (unsafe / "pyproject.toml").write_text(
        '[tool.mutmut]\nsource_paths = ["../outside"]\nonly_mutate = ["*.py"]\n',
        encoding="utf-8",
    )
    with pytest.raises(MutationShardError, match="unsafe path"):
        build_plan(unsafe, 1)


def test_aggregate_rejects_metadata_escape_and_duplicate_indices(tmp_path: Path) -> None:
    project = _project(tmp_path / "project")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _complete_evidence(project, evidence, killed=1, survived=0)
    extra = evidence / "shard-0" / "src" / "agentmemory" / "extra.py.meta"
    extra.write_text("{}", encoding="utf-8")
    with pytest.raises(MutationShardError, match="exactly cover"):
        verify_evidence(project, evidence, 2, 0)
    extra.unlink()

    first = evidence / "shard-0" / "python-mutation-shard.json"
    second = evidence / "shard-1" / "python-mutation-shard.json"
    duplicate = json.loads(first.read_text(encoding="utf-8"))
    second.write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(MutationShardError, match="duplicated"):
        verify_evidence(project, evidence, 2, 0)


def test_worker_applies_only_its_reviewed_partition_and_writes_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project(tmp_path / "project")
    observed: dict[str, object] = {}

    def fake_main(*, args: list[str], prog_name: str, standalone_mode: bool) -> None:
        observed["args"] = args
        observed["prog_name"] = prog_name
        observed["standalone_mode"] = standalone_mode
        observed["patterns"] = tuple(Config.get().only_mutate)
        (project / "mutants").mkdir()

    monkeypatch.setattr(cli, "main", fake_main)
    run_shard(project, 2, 1, 3)
    plan = build_plan(project, 2)
    assert observed == {
        "args": ["run", "--max-children", "3"],
        "prog_name": "mutmut",
        "standalone_mode": False,
        "patterns": plan.shards[1].patterns,
    }
    manifest = json.loads(
        (project / "mutants" / "python-mutation-shard.json").read_text(encoding="utf-8")
    )
    assert manifest["shard_index"] == 1
    assert manifest["plan_digest"] == plan.digest


@pytest.mark.parametrize("children", [0, 33])
def test_worker_rejects_unsafe_parallelism(
    tmp_path: Path,
    children: int,
) -> None:
    project = _project(tmp_path / str(children))
    with pytest.raises(MutationShardError, match="child count"):
        run_shard(project, 2, 0, children)


def test_cli_and_manifest_reject_invalid_inputs(tmp_path: Path) -> None:
    project = _project(tmp_path / "project")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    assert (
        main(
            [
                "verify",
                "--project-root",
                str(project),
                "--evidence",
                str(evidence),
                "--shard-count",
                "2",
                "--minimum",
                "101",
            ]
        )
        == 1
    )
    plan = build_plan(project, 2)
    write_manifest(evidence, plan, 0)
    manifest = evidence / "python-mutation-shard.json"
    manifest.write_text("[]", encoding="utf-8")
    with pytest.raises(MutationShardError, match="root is invalid"):
        verify_evidence(project, evidence, 1, 0)
