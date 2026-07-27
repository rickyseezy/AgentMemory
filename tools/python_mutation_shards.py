"""Plan, execute, and verify deterministic Mutmut CI shards."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
import tomllib
from contextlib import chdir
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from tools.check_python_mutation import MutationEvidenceError, load_score

if TYPE_CHECKING:
    from collections.abc import Sequence

_MANIFEST_NAME = "python-mutation-shard.json"
_MANIFEST_SCHEMA = 1
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_PERCENT = 100.0
_MAX_SHARDS = 64
_MAX_MUTMUT_CHILDREN = 32


class MutationShardError(ValueError):
    """Reject unsafe, incomplete, overlapping, or stale shard evidence."""


@dataclass(frozen=True, slots=True)
class MutationTarget:
    """One configured pattern and the exact source files it owns."""

    pattern: str
    files: tuple[str, ...]
    weight: int


@dataclass(frozen=True, slots=True)
class MutationShard:
    """One deterministic partition of the configured mutation surface."""

    index: int
    patterns: tuple[str, ...]
    files: tuple[str, ...]
    weight: int


@dataclass(frozen=True, slots=True)
class MutationShardPlan:
    """The complete source-bound mutation partition."""

    digest: str
    source_paths: tuple[str, ...]
    configured_patterns: tuple[str, ...]
    shards: tuple[MutationShard, ...]


def build_plan(project_root: Path, shard_count: int) -> MutationShardPlan:
    """Build a deterministic, balanced, exhaustive partition."""
    root = _resolved_directory(project_root)
    if shard_count < 1 or shard_count > _MAX_SHARDS:
        msg = "mutation shard count must be between 1 and 64"
        raise MutationShardError(msg)
    source_paths, patterns = _load_configuration(root / "pyproject.toml")
    source_files = _source_files(root, source_paths)
    targets = _targets(patterns, source_files, root)
    if shard_count > len(targets):
        msg = "mutation shard count exceeds the configured target count"
        raise MutationShardError(msg)

    assignments: list[list[MutationTarget]] = [[] for _ in range(shard_count)]
    weights = [0] * shard_count
    for target in sorted(targets, key=lambda item: (-item.weight, item.pattern)):
        index = min(range(shard_count), key=lambda candidate: (weights[candidate], candidate))
        assignments[index].append(target)
        weights[index] += target.weight

    order = {pattern: index for index, pattern in enumerate(patterns)}
    shards: list[MutationShard] = []
    for index, assigned in enumerate(assignments):
        selected = sorted(assigned, key=lambda item: order[item.pattern])
        files = tuple(sorted(file for target in selected for file in target.files))
        shards.append(
            MutationShard(
                index=index,
                patterns=tuple(target.pattern for target in selected),
                files=files,
                weight=weights[index],
            )
        )
    digest = _plan_digest(root, source_paths, patterns, source_files)
    return MutationShardPlan(
        digest=digest,
        source_paths=source_paths,
        configured_patterns=patterns,
        shards=tuple(shards),
    )


def write_manifest(directory: Path, plan: MutationShardPlan, shard_index: int) -> Path:
    """Persist one canonical source-bound shard manifest."""
    shard = _select_shard(plan, shard_index)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _MANIFEST_NAME
    document = {
        "schema_version": _MANIFEST_SCHEMA,
        "plan_digest": plan.digest,
        "shard_count": len(plan.shards),
        "shard_index": shard.index,
        "patterns": list(shard.patterns),
        "files": list(shard.files),
        "weight": shard.weight,
    }
    path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return path


def verify_evidence(
    project_root: Path,
    evidence_root: Path,
    shard_count: int,
    minimum: float,
) -> str:
    """Verify exact shard coverage and enforce the aggregate mutation score."""
    if minimum < 0 or minimum > _MAX_PERCENT:
        msg = "mutation threshold must be between 0 and 100"
        raise MutationShardError(msg)
    evidence = _resolved_directory(evidence_root)
    plan = build_plan(project_root, shard_count)
    manifests = sorted(evidence.rglob(_MANIFEST_NAME))
    if len(manifests) != shard_count:
        msg = "mutation evidence does not contain exactly one manifest per shard"
        raise MutationShardError(msg)

    seen: set[int] = set()
    for path in manifests:
        document = _load_manifest(path)
        index = _manifest_integer(document, "shard_index")
        if index in seen:
            msg = "mutation shard index is duplicated"
            raise MutationShardError(msg)
        seen.add(index)
        expected = _select_shard(plan, index)
        if (
            document.get("schema_version") != _MANIFEST_SCHEMA
            or document.get("plan_digest") != plan.digest
            or document.get("shard_count") != shard_count
            or document.get("patterns") != list(expected.patterns)
            or document.get("files") != list(expected.files)
            or document.get("weight") != expected.weight
        ):
            msg = "mutation shard manifest does not match the current source plan"
            raise MutationShardError(msg)
        _verify_shard_metadata(path.parent, expected)

    if seen != set(range(shard_count)):
        msg = "mutation shard index set is incomplete"
        raise MutationShardError(msg)
    try:
        score = load_score(evidence)
    except MutationEvidenceError as error:
        raise MutationShardError(str(error)) from error
    summary = (
        f"Python mutation score {score.percent:.2f}% "
        f"({score.killed}/{score.total}; {score.survived} survived)"
    )
    if score.percent < minimum:
        msg = f"{summary}; below {minimum:.2f}%"
        raise MutationShardError(msg)
    return summary


def run_shard(project_root: Path, shard_count: int, shard_index: int, max_children: int) -> None:
    """Run Mutmut for one planned shard and emit its manifest after success."""
    if max_children < 1 or max_children > _MAX_MUTMUT_CHILDREN:
        msg = "Mutmut child count must be between 1 and 32"
        raise MutationShardError(msg)
    root = _resolved_directory(project_root)
    plan = build_plan(root, shard_count)
    shard = _select_shard(plan, shard_index)

    # Mutmut is an optional development dependency and is deliberately loaded only by workers;
    # the aggregate verifier remains dependency-free.
    from mutmut.__main__ import cli  # noqa: PLC0415
    from mutmut.configuration import Config  # noqa: PLC0415

    with chdir(root):
        Config.reset()
        try:
            Config.ensure_loaded()
            configuration = Config.get()
            if tuple(configuration.only_mutate) != plan.configured_patterns:
                msg = "loaded Mutmut configuration differs from the reviewed shard plan"
                raise MutationShardError(msg)
            configuration.only_mutate = list(shard.patterns)
            result = cli.main(
                args=["run", "--max-children", str(max_children)],
                prog_name="mutmut",
                standalone_mode=False,
            )
            if result not in (None, 0):
                msg = "Mutmut shard returned an unexpected result"
                raise MutationShardError(msg)
        finally:
            Config.reset()
    write_manifest(root / "mutants", plan, shard_index)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the shard worker or the aggregate evidence gate."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--project-root", type=Path, default=Path.cwd())
    run_parser.add_argument("--shard-count", type=int, required=True)
    run_parser.add_argument("--shard-index", type=int, required=True)
    run_parser.add_argument("--max-children", type=int, default=4)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--project-root", type=Path, default=Path.cwd())
    verify_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser.add_argument("--shard-count", type=int, required=True)
    verify_parser.add_argument("--minimum", type=float, default=80.0)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "run":
            run_shard(
                arguments.project_root,
                arguments.shard_count,
                arguments.shard_index,
                arguments.max_children,
            )
        else:
            summary = verify_evidence(
                arguments.project_root,
                arguments.evidence,
                arguments.shard_count,
                arguments.minimum,
            )
            sys.stdout.write(summary + "\n")
    except MutationShardError as error:
        sys.stderr.write(f"mutation shard error: {error}\n")
        return 1
    return 0


def _load_configuration(path: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if path.is_symlink() or not path.is_file():
        msg = "reviewed pyproject.toml is missing or unsafe"
        raise MutationShardError(msg)
    try:
        raw = cast("object", tomllib.loads(path.read_text(encoding="utf-8")))
        root = cast("dict[object, object]", raw)
        tool = cast("dict[object, object]", root["tool"])
        mutation = cast("dict[object, object]", tool["mutmut"])
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        msg = "reviewed Mutmut configuration cannot be decoded"
        raise MutationShardError(msg) from error
    source_paths = _string_tuple(mutation.get("source_paths"), "source_paths")
    patterns = _string_tuple(mutation.get("only_mutate"), "only_mutate")
    if len(set(patterns)) != len(patterns):
        msg = "configured mutation patterns are duplicated"
        raise MutationShardError(msg)
    for value in (*source_paths, *patterns):
        candidate = Path(value)
        if candidate.is_absolute() or ".." in candidate.parts or "\x00" in value:
            msg = "mutation configuration contains an unsafe path"
            raise MutationShardError(msg)
    return source_paths, patterns


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in cast("list[object]", value))
    ):
        msg = f"Mutmut {field} must be a non-empty string list"
        raise MutationShardError(msg)
    return tuple(cast("list[str]", value))


def _source_files(root: Path, source_paths: tuple[str, ...]) -> tuple[Path, ...]:
    files: list[Path] = []
    for configured in source_paths:
        source = root / configured
        if source.is_symlink() or not source.is_dir():
            msg = "configured mutation source path is missing or unsafe"
            raise MutationShardError(msg)
        for path in sorted(source.rglob("*.py")):
            if path.is_symlink() or not path.is_file():
                msg = "mutation source contains an unsafe Python path"
                raise MutationShardError(msg)
            files.append(path)
    if not files or len(set(files)) != len(files):
        msg = "configured mutation sources are empty or overlapping"
        raise MutationShardError(msg)
    return tuple(files)


def _targets(
    patterns: tuple[str, ...],
    source_files: tuple[Path, ...],
    root: Path,
) -> tuple[MutationTarget, ...]:
    relative = {path: path.relative_to(root).as_posix() for path in source_files}
    owners: dict[Path, str] = {}
    targets: list[MutationTarget] = []
    for pattern in patterns:
        matched = tuple(
            sorted(value for value in relative.values() if fnmatch.fnmatch(value, pattern))
        )
        if not matched:
            msg = f"mutation pattern matches no source file: {pattern}"
            raise MutationShardError(msg)
        for path, value in relative.items():
            if value not in matched:
                continue
            if path in owners:
                msg = f"mutation source is selected by overlapping patterns: {value}"
                raise MutationShardError(msg)
            owners[path] = pattern
        weight = sum(_line_weight(root / value) for value in matched)
        targets.append(MutationTarget(pattern=pattern, files=matched, weight=weight))
    return tuple(targets)


def _line_weight(path: Path) -> int:
    try:
        content = path.read_bytes()
    except OSError as error:
        msg = "mutation source cannot be read"
        raise MutationShardError(msg) from error
    return max(1, content.count(b"\n") + (not content.endswith(b"\n")))


def _plan_digest(
    root: Path,
    source_paths: tuple[str, ...],
    patterns: tuple[str, ...],
    source_files: tuple[Path, ...],
) -> str:
    files = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source_files
    }
    payload = json.dumps(
        {"source_paths": source_paths, "patterns": patterns, "files": files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _select_shard(plan: MutationShardPlan, index: int) -> MutationShard:
    if index < 0 or index >= len(plan.shards):
        msg = "mutation shard index is outside the plan"
        raise MutationShardError(msg)
    return plan.shards[index]


def _resolved_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        msg = "required directory is missing"
        raise MutationShardError(msg) from error
    if path.is_symlink() or not resolved.is_dir():
        msg = "required directory is unsafe"
        raise MutationShardError(msg)
    return resolved


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        msg = "mutation shard manifest path is unsafe"
        raise MutationShardError(msg)
    size = path.stat().st_size
    if size < 1 or size > _MAX_MANIFEST_BYTES:
        msg = "mutation shard manifest size is invalid"
        raise MutationShardError(msg)
    try:
        document = cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        msg = "mutation shard manifest cannot be decoded"
        raise MutationShardError(msg) from error
    if not isinstance(document, dict):
        msg = "mutation shard manifest root is invalid"
        raise MutationShardError(msg)
    return cast("dict[str, Any]", document)


def _manifest_integer(document: dict[str, Any], field: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        msg = f"mutation shard manifest {field} is invalid"
        raise MutationShardError(msg)
    return value


def _verify_shard_metadata(directory: Path, shard: MutationShard) -> None:
    actual = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*.py.meta")
        if path.is_file() and not path.is_symlink()
    }
    expected = {f"{path}.meta" for path in shard.files}
    if actual != expected:
        msg = "mutation shard metadata does not exactly cover its planned files"
        raise MutationShardError(msg)


if __name__ == "__main__":
    raise SystemExit(main())
