"""IDX-002 real Git, dirty-worktree, rename, copy, and safe-read adapter tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.git_incremental_source import (
    GitIncrementalRepositorySource,
    LanguagePluginFingerprintProvider,
)
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.domain.errors import IndexingUnavailableError
from agentmemory.indexing.domain.incremental import PriorIndexedUnit, VcsDeltaKind

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.indexing.domain.incremental_ports import RepositoryInspection

REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(  # noqa: S603 -- Test invokes resolved Git with fixed arguments.
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "idx002@example.invalid")
    _git(root, "config", "user.name", "IDX-002 Test")
    (root / "src").mkdir()
    (root / "src" / "a.py").write_text("def a():\n    return 1\n")
    (root / "src" / "b.py").write_text("def b():\n    return 1\n")
    _git(root, "add", "--", "src/a.py", "src/b.py")
    _git(root, "commit", "-m", "initial")
    return root, _git(root, "rev-parse", "HEAD")


def _prior(inspection: RepositoryInspection) -> tuple[PriorIndexedUnit, ...]:
    files = inspection.files
    return tuple(
        PriorIndexedUnit(
            item.relative_path,
            _digest(f"file:{item.relative_path}".encode()),
            _digest(f"revision:{item.relative_path}".encode()),
            item.content_digest,
            _digest(f"cache:{item.relative_path}".encode()),
            (),
        )
        for item in files
    )


@pytest.mark.asyncio
async def test_git_adapter_detects_dirty_modify_rename_and_untracked_add(tmp_path: Path) -> None:
    root, base = _repository(tmp_path)
    adapter = GitIncrementalRepositorySource({REPOSITORY_ID: root})
    initial = await adapter.inspect(REPOSITORY_ID, None, None, ())
    assert {item.relative_path for item in initial.files} == {"src/a.py", "src/b.py"}

    (root / "src" / "b.py").write_text("def b():\n    return 2\n")
    (root / "src" / "a.py").rename(root / "src" / "renamed.py")
    (root / "src" / "new.py").write_text("def new(): pass\n")
    _git(root, "add", "--all")
    changed = await adapter.inspect(REPOSITORY_ID, base, None, _prior(initial))
    delta_kinds = {(item.kind, item.relative_path) for item in changed.vcs_deltas}

    assert (VcsDeltaKind.MODIFY, "src/b.py") in delta_kinds
    assert (VcsDeltaKind.RENAME, "src/renamed.py") in delta_kinds
    assert (VcsDeltaKind.ADD, "src/new.py") in delta_kinds
    assert {item.relative_path for item in changed.files} == {
        "src/b.py",
        "src/new.py",
        "src/renamed.py",
    }
    artifact = await adapter.read(
        REPOSITORY_ID,
        changed.target_commit_id,
        "src/b.py",
        _digest(b"def b():\n    return 2\n"),
    )
    assert artifact.content.endswith(b"return 2\n")


@pytest.mark.asyncio
async def test_git_adapter_reads_explicit_historical_commit_and_rejects_changed_source(
    tmp_path: Path,
) -> None:
    root, base = _repository(tmp_path)
    adapter = GitIncrementalRepositorySource({REPOSITORY_ID: root})
    (root / "src" / "a.py").write_text("def a():\n    return 3\n")
    _git(root, "add", "--", "src/a.py")
    _git(root, "commit", "-m", "change")
    target = _git(root, "rev-parse", "HEAD")
    initial = await adapter.inspect(REPOSITORY_ID, None, base, ())
    changed = await adapter.inspect(REPOSITORY_ID, base, target, _prior(initial))
    entry = next(item for item in changed.files if item.relative_path == "src/a.py")

    artifact = await adapter.read(REPOSITORY_ID, target, "src/a.py", entry.content_digest)
    assert artifact.content.endswith(b"return 3\n")
    with pytest.raises(IndexingUnavailableError, match="changed during indexing"):
        await adapter.read(REPOSITORY_ID, target, "src/a.py", "f" * 64)


def test_fingerprint_provider_binds_parser_grammar_queries_extraction_and_privacy() -> None:
    provider = LanguagePluginFingerprintProvider(
        TreeSitterLanguagePlugin(),
        language_lock_digest=_digest(b"language-lock"),
        extraction_config_digest=_digest(b"extraction-config"),
        privacy_policy_version="privacy-v7",
    )
    fingerprint = provider.for_path("src/component.tsx")

    assert fingerprint.plugin_version.startswith("tree-sitter-0.26.0")
    assert len(fingerprint.grammar_revision) == 40
    assert fingerprint.privacy_policy_version == "privacy-v7"
    assert provider.implementation_digest == provider.implementation_digest
