"""IDX-001 local workspace and native parser isolation adapter tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.isolated_tree_sitter import (
    IsolatedTreeSitterLanguagePlugin,
    ParserIsolationPolicy,
)
from agentmemory.indexing.adapters.outbound.workspace_source import (
    LocalWorkspaceSnapshotSource,
    WorkspaceReadPolicy,
)
from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyDecision,
    PolicyLayer,
    PolicyRuleSource,
)
from agentmemory.indexing.domain.errors import (
    IndexingUnavailableError,
    IndexingValidationError,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.indexing.domain.content_policy_ports import PolicySourceDocuments


@dataclass(slots=True)
class _PolicyGate:
    decisions: list[PolicyDecision] = field(default_factory=list[PolicyDecision])

    async def prepare(
        self,
        repository_id: str,
        documents: PolicySourceDocuments,
        observed_at: datetime,
    ) -> IndexContentPolicy:
        revision = IndexPolicyRevision.production_default(BRAIN_ID, repository_id, observed_at)
        agent = (
            PolicyRuleSource.empty(PolicyLayer.AGENTMEMORY_IGNORE)
            if documents.agentmemoryignore is None
            else PolicyRuleSource.from_ignore_bytes(
                PolicyLayer.AGENTMEMORY_IGNORE, 1, documents.agentmemoryignore
            )
        )
        git = (
            PolicyRuleSource.empty(PolicyLayer.GITIGNORE)
            if documents.gitignore is None
            else PolicyRuleSource.from_ignore_bytes(PolicyLayer.GITIGNORE, 1, documents.gitignore)
        )
        return IndexContentPolicy(revision, agent, git)

    async def record(self, decision: PolicyDecision) -> None:
        self.decisions.append(decision)


def _source(root: Path, policy: WorkspaceReadPolicy | None = None) -> LocalWorkspaceSnapshotSource:
    return LocalWorkspaceSnapshotSource(
        root,
        policy,
        content_policy=_PolicyGate(),
        clock=FixedClock(NOW),
    )


@pytest.mark.asyncio
async def test_workspace_capture_is_sorted_relative_and_excludes_symlinks_and_build_data(
    tmp_path: Path,
) -> None:
    root = _seed_workspace(tmp_path)

    artifacts = await _source(root).read(_scope("indexing.snapshot"))
    assert [item.relative_path for item in artifacts] == [
        "outside.py",
        "src/a.py",
        "src/z.py",
    ]
    assert all(not item.relative_path.startswith(str(root)) for item in artifacts)


@pytest.mark.asyncio
async def test_workspace_capture_fails_closed_at_file_and_total_limits(tmp_path: Path) -> None:
    root = _seed_large_workspace(tmp_path)
    policy = WorkspaceReadPolicy(max_files=1, max_file_bytes=16, max_total_bytes=16)
    with pytest.raises(IndexingUnavailableError, match="limits"):
        await _source(root, policy).read(_scope("indexing.snapshot"))

    total_root = tmp_path / "total"
    total_root.mkdir()
    (total_root / "a.py").write_bytes(b"a" * 10)
    (total_root / "b.py").write_bytes(b"b" * 10)
    total_policy = WorkspaceReadPolicy(max_files=2, max_file_bytes=10, max_total_bytes=15)
    with pytest.raises(IndexingUnavailableError, match="limits"):
        await _source(total_root, total_policy).read(_scope("indexing.snapshot"))


def test_workspace_and_parser_policies_reject_unbounded_values(tmp_path: Path) -> None:
    with pytest.raises(IndexingValidationError):
        WorkspaceReadPolicy(max_files=0)
    with pytest.raises(IndexingValidationError):
        ParserIsolationPolicy(max_workers=9)
    with pytest.raises(IndexingValidationError):
        _source(Path("relative"))

    ordinary_file = tmp_path / "ordinary.txt"
    ordinary_file.write_text("not a directory")
    with pytest.raises(IndexingValidationError):
        _source(ordinary_file)
    with pytest.raises(IndexingUnavailableError, match="captured safely"):
        _source(tmp_path / "missing")

    target = tmp_path / "target"
    target.mkdir()
    symlink = tmp_path / "workspace-link"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(IndexingValidationError):
        _source(symlink)


def test_isolated_parser_round_trip_and_graceful_close() -> None:
    plugin = IsolatedTreeSitterLanguagePlugin(policy=ParserIsolationPolicy(1, 10))
    try:
        parsed = plugin.parse("python", "main.py", b"def hello():\n    return 1\n")
        assert parsed.definitions[0].display_name == "hello"
    finally:
        plugin.close()


def test_isolated_parser_retires_failed_workers_and_close_is_idempotent() -> None:
    plugin = IsolatedTreeSitterLanguagePlugin(policy=ParserIsolationPolicy(1, 10))
    plugin.close()
    with pytest.raises(IndexingUnavailableError, match="isolated source parser failed"):
        plugin.parse("unsupported", "main.unknown", b"source\n")
    plugin.close()


def _seed_workspace(root: Path) -> Path:
    (root / "src").mkdir()
    (root / "src" / "z.py").write_bytes(b"z = 1\n")
    (root / "src" / "a.py").write_bytes(b"a = 1\n")
    (root / ".git").mkdir()
    (root / ".git" / "secret").write_bytes(b"private")
    (root / "outside.py").write_bytes(b"outside = 1\n")
    (root / "binary.dat").write_bytes(b"public-prefix\x00private-tail")
    (root / "linked.py").symlink_to(root / "outside.py")
    return root


def _seed_large_workspace(root: Path) -> Path:
    (root / "large.py").write_bytes(b"x" * 17)
    return root
