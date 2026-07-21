"""IDX-007 real Git rename/history and host path-escape boundary tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.git_source_navigation import (
    BoundedLocalPathResolver,
    GitSourceContentAdapter,
)
from agentmemory.indexing.domain.code_entities import SemanticSource, SymbolKind
from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyDecision,
    PolicyLayer,
    PolicyRuleSource,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.source_navigation import (
    SourceEvidence,
    SourceEvidenceKind,
    span_for_offsets,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from agentmemory.indexing.domain.content_policy_ports import PolicySourceDocuments

REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
HISTORICAL = (
    "def café():\n    one = 1\n    two = 2\n    three = 3\n    return one + two + three\n"
).encode()


def _git(root: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(  # noqa: S603 -- Resolved Git and fixed test-owned arguments.
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
    )
    return result.stdout


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "idx007@example.invalid")
    _git(root, "config", "user.name", "IDX-007 Test")
    (root / "src").mkdir()
    (root / "src" / "old.py").write_bytes(HISTORICAL)
    _git(root, "add", "--", "src/old.py")
    _git(root, "commit", "-m", "historical source")
    commit = _git(root, "rev-parse", "HEAD").decode().strip()
    return root, commit


@dataclass(slots=True)
class _Gate:
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


def _evidence(commit: str) -> SourceEvidence:
    fragment = "café".encode()
    start = HISTORICAL.index(fragment)
    return SourceEvidence(
        "1" * 64,
        SourceEvidenceKind.DEFINITION,
        BRAIN_ID,
        PROJECT_ID,
        REPOSITORY_ID,
        "2" * 64,
        commit,
        "3" * 64,
        "4" * 64,
        "src/old.py",
        "5" * 64,
        "python:function:café",
        "café",
        SymbolKind.FUNCTION,
        None,
        span_for_offsets(HISTORICAL, start, start + len(fragment)),
        hashlib.sha256(HISTORICAL).hexdigest(),
        len(HISTORICAL),
        "parser@1",
        "grammar",
        "6" * 64,
        SemanticSource.TREE_SITTER,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_git_adapter_reads_exact_history_and_discovers_renamed_shifted_worktree(
    tmp_path: Path,
) -> None:
    root, commit = _repository(tmp_path)
    gate = _Gate()
    adapter = GitSourceContentAdapter(
        {REPOSITORY_ID: root},
        content_policy=gate,
        clock=FixedClock(NOW),
    )
    evidence = _evidence(commit)

    assert await adapter.historical(evidence) == HISTORICAL
    (root / "src" / "old.py").rename(root / "src" / "new.py")
    (root / "src" / "new.py").write_bytes(b"# shifted\n" + HISTORICAL)
    _git(root, "add", "-A")
    candidates = await adapter.checkout_candidates(evidence)

    assert [(item.commit_id, item.relative_path) for item in candidates] == [(commit, "src/new.py")]
    assert candidates[0].content.startswith(b"# shifted\n")
    assert candidates[0].checkout_dirty is True
    assert any(item.phase.value == "path" for item in gate.decisions)
    assert any(item.phase.value == "content" for item in gate.decisions)


@pytest.mark.asyncio
@pytest.mark.privacy
async def test_navigation_rechecks_policy_before_historical_or_current_read(tmp_path: Path) -> None:
    root, commit = _repository(tmp_path)
    (root / ".agentmemoryignore").write_text("src/old.py\n")
    adapter = GitSourceContentAdapter(
        {REPOSITORY_ID: root},
        content_policy=_Gate(),
        clock=FixedClock(NOW),
    )

    with pytest.raises(IndexingAuthorizationError):
        await adapter.historical(_evidence(commit))
    assert await adapter.checkout_candidates(_evidence(commit)) == ()


@pytest.mark.asyncio
@pytest.mark.security
async def test_local_path_resolution_blocks_traversal_symlinks_and_hash_races(
    tmp_path: Path,
) -> None:
    root, _commit = _repository(tmp_path)
    resolver = BoundedLocalPathResolver({REPOSITORY_ID: root})
    digest = hashlib.sha256(HISTORICAL).hexdigest()

    assert await resolver.resolve(REPOSITORY_ID, "src/old.py", digest) == str(
        (root / "src" / "old.py").resolve()
    )
    assert await resolver.resolve(REPOSITORY_ID, "src/old.py", "f" * 64) is None
    with pytest.raises(IndexingValidationError):
        await resolver.resolve(REPOSITORY_ID, "../outside.py", digest)

    outside = tmp_path / "outside.py"
    outside.write_bytes(HISTORICAL)
    (root / "src" / "escape.py").symlink_to(outside)
    with pytest.raises(IndexingAuthorizationError):
        await resolver.resolve(REPOSITORY_ID, "src/escape.py", digest)
