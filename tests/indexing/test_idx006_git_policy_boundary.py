"""IDX-006 real Git pre-open enforcement and downstream egress isolation tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.git_incremental_source import (
    GitIncrementalRepositorySource,
)
from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyAction,
    PolicyDecision,
    PolicyLayer,
    PolicyRule,
    PolicyRuleSource,
)
from agentmemory.indexing.domain.errors import IndexingAuthorizationError
from tests.core.support import BRAIN_ID, NOW, FixedClock

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

    from agentmemory.indexing.domain.content_policy_ports import PolicySourceDocuments

REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
POLICY_ID = "018f0000-0000-7000-8000-000000000601"


def _git(root: Path, *arguments: str) -> None:
    executable = shutil.which("git")
    assert executable is not None
    subprocess.run(  # noqa: S603 -- Test invokes resolved Git with fixed arguments.
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.email", "idx006@example.invalid")
    _git(root, "config", "user.name", "IDX-006 Test")
    (root / "vendor").mkdir()
    (root / "src").mkdir()
    (root / ".agentmemoryignore").write_text("src/ignored.py\n")
    (root / ".gitignore").write_text("src/git-ignored.py\n")
    (root / "vendor" / "library.py").write_text("do_not_open = True\n")
    (root / "src" / "allowed.py").write_text("allowed = True\n")
    (root / "src" / "ignored.py").write_text("ignored = True\n")
    (root / "src" / "git-ignored.py").write_text("git_ignored = True\n")
    (root / "src" / "large.py").write_bytes(b"x" * 65)
    (root / "src" / "binary.bin").write_bytes(b"abc\x00def")
    (root / "src" / "force.bin").write_bytes(b"abc\x00def")
    (root / "src" / "encrypted.age").write_bytes(b"age-encryption.org/v1\nsecret")
    (root / "src" / "private.py").write_text(
        "<agentmemory-private>never-egress</agentmemory-private>"
    )
    (root / "src" / "link.py").symlink_to(root / "src" / "allowed.py")
    _git(root, "add", "--", ".agentmemoryignore", ".gitignore", "src/allowed.py")
    _git(root, "commit", "-m", "policy baseline")
    return root


@dataclass
class _Gate:
    decisions: list[PolicyDecision] = field(default_factory=list[PolicyDecision])

    async def prepare(
        self,
        repository_id: str,
        documents: PolicySourceDocuments,
        observed_at: datetime,
    ) -> IndexContentPolicy:
        brain = PolicyRuleSource.create(
            PolicyLayer.BRAIN,
            1,
            (
                PolicyRule(
                    PolicyLayer.BRAIN,
                    "brain.force_binary",
                    1,
                    "src/force.bin",
                    PolicyAction.INCLUDE,
                ),
            ),
        )
        revision = IndexPolicyRevision(
            policy_id=POLICY_ID,
            version=1,
            brain_id=BRAIN_ID,
            repository_id=repository_id,
            brain_rules=brain,
            max_file_bytes=64,
            private_block_pairs=(("<agentmemory-private>", "</agentmemory-private>"),),
            exclude_binary=True,
            exclude_generated=True,
            exclude_encrypted=True,
            activated_at=observed_at,
        )
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


@pytest.mark.asyncio
@pytest.mark.privacy
async def test_excluded_paths_never_open_and_excluded_content_never_reaches_egress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    gate = _Gate()
    adapter = GitIncrementalRepositorySource(
        {REPOSITORY_ID: root},
        content_policy=gate,
        clock=FixedClock(NOW),
    )
    opened: list[str] = []
    original = adapter._read_selected  # pyright: ignore[reportPrivateUsage]

    async def read_spy(
        selected_root: Path,
        target: str,
        relative_path: str,
        *,
        explicit_target: bool,
    ) -> bytes:
        opened.append(relative_path)
        return await original(
            selected_root,
            target,
            relative_path,
            explicit_target=explicit_target,
        )

    monkeypatch.setattr(adapter, "_read_selected", read_spy)
    inspection = await adapter.inspect(REPOSITORY_ID, None, None, ())

    assert {item.relative_path for item in inspection.files} == {
        "src/allowed.py",
        "src/force.bin",
    }
    assert set(opened) == {
        "src/allowed.py",
        "src/binary.bin",
        "src/encrypted.age",
        "src/force.bin",
        "src/private.py",
    }
    assert "src/ignored.py" not in opened
    assert "src/large.py" not in opened
    assert "src/link.py" not in opened
    assert "vendor/library.py" not in opened

    egress_payloads: list[bytes] = []
    for entry in inspection.files:
        artifact = await adapter.read(
            REPOSITORY_ID,
            inspection.target_commit_id,
            entry.relative_path,
            entry.content_digest,
            inspection.revision_context,
        )
        egress_payloads.append(artifact.content)

    assert egress_payloads == [b"allowed = True\n", b"abc\x00def"]
    assert all(b"never-egress" not in payload for payload in egress_payloads)
    assert any(decision.reason == "private_block" for decision in gate.decisions)
    assert any(decision.reason == "binary" for decision in gate.decisions)
    assert any(decision.reason == "encrypted" for decision in gate.decisions)


@pytest.mark.asyncio
@pytest.mark.security
async def test_read_reauthorizes_policy_and_rejects_a_now_excluded_artifact(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    gate = _Gate()
    adapter = GitIncrementalRepositorySource(
        {REPOSITORY_ID: root}, content_policy=gate, clock=FixedClock(NOW)
    )
    inspection = await adapter.inspect(REPOSITORY_ID, None, None, ())
    allowed = next(item for item in inspection.files if item.relative_path == "src/allowed.py")
    (root / ".agentmemoryignore").write_text("src/ignored.py\nsrc/allowed.py\n")

    with pytest.raises(IndexingAuthorizationError, match="changed during indexing"):
        await adapter.read(
            REPOSITORY_ID,
            inspection.target_commit_id,
            allowed.relative_path,
            hashlib.sha256(b"allowed = True\n").hexdigest(),
            inspection.revision_context,
        )
