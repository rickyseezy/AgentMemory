"""ID-003 real Git/non-Git repository-topology fixture corpus."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from agentmemory.identity.adapters.outbound.fingerprints import IdentityFingerprinter
from agentmemory.identity.adapters.outbound.repository_topology import (
    GitCliRepositoryTopologyAdapter,
)
from agentmemory.identity.domain.topology import (
    RepositoryRelationType,
    TopologyConfirmationSource,
    TopologyEvidenceKind,
)
from agentmemory.identity.domain.value_objects import StableId, VcsType

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
PROJECT_TWO_ID = StableId("018f0000-0000-7000-8000-000000000011")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHILD_ID = StableId("018f0000-0000-7000-8000-000000000021")


def _git() -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("Git is unavailable in this supported-runtime test environment")
    return executable


def _adapter() -> GitCliRepositoryTopologyAdapter:
    return GitCliRepositoryTopologyAdapter(Path(_git()), IdentityFingerprinter(b"t" * 32))


async def _run(*arguments: str) -> None:
    process = await asyncio.create_subprocess_exec(
        _git(),
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, (stdout, stderr)


async def _init(repository: Path, repository_id: StableId, message: str = "initial") -> None:
    repository.mkdir(parents=True)  # noqa: ASYNC240 -- Isolated fixture setup before subprocess I/O.
    await _run("init", str(repository))
    await _run("-C", str(repository), "config", "user.name", "AgentMemory Test")
    await _run("-C", str(repository), "config", "user.email", "test@example.invalid")
    (repository / "README.md").write_text(f"{message}\n", encoding="utf-8")
    await _run("-C", str(repository), "add", "README.md")
    await _run("-C", str(repository), "commit", "-m", message)
    metadata = repository / ".agentmemory"
    metadata.mkdir(exist_ok=True)
    (metadata / "repository-id").write_text(repository_id.value, encoding="utf-8")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_nested_git_and_submodule_remain_distinct_evidence_backed_entities(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    await _init(parent, REPOSITORY_ID)
    nested = parent / "tools" / "nested"
    await _init(nested, CHILD_ID, "nested")
    nested_result = await _adapter().discover(str(parent), BRAIN_ID)
    contains = [
        candidate
        for candidate in nested_result.candidates
        if candidate.relation_type is RepositoryRelationType.CONTAINS_REPOSITORY
    ]
    assert len(contains) == 1
    assert contains[0].subject_id == REPOSITORY_ID
    assert contains[0].target_id == CHILD_ID
    assert contains[0].subject_id != contains[0].target_id

    submodule_source = tmp_path / "submodule-source"
    await _init(submodule_source, CHILD_ID, "submodule")
    submodule_parent = tmp_path / "submodule-parent"
    await _init(submodule_parent, REPOSITORY_ID, "parent")
    await _run(
        "-c",
        "protocol.file.allow=always",
        "-C",
        str(submodule_parent),
        "submodule",
        "add",
        str(submodule_source),
        "vendor/child",
    )
    child_metadata = submodule_parent / "vendor" / "child" / ".agentmemory"
    child_metadata.mkdir(exist_ok=True)
    (child_metadata / "repository-id").write_text(CHILD_ID.value, encoding="utf-8")
    result = await _adapter().discover(str(submodule_parent), BRAIN_ID)
    submodules = [
        candidate
        for candidate in result.candidates
        if candidate.relation_type is RepositoryRelationType.SUBMODULE_OF
    ]
    assert len(submodules) == 1
    assert submodules[0].subject_id == CHILD_ID
    assert submodules[0].target_id == REPOSITORY_ID
    assert {item.kind for item in submodules[0].evidence} >= {
        TopologyEvidenceKind.GITLINK,
        TopologyEvidenceKind.GITMODULE_DECLARATION,
    }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_fork_is_candidate_only_and_identical_unrelated_trees_do_not_link(
    tmp_path: Path,
) -> None:
    source = tmp_path / "forks" / "source"
    await _init(source, REPOSITORY_ID, "shared-root")
    await _run(
        "-C",
        str(source),
        "remote",
        "add",
        "origin",
        "ssh://git@example.invalid/upstream/source.git",
    )
    fork = tmp_path / "forks" / "fork"
    await _run("clone", "--no-hardlinks", str(source), str(fork))
    metadata = fork / ".agentmemory"
    metadata.mkdir(exist_ok=True)
    (metadata / "repository-id").write_text(CHILD_ID.value, encoding="utf-8")
    await _run(
        "-C",
        str(fork),
        "remote",
        "set-url",
        "origin",
        "ssh://git@example.invalid/forks/child.git",
    )
    fork_result = await _adapter().discover(str(tmp_path / "forks"), BRAIN_ID)
    forks = [
        candidate
        for candidate in fork_result.candidates
        if candidate.relation_type is RepositoryRelationType.FORK_OF
    ]
    assert len(forks) == 1
    assert {forks[0].subject_id, forks[0].target_id} == {REPOSITORY_ID, CHILD_ID}
    assert not forks[0].can_confirm(TopologyConfirmationSource.DETERMINISTIC_VCS)
    assert forks[0].can_confirm(TopologyConfirmationSource.USER)

    unrelated = tmp_path / "unrelated"
    first = unrelated / "first"
    second = unrelated / "second"
    await _init(first, REPOSITORY_ID, "first-history")
    await _init(second, CHILD_ID, "second-history")
    (first / "same.txt").write_text("identical content\n", encoding="utf-8")
    (second / "same.txt").write_text("identical content\n", encoding="utf-8")
    same_remote = "ssh://git@example.invalid/team/similar.git"
    await _run("-C", str(first), "remote", "add", "origin", same_remote)
    await _run("-C", str(second), "remote", "add", "origin", same_remote)
    unrelated_result = await _adapter().discover(str(unrelated), BRAIN_ID)
    assert all(
        candidate.relation_type is not RepositoryRelationType.FORK_OF
        for candidate in unrelated_result.candidates
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_monorepo_projects_share_one_repo_with_distinct_manifest_scope(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "monorepo"
    await _init(repository, REPOSITORY_ID)
    (repository / "packages" / "frontend").mkdir(parents=True)
    (repository / "packages" / "backend").mkdir(parents=True)
    root_manifest = repository / ".agentmemory" / "project.json"
    root_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": PROJECT_ID.value,
                "repository_id": REPOSITORY_ID.value,
                "component_roots": ["packages/frontend"],
            }
        ),
        encoding="utf-8",
    )
    backend_metadata = repository / "packages" / "backend" / ".agentmemory"
    backend_metadata.mkdir()
    (backend_metadata / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": PROJECT_TWO_ID.value,
                "repository_id": REPOSITORY_ID.value,
            }
        ),
        encoding="utf-8",
    )
    result = await _adapter().discover(str(repository), BRAIN_ID)
    project_links = [
        candidate
        for candidate in result.candidates
        if candidate.relation_type is RepositoryRelationType.PROJECT_USES_REPOSITORY
    ]
    assert {candidate.subject_id for candidate in project_links} == {
        PROJECT_ID,
        PROJECT_TWO_ID,
    }
    assert {candidate.target_id for candidate in project_links} == {REPOSITORY_ID}
    assert len({candidate.component_root_fingerprint for candidate in project_links}) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_bare_and_explicit_non_git_workspaces_are_discovered_without_content_guessing(
    tmp_path: Path,
) -> None:
    bare = tmp_path / "repositories" / "bare.git"
    bare.parent.mkdir()
    await _run("init", "--bare", str(bare))
    bare_metadata = bare / ".agentmemory"
    bare_metadata.mkdir()
    (bare_metadata / "repository-id").write_text(REPOSITORY_ID.value, encoding="utf-8")
    bare_result = await _adapter().discover(str(bare.parent), BRAIN_ID)
    assert len(bare_result.repositories) == 1
    assert bare_result.repositories[0].bare
    assert bare_result.repositories[0].vcs_type is VcsType.GIT

    workspace = tmp_path / "non-git"
    metadata = workspace / ".agentmemory"
    metadata.mkdir(parents=True)
    (metadata / "project.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": PROJECT_ID.value,
                "repository_id": REPOSITORY_ID.value,
                "component_roots": ["src"],
            }
        ),
        encoding="utf-8",
    )
    result = await _adapter().discover(str(workspace), BRAIN_ID)
    assert len(result.repositories) == 1
    assert result.repositories[0].vcs_type is VcsType.NONE
    assert len(result.candidates) == 1
    assert result.candidates[0].relation_type is RepositoryRelationType.PROJECT_USES_REPOSITORY
    assert result.unresolved_repositories == 0
