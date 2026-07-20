"""ID-001 manifest, device, and real Git adapter integration tests."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from agentmemory.identity.adapters.outbound.device_identity import LocalDeviceIdentityAdapter
from agentmemory.identity.adapters.outbound.fingerprints import IdentityFingerprinter
from agentmemory.identity.adapters.outbound.git_identity import GitCliIdentityAdapter
from agentmemory.identity.adapters.outbound.manifest_reader import SecureJsonManifestReader
from agentmemory.identity.domain.errors import IdentityDependencyError, IdentityValidationError
from agentmemory.identity.domain.value_objects import Fingerprint, StableId, VcsType

DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")


def _fingerprinter() -> IdentityFingerprinter:
    return IdentityFingerprinter(b"i" * 32)


@pytest.mark.asyncio
async def test_manifest_reader_accepts_strict_manifest_and_rejects_traversal(
    tmp_path: Path,
) -> None:
    metadata = tmp_path / ".agentmemory"
    metadata.mkdir()
    manifest_path = metadata / "project.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": PROJECT_ID.value,
                "repository_id": REPOSITORY_ID.value,
                "display_name": "AgentMemory",
                "component_roots": ["src", "apps/launcher"],
            }
        ),
        encoding="utf-8",
    )
    manifest = await SecureJsonManifestReader().read(str(tmp_path))
    assert manifest is not None
    assert manifest.project_id == PROJECT_ID
    assert manifest.repository_id == REPOSITORY_ID

    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "project_id": PROJECT_ID.value,
                "component_roots": ["../secret"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(IdentityValidationError, match="relative paths"):
        await SecureJsonManifestReader().read(str(tmp_path))


@pytest.mark.asyncio
async def test_manifest_reader_refuses_symlink_and_unknown_fields(tmp_path: Path) -> None:
    metadata = tmp_path / ".agentmemory"
    metadata.mkdir()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    manifest_path = metadata / "project.json"
    manifest_path.symlink_to(target)
    with pytest.raises(IdentityValidationError, match="regular file"):
        await SecureJsonManifestReader().read(str(tmp_path))
    manifest_path.unlink()
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "project_id": PROJECT_ID.value, "credential": "x"}),
        encoding="utf-8",
    )
    with pytest.raises(IdentityValidationError, match="unsupported fields"):
        await SecureJsonManifestReader().read(str(tmp_path))


@pytest.mark.asyncio
async def test_manifest_reader_handles_absence_and_rejects_invalid_shapes(tmp_path: Path) -> None:
    reader = SecureJsonManifestReader()
    assert await reader.read(str(tmp_path)) is None
    metadata = tmp_path / ".agentmemory"
    metadata.mkdir()
    manifest_path = metadata / "project.json"
    for payload, match in [
        (b"not-json", "invalid JSON"),
        (b"[]", "root must be an object"),
        (json.dumps({"schema_version": True, "project_id": PROJECT_ID.value}).encode(), "types"),
        (
            json.dumps(
                {
                    "schema_version": 1,
                    "project_id": PROJECT_ID.value,
                    "component_roots": ["src", "src"],
                }
            ).encode(),
            "unique",
        ),
        (
            json.dumps(
                {
                    "schema_version": 1,
                    "project_id": PROJECT_ID.value,
                    "component_roots": [1],
                }
            ).encode(),
            "relative paths",
        ),
    ]:
        manifest_path.write_bytes(payload)
        with pytest.raises(IdentityValidationError, match=match):
            await reader.read(str(tmp_path))


@pytest.mark.asyncio
async def test_device_adapter_hides_missing_or_non_directory_host_failures(tmp_path: Path) -> None:
    adapter = LocalDeviceIdentityAdapter(
        DEVICE_ID,
        Fingerprint.from_bytes(b"device"),
        verified=True,
        fingerprinter=_fingerprinter(),
    )
    with pytest.raises(IdentityDependencyError) as missing:
        await adapter.observe(str(tmp_path / "missing"))
    assert "missing" not in str(missing.value)
    file_path = tmp_path / "file"
    file_path.write_text("not a directory", encoding="utf-8")
    with pytest.raises(IdentityDependencyError):
        await adapter.observe(str(file_path))


def test_git_adapter_refuses_path_lookup_for_executable() -> None:
    with pytest.raises(IdentityValidationError, match="absolute path"):
        GitCliIdentityAdapter(Path("git"), _fingerprinter())


@pytest.mark.asyncio
@pytest.mark.integration
async def test_real_git_adapter_preserves_repository_across_path_move(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is unavailable in this supported-runtime test environment")
    original = tmp_path / "original"
    original.mkdir()
    await _run(git, "init", str(original))
    await _run(git, "-C", str(original), "config", "user.name", "AgentMemory Test")
    await _run(git, "-C", str(original), "config", "user.email", "test@example.invalid")
    (original / "README.md").write_text("identity\n", encoding="utf-8")
    await _run(git, "-C", str(original), "add", "README.md")
    await _run(git, "-C", str(original), "commit", "-m", "identity")
    await _run(
        git,
        "-C",
        str(original),
        "remote",
        "add",
        "origin",
        "https://user:secret@Example.COM/Org/Repo.git?token=secret",
    )

    device_adapter = LocalDeviceIdentityAdapter(
        DEVICE_ID,
        Fingerprint.from_bytes(b"device"),
        verified=True,
        fingerprinter=_fingerprinter(),
    )
    git_adapter = GitCliIdentityAdapter(Path(git), _fingerprinter())
    first_device = await device_adapter.observe(str(original))
    first = await git_adapter.observe(str(original), first_device)
    assert first is not None
    assert first.vcs_type is VcsType.GIT

    moved = tmp_path / "moved"
    original.rename(moved)
    moved_device = await device_adapter.observe(str(moved))
    second = await git_adapter.observe(str(moved), moved_device)
    assert second is not None
    assert second.repository_fingerprint == first.repository_fingerprint
    assert second.checkout_fingerprint != first.checkout_fingerprint
    assert "secret" not in repr(second)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_real_git_adapter_returns_absence_for_non_git_directory(tmp_path: Path) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git is unavailable in this supported-runtime test environment")
    device_adapter = LocalDeviceIdentityAdapter(
        DEVICE_ID,
        Fingerprint.from_bytes(b"device"),
        verified=True,
        fingerprinter=_fingerprinter(),
    )
    device = await device_adapter.observe(str(tmp_path))
    assert (
        await GitCliIdentityAdapter(Path(git), _fingerprinter()).observe(str(tmp_path), device)
        is None
    )


async def _run(executable: str, *arguments: str) -> None:
    process = await asyncio.create_subprocess_exec(
        executable,
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode(errors="replace")
