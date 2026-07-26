from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from agentmemory.providers.adapters import model_artifact
from agentmemory.providers.adapters.model_artifact import (
    ModelArtifactBinding,
    verify_model_artifact,
)
from agentmemory.providers.adapters.protected_file import (
    read_capability,
    read_provider_credential,
    read_provider_document,
    zero,
)
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.models import ProviderRole

if TYPE_CHECKING:
    from pathlib import Path


def test_strict_json_is_canonical_and_rejects_ambiguity() -> None:
    assert canonical_bytes({"b": 2, "a": "é"}) == b'{"a":"\xc3\xa9","b":2}'
    assert require_object(loads(b'{"a":1}')) == {"a": 1}
    for payload in (b'{"a":1,"a":2}', b'{"x":NaN}', b"{", b"[]"):
        with pytest.raises(StrictJsonError):
            require_object(loads(payload))
    with pytest.raises(StrictJsonError, match="cannot be encoded"):
        canonical_bytes({"bad": object()})
    with pytest.raises(StrictJsonError, match="non-string"):
        require_object({1: "bad"})


def _private_file(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_capability_read_is_descriptor_bound_and_zeroable(tmp_path: Path) -> None:
    path = _private_file(tmp_path / "capability", b"c" * 32)
    secret = read_capability(path)
    assert secret == b"c" * 32
    zero(secret)
    assert secret == b"\0" * 32


@pytest.mark.parametrize(
    ("content", "mode"),
    [(b"short", 0o600), (b"x" * 33, 0o600), (b"x" * 32, 0o644)],
)
def test_capability_rejects_size_and_permissions(tmp_path: Path, content: bytes, mode: int) -> None:
    path = _private_file(tmp_path / "capability", content)
    path.chmod(mode)
    with pytest.raises(PermissionError):
        read_capability(path)


def test_capability_rejects_links(tmp_path: Path) -> None:
    target = _private_file(tmp_path / "target", b"x" * 32)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(target)
    with pytest.raises(OSError, match=r"symbolic|levels"):
        read_capability(symlink)
    hardlink = tmp_path / "hardlink"
    os.link(target, hardlink)
    with pytest.raises(PermissionError):
        read_capability(target)


def test_capability_read_supports_platform_without_nofollow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_file(tmp_path / "capability", b"c" * 32)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    assert read_capability(path) == b"c" * 32


def test_capability_read_rejects_identity_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_file(tmp_path / "capability", b"c" * 32)
    descriptor = os.open(path, os.O_RDONLY)
    observed = os.fstat(descriptor)
    os.close(descriptor)
    changed = SimpleNamespace(
        st_dev=observed.st_dev,
        st_ino=observed.st_ino + 1,
        st_size=observed.st_size,
    )
    observations = iter((observed, changed))

    def changed_fstat(_descriptor: int) -> os.stat_result | SimpleNamespace:
        return next(observations)

    monkeypatch.setattr(os, "fstat", changed_fstat)
    with pytest.raises(PermissionError, match="changed"):
        read_capability(path)


@pytest.mark.parametrize("maximum_bytes", [0, 4097])
def test_provider_credential_rejects_open_ended_length_policy(
    tmp_path: Path,
    maximum_bytes: int,
) -> None:
    path = _private_file(tmp_path / "credential", b"secret")

    with pytest.raises(ValueError, match="length policy"):
        read_provider_credential(path, maximum_bytes)


@pytest.mark.parametrize("maximum_bytes", [0, 4 * 1024 * 1024 + 1])
def test_provider_document_rejects_open_ended_length_policy(
    tmp_path: Path,
    maximum_bytes: int,
) -> None:
    path = _private_file(tmp_path / "document", b"{}")

    with pytest.raises(ValueError, match="length policy"):
        read_provider_document(path, maximum_bytes)


def _bind_model(monkeypatch: pytest.MonkeyPatch, path: Path, role: ProviderRole) -> None:
    monkeypatch.setitem(model_artifact._MODEL_PATHS, role, path)


def test_model_artifact_accepts_only_exact_regular_release_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"real-gguf-fixture"
    path = _private_file(tmp_path / "model.gguf", content)
    _bind_model(monkeypatch, path, ProviderRole.EMBEDDING)
    binding = ModelArtifactBinding(
        ProviderRole.EMBEDDING,
        hashlib.sha256(content).hexdigest(),
        len(content),
    )
    assert binding.path == path
    assert verify_model_artifact(binding) == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize(
    ("digest", "size"),
    [("short", 1), ("g" * 64, 1), ("a" * 64, 0), ("a" * 64, 16 * 1024**3 + 1)],
)
def test_model_artifact_rejects_invalid_inventory_binding(digest: str, size: int) -> None:
    with pytest.raises(ValueError, match="binding"):
        verify_model_artifact(ModelArtifactBinding(ProviderRole.EMBEDDING, digest, size))


def test_model_artifact_rejects_digest_size_mode_and_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _private_file(tmp_path / "model.gguf", b"model")
    _bind_model(monkeypatch, path, ProviderRole.RERANKING)
    with pytest.raises(PermissionError, match="digest"):
        verify_model_artifact(ModelArtifactBinding(ProviderRole.RERANKING, "a" * 64, 5))
    with pytest.raises(PermissionError, match="unsafe"):
        verify_model_artifact(
            ModelArtifactBinding(
                ProviderRole.RERANKING,
                hashlib.sha256(b"model").hexdigest(),
                4,
            )
        )
    path.chmod(0o602)
    with pytest.raises(PermissionError, match="unsafe"):
        verify_model_artifact(
            ModelArtifactBinding(
                ProviderRole.RERANKING,
                hashlib.sha256(b"model").hexdigest(),
                5,
            )
        )
    path.chmod(0o600)
    linked = tmp_path / "linked"
    os.link(path, linked)
    with pytest.raises(PermissionError, match="unsafe"):
        verify_model_artifact(
            ModelArtifactBinding(
                ProviderRole.RERANKING,
                hashlib.sha256(b"model").hexdigest(),
                5,
            )
        )
    linked.unlink()
    symlink = tmp_path / "symlink"
    symlink.symlink_to(path)
    _bind_model(monkeypatch, symlink, ProviderRole.RERANKING)
    with pytest.raises(OSError, match=r"symbolic|levels"):
        verify_model_artifact(
            ModelArtifactBinding(
                ProviderRole.RERANKING,
                hashlib.sha256(b"model").hexdigest(),
                5,
            )
        )


def test_model_artifact_supports_platform_without_nofollow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"model"
    path = _private_file(tmp_path / "model.gguf", content)
    _bind_model(monkeypatch, path, ProviderRole.EXTRACTION)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    binding = ModelArtifactBinding(
        ProviderRole.EXTRACTION, hashlib.sha256(content).hexdigest(), len(content)
    )
    assert verify_model_artifact(binding) == binding.sha256


@pytest.mark.parametrize("mode", ["early-eof", "trailing-byte", "identity-drift"])
def test_model_artifact_rejects_stream_and_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    content = b"model"
    path = _private_file(tmp_path / "model.gguf", content)
    _bind_model(monkeypatch, path, ProviderRole.EXTRACTION)
    binding = ModelArtifactBinding(
        ProviderRole.EXTRACTION, hashlib.sha256(content).hexdigest(), len(content)
    )
    real_read = os.read
    if mode == "early-eof":

        def early_eof(_descriptor: int, _size: int) -> bytes:
            return b""

        monkeypatch.setattr(os, "read", early_eof)
    elif mode == "trailing-byte":
        calls = iter((content, b"x"))

        def trailing_byte(_descriptor: int, _size: int) -> bytes:
            return next(calls)

        monkeypatch.setattr(os, "read", trailing_byte)
    else:
        descriptor = os.open(path, os.O_RDONLY)
        observed = os.fstat(descriptor)
        os.close(descriptor)
        changed = SimpleNamespace(
            st_dev=observed.st_dev,
            st_ino=observed.st_ino + 1,
            st_size=observed.st_size,
        )
        observations = iter((observed, changed))

        def changed_fstat(_descriptor: int) -> os.stat_result | SimpleNamespace:
            return next(observations)

        monkeypatch.setattr(os, "fstat", changed_fstat)
        monkeypatch.setattr(os, "read", real_read)
    with pytest.raises(PermissionError, match=r"drifted|changed"):
        verify_model_artifact(binding)
