"""Fail-closed verification of release-injected GGUF model artifacts."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from agentmemory.providers.domain.models import ProviderRole

_CHUNK_BYTES = 1024 * 1024
_SHA256_HEX_CHARACTERS = 64
_MODEL_PATHS = {
    ProviderRole.EMBEDDING: Path("/models/embedding/model.gguf"),
    ProviderRole.RERANKING: Path("/models/reranking/model.gguf"),
    ProviderRole.EXTRACTION: Path("/models/extraction/model.gguf"),
}


@dataclass(frozen=True, slots=True)
class ModelArtifactBinding:
    """Exact signed inventory projection needed by the sidecar."""

    role: ProviderRole
    sha256: str
    size: int

    @property
    def path(self) -> Path:
        """Return the only mount path accepted for this role."""
        return _MODEL_PATHS[self.role]


def verify_model_artifact(binding: ModelArtifactBinding) -> str:
    """Hash a regular immutable mount leaf and return its verified digest."""
    if (
        len(binding.sha256) != _SHA256_HEX_CHARACTERS
        or any(character not in "0123456789abcdef" for character in binding.sha256)
        or not 1 <= binding.size <= 16 * 1024 * 1024 * 1024
    ):
        msg = "model artifact binding is invalid"
        raise ValueError(msg)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(binding.path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != binding.size
            or stat.S_IMODE(before.st_mode) & 0o002
        ):
            msg = "model artifact file is unsafe"
            raise PermissionError(msg)
        digest = hashlib.sha256()
        observed = 0
        while observed < binding.size:
            chunk = os.read(descriptor, min(_CHUNK_BYTES, binding.size - observed))
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        if observed != binding.size or os.read(descriptor, 1):
            msg = "model artifact length drifted"
            raise PermissionError(msg)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            msg = "model artifact changed while hashing"
            raise PermissionError(msg)
        observed_digest = digest.hexdigest()
        if observed_digest != binding.sha256:
            msg = "model artifact digest does not match the release inventory"
            raise PermissionError(msg)
        return observed_digest
    finally:
        os.close(descriptor)
