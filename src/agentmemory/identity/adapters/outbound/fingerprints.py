"""Installation-keyed privacy-safe identity fingerprint adapter."""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from dataclasses import dataclass

from agentmemory.identity.domain.errors import IdentityValidationError
from agentmemory.identity.domain.services import normalize_git_remote
from agentmemory.identity.domain.value_objects import Fingerprint, StableId, VcsType

_MIN_KEY_BYTES = 32
_OBJECT_ID_LENGTHS = frozenset({40, 64})


@dataclass(frozen=True, slots=True)
class IdentityFingerprinter:
    """Create versioned HMAC indexes without persisting raw host evidence."""

    _key: bytes

    def __post_init__(self) -> None:
        """Require an installation-secret key with at least 256 bits."""
        if len(self._key) < _MIN_KEY_BYTES:
            msg = "identity index key must contain at least 256 bits"
            raise IdentityValidationError(msg)

    def remote(self, remote: str) -> Fingerprint:
        """Normalize then immediately HMAC one approved network remote."""
        return self._digest(
            {"algorithm": "GitRemoteFingerprintV1", "remote": normalize_git_remote(remote)}
        )

    def repository(
        self,
        vcs_type: VcsType,
        object_format: str,
        root_ids: tuple[str, ...],
        stable_repository_id: StableId | None,
        primary_remote: str | None,
    ) -> Fingerprint:
        """Bind VCS type, canonical roots, configured ID, and normalized remote."""
        normalized_format = object_format.strip().lower()
        expected_length = 40 if normalized_format == "sha1" else 64
        roots = tuple(sorted(set(root_ids)))
        if (
            normalized_format not in {"sha1", "sha256"}
            or not roots
            or any(
                len(value) != expected_length
                or len(value) not in _OBJECT_ID_LENGTHS
                or any(character not in "0123456789abcdef" for character in value)
                for value in roots
            )
        ):
            msg = "Git root identity evidence is malformed"
            raise IdentityValidationError(msg)
        remote_fingerprint = None if primary_remote is None else self.remote(primary_remote).value
        return self._digest(
            {
                "algorithm": "GitRepositoryFingerprintV1",
                "object_format": normalized_format,
                "primary_remote_fingerprint": remote_fingerprint,
                "root_ids": list(roots),
                "stable_repository_id": (
                    None if stable_repository_id is None else stable_repository_id.value
                ),
                "vcs_type": vcs_type.value,
            }
        )

    def path(self, device_id: StableId, volume_identity: str, real_path: str) -> Fingerprint:
        """Hash mutable path evidence separately from durable Repository identity."""
        normalized_path = unicodedata.normalize("NFC", real_path)
        normalized_volume = unicodedata.normalize("NFC", volume_identity)
        if not normalized_path or not normalized_volume:
            msg = "path identity evidence is incomplete"
            raise IdentityValidationError(msg)
        return self._digest(
            {
                "algorithm": "CanonicalPathFingerprintV1",
                "device_id": device_id.value,
                "real_path": normalized_path,
                "volume_identity": normalized_volume,
            }
        )

    def checkout(
        self,
        repository_fingerprint: Fingerprint,
        device_id: StableId,
        volume_fingerprint: Fingerprint,
        path_fingerprint: Fingerprint,
        worktree_identity: str | None,
    ) -> Fingerprint:
        """Bind one clone/worktree observation without making its path a Repository ID."""
        return self._digest(
            {
                "algorithm": "CheckoutFingerprintV1",
                "device_id": device_id.value,
                "path_fingerprint": path_fingerprint.value,
                "repository_fingerprint": repository_fingerprint.value,
                "volume_fingerprint": volume_fingerprint.value,
                "worktree_identity": worktree_identity,
            }
        )

    def opaque(self, algorithm: str, value: str) -> Fingerprint:
        """HMAC a bounded adapter-only identity such as a volume or worktree ID."""
        if not algorithm or not value:
            msg = "opaque identity evidence is incomplete"
            raise IdentityValidationError(msg)
        return self._digest({"algorithm": algorithm, "value": value})

    def _digest(self, value: dict[str, object]) -> Fingerprint:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return Fingerprint(hmac.new(self._key, canonical, hashlib.sha256).hexdigest())
