"""PF-005 bounded, content-addressed workspace checkpoint contract."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from agentmemory.operations.domain.errors import DomainValidationError

if TYPE_CHECKING:
    from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id

_MAX_CHANGES: Final = 10_000
_MAX_FILE_BYTES: Final = 2 * 1024 * 1024
_MAX_PAYLOAD_BYTES: Final = 16 * 1024 * 1024
_MAX_RELATIVE_PATH_BYTES: Final = 4096


class WorkspaceIndexCoverage(StrEnum):
    """Content-free current indexing coverage visible to the transient bridge."""

    PENDING = "pending"
    INDEXING = "indexing"
    COMPLETE = "complete"
    PARTIAL = "partial"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class WorkspaceCheckpointChange:
    """One authorized relative file delta with verified content digest."""

    relative_path: str
    sha256: Sha256Digest
    content: bytes
    deleted: bool

    def __post_init__(self) -> None:
        """Reject absolute/traversing names, oversized content, and digest substitution."""
        segments = self.relative_path.split("/")
        invalid_path = (
            not self.relative_path
            or len(self.relative_path.encode("utf-8")) > _MAX_RELATIVE_PATH_BYTES
            or self.relative_path.startswith("/")
            or "\\" in self.relative_path
            or any(segment in {"", ".", ".."} for segment in segments)
            or any(character in self.relative_path for character in "\x00\r\n")
        )
        content = bytes(self.content)
        digest = hashlib.sha256(content).hexdigest()
        if (
            invalid_path
            or len(content) > _MAX_FILE_BYTES
            or (self.deleted and content)
            or (not self.deleted and digest != self.sha256.value)
        ):
            message = "workspace checkpoint change is invalid"
            raise DomainValidationError(message)
        object.__setattr__(self, "content", content)

    def document(self) -> dict[str, object]:
        """Return the exact Go-compatible canonical transport projection."""
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256.value,
            "content_base64": base64.b64encode(self.content).decode("ascii"),
            "deleted": self.deleted,
        }


@dataclass(frozen=True, slots=True)
class WorkspaceCheckpointBatch:
    """One terminal ordered workspace delta accepted only by exact digest."""

    session_id: Uuid7Id
    workspace_fingerprint: Sha256Digest
    batch_digest: Sha256Digest
    partial: bool
    changes: tuple[WorkspaceCheckpointChange, ...]

    def __post_init__(self) -> None:
        """Require deterministic ordering, bounded bytes, and exact canonical digest."""
        if len(self.changes) > _MAX_CHANGES:
            message = "workspace checkpoint has too many changes"
            raise DomainValidationError(message)
        paths = tuple(change.relative_path for change in self.changes)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            message = "workspace checkpoint paths are not canonical"
            raise DomainValidationError(message)
        canonical = self.canonical_bytes()
        if (
            len(canonical) > _MAX_PAYLOAD_BYTES
            or hashlib.sha256(canonical).hexdigest() != self.batch_digest.value
        ):
            message = "workspace checkpoint digest is invalid"
            raise DomainValidationError(message)

    def canonical_bytes(self) -> bytes:
        """Encode exactly the request document used by the Go digest, with an empty digest field."""
        return json.dumps(
            {
                "session_id": self.session_id.value,
                "workspace_fingerprint": self.workspace_fingerprint.value,
                "batch_digest": "",
                "partial": self.partial,
                "changes": [change.document() for change in self.changes],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()


@dataclass(frozen=True, slots=True)
class WorkspaceCheckpointIngestionResult:
    """Content-free idempotent result produced by canonical ingestion."""

    result_sha256: Sha256Digest
    event_count: int

    def __post_init__(self) -> None:
        """Require a bounded result corresponding to at most one event per change."""
        if isinstance(self.event_count, bool) or not 0 <= self.event_count <= _MAX_CHANGES:
            message = "workspace checkpoint ingestion result is invalid"
            raise DomainValidationError(message)
